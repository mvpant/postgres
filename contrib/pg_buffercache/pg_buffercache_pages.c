/*-------------------------------------------------------------------------
 *
 * pg_buffercache_pages.c
 *	  display some contents of the buffer cache
 *
 *	  contrib/pg_buffercache/pg_buffercache_pages.c
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "funcapi.h"
#include "storage/buf_internals.h"
#include "storage/bufmgr.h"
#include "utils/shm_tree.h"


#define NUM_BUFFERCACHE_PAGES_MIN_ELEM	8
#define NUM_BUFFERCACHE_PAGES_ELEM	9

PG_MODULE_MAGIC;

/*
 * Record structure holding the to be exposed cache data.
 */
typedef struct
{
	uint32		bufferid;
	Oid			relfilenode;
	Oid			reltablespace;
	Oid			reldatabase;
	ForkNumber	forknum;
	BlockNumber blocknum;
	bool		isvalid;
	bool		isdirty;
	uint16		usagecount;

	/*
	 * An int32 is sufficiently large, as MAX_BACKENDS prevents a buffer from
	 * being pinned by too many backends and each backend will only pin once
	 * because of bufmgr.c's PrivateRefCount infrastructure.
	 */
	int32		pinning_backends;
} BufferCachePagesRec;


/*
 * Function context for data persisting over repeated calls.
 */
typedef struct
{
	TupleDesc	tupdesc;
	BufferCachePagesRec *record;
} BufferCachePagesContext;


/*
 * Function returning data from the shared buffer cache - buffer number,
 * relation node/tablespace/database/blocknum and dirty indicator.
 */
PG_FUNCTION_INFO_V1(pg_buffercache_pages);

Datum
pg_buffercache_pages(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	Datum		result;
	MemoryContext oldcontext;
	BufferCachePagesContext *fctx;	/* User function context. */
	TupleDesc	tupledesc;
	TupleDesc	expected_tupledesc;
	HeapTuple	tuple;

	if (SRF_IS_FIRSTCALL())
	{
		int			i;

		funcctx = SRF_FIRSTCALL_INIT();

		/* Switch context when allocating stuff to be used in later calls */
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		/* Create a user function context for cross-call persistence */
		fctx = (BufferCachePagesContext *) palloc(sizeof(BufferCachePagesContext));

		/*
		 * To smoothly support upgrades from version 1.0 of this extension
		 * transparently handle the (non-)existence of the pinning_backends
		 * column. We unfortunately have to get the result type for that... -
		 * we can't use the result type determined by the function definition
		 * without potentially crashing when somebody uses the old (or even
		 * wrong) function definition though.
		 */
		if (get_call_result_type(fcinfo, NULL, &expected_tupledesc) != TYPEFUNC_COMPOSITE)
			elog(ERROR, "return type must be a row type");

		if (expected_tupledesc->natts < NUM_BUFFERCACHE_PAGES_MIN_ELEM ||
			expected_tupledesc->natts > NUM_BUFFERCACHE_PAGES_ELEM)
			elog(ERROR, "incorrect number of output arguments");

		/* Construct a tuple descriptor for the result rows. */
		tupledesc = CreateTemplateTupleDesc(expected_tupledesc->natts, false);
		TupleDescInitEntry(tupledesc, (AttrNumber) 1, "bufferid",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 2, "relfilenode",
						   OIDOID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 3, "reltablespace",
						   OIDOID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 4, "reldatabase",
						   OIDOID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 5, "relforknumber",
						   INT2OID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 6, "relblocknumber",
						   INT8OID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 7, "isdirty",
						   BOOLOID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 8, "usage_count",
						   INT2OID, -1, 0);

		if (expected_tupledesc->natts == NUM_BUFFERCACHE_PAGES_ELEM)
			TupleDescInitEntry(tupledesc, (AttrNumber) 9, "pinning_backends",
							   INT4OID, -1, 0);

		fctx->tupdesc = BlessTupleDesc(tupledesc);

		/* Allocate NBuffers worth of BufferCachePagesRec records. */
		fctx->record = (BufferCachePagesRec *)
			MemoryContextAllocHuge(CurrentMemoryContext,
								   sizeof(BufferCachePagesRec) * NBuffers);

		/* Set max calls and remember the user function context. */
		funcctx->max_calls = NBuffers;
		funcctx->user_fctx = fctx;

		/* Return to original context when allocating transient memory */
		MemoryContextSwitchTo(oldcontext);

		/*
		 * Scan through all the buffers, saving the relevant fields in the
		 * fctx->record structure.
		 *
		 * We don't hold the partition locks, so we don't get a consistent
		 * snapshot across all buffers, but we do grab the buffer header
		 * locks, so the information of each buffer is self-consistent.
		 */
		for (i = 0; i < NBuffers; i++)
		{
			BufferDesc *bufHdr;
			uint32		buf_state;

			bufHdr = GetBufferDescriptor(i);
			/* Lock each buffer header before inspecting. */
			buf_state = LockBufHdr(bufHdr);

			fctx->record[i].bufferid = BufferDescriptorGetBuffer(bufHdr);
			fctx->record[i].relfilenode = bufHdr->tag.rnode.relNode;
			fctx->record[i].reltablespace = bufHdr->tag.rnode.spcNode;
			fctx->record[i].reldatabase = bufHdr->tag.rnode.dbNode;
			fctx->record[i].forknum = bufHdr->tag.forkNum;
			fctx->record[i].blocknum = bufHdr->tag.blockNum;
			fctx->record[i].usagecount = BUF_STATE_GET_USAGECOUNT(buf_state);
			fctx->record[i].pinning_backends = BUF_STATE_GET_REFCOUNT(buf_state);

			if (buf_state & BM_DIRTY)
				fctx->record[i].isdirty = true;
			else
				fctx->record[i].isdirty = false;

			/* Note if the buffer is valid, and has storage created */
			if ((buf_state & BM_VALID) && (buf_state & BM_TAG_VALID))
				fctx->record[i].isvalid = true;
			else
				fctx->record[i].isvalid = false;

			UnlockBufHdr(bufHdr, buf_state);
		}
	}

	funcctx = SRF_PERCALL_SETUP();

	/* Get the saved state */
	fctx = funcctx->user_fctx;

	if (funcctx->call_cntr < funcctx->max_calls)
	{
		uint32		i = funcctx->call_cntr;
		Datum		values[NUM_BUFFERCACHE_PAGES_ELEM];
		bool		nulls[NUM_BUFFERCACHE_PAGES_ELEM];

		values[0] = Int32GetDatum(fctx->record[i].bufferid);
		nulls[0] = false;

		/*
		 * Set all fields except the bufferid to null if the buffer is unused
		 * or not valid.
		 */
		if (fctx->record[i].blocknum == InvalidBlockNumber ||
			fctx->record[i].isvalid == false)
		{
			nulls[1] = true;
			nulls[2] = true;
			nulls[3] = true;
			nulls[4] = true;
			nulls[5] = true;
			nulls[6] = true;
			nulls[7] = true;
			/* unused for v1.0 callers, but the array is always long enough */
			nulls[8] = true;
		}
		else
		{
			values[1] = ObjectIdGetDatum(fctx->record[i].relfilenode);
			nulls[1] = false;
			values[2] = ObjectIdGetDatum(fctx->record[i].reltablespace);
			nulls[2] = false;
			values[3] = ObjectIdGetDatum(fctx->record[i].reldatabase);
			nulls[3] = false;
			values[4] = ObjectIdGetDatum(fctx->record[i].forknum);
			nulls[4] = false;
			values[5] = Int64GetDatum((int64) fctx->record[i].blocknum);
			nulls[5] = false;
			values[6] = BoolGetDatum(fctx->record[i].isdirty);
			nulls[6] = false;
			values[7] = Int16GetDatum(fctx->record[i].usagecount);
			nulls[7] = false;
			/* unused for v1.0 callers, but the array is always long enough */
			values[8] = Int32GetDatum(fctx->record[i].pinning_backends);
			nulls[8] = false;
		}

		/* Build and return the tuple. */
		tuple = heap_form_tuple(fctx->tupdesc, values, nulls);
		result = HeapTupleGetDatum(tuple);

		SRF_RETURN_NEXT(funcctx, result);
	}
	else
		SRF_RETURN_DONE(funcctx);
}

PG_FUNCTION_INFO_V1(pg_buffertree_common);

Datum
pg_buffertree_common(PG_FUNCTION_ARGS)
{
	TupleDesc	tupdesc;
	Datum		values[18];
	bool		nulls[18];
	long		*stats;

	/* Initialise NULL flags array */
	MemSet(nulls, 0, sizeof(nulls));

	/* Initialise attributes information in the tuple descriptor */
	tupdesc = CreateTemplateTupleDesc(18, false);
	TupleDescInitEntry(tupdesc, (AttrNumber) 1, "leaves_used",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2, "node4_used",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 3, "node16_used",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 4, "node48_used",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 5, "node256_used",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 6, "subtrees_used",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 7, "leaves_total",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 8, "node4_total",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 9, "node16_total",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 10, "node48_total",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 11, "node256_total",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 12, "subtrees_total",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 13, "leaves_mem",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 14, "node4_mem",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 15, "node16_mem",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 16, "node48_mem",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 17, "node256_mem",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 18, "subtrees_mem",
					   INT4OID, -1, 0);

	BlessTupleDesc(tupdesc);

	stats = BufTreeStats();

	/* Fill values */
	values[0] = Int32GetDatum(stats[0]);
	values[1] = Int32GetDatum(stats[1]);
	values[2] = Int32GetDatum(stats[2]);
	values[3] = Int32GetDatum(stats[3]);
	values[4] = Int32GetDatum(stats[4]);
	values[5] = Int32GetDatum(stats[5]);
	values[6] = Int32GetDatum(stats[6]);
	values[7] = Int32GetDatum(stats[7]);
	values[8] = Int32GetDatum(stats[8]);
	values[9] = Int32GetDatum(stats[9]);
	values[10] = Int32GetDatum(stats[10]);
	values[11] = Int32GetDatum(stats[11]);
	values[12] = Int32GetDatum(stats[12]);
	values[13] = Int32GetDatum(stats[13]);
	values[14] = Int32GetDatum(stats[14]);
	values[15] = Int32GetDatum(stats[15]);
	values[16] = Int32GetDatum(stats[16]);
	values[17] = Int32GetDatum(stats[17]);

	/* Returns the record as Datum */
	PG_RETURN_DATUM(HeapTupleGetDatum(
									  heap_form_tuple(tupdesc, values, nulls)));
}

#define NUM_BUFFERTREE_STATS_ELEM	9

/*
 * Function context for data persisting over repeated calls.
 */
typedef struct
{
	TupleDesc	tupdesc;
	ARTREE_STATS *record;
} BufferTreeStatsContext;

typedef struct
{
	int record_idx;
	ARTREE_STATS *record;
} TreeIteratorState;

static int
StatsIteratorCallback(void *data, const uint8 *k, uint32_t k_len, void *val)
{
	TreeIteratorState *state = (TreeIteratorState *) data;
	BufferTag *tag = (BufferTag *) k;
	ARTREE *subtree = (ARTREE *) val;
	ARTREE_STATS *stats = &state->record[state->record_idx++];

	artree_fill_stats(subtree, stats);
	stats->rnode = tag->rnode;
	stats->forkNum = tag->forkNum;

	return 0;
}

PG_FUNCTION_INFO_V1(pg_buffertree_stats);

Datum
pg_buffertree_stats(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	Datum		result;
	MemoryContext oldcontext;
	BufferTreeStatsContext *fctx;	/* User function context. */
	TupleDesc	tupledesc;
	TupleDesc	expected_tupledesc;
	HeapTuple	tuple;

	if (SRF_IS_FIRSTCALL())
	{
		ARTREE_STATS		stats;
		TreeIteratorState	iter_state;
		int					max_calls;

		funcctx = SRF_FIRSTCALL_INIT();

		/* Switch context when allocating stuff to be used in later calls */
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		/* Create a user function context for cross-call persistence */
		fctx = (BufferTreeStatsContext *) palloc(sizeof(BufferTreeStatsContext));

		if (get_call_result_type(fcinfo, NULL, &expected_tupledesc) != TYPEFUNC_COMPOSITE)
			elog(ERROR, "return type must be a row type");

		if (expected_tupledesc->natts != NUM_BUFFERTREE_STATS_ELEM)
			elog(ERROR, "incorrect number of output arguments");

		/* Construct a tuple descriptor for the result rows. */
		tupledesc = CreateTemplateTupleDesc(expected_tupledesc->natts, false);
		TupleDescInitEntry(tupledesc, (AttrNumber) 1, "relfilenode",
						   OIDOID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 2, "reltablespace",
						   OIDOID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 3, "reldatabase",
						   OIDOID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 4, "relforknumber",
						   INT2OID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 5, "nleaves",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 6, "nelem4",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 7, "nelem16",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 8, "nelem48",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupledesc, (AttrNumber) 9, "nelem256",
						   INT4OID, -1, 0);

		fctx->tupdesc = BlessTupleDesc(tupledesc);

		/* Lock main tree while we collect stats */
		BufLockMainTree(LW_SHARED);
		BufGetMainTreeStats(&stats);
		max_calls = stats.nleaves + 1;

		fctx->record = (ARTREE_STATS *)
			MemoryContextAllocHuge(CurrentMemoryContext,
								   sizeof(ARTREE_STATS) * max_calls);

		/* Set max calls and remember the user function context. */
		funcctx->max_calls = max_calls;
		funcctx->user_fctx = fctx;

		/* Return to original context when allocating transient memory */
		MemoryContextSwitchTo(oldcontext);

		iter_state.record_idx = 0;
		iter_state.record = fctx->record;
		artree_iter(BufGetMainTree(), StatsIteratorCallback, &iter_state);

		if (max_calls - 1 != iter_state.record_idx)
			elog(ERROR, "incorrect stats in Buffer Shared Tree");

		/* Save stats of the main buffer tree as last record */
		fctx->record[iter_state.record_idx] = stats;

		/* Don't forget to unlock once done */
		BufUnLockMainTree();
	}

	funcctx = SRF_PERCALL_SETUP();

	/* Get the saved state */
	fctx = funcctx->user_fctx;

	if (funcctx->call_cntr < funcctx->max_calls)
	{
		uint32		i = funcctx->call_cntr;
		Datum		values[NUM_BUFFERTREE_STATS_ELEM];
		bool		nulls[NUM_BUFFERTREE_STATS_ELEM];

		MemSet((void *) nulls, 0, sizeof(nulls));

		values[0] = ObjectIdGetDatum(fctx->record[i].rnode.relNode);
		values[1] = ObjectIdGetDatum(fctx->record[i].rnode.spcNode);
		values[2] = ObjectIdGetDatum(fctx->record[i].rnode.dbNode);
		values[3] = ObjectIdGetDatum(fctx->record[i].forkNum);
		values[4] = Int32GetDatum(fctx->record[i].nleaves);
		values[5] = Int32GetDatum(fctx->record[i].nelem4);
		values[6] = Int32GetDatum(fctx->record[i].nelem16);
		values[7] = Int32GetDatum(fctx->record[i].nelem48);
		values[8] = Int32GetDatum(fctx->record[i].nelem256);

		/* Build and return the tuple. */
		tuple = heap_form_tuple(fctx->tupdesc, values, nulls);
		result = HeapTupleGetDatum(tuple);

		SRF_RETURN_NEXT(funcctx, result);
	}
	else
		SRF_RETURN_DONE(funcctx);
}
