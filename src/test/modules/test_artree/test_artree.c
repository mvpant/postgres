#include "postgres.h"

#include "lib/artree.h"
#include "utils/shm_tree.h"

#include "fmgr.h"
#include "nodes/bitmapset.h"
#include "utils/memutils.h"
#include "utils/timestamp.h"
#include "storage/block.h"
#include "storage/itemptr.h"
#include "miscadmin.h"
#include "utils/builtins.h"

#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "funcapi.h"
#include "storage/buf_internals.h"
#include "storage/bufmgr.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(test_artree);
PG_FUNCTION_INFO_V1(pg_stat_get_shmtree);

static void test_art_insert(char *filepath);
static void test_art_insert_search_delete(char *filepath);

/*
 * SQL-callable entry point to perform all tests.
 */
Datum
test_artree(PG_FUNCTION_ARGS)
{
    text *txt = PG_GETARG_TEXT_PP(0);
    char *filepath = text_to_cstring(txt);
    MemoryContext old_context, test_ctx;

    test_ctx = AllocSetContextCreate(
        CurrentMemoryContext, "test_artree context", ALLOCSET_DEFAULT_SIZES);

    old_context = MemoryContextSwitchTo(test_ctx);

    MemoryContextStats(old_context);

    elog(LOG, "%s", filepath);

    test_art_insert(filepath);

    MemoryContextStats(old_context);

    MemoryContextReset(test_ctx);

    test_art_insert_search_delete(filepath);

    MemoryContextSwitchTo(old_context);

    MemoryContextDelete(test_ctx);

    PG_RETURN_VOID();
}

static void
test_art_insert(char *filepath)
{
    int len;
    char buf[512];
    FILE *f;
    uint64 line;
    art_tree *art;

    elog(LOG, "test_art_insert start \n\n");
    art = art_create();

    f = fopen(filepath, "r");

    line = 1;
    while (fgets(buf, sizeof buf, f)) {
        void *value;
        len = strlen(buf);
        buf[len - 1] = '\0';
        value = art_insert(art, (uint8 *) buf, len, (void *) line);
        if (value != NULL) {
            elog(WARNING, "line: " UINT64_FORMAT " str: %s\n", line, buf);
        }
        if (art_num_entries(art) != line) {
            elog(WARNING, "line: " UINT64_FORMAT " size: " UINT64_FORMAT "\n",
                 line, art_num_entries(art));
        }
        line++;
    }
    elog(LOG, "key len %d\n", len);

    fclose(f);

    art_print_nodes_proportion(art);

    elog(LOG, "art_size " UINT64_FORMAT, art_num_entries(art));

    elog(LOG, "test_art_insert end \n\n");
}


static void
test_art_insert_search_delete(char *filepath)
{
    int len;
    char buf[512];
    FILE *f;
    uint64 line;
    art_tree *art;
    const int32 batch_size = 10;
    int32 curr_batch_val;

    elog(LOG, "test_art_insert_search_delete start \n\n");
    art = art_create();

    f = fopen(filepath, "r");

    line = 1;
    while (fgets(buf, sizeof buf, f)) {
        void *value;
        len = strlen(buf);
        buf[len - 1] = '\0';
        value = art_insert(art, (uint8 *) buf, len, (void *) line);
        if (value != NULL) {
            elog(WARNING, "line: " UINT64_FORMAT " str: %s\n", line, buf);
        }
        line++;
    }

    fseek(f, 0, SEEK_SET);

    // search everything
    line = 1;
    while (fgets(buf, sizeof buf, f)) {
        uintptr_t val;
        len = strlen(buf);
        buf[len - 1] = '\0';

        val = (uintptr_t) art_search(art, (uint8 *) buf, len);
        if (line != val) {
            elog(WARNING,
                 "search line: " UINT64_FORMAT " val: " UINT64_FORMAT
                 " str: %s\n",
                 line, val, buf);
        }
        line++;
    }

    fseek(f, 0, SEEK_SET);

    // delete every batch_size
    line = 1;
    curr_batch_val = -batch_size;
    while (fgets(buf, sizeof buf, f)) {
        len = strlen(buf);
        buf[len - 1] = '\0';

        curr_batch_val++;
        if (curr_batch_val > 0) {
            uintptr_t val = (uintptr_t) art_delete(art, (uint8 *) buf, len);
            if (line != val) {
                elog(WARNING,
                     "delete line: " UINT64_FORMAT " val: " UINT64_FORMAT
                     " str: %s\n",
                     line, val, buf);
            }
            if (curr_batch_val >= batch_size) {
                curr_batch_val = -batch_size;
            }
        }
        line++;
    }

    fseek(f, 0, SEEK_SET);

    // search in pruned tree
    line = 1;
    curr_batch_val = -batch_size;
    while (fgets(buf, sizeof buf, f)) {
        len = strlen(buf);
        buf[len - 1] = '\0';

        curr_batch_val++;
        if (curr_batch_val <= 0) {
            uintptr_t val;
            val = (uintptr_t) art_search(art, (uint8 *) buf, len);
            if (line != val) {
                elog(WARNING,
                     "search pruned 1 line: " UINT64_FORMAT " val: " UINT64_FORMAT
                     " str: %s\n",
                     line, val, buf);
            }
        } else {
            void *val = art_search(art, (uint8 *) buf, len);
            if (val != NULL) {
                elog(WARNING,
                     "search pruned 2 line: " UINT64_FORMAT " val: " UINT64_FORMAT
                     " str: %s\n",
                     line, (uintptr_t) val, buf);
            }
            if (curr_batch_val >= batch_size) {
                curr_batch_val = -batch_size;
            }
        }
        line++;
    }

    fclose(f);

    art_print_nodes_proportion(art);

    elog(LOG, "test_art_insert_search_delete end \n\n");

    elog(LOG, "art_size " UINT64_FORMAT, art_num_entries(art));
}

Datum
pg_stat_get_shmtree(PG_FUNCTION_ARGS)
{
	TupleDesc	tupdesc;
	Datum		values[6];
	bool		nulls[6];
	long *vals;

	/* Initialise values and NULL flags arrays */
	MemSet(values, 0, sizeof(values));
	MemSet(nulls, 0, sizeof(nulls));

	/* Initialise attributes information in the tuple descriptor */
	tupdesc = CreateTemplateTupleDesc(6, false);
	TupleDescInitEntry(tupdesc, (AttrNumber) 1, "leafs",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2, "node4",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 3, "node16",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 4, "node48",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 5, "node256",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 6, "subtrees",
					   INT4OID, -1, 0);

	BlessTupleDesc(tupdesc);

	vals = BufTreeStats();

	/* Fill values and NULLs */
	values[0] = Int32GetDatum(vals[0]);
	values[1] = Int32GetDatum(vals[1]);
	values[2] = Int32GetDatum(vals[2]);
	values[3] = Int32GetDatum(vals[3]);
	values[4] = Int32GetDatum(vals[4]);
	values[5] = Int32GetDatum(vals[5]);

	/* Returns the record as Datum */
	PG_RETURN_DATUM(HeapTupleGetDatum(
									  heap_form_tuple(tupdesc, values, nulls)));
}
