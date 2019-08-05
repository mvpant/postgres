/*-------------------------------------------------------------------------
 *
 * buf_table.c
 *	  routines for mapping BufferTags to buffer indexes.
 *
 * Note: the routines in this file do no locking of their own.  The caller
 * must hold a suitable lock on the appropriate BufMappingLock, as specified
 * in the comments.  We can't do the locking inside these functions because
 * in most cases the caller needs to adjust the buffer header contents
 * before the lock is released (see notes in README).
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/storage/buffer/buf_table.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "storage/bufmgr.h"
#include "storage/buf_internals.h"


/* entry for buffer lookup hashtable */
typedef struct
{
	BufferTag	key;			/* Tag of a disk page */
	int			id;				/* Associated buffer ID */
} BufferLookupEnt;

static HTAB *SharedBufHash;

static SHMTREE *SharedBufTree;

static SHMTREEBLK *SharedBlockSubtrees;

#define PAYLOAD_MOD 0xF0000000

// #define VALIDATE_ART 1

#define USE_ART 1

// #define USE_HASH 1

SHMTREE *
BufGetMainTree()
{
	return SharedBufTree;
}

void BufLockMainTree(LWLockMode mode)
{
	LWLockAcquire(shmtree_getlock(SharedBufTree), mode);
}

void BufUnLockMainTree()
{
	LWLockRelease(shmtree_getlock(SharedBufTree));
}

void BufTryLockTree(SHMTREE *tree, LWLockMode mode)
{
	if (tree) LWLockAcquire(shmtree_getlock(tree), mode);
}

void BufTryUnLockTree(SHMTREE *tree)
{
	if (tree) LWLockRelease(shmtree_getlock(tree));
}

/*
 * Estimate space needed for mapping hashtable
 *		size is the desired hash table size (possibly more than NBuffers)
 */
Size
BufTableShmemSize(int size)
{
    Size hashsize = hash_estimate_size(size, sizeof(BufferLookupEnt));
    Size shmtree = shmtree_estimate_size(sizeof(BufferTag));

	return hashsize + shmtree;
}

/*
 * Initialize shmem hash table for mapping buffers
 *		size is the desired hash table size (possibly more than NBuffers)
 */
void
InitBufTable(int size)
{
	HASHCTL		info;
    SHMTREECTL  tinfo;
	bool found;

	/* assume no locking is needed yet */

	/* BufferTag maps to Buffer */
	info.keysize = sizeof(BufferTag);
	info.entrysize = sizeof(BufferLookupEnt);
	info.num_partitions = NUM_BUFFER_PARTITIONS;

	SharedBufHash = ShmemInitHash("Shared Buffer Lookup Table",
								  size, size,
								  &info,
								  HASH_ELEM | HASH_BLOBS | HASH_PARTITION);

	tinfo.keysize = sizeof(BufferTag) - sizeof(BlockNumber);
	tinfo.entrysize = sizeof(BufferLookupEnt);
	SharedBufTree = ShmemInitTree("Shared Buffer Lookup Tree",
								  &tinfo,
								  SHMTREE_ELEM);

	SharedBlockSubtrees = ShmemInitStruct("Shared Buffer BlkTrees",
							   shmtree_get_blktree_size(),
							   &found);
	shmtree_build_blktree(SharedBlockSubtrees, SharedBufTree);
}

/*
 * BufTableHashCode
 *		Compute the hash code associated with a BufferTag
 *
 * This must be passed to the lookup/insert/delete routines along with the
 * tag.  We do it like this because the callers need to know the hash code
 * in order to determine which buffer partition to lock, and we don't want
 * to do the hash computation twice (hash_any is a bit slow).
 */
uint32
BufTableHashCode(BufferTag *tagPtr)
{
	return get_hash_value(SharedBufHash, (void *) tagPtr);
}

/*
 * BufTableLookup
 *		Lookup the given BufferTag; return buffer ID, or -1 if not found
 *
 * Caller must hold at least share lock on BufMappingLock for tag's partition
 */
int
BufTableLookup(SHMTREE *subtree, BufferTag *tagPtr, uint32 hashcode)
{
	BufferLookupEnt *result;
#ifdef USE_ART
	bool good = false;
	uintptr_t shmresult = 0;

	if (subtree)
	{
		shmresult = (uintptr_t) shmtree_search(
			subtree, (const uint8_t *) &tagPtr->blockNum);
	}
#endif
#ifdef USE_HASH
	result = (BufferLookupEnt *)
		hash_search_with_hash_value(SharedBufHash,
									(void *) tagPtr,
									hashcode,
									HASH_FIND,
									NULL);
#endif
#ifdef VALIDATE_ART
	if (!shmresult)
	{
		good = (result == NULL);
		if (!good)
		{
			elog(WARNING, "lookup:shmtree did not found, hash did.");
		}
	}
	else
	{
		good = (result != NULL);
		if (good)
		{
			good = result->id == (shmresult & ~PAYLOAD_MOD);
			if (!good) {
				elog(WARNING, "lookup:shmtree mismatch. hash=%d tree=%zu",
					result->id, shmresult & ~PAYLOAD_MOD);
			}
		}
		else
		{
			elog(WARNING, "lookup:shmtree found tag, hash not.");
		}
	}
#endif
#ifdef USE_ART
	if (!shmresult)
		return -1;

	return shmresult & ~PAYLOAD_MOD;
#endif
#ifdef USE_HASH
	if (!result)
		return -1;

	return result->id;
#endif
}

/*
 * BufTableInsert
 *		Insert a hashtable entry for given tag and buffer ID,
 *		unless an entry already exists for that tag
 *
 * Returns -1 on successful insertion.  If a conflicting entry exists
 * already, returns the buffer ID in that entry.
 *
 * Caller must hold exclusive lock on BufMappingLock for tag's partition
 */
int
BufTableInsert(SHMTREE *subtree, BufferTag *tagPtr, uint32 hashcode, int buf_id)
{
	BufferLookupEnt *result;
	bool		found;

	Assert(buf_id >= 0);		/* -1 is reserved for not-in-table */
	Assert(tagPtr->blockNum != P_NEW);	/* invalid tag */

#ifdef USE_ART
	bool good = false;
	uintptr_t shmresult;
	uint64_t payload = PAYLOAD_MOD | buf_id;

	Assert(subtree);

	shmresult = (uintptr_t) shmtree_insert(
		subtree, (const uint8_t *) &tagPtr->blockNum, (void *) payload);
#endif
#ifdef USE_HASH
	result = (BufferLookupEnt *)
		hash_search_with_hash_value(SharedBufHash,
									(void *) tagPtr,
									hashcode,
									HASH_ENTER,
									&found);
#endif
#ifdef VALIDATE_ART
	if (shmresult) // found existing tag
	{
		good = (result != NULL);
		if (good)
		{
			good = result->id == (shmresult & ~PAYLOAD_MOD);
			if (!good)
			{
				elog(WARNING, "insert:shmtree mismatch. hash=%d told=%zu tnew=%d",
						result->id, shmresult & ~PAYLOAD_MOD, buf_id);
			}
		}
		else
		{
			elog(WARNING, "insert:shmtree found old, hash did not");
		}
	}
	else // didnt find anything
	{
		if (found)
		{
			elog(WARNING, "insert:shmtree did not find, but hash did");
		}
		result->id = buf_id;
	}
#endif
#ifdef USE_ART
	if (shmresult)
		return shmresult & ~PAYLOAD_MOD;

	return -1;
#endif
#ifdef USE_HASH
	if (found)					/* found something already in the table */
		return result->id;

	result->id = buf_id;

	return -1;
#endif
}

/*
 * BufTableDelete
 *		Delete the hashtable entry for given tag (which must exist)
 *
 * Caller must hold exclusive lock on BufMappingLock for tag's partition
 */
void
BufTableDelete(SHMTREE *subtree, BufferTag *tagPtr, uint32 hashcode)
{
	BufferLookupEnt *result;
	bool good = false;
	uintptr_t shmresult;

#ifdef USE_ART
	Assert(subtree);

	shmresult = (uintptr_t) shmtree_delete(
		subtree, (const uint8_t *) &tagPtr->blockNum);
#endif
#ifdef USE_HASH
	result = (BufferLookupEnt *)
		hash_search_with_hash_value(SharedBufHash,
									(void *) tagPtr,
									hashcode,
									HASH_REMOVE,
									NULL);
#endif
#ifdef USE_ART
	if (!shmresult)
	{
		elog(WARNING, "delete:shmtree corrupted");
	}
#endif
#ifdef VALIDATE_ART
	else
	{
		good = result->id == (shmresult & ~PAYLOAD_MOD);
		if (!good)
		{
			elog(WARNING, "delete:shmtree mismatch. hash=%d tree=%zu",
					result->id, shmresult & ~PAYLOAD_MOD);
		}
	}
#endif
#ifdef USE_HASH
	if (!result)				/* shouldn't happen */
		elog(ERROR, "shared buffer hash table corrupted");
#endif
}

long *
BufTreeStats(void)
{
	return shmtree_nodes_used(SharedBufTree, SharedBlockSubtrees);
}

SHMTREE *
BufInstallSubtree(SMgrRelation smgr, BufferTag *tagPtr)
{
	SHMTREE *subtree;
	uintptr_t shmresult;

	subtree = smgr->cached_forks[tagPtr->forkNum];
	if (!subtree)
	{
		subtree = shmtree_alloc_blktree(SharedBlockSubtrees);
		shmresult = (uintptr_t) shmtree_insert(
			SharedBufTree, (const uint8_t *) tagPtr, (void *) subtree);
		// check no collision appeared, if it is => dealloc?
		if (shmresult != 0)
		{
			shmtree_dealloc_blktree(SharedBlockSubtrees, subtree);
			subtree = (SHMTREE *) shmresult;
			elog(WARNING, "install:subtree collision.");
		}
		smgr->cached_forks[tagPtr->forkNum] = subtree;
	}
	return subtree;
}

void
BufUnistallSubtree(BufferTag *tagPtr)
{
	SHMTREE *subtree;

	subtree = (SHMTREE *) shmtree_delete(
		SharedBufTree, (const uint8_t *) tagPtr);

	if (subtree)
	{
		shmtree_dealloc_blktree(SharedBlockSubtrees, subtree);
	}
	// todo: send message to backends to invalidate cache...
	// or it is(probably) already done in CacheInvalidateSmgr(rnode);
	// need to check that functionality, so we can move towards subtree recycling
}

SHMTREE *
BufLookupSubtree(SMgrRelation smgr, BufferTag *tagPtr)
{
	SHMTREE *subtree;
	
	// todo: need somehow invalidate subtree (add & check flag inside art_tree?)
	// but first recycle functionaly required
	subtree = smgr->cached_forks[tagPtr->forkNum];
	if (!subtree)
	{
		subtree = (SHMTREE *) shmtree_search(
			SharedBufTree, (const uint8_t *) tagPtr);
		smgr->cached_forks[tagPtr->forkNum] = subtree;
	}

	return subtree;
}

SHMTREE *
BufLookupSubtreeNoCache(BufferTag *tagPtr)
{
	SHMTREE *subtree;
	
	subtree = (SHMTREE *) shmtree_search(
		SharedBufTree, (const uint8_t *) tagPtr);

	return subtree;
}
