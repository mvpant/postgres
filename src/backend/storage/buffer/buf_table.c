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
#include "port/pg_bswap.h"


/* entry for buffer lookup hashtable */
typedef struct
{
	BufferTag	key;			/* Tag of a disk page */
	int			id;				/* Associated buffer ID */
} BufferLookupEnt;

static HTAB *SharedBufHash;

static ARTREE *SharedBufTree;

static FreeListARTree *SharedBlockSubtrees;

/*
 * quantity of leafs should depends on NBuffers and subtree's pool size...
 * if we won't recycle empty subtrees, then, eventually, pool will be exhausted.
 */
#define NODESUBTREE_NELEM 10000

#define PAYLOAD_MOD 0xF0000000

// #define VALIDATE_ART 1

#define USE_ART 1

// #define USE_HASH 1

#ifdef WORDS_BIGENDIAN
#define SETUP_BLOCK_KEY(tagPtr) (tagPtr->blockNum)
#else
#define SETUP_BLOCK_KEY(tagPtr) (pg_bswap32(tagPtr->blockNum))
#endif

ARTREE *
BufGetMainTree()
{
	return SharedBufTree;
}

void BufLockMainTree(LWLockMode mode)
{
	LWLockAcquire(artree_getlock(SharedBufTree), mode);
}

void BufUnLockMainTree()
{
	LWLockRelease(artree_getlock(SharedBufTree));
}

void BufTryLockTree(ARTREE *artp, LWLockMode mode)
{
	if (artp) LWLockAcquire(artree_getlock(artp), mode);
}

void BufTryUnLockTree(ARTREE *artp)
{
	if (artp) LWLockRelease(artree_getlock(artp));
}

/*
 * Estimate space needed for mapping hashtable
 *		size is the desired hash table size (possibly more than NBuffers)
 */
Size
BufTableShmemSize(int size)
{
#ifdef USE_HASH
    Size hashsize = hash_estimate_size(size, sizeof(BufferLookupEnt));
#else
	Size hashsize = 0;
#endif

	return hashsize;
}

/*
 * Estimate space needed for mapping tree
 */
Size
BufTreeShmemSize(int size)
{
#ifdef USE_ART
	Size treesize = artree_estimate_size(NODESUBTREE_NELEM,
										 sizeof(BufferTag) - sizeof(BlockNumber),
										 size,
										 sizeof(BlockNumber),
										 0);
#else
	Size treesize = 0;
#endif

	return treesize;
}

/*
 * Initialize shmem hash table for mapping buffers
 *		size is the desired hash table size (possibly more than NBuffers)
 */
void
InitBufTable(int size)
{
	HASHCTL		info;
	ARTREECTL  tinfo;
	bool found;

	/* assume no locking is needed yet */

#ifdef USE_HASH
	/* BufferTag maps to Buffer */
	info.keysize = sizeof(BufferTag);
	info.entrysize = sizeof(BufferLookupEnt);
	info.num_partitions = NUM_BUFFER_PARTITIONS;

	SharedBufHash = ShmemInitHash("Shared Buffer Lookup Table",
								  size, size,
								  &info,
								  HASH_ELEM | HASH_BLOBS | HASH_PARTITION);
#endif
#ifdef USE_ART
	tinfo.keysize = sizeof(BufferTag) - sizeof(BlockNumber);
	/* in case of buffer tree we can save id inside leaf pointer */
	tinfo.entrysize = 0;
	SharedBufTree = ShmemInitTree("Shared Buffer Lookup Tree",
								  NODESUBTREE_NELEM,
								  NBuffers,
								  &tinfo,
								  ARTREE_ELEM);

	SharedBlockSubtrees = ShmemInitStruct("Shared Buffer Block Trees",
										  artree_subtreelist_size(NODESUBTREE_NELEM),
										  &found);

	artree_build_subtreelist(SharedBlockSubtrees, SharedBufTree,
							 NODESUBTREE_NELEM, NBuffers);
#endif
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
BufTableLookup(ARTREE *subtree, BufferTag *tagPtr, uint32 hashcode)
{
	BufferLookupEnt *result;
#ifdef USE_ART
	uintptr_t shmresult = 0;

	if (subtree)
	{
		uint32 block_key = SETUP_BLOCK_KEY(tagPtr);
		shmresult = (uintptr_t) artree_search(
			subtree, (const uint8 *) &block_key);
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
		if (result != NULL)
		{
			elog(WARNING, "lookup:artree didn't find, hash did.");
		}
	}
	else
	{
		if (result != NULL)
		{
			if (result->id != (shmresult & ~PAYLOAD_MOD)) {
				elog(WARNING, "lookup:artree mismatch. hash=%d tree=%zu",
					result->id, shmresult & ~PAYLOAD_MOD);
			}
		}
		else
		{
			elog(WARNING, "lookup:artree found tag, hash didn't.");
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
BufTableInsert(ARTREE *subtree, BufferTag *tagPtr, uint32 hashcode, int buf_id)
{
	BufferLookupEnt *result;
	bool		found;

	Assert(buf_id >= 0);		/* -1 is reserved for not-in-table */
	Assert(tagPtr->blockNum != P_NEW);	/* invalid tag */

#ifdef USE_ART
	uintptr_t shmresult;
	uint64_t payload = PAYLOAD_MOD | buf_id;
	uint32 block_key = SETUP_BLOCK_KEY(tagPtr);

	Assert(subtree);

	shmresult = (uintptr_t) artree_insert(
		subtree, (const uint8 *) &block_key, (void *) payload);
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
	if (shmresult) /* found existing tag */
	{
		if (result != NULL)
		{
			if (result->id != (shmresult & ~PAYLOAD_MOD))
			{
				elog(WARNING, "insert:artree mismatch. hash=%d told=%zu tnew=%d",
						result->id, shmresult & ~PAYLOAD_MOD, buf_id);
			}
		}
		else
		{
			elog(WARNING, "insert:artree found old, hash did not");
		}
	}
	else /* didnt find anything */
	{
		if (found)
		{
			elog(WARNING, "insert:artree did not find, but hash did");
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
BufTableDelete(ARTREE *subtree, BufferTag *tagPtr, uint32 hashcode)
{
	BufferLookupEnt *result;
	uintptr_t shmresult;

#ifdef USE_ART
	Assert(subtree);
	uint32 block_key = SETUP_BLOCK_KEY(tagPtr);

	shmresult = (uintptr_t) artree_delete(
		subtree, (const uint8 *) &block_key);
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
		elog(WARNING, "delete:artree corrupted");
	}
#endif
#ifdef VALIDATE_ART
	else
	{
		if (result->id != (shmresult & ~PAYLOAD_MOD))
		{
			elog(WARNING, "delete:artree mismatch. hash=%d tree=%zu",
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
	return artree_nodes_used(SharedBufTree, SharedBlockSubtrees, NODESUBTREE_NELEM);
}

ARTREE *
BufInstallSubtree(SMgrRelation smgr, BufferTag *tagPtr)
{
	ARTREE *subtree;
	uintptr_t shmresult;

	subtree = smgr->cached_forks[tagPtr->forkNum];
	if (!subtree)
	{
		subtree = artree_alloc_subtree(SharedBlockSubtrees);
		shmresult = (uintptr_t) artree_insert(
			SharedBufTree, (const uint8 *) tagPtr, (void *) subtree);
		if (shmresult != 0)
		{
			artree_dealloc_subtree(SharedBlockSubtrees, subtree);
			subtree = (ARTREE *) shmresult;
			elog(DEBUG1, "BufInstallSubtree: collision occured.");
		}
		smgr->cached_forks[tagPtr->forkNum] = subtree;
	}
	return subtree;
}

void
BufUnistallSubtree(BufferTag *tagPtr)
{
	ARTREE *subtree;

	subtree = (ARTREE *) artree_delete(
		SharedBufTree, (const uint8 *) tagPtr);

	if (subtree)
	{
		artree_dealloc_subtree(SharedBlockSubtrees, subtree);
	}
	// todo: send message to backends to invalidate cache...
	// or it is(probably) already done in CacheInvalidateSmgr(rnode);
	// need to check that functionality, so we can move towards subtree recycling
	// smgrdounlinkfork
}

ARTREE *
BufLookupSubtree(SMgrRelation smgr, BufferTag *tagPtr)
{
	ARTREE *subtree;
	
	// todo: need somehow invalidate subtree (add & check flag inside art_tree?)
	// but first recycle functionaly required
	subtree = smgr->cached_forks[tagPtr->forkNum];
	if (!subtree)
	{
		subtree = (ARTREE *) artree_search(
			SharedBufTree, (const uint8 *) tagPtr);
		smgr->cached_forks[tagPtr->forkNum] = subtree;
	}

	return subtree;
}

ARTREE *
BufLookupSubtreeNoCache(BufferTag *tagPtr)
{
	ARTREE *subtree;
	
	subtree = (ARTREE *) artree_search(
		SharedBufTree, (const uint8 *) tagPtr);

	return subtree;
}
