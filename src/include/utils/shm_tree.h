
#ifndef ARTREE_H
#define ARTREE_H

#include "storage/lwlock.h"
#include "storage/relfilenode.h"
#include "common/relpath.h"

/*
 * Space allocation function for a tree --- designed to match malloc().
 * Note: there is no free function API; can't destroy a tree unless you
 * use the default allocator.
 */
typedef void *(*TreeAllocFunc) (Size request);

typedef struct ARTMEMHDR ARTMEMHDR;

typedef struct ARTREE ARTREE;

typedef struct FreeListARTree FreeListARTree;

typedef struct ARTREECTL {
	Size keysize;		 /* key length in bytes */
	Size entrysize;		 /* total user element size in bytes */
	TreeAllocFunc alloc; /* memory allocator */
	MemoryContext hcxt;  /* context to use for allocations */
	ARTMEMHDR *tctl;	 /* location of memory header in shared mem */
} ARTREECTL;

/* Flags to indicate which parameters are supplied */
#define ARTREE_ELEM		0x0001	/* Set keysize and entrysize */
#define ARTREE_ALLOC		0x0002	/* Set memory allocator */
#define ARTREE_CONTEXT		0x0004	/* Set memory allocation context */
#define ARTREE_SHARED_MEM 	0x0008	/* Tree is in shared memory */
#define ARTREE_ATTACH		0x0010	/* Do not initialize tctl */
#define ARTREE_COMPOUND		0x0020  /* Tree consists of two parts */

typedef struct ARTREE_STATS {
	RelFileNode rnode;
	ForkNumber	forkNum;
	uint32		nleaves;
	uint32		nelem4;
	uint32		nelem16;
	uint32		nelem48;
	uint32		nelem256;
} ARTREE_STATS;

typedef struct ARTREE_DATA_SIZE {
	uint16 n4_size;
	uint16 n16_size;
	uint16 n48_size;
	uint16 n256_size;
	uint16 subtree_size;
	uint16 baseleaf_size;
} ARTREE_DATA_SIZE;

extern ARTREE *artree_create(const char *treename, long num_subtrees, long nelem,
							 ARTREECTL *info, int flags);
extern int artree_destroy(ARTREE *t);
extern void *artree_insert(ARTREE *artp, const uint8 *key, void *value);
extern void *artree_delete(ARTREE *artp, const uint8 *key);
extern void *artree_search(ARTREE *artp, const uint8 *key);

extern ARTREE_DATA_SIZE artree_get_data_size(void);
extern Size artree_estimate_size(long num_subtrees, Size subtree_keysize, long num_entries,
								 Size keysize, Size entrysize);
extern Size artree_get_shared_size(ARTREECTL *info, int flags);
extern long *artree_nodes_used(ARTREE *artp, FreeListARTree *artlist);
extern LWLock *artree_getlock(ARTREE *artp);
extern void artree_fill_stats(ARTREE *artp, ARTREE_STATS *stats);

extern Size artree_subtreelist_size(long num_subtrees);
extern void artree_build_subtreelist(FreeListARTree *artlist, ARTREE *buftree,
									 long num_subtrees, int num_buffers);
extern ARTREE *artree_alloc_subtree(FreeListARTree *artlist);
extern void artree_dealloc_subtree(FreeListARTree *artlist, ARTREE *artp);

typedef int(*art_callback)(void *data, const uint8 *key, uint32 key_len, void *value);
extern int artree_iter(ARTREE *artp, art_callback cb, void *data);
extern int artree_iter_prefix(ARTREE *artp, const uint8 *prefix,
							  int prefix_len, art_callback cb, void *data);

#endif
