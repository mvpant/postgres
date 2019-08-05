
#ifndef SHMTREE_H
#define SHMTREE_H

#include "storage/lwlock.h"

/*
 * Space allocation function for a tree --- designed to match malloc().
 * Note: there is no free function API; can't destroy a tree unless you
 * use the default allocator.
 */
typedef void *(*TreeAllocFunc) (Size request);

typedef struct SHMTREEHDR SHMTREEHDR;

typedef struct SHMTREE SHMTREE;

typedef struct FreeListARTree FreeListARTree;

typedef struct ARTREECTL {
	Size keysize;		 /* key length in bytes */
	Size entrysize;		 /* total user element size in bytes */
	TreeAllocFunc alloc; /* memory allocator */
	MemoryContext hcxt;  /* context to use for allocations */
	SHMTREEHDR *tctl;	 /* location of header in shared mem */
} ARTREECTL;

/* Flags to indicate which parameters are supplied */
#define ARTREE_ELEM		0x0001	/* Set keysize and entrysize */
#define ARTREE_ALLOC		0x0002	/* Set memory allocator */
#define ARTREE_CONTEXT		0x0004	/* Set memory allocation context */
#define ARTREE_SHARED_MEM 	0x0008	/* Tree is in shared memory */
#define ARTREE_ATTACH		0x0010	/* Do not initialize hctl */

extern SHMTREE *artree_create(const char *tabname, ARTREECTL *info, int flags);
extern int artree_destroy(SHMTREE *t);
extern void *artree_insert(SHMTREE *shmt, const uint8 *key, void *value);
extern void *artree_delete(SHMTREE *shmt, const uint8 *key);
extern void *artree_search(SHMTREE *shmt, const uint8 *key);

extern void artree_memory_usage(SHMTREE *shmt);
extern void artree_nodes_proportion(SHMTREE *shmt);
extern Size artree_estimate_size(Size keysize);
extern Size artree_get_shared_size(ARTREECTL *info, int flags);
extern long *artree_nodes_used(SHMTREE *shmt, FreeListARTree *artlist);
extern LWLock *artree_getlock(SHMTREE *shmt);

extern Size artree_subtreelist_size(void);
extern void artree_build_subtreelist(FreeListARTree *artlist, SHMTREE *buftree);
extern SHMTREE *artree_alloc_subtree(FreeListARTree *artlist);
extern void artree_dealloc_subtree(FreeListARTree *artlist, SHMTREE *shmt);

typedef int(*art_callback)(void *data, const uint8 *key, uint32 key_len, void *value);
extern int artree_iter(SHMTREE *shmt, art_callback cb, void *data);
extern int artree_iter_prefix(SHMTREE *shmt, const uint8 *prefix,
							  int prefix_len, art_callback cb, void *data);

#endif
