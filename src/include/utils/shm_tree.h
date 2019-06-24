
#ifndef SHMTREE_H
#define SHMTREE_H

/*
 * Space allocation function for a tree --- designed to match malloc().
 * Note: there is no free function API; can't destroy a tree unless you
 * use the default allocator.
 */
typedef void *(*TreeAllocFunc) (Size request);

typedef struct SHMTREEHDR SHMTREEHDR;

typedef struct SHMTREE SHMTREE;

typedef struct SHMTREECTL {
    Size keysize;        /* hash key length in bytes */
    Size entrysize;      /* total user element size in bytes */
    TreeAllocFunc alloc; /* memory allocator */
    MemoryContext hcxt;  /* context to use for allocations */
    SHMTREEHDR *tctl;    /* location of header in shared mem */
} SHMTREECTL;

/* Flags to indicate which parameters are supplied */
#define SHMTREE_ELEM		0x0001	/* Set keysize and entrysize */
#define SHMTREE_ALLOC		0x0002	/* Set memory allocator */
#define SHMTREE_CONTEXT	   	0x0004	/* Set memory allocation context */
#define SHMTREE_SHARED_MEM 	0x0008	/* Tree is in shared memory */
#define SHMTREE_ATTACH		0x0010	/* Do not initialize hctl */

extern SHMTREE *shmtree_create(const char *tabname, SHMTREECTL *info, int flags);
extern int shmtree_destroy(SHMTREE *t);
extern void* shmtree_insert(SHMTREE *shmt, const unsigned char *key, void *value);
extern void* shmtree_delete(SHMTREE *shmt, const unsigned char *key);
extern void* shmtree_search(SHMTREE *shmt, const unsigned char *key);

extern uint64 shmtree_num_entries(SHMTREE *shmt);
extern void shmtree_memory_usage(SHMTREE *shmt);
extern void shmtree_nodes_proportion(SHMTREE *shmt);
extern Size shmtree_estimate_size(Size keysize);
extern Size shmtree_get_shared_size(SHMTREECTL *info, int flags);
extern long * shmtree_nodes_used(SHMTREE *shmt);

#endif
