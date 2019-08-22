
#include "postgres.h"

#include <limits.h>

#include "utils/shm_tree.h"
#include "utils/memutils.h"
#include "storage/shmem.h"
#include "storage/spin.h"
#include "storage/lwlock.h"
#include "storage/bufmgr.h"

#if defined(__i386__) || defined(__amd64__)
#include <emmintrin.h>
#endif

#define IGNORE_UNUSED(var) (void) (var)

static long stats[18];

/*
 * Constants
 *
 * The adaptive radix tree consists of 4 types of nodes, which
 * have different size and children capacity.
 */
#define NODE4 1
#define NODE16 2
#define NODE48 3
#define NODE256 4
#define NODELEAF 5
#define NODE_FREELIST_IDX(type) (type - 1)

/*
 * Thresholds that trigger nodes replacement.
 *
 * During node replacement operation node can 'grow' or 'shrink', e.g. node16
 * with 16 children can be replaced with node48 after reaching its maximum
 * capacity. Then node48 will only shrink backward to node16 after decreasing
 * to its minimum threshold, which definitely should be less that node16 max
 * size to prevent 'ping-ponging' between different node types.
 */
#define NODE4_MIN 1
#define NODE4_MAX 4
#define NODE16_MIN 3
#define NODE16_MAX 16
#define NODE48_MIN 12
#define NODE48_MAX 48
#define NODE256_MIN 37
#define NODE256_MAX 256

/*
 * Additionally, at the front of each node, a header of constant size
 * stores the node type, the number of children, and the compressed path.
 * The total size of header is 16 bytes.
 */
#define MAX_PREFIX_LEN 10

typedef struct art_node
{
	uint8 type;
	uint8 num_children;
	uint32 partial_len;
	uint8 partial[MAX_PREFIX_LEN];
} art_node;

typedef struct art_node4
{
	art_node n;
	uint8 keys[4];
	art_node *children[4];
} art_node4;

typedef struct art_node16
{
	art_node n;
	uint8 keys[16];
	art_node *children[16];
} art_node16;

typedef struct art_node48
{
	art_node n;
	uint8 keys[256];
	art_node *children[48];
} art_node48;

typedef struct art_node256
{
	art_node n;
	art_node *children[256];
} art_node256;

typedef struct art_leaf
{
	void *value;
	uint32 key_len;
	uint8 key[FLEXIBLE_ARRAY_MEMBER];
} art_leaf;

typedef union NodePointer
{
	art_node4 *p1;
	art_node16 *p2;
	art_node48 *p3;
	art_node256 *p4;
} NodePointer;

typedef struct art_tree
{
	LWLock lock;
	art_node *root;
	uint32 leaves;
	uint32 size4;
	uint32 size16;
	uint32 size48;
	uint32 size256;
} art_tree;

/**
 * Macros to manipulate pointer tags
 */
#define IS_LEAF(x) (((uintptr_t) x & 1))
#define SET_LEAF(x) ((void *) ((uintptr_t) x | 1))
#define LEAF_RAW(x) ((art_leaf *) ((void *) ((uintptr_t) x & ~1)))

typedef struct NODEELEMENT
{
	struct NODEELEMENT *link;
} NODEELEMENT;

/*
 * Macros to access content of linked-list item
 */
#define NODEELEMENT_DATA(link)  \
	(((char *) (link)) + MAXALIGN(sizeof(NODEELEMENT)))
#define NODEELEMENT_LINK(data)  \
	((NODEELEMENT *) (((char *) (data)) - MAXALIGN(sizeof(NODEELEMENT))))

typedef struct FreeListNode
{
	slock_t		mutex;
	long		nentries;
	NODEELEMENT *freeList;
} FreeListNode;

typedef struct FreeListMeta
{
	long		init_nelem;  /* number of entries at initialization */
	long		max_nelem;   /* total number of allocated entries */
	int			nelem_alloc; /* number of entries to allocate at once */
} FreeListMeta;

/*
 * Header structure for a tree --- contains all changeable info
 *
 * In a shared-memory tree, the ARTMEMHDR is in shared memory, while
 * each backend has a local ARTREE struct.
 */
struct ARTMEMHDR
{
	FreeListNode freeList[4];
	FreeListMeta freeListMeta[4];
};

typedef struct LEAFMEMHDR
{
	FreeListNode freeList;
	FreeListMeta freeListMeta;

	Size keysize;	 /* key length in bytes */
	Size entrysize;  /* total user element size in bytes */
} LEAFMEMHDR;

typedef struct TREEHDR
{
	ARTMEMHDR *nctl;	 /* => shared nodes freeList */
	LEAFMEMHDR *lctl;	 /* => shared leafs freeList */
	art_tree *tree;		 /* allocated right after tctl & lctl header struct */
	Size keysize;		 /* key length in bytes */
	Size entrysize;		 /* total user element size in bytes */
	char *treename;
} TREEHDR;

/*
 * Top control structure for tree --- in a shared tree, each backend
 * has its own copy (OK since no fields change at runtime)
 */
struct ARTREE
{
	TREEHDR hdr;
	TreeAllocFunc alloc; /* memory allocator */
	MemoryContext tcxt;	 /* memory context if default allocator used */
	bool isshared;	/* true if tree is in shared memory */
};

typedef struct FreeListARTree
{
	slock_t		mutex;
	long		nentries;
	long		init_nelem;
	LEAFMEMHDR *child_leaf_memhdr;
	NODEELEMENT *freeList;
} FreeListARTree;

/* allocation */
static art_node *alloc_node(ARTREE *artp, uint8 type);
static void dealloc_node(ARTREE *artp, art_node *n);
static art_leaf *alloc_leaf(ARTREE *artp);
static void dealloc_leaf(ARTREE *artp, art_leaf *n);
static bool nodes_alloc(ARTREE *artp, int nelem, uint8 ntype);
static bool leafs_alloc(ARTREE *artp, int nelem);
static int choose_nelem_alloc(ARTREE *artp, uint8 ntype);

/* utility */
static int check_prefix(const art_node *n, const uint8 *key, int key_len, int depth);
static int longest_common_prefix(art_leaf *l1, art_leaf *l2, int depth);
static void copy_header(art_node *dest, art_node *src);
static art_node ** find_child(art_node *n, uint8 c);
static int prefix_mismatch(const art_node *n, const uint8 *key, int key_len, int depth);
static int leaf_prefix_matches(const art_leaf *n, const uint8 *prefix, int prefix_len);

/* nodes maintenance */
static art_leaf * make_leaf(ARTREE *artp, const uint8 *key, int key_len, void *value);
static void add_child256(art_node256 *n, art_node **ref, uint8 c, void *child);
static void add_child48(ARTREE *artp, art_node48 *n, art_node **ref, uint8 c, void *child);
static void add_child16(ARTREE *artp, art_node16 *n, art_node **ref, uint8 c, void *child);
static void add_child4(ARTREE *artp, art_node4 *n, art_node **ref, uint8 c, void *child);
static void add_child(ARTREE *artp, art_node *n, art_node **ref, uint8 c, void *child);
static void remove_child256(ARTREE *artp, art_node256 *n, art_node **ref, uint8 c);
static void remove_child48(ARTREE *artp, art_node48 *n, art_node **ref, uint8 c);
static void remove_child16(ARTREE *artp, art_node16 *n, art_node **ref, art_node **l);
static void remove_child4(ARTREE *artp, art_node4 *n, art_node **ref, art_node **l);
static void remove_child(ARTREE *artp, art_node *n, art_node **ref, uint8 c, art_node **l);

/* destroy */
static void destroy_node(ARTREE *artp, art_node *n);
static int art_tree_destroy(ARTREE *artp, art_tree *t);

/* basic operations */
static void *art_insert(ARTREE *artp, const uint8 *key, int key_len,
                        void *value);
static void *art_delete(ARTREE *artp, const uint8 *key, int key_len);
static void *art_search(const art_tree *t, const uint8 *key, int key_len);
static art_leaf * minimum(const art_node *n);

/* iterator */
static int art_iter(art_tree *t, art_callback cb, void *data);
static int art_iter_prefix(art_tree *t, const uint8 *key, int key_len, art_callback cb,
						   void *data);
static int recursive_iter(art_node *n, art_callback cb, void *data);

/*
 * memory allocation support
 */
static MemoryContext CurrentTreeCxt = NULL;

/*
 * bunch of random numbers
 */
#define NODESUBTREE_NELEM 10000
#define NODE4_NELEM(x)		((x) >> 1)
#define NODE16_NELEM(x)		((x) >> 2)
#define NODE48_NELEM(x)		((x) >> 5)
#define NODE256_NELEM(x)	((x) >> 6)

static const char SUBTREE_NAME[] = "subtree";
#define TO_STR(x) #x
#define STR_LEN(x) (sizeof(TO_STR(x)))
#define SUBTREE_SIZE \
	MAXALIGN((MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(TREEHDR)) \
	 + MAXALIGN(sizeof(art_tree)) + sizeof(SUBTREE_NAME) \
	 + STR_LEN(NODESUBTREE_NELEM)))

static ARTREE_DATA_SIZE mem_info = {
	.n4_size = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node4)),
	.n16_size = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node16)),
	.n48_size = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node48)),
	.n256_size = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node256)),
	.subtree_size = SUBTREE_SIZE,
	.baseleaf_size = MAXALIGN(sizeof(art_leaf))
};

static void *
TreeAlloc(Size size)
{
	Assert(MemoryContextIsValid(CurrentTreeCxt));
	return MemoryContextAlloc(CurrentTreeCxt, size);
}

ARTREE *
artree_create(const char *treename, long num_subtrees, long nelem, ARTREECTL *info, int flags)
{
    ARTREE *artp;
	ARTMEMHDR *node_memhdr;
	LEAFMEMHDR *leaf_memhdr;
    art_tree *art;

	if (flags & ARTREE_SHARED_MEM)
	{
		/* Set up to allocate the tree header */
		CurrentTreeCxt = TopMemoryContext;
	}
	else
	{
		/* Create the tree's private memory context */
		if (flags & ARTREE_CONTEXT)
			CurrentTreeCxt = info->hcxt;
		else
			CurrentTreeCxt = TopMemoryContext;
		CurrentTreeCxt = AllocSetContextCreate(CurrentTreeCxt,
											   "artree",
											   ALLOCSET_DEFAULT_SIZES);
	}

	/* Initialize the tree structure, plus a copy of the tree name */
	artp = (ARTREE *) TreeAlloc(sizeof(ARTREE) + strlen(treename) + 1);
	MemSet(artp, 0, sizeof(ARTREE));

	artp->hdr.treename = (char *) (artp + 1);
	strcpy(artp->hdr.treename, treename);

	/* If we have a private context, label it with tree's name */
	if (!(flags & ARTREE_SHARED_MEM))
		MemoryContextSetIdentifier(CurrentTreeCxt, artp->hdr.treename);

	/* And select the entry allocation function, too. */
	if (flags & ARTREE_ALLOC)
		artp->alloc = info->alloc;
	else
		artp->alloc = TreeAlloc;

	if (flags & ARTREE_SHARED_MEM)
	{
		artp->hdr.nctl = info->tctl;
		artp->hdr.lctl = (LEAFMEMHDR *) (((char *) info->tctl) + sizeof(ARTMEMHDR));
		artp->hdr.tree = (art_tree *) (((char *) info->tctl) +
									   sizeof(ARTMEMHDR) + sizeof(LEAFMEMHDR));
		artp->tcxt = NULL;
		artp->isshared = true;

		if (flags & ARTREE_ATTACH)
		{
			leaf_memhdr = artp->hdr.lctl;
			artp->hdr.keysize = leaf_memhdr->keysize;

			return artp;
		}
	}
	else
	{
		artp->hdr.nctl = NULL;
		artp->hdr.lctl = NULL;
		artp->hdr.tree = NULL;
		artp->tcxt = CurrentTreeCxt;
		artp->isshared = false;
	}

	if (!artp->hdr.nctl)
	{
		artp->hdr.nctl = (ARTMEMHDR *) artp->alloc(sizeof(ARTMEMHDR));
		if (!artp->hdr.nctl)
			ereport(ERROR,
					(errcode(ERRCODE_OUT_OF_MEMORY),
					 errmsg("out of memory")));
	}

	MemSet(artp->hdr.nctl, 0, sizeof(ARTMEMHDR));

	node_memhdr = artp->hdr.nctl;
	leaf_memhdr = artp->hdr.lctl;
    art = artp->hdr.tree;
    art->root = NULL;
	art->leaves = 0;
    art->size4 = 0;
    art->size16 = 0;
    art->size48 = 0;
    art->size256 = 0;

	LWLockInitialize(&art->lock, LWTRANCHE_BUFFER_MAPPING);

	/*
	 * tree now allocates space for key and data but you have to say how
	 * much space to allocate
	 */
	if (flags & ARTREE_ELEM)
	{
		leaf_memhdr->keysize = info->keysize;
		leaf_memhdr->entrysize = info->entrysize;
	}

	/* make local copies of heavily-used constant fields */
	artp->hdr.keysize = leaf_memhdr->keysize;
	artp->hdr.entrysize = leaf_memhdr->entrysize;

	if (flags & ARTREE_SHARED_MEM)
	{
		int		i;
		int		nleafs;
		uint8	node_types[] = { NODE4, NODE16, NODE48, NODE256 };
		int		nelem_alloc[] = { NODE4_NELEM(nelem), NODE16_NELEM(nelem),
								  NODE48_NELEM(nelem), NODE256_NELEM(nelem) };

		/* first nodes of different type */
		for (i = 0; i < sizeof(nelem_alloc) / sizeof(nelem_alloc[0]); i++)
		{
			node_memhdr->freeList[i].nentries = 0;
			node_memhdr->freeListMeta[i].init_nelem = nelem_alloc[i];
			node_memhdr->freeListMeta[i].max_nelem = 0;
			node_memhdr->freeListMeta[i].nelem_alloc = choose_nelem_alloc(artp, node_types[i]);

			SpinLockInit(&node_memhdr->freeList[i].mutex);

			if (!nodes_alloc(artp, nelem_alloc[i], node_types[i]))
				ereport(ERROR,
						(errcode(ERRCODE_OUT_OF_MEMORY),
						 errmsg("out of memory")));
		}

		if (flags & ARTREE_COMPOUND)
		{
			nleafs = num_subtrees;
		}
		else
		{
			nleafs = nelem;
		}

		leaf_memhdr->freeListMeta.init_nelem = nleafs;
		leaf_memhdr->freeListMeta.max_nelem = 0;
		leaf_memhdr->freeListMeta.nelem_alloc = choose_nelem_alloc(artp, NODELEAF);

		SpinLockInit(&leaf_memhdr->freeList.mutex);

		/* and now its time of leafs */
		if (!leafs_alloc(artp, nleafs))
			ereport(ERROR,
					(errcode(ERRCODE_OUT_OF_MEMORY),
					 errmsg("out of memory")));
	}

    return artp;
}


static int
choose_nelem_alloc(ARTREE *artp, uint8 ntype)
{
	int			nelem_alloc;

	/* FIXME */
	switch (ntype) {
	case NODE4:
		nelem_alloc = 128;
		break;
	case NODE16:
		nelem_alloc = 64;
		break;
	case NODE48:
		nelem_alloc = 32;
		break;
	case NODE256:
		nelem_alloc = 16;
		break;
	case NODELEAF:
		nelem_alloc = 32;
		break;
	default:
		elog(ERROR, "choose_nelem_alloc: unknown art_node type");
	}

	return nelem_alloc;
}

/*
 * allocate some new nodes and link them into the indicated free list
 */
static bool
nodes_alloc(ARTREE *artp, int nelem, uint8 ntype)
{
    ARTMEMHDR *memhdr = artp->hdr.nctl;
    Size elementSize;
    NODEELEMENT *firstElement;
    NODEELEMENT *tmpElement;
    NODEELEMENT *prevElement;
    int i;
	int freelist_idx = NODE_FREELIST_IDX(ntype);

	/* Each element has a NODEELEMENT header plus user data. */
	elementSize = MAXALIGN(sizeof(NODEELEMENT));

    switch (ntype) {
    case NODE4:
        elementSize += MAXALIGN(sizeof(art_node4));
        break;
    case NODE16:
        elementSize += MAXALIGN(sizeof(art_node16));
        break;
    case NODE48:
        elementSize += MAXALIGN(sizeof(art_node48));
        break;
    case NODE256:
        elementSize += MAXALIGN(sizeof(art_node256));
        break;
    default:
		elog(ERROR, "nodes_alloc: unknown art_node type");
    }

    CurrentTreeCxt = artp->tcxt;
    firstElement = (NODEELEMENT *) artp->alloc(nelem * elementSize);

    if (!firstElement)
        return false;

    /* prepare to link all the new nodes into the freelist */
    prevElement = NULL;
    tmpElement = firstElement;
    for (i = 0; i < nelem; i++) {
        tmpElement->link = prevElement;
        prevElement = tmpElement;
        tmpElement = (NODEELEMENT *) (((char *) tmpElement) + elementSize);
    }
    
	SpinLockAcquire(&memhdr->freeList[freelist_idx].mutex);

    /* freelist could be nonempty if two backends did this concurrently */
    firstElement->link = memhdr->freeList[freelist_idx].freeList;
    memhdr->freeList[freelist_idx].freeList = prevElement;
    memhdr->freeList[freelist_idx].nentries += nelem;
	memhdr->freeListMeta[freelist_idx].max_nelem += nelem;

	SpinLockRelease(&memhdr->freeList[freelist_idx].mutex);

	return true;
}

/*
 * allocate some new leafs and link them into the indicated free list
 */
static bool
leafs_alloc(ARTREE *artp, int nelem)
{
	LEAFMEMHDR *memhdr = artp->hdr.lctl;
	Size elementSize;
	NODEELEMENT *firstElement;
	NODEELEMENT *tmpElement;
	NODEELEMENT *prevElement;
	int i;

	/* Each element has a NODEELEMENT header plus user data. */
	elementSize = MAXALIGN(sizeof(NODEELEMENT));
	elementSize += MAXALIGN(sizeof(art_leaf)) + artp->hdr.keysize + artp->hdr.entrysize;

	CurrentTreeCxt = artp->tcxt;
	firstElement = (NODEELEMENT *) artp->alloc(nelem * elementSize);

	if (!firstElement)
		return false;

	/* prepare to link all the new nodes into the freelist */
	prevElement = NULL;
	tmpElement = firstElement;
	for (i = 0; i < nelem; i++) {
		tmpElement->link = prevElement;
		prevElement = tmpElement;
		tmpElement = (NODEELEMENT *) (((char *) tmpElement) + elementSize);
	}
	
	SpinLockAcquire(&memhdr->freeList.mutex);

	/* freelist could be nonempty if two backends did this concurrently */
	firstElement->link = memhdr->freeList.freeList;
	memhdr->freeList.freeList = prevElement;
	memhdr->freeList.nentries = nelem;
	memhdr->freeListMeta.max_nelem += nelem;

	SpinLockRelease(&memhdr->freeList.mutex);

	return true;
}

Size
artree_get_shared_size(ARTREECTL *info, int flags)
{
	return sizeof(ARTMEMHDR) + sizeof(LEAFMEMHDR) + sizeof(art_tree);
}

Size
artree_subtreelist_size(long num_subtrees)
{
	Size size;
	size = MAXALIGN(sizeof(FreeListARTree)) + sizeof(LEAFMEMHDR);
	size = add_size(size, mul_size(mem_info.subtree_size, num_subtrees));
	return size;
}

LWLock *
artree_getlock(ARTREE *artp)
{
    return &artp->hdr.tree->lock;
}

void
artree_build_subtreelist(FreeListARTree *artlist, ARTREE *buftree,
						 long num_subtrees, int num_buffers)
{
	NODEELEMENT *firstElement;
	NODEELEMENT *tmpElement;
	NODEELEMENT *prevElement;
	int i;
	Size elementSize;

	/* subtrees share buftree's freeLists of nodes */
	ARTMEMHDR *node_memhdr = buftree->hdr.nctl;
	LEAFMEMHDR *leaf_memhdr = (LEAFMEMHDR *) (((char *) artlist) +
											  MAXALIGN(sizeof(FreeListARTree)));
	int trancheid = LWLockNewTrancheId();
	LWLockRegisterTranche(trancheid, "blocktrees");

	/*
	 * FIXME: this dirty stuff is used to allocate proper number of leafs with
	 * BlockNumber keysize.
	 */
	ARTREE tmp_art;
	tmp_art.hdr.lctl = leaf_memhdr;
	tmp_art.hdr.keysize = sizeof(BlockNumber);
	tmp_art.hdr.entrysize = 0;
	tmp_art.alloc = ShmemAllocNoError;
	leafs_alloc(&tmp_art, num_buffers + 100);
	leaf_memhdr->freeListMeta.init_nelem = num_buffers + 100;

	CurrentTreeCxt = TopMemoryContext;

	elementSize = mem_info.subtree_size;

	firstElement = (NODEELEMENT *) (((char *) artlist) +
									MAXALIGN(sizeof(FreeListARTree)) +
									sizeof(LEAFMEMHDR));

	prevElement = NULL;
	tmpElement = firstElement;
	for (i = 0; i < num_subtrees; i++)
	{
		TREEHDR *hdr;
		char *ptr;

		ptr = (char *) tmpElement;
		MemSet(ptr, 0, elementSize);

		ptr += MAXALIGN(sizeof(NODEELEMENT));
		hdr = (TREEHDR *) ptr;

		ptr += MAXALIGN(sizeof(TREEHDR));
		hdr->nctl = node_memhdr;
		hdr->lctl = leaf_memhdr;
		hdr->tree = (art_tree *) ptr;
		hdr->keysize = sizeof(BlockNumber);

		ptr += MAXALIGN(sizeof(art_tree));
		hdr->treename = ptr;

		strcpy(hdr->treename, SUBTREE_NAME);
		ptr += sizeof(SUBTREE_NAME);

		sprintf(ptr, "%d", i);

		LWLockInitialize(&hdr->tree->lock, trancheid);

		tmpElement->link = prevElement;
		prevElement = tmpElement;
		tmpElement = (NODEELEMENT *) (((char *) tmpElement) + elementSize);
	}

	SpinLockInit(&artlist->mutex);
	artlist->freeList = prevElement;
	artlist->nentries = num_subtrees;
	artlist->init_nelem = num_subtrees;
	artlist->child_leaf_memhdr = leaf_memhdr;
}

ARTREE *
artree_alloc_subtree(FreeListARTree *artlist)
{
	NODEELEMENT *tmpElement;
	ARTREE *artp;

	SpinLockAcquire(&artlist->mutex);
	tmpElement = artlist->freeList;
	artlist->freeList = tmpElement->link;
	artlist->nentries--;
	Assert(artlist->nentries >= 0);
	SpinLockRelease(&artlist->mutex);

	tmpElement->link = NULL;
	artp = (ARTREE *) NODEELEMENT_DATA(tmpElement);
	// elog(WARNING, "shmtree_alloc_blktree: %p %s", artp, artp->hdr.treename);
	return artp;
}

void
artree_dealloc_subtree(FreeListARTree *artlist, ARTREE *artp)
{
	NODEELEMENT *tmpElement;
	TREEHDR *hdr = (TREEHDR *) artp;

	// elog(WARNING, "shmtree_dealloc_blktree: %p %s", artp, artp->hdr.treename);

	Assert(hdr->tree->size4 == 0);
	Assert(hdr->tree->size16 == 0);
	Assert(hdr->tree->size48 == 0);
	Assert(hdr->tree->size256 == 0);
	Assert(hdr->tree->leaves == 0);
	Assert(hdr->tree->root == NULL);

	tmpElement = NODEELEMENT_LINK(hdr);

	SpinLockAcquire(&artlist->mutex);
	tmpElement->link = artlist->freeList;
	artlist->freeList = tmpElement;
	artlist->nentries++;
	Assert(artlist->nentries <= artlist->init_nelem);
	SpinLockRelease(&artlist->mutex);
}

ARTREE_DATA_SIZE
artree_get_data_size()
{
	return mem_info;
}

Size
artree_estimate_size(long num_subtrees, Size subtree_keysize,
					 long num_entries, Size keysize, Size entrysize)
{
	Size		size;
	long elementSize;

	/* should match artree_get_shared_size */
	size = sizeof(ARTMEMHDR) + sizeof(LEAFMEMHDR) + sizeof(art_tree);

	/* first nodes that shared between all trees */
	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node4));
	size = add_size(size, mul_size(NODE4_NELEM(num_entries), elementSize));

	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node16));
	size = add_size(size, mul_size(NODE16_NELEM(num_entries), elementSize));

	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node48));
	size = add_size(size, mul_size(NODE48_NELEM(num_entries), elementSize));

	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node256));
	size = add_size(size, mul_size(NODE256_NELEM(num_entries), elementSize));

	/* then leafs in the main tree for subtrees */
	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_leaf))
		+ subtree_keysize;
	size = add_size(size, mul_size(num_subtrees, elementSize));

	/* then leafs inside subtrees for BlockNumber */
	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_leaf))
		+ keysize + entrysize;
	size = add_size(size, mul_size(num_entries + 100, elementSize));

	size = add_size(size, artree_subtreelist_size(num_subtrees));

	return size;
}

int
artree_destroy(ARTREE *artp)
{
    return art_tree_destroy(artp, artp->hdr.tree);
}

void *
artree_insert(ARTREE *artp, const uint8 *key, void *value)
{
    return art_insert(artp, key, artp->hdr.keysize, value);
}

void *
artree_delete(ARTREE *artp, const uint8 *key)
{
    return art_delete(artp, key, artp->hdr.keysize);
}

void *
artree_search(ARTREE *artp, const uint8 *key)
{
    return art_search(artp->hdr.tree, key, artp->hdr.keysize);
}

int
artree_iter(ARTREE *artp, art_callback cb, void *data)
{
	return art_iter(artp->hdr.tree, cb, data);
}

int
artree_iter_prefix(ARTREE *artp,
					const uint8 *prefix,
					int prefix_len,
					art_callback cb,
					void *data)
{
	Assert(prefix_len > 0);
	return art_iter_prefix(artp->hdr.tree, prefix, prefix_len, cb, data);
}

long *
artree_nodes_used(ARTREE *artp, FreeListARTree *artlist)
{
	ARTMEMHDR *node_memhdr = artp->hdr.nctl;
	LEAFMEMHDR *child_leaf_memhdr = artlist->child_leaf_memhdr;
	long n4init_elems = node_memhdr->freeListMeta[NODE_FREELIST_IDX(NODE4)].init_nelem,
		 n16init_elems = node_memhdr->freeListMeta[NODE_FREELIST_IDX(NODE16)].init_nelem,
		 n48init_elems = node_memhdr->freeListMeta[NODE_FREELIST_IDX(NODE48)].init_nelem,
		 n256init_elems = node_memhdr->freeListMeta[NODE_FREELIST_IDX(NODE256)].init_nelem,
		 nleaves_total = child_leaf_memhdr->freeListMeta.init_nelem,
		 nleaves_curr = child_leaf_memhdr->freeList.nentries;

	/* do not bother with lock acquiring */
	stats[0] = nleaves_total - nleaves_curr;
	stats[1] = n4init_elems - node_memhdr->freeList[NODE_FREELIST_IDX(NODE4)].nentries;
	stats[2] = n16init_elems - node_memhdr->freeList[NODE_FREELIST_IDX(NODE16)].nentries;
	stats[3] = n48init_elems - node_memhdr->freeList[NODE_FREELIST_IDX(NODE48)].nentries;
	stats[4] = n256init_elems - node_memhdr->freeList[NODE_FREELIST_IDX(NODE256)].nentries;
	stats[5] = artlist->init_nelem - artlist->nentries;
	stats[6] = nleaves_total;
	stats[7] = n4init_elems;
	stats[8] = n16init_elems;
	stats[9] = n48init_elems;
	stats[10] = n256init_elems;
	stats[11] = artlist->init_nelem;

	stats[12] = mul_size(nleaves_total, mem_info.baseleaf_size + child_leaf_memhdr->keysize);
	stats[13] = mul_size(n4init_elems, mem_info.n4_size);
	stats[14] = mul_size(n16init_elems, mem_info.n16_size);
	stats[15] = mul_size(n48init_elems, mem_info.n48_size);
	stats[16] = mul_size(n256init_elems, mem_info.n256_size);

	stats[17] = artree_subtreelist_size(artlist->init_nelem);

	return stats;
}

void
artree_fill_stats(ARTREE *artp, ARTREE_STATS *stats)
{
	stats->nleaves = artp->hdr.tree->leaves;
	stats->nelem4 = artp->hdr.tree->size4;
	stats->nelem16 = artp->hdr.tree->size16;
	stats->nelem48 = artp->hdr.tree->size48;
	stats->nelem256 = artp->hdr.tree->size256;
}


/**
 * Allocates a node of the given type.
 */
static art_node *
alloc_node(ARTREE *artp, uint8 type)
{
    ARTMEMHDR *memhdr = artp->hdr.nctl;
    NODEELEMENT *tmpElement;
    int freelist_idx;
    art_node *n;

	switch (type) {
	case NODE4:
		artp->hdr.tree->size4++;
		break;
	case NODE16:
		artp->hdr.tree->size16++;
		break;
	case NODE48:
		artp->hdr.tree->size48++;
		break;
	case NODE256:
		artp->hdr.tree->size256++;
		break;
	default:
		elog(ERROR, "alloc_node: unknown art_node type");
	}

	freelist_idx = NODE_FREELIST_IDX(type);

    SpinLockAcquire(&memhdr->freeList[freelist_idx].mutex);

    tmpElement = memhdr->freeList[freelist_idx].freeList;

	if (!tmpElement)
		elog(WARNING, "alloc_node: list number %d is exhausted", type);

    memhdr->freeList[freelist_idx].freeList = tmpElement->link;
    memhdr->freeList[freelist_idx].nentries--;

    SpinLockRelease(&memhdr->freeList[freelist_idx].mutex);

	tmpElement->link = NULL;

    n = (art_node *) NODEELEMENT_DATA(tmpElement);
    n->type = type;
	// elog(WARNING, "alloc_node: %zu type=%d", (uintptr_t) n, type);
    return n;
}

static void
dealloc_node(ARTREE *artp, art_node *node)
{
    ARTMEMHDR *memhdr = artp->hdr.nctl;
    NODEELEMENT *tmpElement;
    Size elementSize;
	uint8 freelist_idx;
	uint8 type = node->type;

	switch (type) {
    case NODE4:
        elementSize = MAXALIGN(sizeof(art_node4));
		artp->hdr.tree->size4--;
        break;
    case NODE16:
        elementSize = MAXALIGN(sizeof(art_node16));
		artp->hdr.tree->size16--;
        break;
    case NODE48:
        elementSize = MAXALIGN(sizeof(art_node48));
		artp->hdr.tree->size48--;
        break;
    case NODE256:
        elementSize = MAXALIGN(sizeof(art_node256));
		artp->hdr.tree->size256--;
        break;
    default:
        elog(ERROR, "dealloc_node: unknown art_node type");
    }

	freelist_idx = NODE_FREELIST_IDX(type);
    tmpElement = NODEELEMENT_LINK(node);
	MemSet(node, 0, elementSize);

    SpinLockAcquire(&memhdr->freeList[freelist_idx].mutex);

    tmpElement->link = memhdr->freeList[freelist_idx].freeList;
    memhdr->freeList[freelist_idx].freeList = tmpElement;
    memhdr->freeList[freelist_idx].nentries++;

    SpinLockRelease(&memhdr->freeList[freelist_idx].mutex);
	// elog(WARNING, "dealloc_node: %zu type=%d", (uintptr_t) node, type);
}

static art_leaf *
alloc_leaf(ARTREE *artp)
{
    LEAFMEMHDR *memhdr = artp->hdr.lctl;
    NODEELEMENT *tmpElement;
    art_leaf *n;

    SpinLockAcquire(&memhdr->freeList.mutex);

    tmpElement = memhdr->freeList.freeList;
    memhdr->freeList.freeList = tmpElement->link;
    memhdr->freeList.nentries--;

    SpinLockRelease(&memhdr->freeList.mutex);

	tmpElement->link = NULL;
	artp->hdr.tree->leaves++;

    n = (art_leaf *) NODEELEMENT_DATA(tmpElement);
    return n;
}

static void
dealloc_leaf(ARTREE *artp, art_leaf *node)
{
    LEAFMEMHDR *memhdr = artp->hdr.lctl;
    NODEELEMENT *tmpElement;
    Size elementSize = MAXALIGN(sizeof(art_leaf));
    tmpElement = NODEELEMENT_LINK(node);

	Assert(tmpElement->link == NULL);

    MemSet(node, 0, elementSize);

    SpinLockAcquire(&memhdr->freeList.mutex);

    tmpElement->link = memhdr->freeList.freeList;
    memhdr->freeList.freeList = tmpElement;
    memhdr->freeList.nentries++;

    SpinLockRelease(&memhdr->freeList.mutex);

	artp->hdr.tree->leaves--;
}

/*
 * Recursively destroys the tree
 */
static void
destroy_node(ARTREE *artp, art_node *n)
{
    int i, idx;
    NodePointer p;

    if (!n) {
        return;
    }
    if (IS_LEAF(n)) {
        // pfree(LEAF_RAW(n));
        dealloc_leaf(artp, LEAF_RAW(n));
        return;
    }

    switch (n->type) {
    case NODE4:
        p.p1 = (art_node4 *) n;
        for (i = 0; i < n->num_children; i++) {
            destroy_node(artp, p.p1->children[i]);
        }
        break;

    case NODE16:
        p.p2 = (art_node16 *) n;
        for (i = 0; i < n->num_children; i++) {
            destroy_node(artp, p.p2->children[i]);
        }
        break;

    case NODE48:
        p.p3 = (art_node48 *) n;
        for (i = 0; i < 256; i++) {
            idx = ((art_node48 *) n)->keys[i];
            if (!idx)
                continue;
            destroy_node(artp, p.p3->children[idx - 1]);
        }
        break;

    case NODE256:
        p.p4 = (art_node256 *) n;
        for (i = 0; i < 256; i++) {
            if (p.p4->children[i])
                destroy_node(artp, p.p4->children[i]);
        }
        break;

    default:
        elog(ERROR, "destroy_node: unknown art_node type");
    }

    // pfree(n);
    dealloc_node(artp, n);
}

/**
 * Destroys an ART tree
 * @return 0 on success.
 */
static int
art_tree_destroy(ARTREE *artp, art_tree *t)
{
    destroy_node(artp, t->root);
	/* clear dangling pointer to the root node that is in freelist now */
	t->root = NULL;
    return 0;
}

static art_node **
find_child(art_node *n, uint8 c)
{
    int i, mask, bitfield;
    NodePointer p;
#if defined(__i386__) || defined(__amd64__)
    __m128i cmp;
#endif
    switch (n->type) {
    case NODE4:
        p.p1 = (art_node4 *) n;
        for (i = 0; i < n->num_children; i++) {
            /* this cast works around a bug in gcc 5.1 when unrolling loops
             * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=59124
             */
            if (((uint8 *) p.p1->keys)[i] == c)
                return &p.p1->children[i];
        }
        break;

    case NODE16:
        p.p2 = (art_node16 *) n;

#if defined(__i386__) || defined(__amd64__)
        // Compare the key to all 16 stored keys
        cmp = _mm_cmpeq_epi8(_mm_set1_epi8(c),
                             _mm_loadu_si128((__m128i *) p.p2->keys));

        // Use a mask to ignore children that don't exist
        mask = (1 << n->num_children) - 1;
        bitfield = _mm_movemask_epi8(cmp) & mask;
#else
        // Compare the key to all 16 stored keys
        bitfield = 0;
        for (i = 0; i < 16; ++i) {
            if (p.p2->keys[i] == c)
                bitfield |= (1 << i);
        }

        // Use a mask to ignore children that don't exist
        mask = (1 << n->num_children) - 1;
        bitfield &= mask;
#endif

        /*
         * If we have a match (any bit set) then we can
         * return the pointer match using ctz to get
         * the index.
         */
        if (bitfield)
            return &p.p2->children[__builtin_ctz(bitfield)];
        break;

    case NODE48:
        p.p3 = (art_node48 *) n;
        i = p.p3->keys[c];
        if (i)
            return &p.p3->children[i - 1];
        break;

    case NODE256:
        p.p4 = (art_node256 *) n;
        if (p.p4->children[c])
            return &p.p4->children[c];
        break;

	default:
        elog(ERROR, "find_child: unknown art_node type");
    }
    return NULL;
}

/**
 * Returns the number of prefix characters shared between
 * the key and node.
 */
static int
check_prefix(const art_node *n, const uint8 *key, int key_len,
             int depth)
{
    int max_cmp = Min(Min(n->partial_len, MAX_PREFIX_LEN), key_len - depth);
    int idx;
    for (idx = 0; idx < max_cmp; idx++) {
        if (n->partial[idx] != key[depth + idx])
            return idx;
    }
    return idx;
}

/**
 * Checks if a leaf matches
 * @return 0 on success.
 */
static int
leaf_matches(const art_leaf *n, const uint8 *key, int key_len,
             int depth)
{
    IGNORE_UNUSED(depth);
    // Fail if the key lengths are different
    if (n->key_len != (uint32) key_len)
        return 1;

    // Compare the keys starting at the depth
    return memcmp(n->key, key, key_len);
}

/**
 * Searches for a value in the ART tree
 * @arg t The tree
 * @arg key The key
 * @arg key_len The length of the key
 * @return NULL if the item was not found, otherwise
 * the value pointer is returned.
 */
static void *
art_search(const art_tree *t, const uint8 *key, int key_len)
{
    art_node **child;
    art_node *n = t->root;
    int prefix_len, depth = 0;
    while (n) {
        // Might be a leaf
        if (IS_LEAF(n)) {
            n = (art_node *) LEAF_RAW(n);
            // Check if the expanded path matches
            if (!leaf_matches((art_leaf *) n, key, key_len, depth)) {
                return ((art_leaf *) n)->value;
            }
            return NULL;
        }

        // Bail if the prefix does not match
        if (n->partial_len) {
            prefix_len = check_prefix(n, key, key_len, depth);
            if (prefix_len != Min(MAX_PREFIX_LEN, n->partial_len))
                return NULL;
            depth = depth + n->partial_len;
        }

        // Recursively search
        child = find_child(n, key[depth]);
        n = (child) ? *child : NULL;
        depth++;
    }
    return NULL;
}

// Find the minimum leaf under a node
static art_leaf *
minimum(const art_node *n)
{
    int idx;
    // Handle base cases
    if (!n)
        return NULL;
    if (IS_LEAF(n))
        return LEAF_RAW(n);

    switch (n->type) {
    case NODE4:
        return minimum(((const art_node4 *) n)->children[0]);
    case NODE16:
        return minimum(((const art_node16 *) n)->children[0]);
    case NODE48:
        idx = 0;
        while (!((const art_node48 *) n)->keys[idx])
            idx++;
        idx = ((const art_node48 *) n)->keys[idx] - 1;
        return minimum(((const art_node48 *) n)->children[idx]);
    case NODE256:
        idx = 0;
        while (!((const art_node256 *) n)->children[idx])
            idx++;
        return minimum(((const art_node256 *) n)->children[idx]);
    default:
        elog(ERROR, "minimum: unknown art_node type");
    }
}

static art_leaf *
make_leaf(ARTREE *artp, const uint8 *key, int key_len, void *value)
{
    art_leaf *l = (art_leaf *) alloc_leaf(artp);
    l->value = value;
    l->key_len = key_len;
    memcpy(l->key, key, key_len);
    return l;
}

static int
longest_common_prefix(art_leaf *l1, art_leaf *l2, int depth)
{
    int max_cmp = Min(l1->key_len, l2->key_len) - depth;
    int idx;
    for (idx = 0; idx < max_cmp; idx++) {
        if (l1->key[depth + idx] != l2->key[depth + idx])
            return idx;
    }
    return idx;
}

static void
copy_header(art_node *dest, art_node *src)
{
	dest->num_children = src->num_children;
	dest->partial_len = src->partial_len;
	memcpy(dest->partial, src->partial, Min(MAX_PREFIX_LEN, src->partial_len));
}

static void
add_child256(art_node256 *n, art_node **ref, uint8 c, void *child)
{
	IGNORE_UNUSED(ref);
	n->n.num_children++;
	n->children[c] = (art_node *) child;
}

static void
add_child48(ARTREE *artp, art_node48 *n, art_node **ref, uint8 c, void *child)
{
    if (n->n.num_children < NODE48_MAX) {
        int pos = 0;
        while (n->children[pos])
            pos++;
        n->children[pos] = (art_node *) child;
        n->keys[c] = pos + 1;
        n->n.num_children++;
    } else {
        art_node256 *new_node = (art_node256 *) alloc_node(artp, NODE256);
        for (int i = 0; i < 256; i++) {
            if (n->keys[i]) {
                new_node->children[i] = n->children[n->keys[i] - 1];
            }
        }
        copy_header((art_node *) new_node, (art_node *) n);
        *ref = (art_node *) new_node;
        // pfree(n);
        dealloc_node(artp, (art_node *) n);
        add_child256(new_node, ref, c, child);
    }
}

static void
add_child16(ARTREE *artp, art_node16 *n, art_node **ref, uint8 c, void *child)
{
    if (n->n.num_children < NODE16_MAX) {
        unsigned idx, bitfield;
        unsigned mask = (1 << n->n.num_children) - 1;

#if defined(__i386__) || defined(__amd64__)
        __m128i cmp;

        // Compare the key to all 16 stored keys
        cmp = _mm_cmplt_epi8(_mm_set1_epi8(c),
                             _mm_loadu_si128((__m128i *) n->keys));

        // Use a mask to ignore children that don't exist
        bitfield = _mm_movemask_epi8(cmp) & mask;
#else
        // Compare the key to all 16 stored keys
        bitfield = 0;
        for (short i = 0; i < 16; ++i) {
            if (c < n->keys[i])
                bitfield |= (1 << i);
        }

        // Use a mask to ignore children that don't exist
        bitfield &= mask;
#endif

        // Check if less than any
        if (bitfield) {
            idx = __builtin_ctz(bitfield);
            memmove(n->keys + idx + 1, n->keys + idx, n->n.num_children - idx);
            memmove(n->children + idx + 1, n->children + idx,
                    (n->n.num_children - idx) * sizeof(void *));
        } else
            idx = n->n.num_children;

        // Set the child
        n->keys[idx] = c;
        n->children[idx] = (art_node *) child;
        n->n.num_children++;

    } else {
        art_node48 *new_node = (art_node48 *) alloc_node(artp, NODE48);

        // Copy the child pointers and populate the key map
        memcpy(new_node->children, n->children,
               sizeof(void *) * n->n.num_children);
        for (int i = 0; i < n->n.num_children; i++) {
            new_node->keys[n->keys[i]] = i + 1;
        }
        copy_header((art_node *) new_node, (art_node *) n);
        *ref = (art_node *) new_node;
        // pfree(n);
        dealloc_node(artp, (art_node *) n);
        add_child48(artp, new_node, ref, c, child);
    }
}

static void
add_child4(ARTREE *artp, art_node4 *n, art_node **ref, uint8 c, void *child)
{
    if (n->n.num_children < NODE4_MAX) {
        int idx;
        for (idx = 0; idx < n->n.num_children; idx++) {
            if (c < n->keys[idx])
                break;
        }

        // Shift to make room
        memmove(n->keys + idx + 1, n->keys + idx, n->n.num_children - idx);
        memmove(n->children + idx + 1, n->children + idx,
                (n->n.num_children - idx) * sizeof(void *));

        // Insert element
        n->keys[idx] = c;
        n->children[idx] = (art_node *) child;
        n->n.num_children++;

    } else {
        art_node16 *new_node = (art_node16 *) alloc_node(artp, NODE16);

        // Copy the child pointers and the key map
        memcpy(new_node->children, n->children,
               sizeof(void *) * n->n.num_children);
        memcpy(new_node->keys, n->keys, sizeof(uint8) * n->n.num_children);
        copy_header((art_node *) new_node, (art_node *) n);
        *ref = (art_node *) new_node;
        // pfree(n);
        dealloc_node(artp, (art_node *) n);
        add_child16(artp, new_node, ref, c, child);
    }
}

static void
add_child(ARTREE *artp, art_node *n, art_node **ref, uint8 c, void *child)
{
    switch (n->type) {
    case NODE4:
        return add_child4(artp, (art_node4 *) n, ref, c, child);
    case NODE16:
        return add_child16(artp, (art_node16 *) n, ref, c, child);
    case NODE48:
        return add_child48(artp, (art_node48 *) n, ref, c, child);
    case NODE256:
        return add_child256((art_node256 *) n, ref, c, child);
    default:
        elog(ERROR, "add_child: unknown art_node type");
    }
}

/**
 * Calculates the index at which the prefixes mismatch
 */
static int
prefix_mismatch(const art_node *n, const uint8 *key, int key_len, int depth)
{
    int max_cmp = Min(Min(MAX_PREFIX_LEN, n->partial_len), key_len - depth);
    int idx;
    for (idx = 0; idx < max_cmp; idx++) {
        if (n->partial[idx] != key[depth + idx])
            return idx;
    }

    // If the prefix is short we can avoid finding a leaf
    if (n->partial_len > MAX_PREFIX_LEN) {
        // Prefix is longer than what we've checked, find a leaf
        art_leaf *l = minimum(n);
        max_cmp = Min(l->key_len, key_len) - depth;
        for (; idx < max_cmp; idx++) {
            if (l->key[idx + depth] != key[depth + idx])
                return idx;
        }
    }
    return idx;
}

static void *
recursive_insert(ARTREE *artp, art_node *n, art_node **ref, const uint8 *key,
                 int key_len, void *value, int depth, int *old)
{
    art_node4 *new_node;
    art_leaf *l;
    art_node **child;
    // If we are at a NULL node, inject a leaf
    if (!n) {
        *ref = (art_node *) SET_LEAF(make_leaf(artp, key, key_len, value));
        return NULL;
    }

    // If we are at a leaf, we need to replace it with a node
    if (IS_LEAF(n)) {
        int longest_prefix;
        art_leaf *l2;
        l = LEAF_RAW(n);

        // Check if we are updating an existing value
        if (!leaf_matches(l, key, key_len, depth)) {
            void *old_val = l->value;
			// todo: add command variety like in hashtable e.g. HASH_ENTER
			// instead of simple in-place update
			// l->value = value;
            *old = 1;
            return old_val;
        }

        // New value, we must split the leaf into a node4
        new_node = (art_node4 *) alloc_node(artp, NODE4);

        // Create a new leaf
        l2 = make_leaf(artp, key, key_len, value);

        // Determine longest prefix
        longest_prefix = longest_common_prefix(l, l2, depth);
        new_node->n.partial_len = longest_prefix;
        memcpy(new_node->n.partial, key + depth,
               Min(MAX_PREFIX_LEN, longest_prefix));
        // Add the leafs to the new node4
        *ref = (art_node *) new_node;
        add_child4(artp, new_node, ref, l->key[depth + longest_prefix],
                   SET_LEAF(l));
        add_child4(artp, new_node, ref, l2->key[depth + longest_prefix],
                   SET_LEAF(l2));
        return NULL;
    }

    // Check if given node has a prefix
    if (n->partial_len) {
        // Determine if the prefixes differ, since we need to split
        int prefix_diff = prefix_mismatch(n, key, key_len, depth);
		if ((uint32) prefix_diff >= n->partial_len) {
            depth += n->partial_len;
            goto RECURSE_SEARCH;
        }

        // Create a new node
        new_node = (art_node4 *) alloc_node(artp, NODE4);
        *ref = (art_node *) new_node;
        new_node->n.partial_len = prefix_diff;
        memcpy(new_node->n.partial, n->partial,
               Min(MAX_PREFIX_LEN, prefix_diff));

        // Adjust the prefix of the old node
        if (n->partial_len <= MAX_PREFIX_LEN) {
            add_child4(artp, new_node, ref, n->partial[prefix_diff], n);
            n->partial_len -= (prefix_diff + 1);
            memmove(n->partial, n->partial + prefix_diff + 1,
                    Min(MAX_PREFIX_LEN, n->partial_len));
        } else {
            n->partial_len -= (prefix_diff + 1);
            l = minimum(n);
            add_child4(artp, new_node, ref, l->key[depth + prefix_diff], n);
            memcpy(n->partial, l->key + depth + prefix_diff + 1,
                   Min(MAX_PREFIX_LEN, n->partial_len));
        }

        // Insert the new leaf
        l = make_leaf(artp, key, key_len, value);
        add_child4(artp, new_node, ref, key[depth + prefix_diff], SET_LEAF(l));
        return NULL;
    }

RECURSE_SEARCH:;

    // Find a child to recurse to
    child = find_child(n, key[depth]);
    if (child) {
        return recursive_insert(artp, *child, child, key, key_len, value,
                                depth + 1, old);
    }

    // No child, node goes within us
    l = make_leaf(artp, key, key_len, value);
    add_child(artp, n, ref, key[depth], SET_LEAF(l));
    return NULL;
}

/**
 * Inserts a new value into the ART tree
 * @arg t The tree
 * @arg key The key
 * @arg key_len The length of the key
 * @arg value Opaque value.
 * @return NULL if the item was newly inserted, otherwise
 * the old value pointer is returned.
 */
static void *
art_insert(ARTREE *artp, const uint8 *key, int key_len, void *value)
{
    int old_val = 0;
    art_tree *t = artp->hdr.tree;
    void *old = recursive_insert(artp, t->root, &t->root, key, key_len, value, 0,
                                 &old_val);
    return old;
}

static void
remove_child256(ARTREE *artp, art_node256 *n, art_node **ref, uint8 c)
{
    n->children[c] = NULL;
    n->n.num_children--;

    // Resize to a node48 on underflow, not immediately to prevent
    // trashing if we sit on the 48/49 boundary
    if (n->n.num_children == NODE256_MIN) {
        int i, pos = 0;
        art_node48 *new_node = (art_node48 *) alloc_node(artp, NODE48);
        *ref = (art_node *) new_node;
        copy_header((art_node *) new_node, (art_node *) n);

        for (i = 0; i < 256; i++) {
            if (n->children[i]) {
                new_node->children[pos] = n->children[i];
                new_node->keys[i] = pos + 1;
                pos++;
            }
        }
        // pfree(n);
        dealloc_node(artp, (art_node *) n);
    }
}

static void
remove_child48(ARTREE *artp, art_node48 *n, art_node **ref, uint8 c)
{
    int pos = n->keys[c];
    n->keys[c] = 0;
    n->children[pos - 1] = NULL;
    n->n.num_children--;

    if (n->n.num_children == NODE48_MIN) {
        int i, child = 0;
        art_node16 *new_node = (art_node16 *) alloc_node(artp, NODE16);
        *ref = (art_node *) new_node;
        copy_header((art_node *) new_node, (art_node *) n);

        for (i = 0; i < 256; i++) {
            pos = n->keys[i];
            if (pos) {
                new_node->keys[child] = i;
                new_node->children[child] = n->children[pos - 1];
                child++;
            }
        }
        // pfree(n);
        dealloc_node(artp, (art_node *) n);
    }
}

static void
remove_child16(ARTREE *artp, art_node16 *n, art_node **ref, art_node **l)
{
    int pos = l - n->children;
    memmove(n->keys + pos, n->keys + pos + 1, n->n.num_children - 1 - pos);
    memmove(n->children + pos, n->children + pos + 1,
            (n->n.num_children - 1 - pos) * sizeof(void *));
    n->n.num_children--;

    if (n->n.num_children == NODE16_MIN) {
        art_node4 *new_node = (art_node4 *) alloc_node(artp, NODE4);
        *ref = (art_node *) new_node;
        copy_header((art_node *) new_node, (art_node *) n);
        memcpy(new_node->keys, n->keys, 4);
        memcpy(new_node->children, n->children, 4 * sizeof(void *));
        // pfree(n);
        dealloc_node(artp, (art_node *) n);
    }
}

static void
remove_child4(ARTREE *artp, art_node4 *n, art_node **ref, art_node **l)
{
    int pos = l - n->children;
    memmove(n->keys + pos, n->keys + pos + 1, n->n.num_children - 1 - pos);
    memmove(n->children + pos, n->children + pos + 1,
            (n->n.num_children - 1 - pos) * sizeof(void *));
    n->n.num_children--;

    // Remove nodes with only a single child
    if (n->n.num_children == NODE4_MIN) {
        art_node *child = n->children[0];
        if (!IS_LEAF(child)) {
            // Concatenate the prefixes
            int prefix = n->n.partial_len;
            if (prefix < MAX_PREFIX_LEN) {
                n->n.partial[prefix] = n->keys[0];
                prefix++;
            }
            if (prefix < MAX_PREFIX_LEN) {
                int sub_prefix =
                    Min(child->partial_len, MAX_PREFIX_LEN - prefix);
                memcpy(n->n.partial + prefix, child->partial, sub_prefix);
                prefix += sub_prefix;
            }

            // Store the prefix in the child
            memcpy(child->partial, n->n.partial, Min(prefix, MAX_PREFIX_LEN));
            child->partial_len += n->n.partial_len + 1;
        }
        *ref = child;
        // pfree(n);
        dealloc_node(artp, (art_node *) n);
    }
}

static void
remove_child(ARTREE *artp, art_node *n, art_node **ref, uint8 c, art_node **l)
{
    switch (n->type) {
    case NODE4:
        return remove_child4(artp, (art_node4 *) n, ref, l);
    case NODE16:
        return remove_child16(artp, (art_node16 *) n, ref, l);
    case NODE48:
        return remove_child48(artp, (art_node48 *) n, ref, c);
    case NODE256:
        return remove_child256(artp, (art_node256 *) n, ref, c);
    default:
        elog(ERROR, "remove_child: unknown art_node type");
    }
}

static art_leaf *
recursive_delete(ARTREE *artp, art_node *n, art_node **ref, const uint8 *key,
                 int key_len, int depth)
{
    art_node **child;
    // Search terminated
    if (!n)
        return NULL;

    // Handle hitting a leaf node
    if (IS_LEAF(n)) {
        art_leaf *l = LEAF_RAW(n);
        if (!leaf_matches(l, key, key_len, depth)) {
            *ref = NULL;
            return l;
        }
        return NULL;
    }

    // Bail if the prefix does not match
    if (n->partial_len) {
        int prefix_len = check_prefix(n, key, key_len, depth);
        if (prefix_len != Min(MAX_PREFIX_LEN, n->partial_len)) {
            return NULL;
        }
        depth = depth + n->partial_len;
    }

    // Find child node
    child = find_child(n, key[depth]);
    if (!child)
        return NULL;

    // If the child is leaf, delete from this node
    if (IS_LEAF(*child)) {
        art_leaf *l = LEAF_RAW(*child);
        if (!leaf_matches(l, key, key_len, depth)) {
            remove_child(artp, n, ref, key[depth], child);
            return l;
        }
        return NULL;
    } else {
        return recursive_delete(artp, *child, child, key, key_len, depth + 1);
    }
}

/**
 * Deletes a value from the ART tree
 * @arg t The tree
 * @arg key The key
 * @arg key_len The length of the key
 * @return NULL if the item was not found, otherwise
 * the value pointer is returned.
 */
static void *
art_delete(ARTREE *artp, const uint8 *key, int key_len)
{
    art_tree *t = artp->hdr.tree;
    art_leaf *l = recursive_delete(artp, t->root, &t->root, key, key_len, 0);
    if (l) {
        void *old = l->value;
        // pfree(l);
        dealloc_leaf(artp, l);
        return old;
    }
    return NULL;
}

// Recursively iterates over the tree
static int
recursive_iter(art_node *n, art_callback cb, void *data)
{
	int i, idx, res;
	// Handle base cases
	if (!n) return 0;
	if (IS_LEAF(n)) {
		art_leaf *l = LEAF_RAW(n);
		return cb(data, (const uint8 *) l->key, l->key_len, l->value);
	}

	switch (n->type) {
	case NODE4:
		for (i = 0; i < n->num_children; i++) {
			res = recursive_iter(((art_node4 *) n)->children[i], cb, data);
			if (res) return res;
		}
		break;
	case NODE16:
		for (i = 0; i < n->num_children; i++) {
			res = recursive_iter(((art_node16 *) n)->children[i], cb, data);
			if (res) return res;
		}
		break;
	case NODE48:
		for (i = 0; i < 256; i++) {
			idx = ((art_node48 *) n)->keys[i];
			if (!idx) continue;
			res = recursive_iter(((art_node48 *) n)->children[idx - 1], cb, data);
			if (res) return res;
		}
		break;
	case NODE256:
		for (i = 0; i < 256; i++) {
			if (!((art_node256 *) n)->children[i])
				continue;
			res = recursive_iter(((art_node256 *) n)->children[i], cb, data);
			if (res) return res;
		}
		break;
	default:
		elog(ERROR, "recursive_iter: unknown art_node type");
	}
	return 0;
}

/**
 * Iterates through the entries pairs in the map,
 * invoking a callback for each. The call back gets a
 * key, value for each and returns an integer stop value.
 * If the callback returns non-zero, then the iteration stops.
 * @arg t The tree to iterate over
 * @arg cb The callback function to invoke
 * @arg data Opaque handle passed to the callback
 * @return 0 on success, or the return of the callback.
 */
static int
art_iter(art_tree *t, art_callback cb, void *data)
{
	return recursive_iter(t->root, cb, data);
}

/**
 * Checks if a leaf prefix matches
 * @return 0 on success.
 */
static int
leaf_prefix_matches(const art_leaf *n, const uint8 *prefix, int prefix_len)
{
	// Fail if the key length is too short
	if (n->key_len < (uint32) prefix_len)
		return 1;

	// Compare the keys
	return memcmp(n->key, prefix, prefix_len);
}

/**
 * Iterates through the entries pairs in the map,
 * invoking a callback for each that matches a given prefix.
 * The call back gets a key, value for each and returns an integer stop value.
 * If the callback returns non-zero, then the iteration stops.
 * @arg t The tree to iterate over
 * @arg prefix The prefix of keys to read
 * @arg prefix_len The length of the prefix
 * @arg cb The callback function to invoke
 * @arg data Opaque handle passed to the callback
 * @return 0 on success, or the return of the callback.
 */
static int
art_iter_prefix(art_tree *t, const uint8 *key, int key_len, art_callback cb, void *data)
{
	art_node **child;
	art_node *n = t->root;
	int prefix_len, depth = 0;
	while (n)
	{
		// Might be a leaf
		if (IS_LEAF(n))
		{
			n = (art_node *) LEAF_RAW(n);
			// Check if the expanded path matches
			if (!leaf_prefix_matches((art_leaf *) n, key, key_len)) {
				art_leaf *l = (art_leaf *) n;
				return cb(data, (const uint8 *) l->key, l->key_len, l->value);
			}
			return 0;
		}

		// If the depth matches the prefix, we need to handle this node
		if (depth == key_len)
		{
			art_leaf *l = minimum(n);
			if (!leaf_prefix_matches(l, key, key_len))
				return recursive_iter(n, cb, data);
			return 0;
		}

		// Bail if the prefix does not match
		if (n->partial_len)
		{
			prefix_len = prefix_mismatch(n, key, key_len, depth);

			// Guard if the mis-match is longer than the MAX_PREFIX_LEN
			if ((uint32_t) prefix_len > n->partial_len) {
				prefix_len = n->partial_len;
			}

			// If there is no match, search is terminated
			if (!prefix_len) {
				return 0;

			// If we've matched the prefix, iterate on this node
			} else if (depth + prefix_len == key_len) {
				return recursive_iter(n, cb, data);
			}

			// if there is a full match, go deeper
			depth = depth + n->partial_len;
		}

		// Recursively search
		child = find_child(n, key[depth]);
		n = (child) ? *child : NULL;
		depth++;
	}
	return 0;
}
