
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

static long stats[12];

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
#define LEAF_FREELIST_IDX(type) NODE_FREELIST_IDX(type)

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

typedef struct FreeListARTree
{
	slock_t		mutex;
	long		nentries;
	NODEELEMENT *freeList;
} FreeListARTree;

/*
 * Header structure for a tree --- contains all changeable info
 *
 * In a shared-memory tree, the SHMTREEHDR is in shared memory, while
 * each backend has a local SHMTREE struct.
 */
struct SHMTREEHDR
{
	FreeListNode freeList[5];

	Size keysize;	 /* key length in bytes */
	Size entrysize;  /* total user element size in bytes */
	int nelem_alloc; /* number of entries to allocate at once */
};

/*
 * Top control structure for tree --- in a shared tree, each backend
 * has its own copy (OK since no fields change at runtime)
 */
struct SHMTREE
{
	SHMTREEHDR *tctl;	 /* => shared control information */
	art_tree *tree;		 /* allocated right after tctl header struct */
	TreeAllocFunc alloc; /* memory allocator */
	MemoryContext tcxt;	 /* memory context if default allocator used */
	Size keysize;		 /* key length in bytes */
	Size entrysize;		 /* total user element size in bytes */
	char *treename;
	uintptr_t shm_addr;
	bool isshared;	/* true if tree is in shared memory */
};

/* allocation */
static art_node *alloc_node(SHMTREE *shmt, uint8 type);
static void dealloc_node(SHMTREE *shmt, art_node *n);
static art_leaf *alloc_leaf(SHMTREE *shmt);
static void dealloc_leaf(SHMTREE *shmt, art_leaf *n);
static bool element_alloc(SHMTREE *shmt, int nelem, int ntype);

/* utility */
static int check_prefix(const art_node *n, const uint8 *key, int key_len, int depth);
static int longest_common_prefix(art_leaf *l1, art_leaf *l2, int depth);
static void copy_header(art_node *dest, art_node *src);
static art_node ** find_child(art_node *n, uint8 c);
static int prefix_mismatch(const art_node *n, const uint8 *key, int key_len, int depth);
static int leaf_prefix_matches(const art_leaf *n, const uint8 *prefix, int prefix_len);

/* nodes maintenance */
static art_leaf * make_leaf(SHMTREE *shmt, const uint8 *key, int key_len, void *value);
static void add_child256(art_node256 *n, art_node **ref, uint8 c, void *child);
static void add_child48(SHMTREE *shmt, art_node48 *n, art_node **ref, uint8 c, void *child);
static void add_child16(SHMTREE *shmt, art_node16 *n, art_node **ref, uint8 c, void *child);
static void add_child4(SHMTREE *shmt, art_node4 *n, art_node **ref, uint8 c, void *child);
static void add_child(SHMTREE *shmt, art_node *n, art_node **ref, uint8 c, void *child);
static void remove_child256(SHMTREE *shmt, art_node256 *n, art_node **ref, uint8 c);
static void remove_child48(SHMTREE *shmt, art_node48 *n, art_node **ref, uint8 c);
static void remove_child16(SHMTREE *shmt, art_node16 *n, art_node **ref, art_node **l);
static void remove_child4(SHMTREE *shmt, art_node4 *n, art_node **ref, art_node **l);
static void remove_child(SHMTREE *shmt, art_node *n, art_node **ref, uint8 c, art_node **l);

/* destroy */
static void destroy_node(SHMTREE *shmt, art_node *n);
static int art_tree_destroy(SHMTREE *shmt, art_tree *t);

/* basic operations */
static void *art_insert(SHMTREE *shmt, const uint8 *key, int key_len,
                        void *value);
static void *art_delete(SHMTREE *shmt, const uint8 *key, int key_len);
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
#define NODE4_NELEM		(NBuffers >> 2)
#define NODE16_NELEM	(NBuffers >> 3)
#define NODE48_NELEM	(NBuffers >> 4)
#define NODE256_NELEM	(NBuffers >> 5)
#define NODELEAF_NELEM	(NBuffers << 1)
#define NODESUBTREE_NELEM 10000

static void *
TreeAlloc(Size size)
{
	Assert(MemoryContextIsValid(CurrentTreeCxt));
	return MemoryContextAlloc(CurrentTreeCxt, size);
}

SHMTREE *
artree_create(const char *treename, ARTREECTL *info, int flags)
{
    SHMTREE *shmt;
    SHMTREEHDR *shmth;
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
        CurrentTreeCxt =
            AllocSetContextCreate(CurrentTreeCxt, "shmtree", ALLOCSET_DEFAULT_SIZES);
	}

	/* Initialize the tree structure, plus a copy of the tree name */
	shmt = (SHMTREE *) TreeAlloc(sizeof(SHMTREE) + strlen(treename) + 1);
	MemSet(shmt, 0, sizeof(SHMTREE));

	shmt->treename = (char *) (shmt + 1);
	strcpy(shmt->treename, treename);

	/* If we have a private context, label it with tree's name */
	if (!(flags & ARTREE_SHARED_MEM))
		MemoryContextSetIdentifier(CurrentTreeCxt, shmt->treename);

	/* And select the entry allocation function, too. */
	if (flags & ARTREE_ALLOC)
		shmt->alloc = info->alloc;
	else
		shmt->alloc = TreeAlloc;

	if (flags & ARTREE_SHARED_MEM)
	{
		shmt->tctl = info->tctl;
		shmt->tree = (art_tree *) (((char *) info->tctl) + sizeof(SHMTREEHDR));
		shmt->tcxt = NULL;
		shmt->isshared = true;

		if (flags & ARTREE_ATTACH)
		{
			shmth = shmt->tctl;
			shmt->keysize = shmth->keysize;

			return shmt;
		}
	}
	else
	{
		shmt->tctl = NULL;
		shmt->tree = NULL;
		shmt->tcxt = CurrentTreeCxt;
		shmt->isshared = false;
	}

	if (!shmt->tctl)
	{
		shmt->tctl = (SHMTREEHDR *) shmt->alloc(sizeof(SHMTREEHDR));
		if (!shmt->tctl)
			ereport(ERROR,
					(errcode(ERRCODE_OUT_OF_MEMORY),
					 errmsg("out of memory")));
	}

	MemSet(shmt->tctl, 0, sizeof(SHMTREEHDR));

	shmth = shmt->tctl;
    art = shmt->tree;
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
		// Assert(info->entrysize >= info->keysize);
		shmth->keysize = info->keysize;
		shmth->entrysize = info->entrysize;
	}

	/* make local copies of heavily-used constant fields */
	shmt->keysize = shmth->keysize;

	if (flags & ARTREE_SHARED_MEM)
	{
        if (!element_alloc(shmt, NODE4_NELEM, NODE4))
            ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory")));
        if (!element_alloc(shmt, NODE16_NELEM, NODE16))
            ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory")));
        if (!element_alloc(shmt, NODE48_NELEM, NODE48))
            ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory")));
        if (!element_alloc(shmt, NODE256_NELEM, NODE256))
            ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory")));
        if (!element_alloc(shmt, NODELEAF_NELEM, NODELEAF))
            ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY), errmsg("out of memory")));
	}

    return shmt;
}

/*
 * allocate some new elements and link them into the indicated free list
 */
static bool
element_alloc(SHMTREE *shmt, int nelem, int ntype)
{
    SHMTREEHDR *shmth = shmt->tctl;
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
    case NODELEAF:
        elementSize += MAXALIGN(sizeof(art_leaf)) + shmt->keysize;
        break;
    default:
		elog(ERROR, "element_alloc: unknown art_node type");
    }

    CurrentTreeCxt = shmt->tcxt;
    firstElement = (NODEELEMENT *) shmt->alloc(nelem * elementSize);

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
    
    SpinLockInit(&shmth->freeList[freelist_idx].mutex);
    // SpinLockAcquire(&shmth->freeList[freelist_idx].mutex);

    /* freelist could be nonempty if two backends did this concurrently */
    firstElement->link = shmth->freeList[freelist_idx].freeList;
    shmth->freeList[freelist_idx].freeList = prevElement;
    shmth->freeList[freelist_idx].nentries = nelem;

    // SpinLockRelease(&shmth->freeList[freelist_idx].mutex);

	return true;
}

Size
artree_get_shared_size(ARTREECTL *info, int flags)
{
	return sizeof(SHMTREEHDR) + sizeof(art_tree);
}

Size
artree_subtreelist_size()
{
	Size size, elementSize;
	size = MAXALIGN(sizeof(FreeListARTree));
	// we will reuse existing shmtreehdr of sharedbuftree...
	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + sizeof(SHMTREE *) + sizeof(art_tree);
	size = add_size(size, mul_size(elementSize, NODESUBTREE_NELEM));
	return size;
}

LWLock *
artree_getlock(SHMTREE *shmt)
{
    return &shmt->tree->lock;
}

void
artree_build_subtreelist(FreeListARTree *artlist, SHMTREE *buftree)
{
	// chain and init shmtrees using original copy(share freelists)
	NODEELEMENT *firstElement;
	NODEELEMENT *tmpElement;
	NODEELEMENT *prevElement;
	int i;
	int nelem = NODESUBTREE_NELEM;
	Size elementSize;

	SHMTREE *shmt;
	SHMTREEHDR *shmth = buftree->tctl;
	uintptr_t *node_shmt;
	char *treename = "blktree";
	char *ptr;
	int trancheid = LWLockNewTrancheId();

	CurrentTreeCxt = TopMemoryContext;

	elementSize =
		MAXALIGN(sizeof(NODEELEMENT)) + sizeof(SHMTREE *) + sizeof(art_tree);

	firstElement =
		(NODEELEMENT *) (((char *) artlist) + MAXALIGN(sizeof(FreeListARTree)));

	prevElement = NULL;
	tmpElement = firstElement;
	for (i = 0; i < nelem; i++)
	{
		// alloc non-shared, but forked shmtree
		shmt = (SHMTREE *) TreeAlloc(sizeof(SHMTREE) + strlen(treename) + 6);
		MemSet(shmt, 0, sizeof(SHMTREE));
		shmt->treename = (char *) (shmt + 1);
		strcpy(shmt->treename, treename);
		shmt->keysize = sizeof(BlockNumber);
		shmt->tctl = shmth;

		sprintf(shmt->treename + strlen(treename), "%d", i);
		// skip nodelement, next is shmtree pointer
		ptr = (((char *) tmpElement) + MAXALIGN(sizeof(NODEELEMENT)));
		node_shmt = (uintptr_t *) ptr;
		*node_shmt = (uintptr_t) shmt;
		// save spot in shared memory, that can be used for deallocation
		// maybe fix this weird alloc scheme later?
		shmt->shm_addr = (uintptr_t) node_shmt;

		ptr += sizeof(SHMTREE *);
		shmt->tree = (art_tree *) ptr;
		MemSet(shmt->tree, 0, sizeof(art_tree));
		shmt->isshared = true;

		LWLockInitialize(&shmt->tree->lock, trancheid);
		LWLockRegisterTranche(shmt->tree->lock.tranche, "blktree");

		Assert(node_shmt);
		Assert(*node_shmt);

		tmpElement->link = prevElement;
		prevElement = tmpElement;
		tmpElement = (NODEELEMENT *) (((char *) tmpElement) + elementSize);
	}

	SpinLockInit(&artlist->mutex);
	artlist->freeList = prevElement;
	artlist->nentries = NODESUBTREE_NELEM;
}

SHMTREE *
artree_alloc_subtree(FreeListARTree *artlist)
{
	NODEELEMENT *tmpElement;
	SHMTREE *shmt;
	uintptr_t *node_shmt;

	SpinLockAcquire(&artlist->mutex);
	tmpElement = artlist->freeList;
	artlist->freeList = tmpElement->link;
	artlist->nentries--;
	Assert(artlist->nentries >= 0);
	SpinLockRelease(&artlist->mutex);

	tmpElement->link = NULL;
	node_shmt = (uintptr_t *) NODEELEMENT_DATA(tmpElement);
	shmt = (SHMTREE *) (*node_shmt);
	Assert(shmt->shm_addr == (uintptr_t) node_shmt);
	// elog(WARNING, "shmtree_alloc_blktree: %p %s", shmt, shmt->treename);
	return shmt;
}

void
artree_dealloc_subtree(FreeListARTree *artlist, SHMTREE *shmt)
{
	NODEELEMENT *tmpElement;
	char *ptr;
	uintptr_t *node_shmt;

	// elog(WARNING, "shmtree_dealloc_blktree: %p %s", shmt, shmt->treename);

    // maybe fix this weird alloc scheme later?
	tmpElement = NODEELEMENT_LINK(shmt->shm_addr);
	ptr = NODEELEMENT_DATA(tmpElement);
    node_shmt = (uintptr_t *) ptr;
	Assert(node_shmt);
    Assert(*node_shmt == (uintptr_t) shmt);
	Assert(shmt->tree->root == NULL);

	SpinLockAcquire(&artlist->mutex);
	tmpElement->link = artlist->freeList;
	artlist->freeList = tmpElement;
	artlist->nentries++;
	Assert(artlist->nentries <= NODESUBTREE_NELEM);
	SpinLockRelease(&artlist->mutex);
}

Size
artree_estimate_size(Size keysize)
{
	Size		size;
	long elementSize;

	size = MAXALIGN(sizeof(SHMTREEHDR));

	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node4));
	size = add_size(size, mul_size(NODE4_NELEM, elementSize));

	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node16));
	size = add_size(size, mul_size(NODE16_NELEM, elementSize));

	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node48));
	size = add_size(size, mul_size(NODE48_NELEM, elementSize));

	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_node256));
	size = add_size(size, mul_size(NODE256_NELEM, elementSize));

	elementSize = MAXALIGN(sizeof(NODEELEMENT)) + MAXALIGN(sizeof(art_leaf)) + keysize;
	size = add_size(size, mul_size(NODELEAF_NELEM, elementSize));

	size = add_size(size, artree_subtreelist_size());

	return size;
}

int
artree_destroy(SHMTREE *shmt)
{
    return art_tree_destroy(shmt, shmt->tree);
}

void *
artree_insert(SHMTREE *shmt, const uint8 *key, void *value)
{
    return art_insert(shmt, key, shmt->keysize, value);
}

void *
artree_delete(SHMTREE *shmt, const uint8 *key)
{
    return art_delete(shmt, key, shmt->keysize);
}

void *
artree_search(SHMTREE *shmt, const uint8 *key)
{
    return art_search(shmt->tree, key, shmt->keysize);
}

int
artree_iter(SHMTREE *shmt, art_callback cb, void *data)
{
	return art_iter(shmt->tree, cb, data);
}

int
artree_iter_prefix(SHMTREE *shmt,
					const uint8 *prefix,
					int prefix_len,
					art_callback cb,
					void *data)
{
	Assert(prefix_len > 0);
	return art_iter_prefix(shmt->tree, prefix, prefix_len, cb, data);
}

void
artree_memory_usage(SHMTREE *shmt)
{

}

void
artree_nodes_proportion(SHMTREE *shmt)
{
    art_tree *t = shmt->tree;
	fprintf(stderr,
			"Node4: %u Node16: %u Node48: %u Node256: %u\n",
			t->size4, t->size16, t->size48, t->size256);
}

long *
artree_nodes_used(SHMTREE *shmt, FreeListARTree *artlist)
{
	SHMTREEHDR *shmth = shmt->tctl;
	/* do not bother with lock acquiring */
	stats[0] = NODELEAF_NELEM - shmth->freeList[4].nentries;
	stats[1] = NODE4_NELEM - shmth->freeList[0].nentries;
	stats[2] = NODE16_NELEM - shmth->freeList[1].nentries;
	stats[3] = NODE48_NELEM - shmth->freeList[2].nentries;
	stats[4] = NODE256_NELEM - shmth->freeList[3].nentries;
	stats[5] = NODESUBTREE_NELEM - artlist->nentries;
	stats[6] = NODELEAF_NELEM;
	stats[7] = NODE4_NELEM;
	stats[8] = NODE16_NELEM;
	stats[9] = NODE48_NELEM;
	stats[10] = NODE256_NELEM;
	stats[11] = NODESUBTREE_NELEM;

	return stats;
}


/**
 * Allocates a node of the given type.
 */
static art_node *
alloc_node(SHMTREE *shmt, uint8 type)
{
    SHMTREEHDR *shmth = shmt->tctl;
    NODEELEMENT *tmpElement;
    int freelist_idx;
    art_node *n;

	switch (type) {
	case NODE4:
		shmt->tree->size4++;
		break;
	case NODE16:
		shmt->tree->size16++;
		break;
	case NODE48:
		shmt->tree->size48++;
		break;
	case NODE256:
		shmt->tree->size256++;
		break;
	default:
		elog(ERROR, "alloc_node: unknown art_node type");
	}

	freelist_idx = NODE_FREELIST_IDX(type);

    SpinLockAcquire(&shmth->freeList[freelist_idx].mutex);

    tmpElement = shmth->freeList[freelist_idx].freeList;
    shmth->freeList[freelist_idx].freeList = tmpElement->link;
    shmth->freeList[freelist_idx].nentries--;

    SpinLockRelease(&shmth->freeList[freelist_idx].mutex);

	tmpElement->link = NULL;

    n = (art_node *) NODEELEMENT_DATA(tmpElement);
    n->type = type;
	// elog(WARNING, "alloc_node: %zu type=%d", (uintptr_t) n, type);
    return n;
}

static void
dealloc_node(SHMTREE *shmt, art_node *node)
{
    SHMTREEHDR *shmth = shmt->tctl;
    NODEELEMENT *tmpElement;
    Size elementSize;
	uint8 freelist_idx;
	uint8 type = node->type;

	switch (type) {
    case NODE4:
        elementSize = MAXALIGN(sizeof(art_node4));
		shmt->tree->size4--;
        break;
    case NODE16:
        elementSize = MAXALIGN(sizeof(art_node16));
		shmt->tree->size16--;
        break;
    case NODE48:
        elementSize = MAXALIGN(sizeof(art_node48));
		shmt->tree->size48--;
        break;
    case NODE256:
        elementSize = MAXALIGN(sizeof(art_node256));
		shmt->tree->size256--;
        break;
    default:
        elog(ERROR, "dealloc_node: unknown art_node type");
    }

	freelist_idx = NODE_FREELIST_IDX(type);
    tmpElement = NODEELEMENT_LINK(node);
	MemSet(node, 0, elementSize);

    SpinLockAcquire(&shmth->freeList[freelist_idx].mutex);

    tmpElement->link = shmth->freeList[freelist_idx].freeList;
    shmth->freeList[freelist_idx].freeList = tmpElement;
    shmth->freeList[freelist_idx].nentries++;

    SpinLockRelease(&shmth->freeList[freelist_idx].mutex);
	// elog(WARNING, "dealloc_node: %zu type=%d", (uintptr_t) node, type);
}

static art_leaf *
alloc_leaf(SHMTREE *shmt)
{
    SHMTREEHDR *shmth = shmt->tctl;
    NODEELEMENT *tmpElement;
    art_leaf *n;
	uint8 freelist_idx = LEAF_FREELIST_IDX(NODELEAF);

    SpinLockAcquire(&shmth->freeList[freelist_idx].mutex);

    tmpElement = shmth->freeList[freelist_idx].freeList;
    shmth->freeList[freelist_idx].freeList = tmpElement->link;
    shmth->freeList[freelist_idx].nentries--;

    SpinLockRelease(&shmth->freeList[freelist_idx].mutex);

	tmpElement->link = NULL;
	shmt->tree->leaves++;

    n = (art_leaf *) NODEELEMENT_DATA(tmpElement);
    return n;
}

static void
dealloc_leaf(SHMTREE *shmt, art_leaf *node)
{
    SHMTREEHDR *shmth = shmt->tctl;
    NODEELEMENT *tmpElement;
    Size elementSize = MAXALIGN(sizeof(art_leaf));
	uint8 freelist_idx = LEAF_FREELIST_IDX(NODELEAF);
    tmpElement = NODEELEMENT_LINK(node);

	Assert(tmpElement->link == NULL);

    MemSet(node, 0, elementSize);

    SpinLockAcquire(&shmth->freeList[freelist_idx].mutex);

    tmpElement->link = shmth->freeList[freelist_idx].freeList;
    shmth->freeList[freelist_idx].freeList = tmpElement;
    shmth->freeList[freelist_idx].nentries++;

    SpinLockRelease(&shmth->freeList[freelist_idx].mutex);

	shmt->tree->leaves--;
}

/*
 * Recursively destroys the tree
 */
static void
destroy_node(SHMTREE *shmt, art_node *n)
{
    int i, idx;
    NodePointer p;

    if (!n) {
        return;
    }
    if (IS_LEAF(n)) {
        // pfree(LEAF_RAW(n));
        dealloc_leaf(shmt, LEAF_RAW(n));
        return;
    }

    switch (n->type) {
    case NODE4:
        p.p1 = (art_node4 *) n;
        for (i = 0; i < n->num_children; i++) {
            destroy_node(shmt, p.p1->children[i]);
        }
        break;

    case NODE16:
        p.p2 = (art_node16 *) n;
        for (i = 0; i < n->num_children; i++) {
            destroy_node(shmt, p.p2->children[i]);
        }
        break;

    case NODE48:
        p.p3 = (art_node48 *) n;
        for (i = 0; i < 256; i++) {
            idx = ((art_node48 *) n)->keys[i];
            if (!idx)
                continue;
            destroy_node(shmt, p.p3->children[idx - 1]);
        }
        break;

    case NODE256:
        p.p4 = (art_node256 *) n;
        for (i = 0; i < 256; i++) {
            if (p.p4->children[i])
                destroy_node(shmt, p.p4->children[i]);
        }
        break;

    default:
        elog(ERROR, "destroy_node: unknown art_node type");
    }

    // pfree(n);
    dealloc_node(shmt, n);
}

/**
 * Destroys an ART tree
 * @return 0 on success.
 */
static int
art_tree_destroy(SHMTREE *shmt, art_tree *t)
{
    destroy_node(shmt, t->root);
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
make_leaf(SHMTREE *shmt, const uint8 *key, int key_len, void *value)
{
    art_leaf *l = (art_leaf *) alloc_leaf(shmt);
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
add_child48(SHMTREE *shmt, art_node48 *n, art_node **ref, uint8 c, void *child)
{
    if (n->n.num_children < NODE48_MAX) {
        int pos = 0;
        while (n->children[pos])
            pos++;
        n->children[pos] = (art_node *) child;
        n->keys[c] = pos + 1;
        n->n.num_children++;
    } else {
        art_node256 *new_node = (art_node256 *) alloc_node(shmt, NODE256);
        for (int i = 0; i < 256; i++) {
            if (n->keys[i]) {
                new_node->children[i] = n->children[n->keys[i] - 1];
            }
        }
        copy_header((art_node *) new_node, (art_node *) n);
        *ref = (art_node *) new_node;
        // pfree(n);
        dealloc_node(shmt, (art_node *) n);
        add_child256(new_node, ref, c, child);
    }
}

static void
add_child16(SHMTREE *shmt, art_node16 *n, art_node **ref, uint8 c, void *child)
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
        art_node48 *new_node = (art_node48 *) alloc_node(shmt, NODE48);

        // Copy the child pointers and populate the key map
        memcpy(new_node->children, n->children,
               sizeof(void *) * n->n.num_children);
        for (int i = 0; i < n->n.num_children; i++) {
            new_node->keys[n->keys[i]] = i + 1;
        }
        copy_header((art_node *) new_node, (art_node *) n);
        *ref = (art_node *) new_node;
        // pfree(n);
        dealloc_node(shmt, (art_node *) n);
        add_child48(shmt, new_node, ref, c, child);
    }
}

static void
add_child4(SHMTREE *shmt, art_node4 *n, art_node **ref, uint8 c, void *child)
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
        art_node16 *new_node = (art_node16 *) alloc_node(shmt, NODE16);

        // Copy the child pointers and the key map
        memcpy(new_node->children, n->children,
               sizeof(void *) * n->n.num_children);
        memcpy(new_node->keys, n->keys, sizeof(uint8) * n->n.num_children);
        copy_header((art_node *) new_node, (art_node *) n);
        *ref = (art_node *) new_node;
        // pfree(n);
        dealloc_node(shmt, (art_node *) n);
        add_child16(shmt, new_node, ref, c, child);
    }
}

static void
add_child(SHMTREE *shmt, art_node *n, art_node **ref, uint8 c, void *child)
{
    switch (n->type) {
    case NODE4:
        return add_child4(shmt, (art_node4 *) n, ref, c, child);
    case NODE16:
        return add_child16(shmt, (art_node16 *) n, ref, c, child);
    case NODE48:
        return add_child48(shmt, (art_node48 *) n, ref, c, child);
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
recursive_insert(SHMTREE *shmt, art_node *n, art_node **ref, const uint8 *key,
                 int key_len, void *value, int depth, int *old)
{
    art_node4 *new_node;
    art_leaf *l;
    art_node **child;
    // If we are at a NULL node, inject a leaf
    if (!n) {
        *ref = (art_node *) SET_LEAF(make_leaf(shmt, key, key_len, value));
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
        new_node = (art_node4 *) alloc_node(shmt, NODE4);

        // Create a new leaf
        l2 = make_leaf(shmt, key, key_len, value);

        // Determine longest prefix
        longest_prefix = longest_common_prefix(l, l2, depth);
        new_node->n.partial_len = longest_prefix;
        memcpy(new_node->n.partial, key + depth,
               Min(MAX_PREFIX_LEN, longest_prefix));
        // Add the leafs to the new node4
        *ref = (art_node *) new_node;
        add_child4(shmt, new_node, ref, l->key[depth + longest_prefix],
                   SET_LEAF(l));
        add_child4(shmt, new_node, ref, l2->key[depth + longest_prefix],
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
        new_node = (art_node4 *) alloc_node(shmt, NODE4);
        *ref = (art_node *) new_node;
        new_node->n.partial_len = prefix_diff;
        memcpy(new_node->n.partial, n->partial,
               Min(MAX_PREFIX_LEN, prefix_diff));

        // Adjust the prefix of the old node
        if (n->partial_len <= MAX_PREFIX_LEN) {
            add_child4(shmt, new_node, ref, n->partial[prefix_diff], n);
            n->partial_len -= (prefix_diff + 1);
            memmove(n->partial, n->partial + prefix_diff + 1,
                    Min(MAX_PREFIX_LEN, n->partial_len));
        } else {
            n->partial_len -= (prefix_diff + 1);
            l = minimum(n);
            add_child4(shmt, new_node, ref, l->key[depth + prefix_diff], n);
            memcpy(n->partial, l->key + depth + prefix_diff + 1,
                   Min(MAX_PREFIX_LEN, n->partial_len));
        }

        // Insert the new leaf
        l = make_leaf(shmt, key, key_len, value);
        add_child4(shmt, new_node, ref, key[depth + prefix_diff], SET_LEAF(l));
        return NULL;
    }

RECURSE_SEARCH:;

    // Find a child to recurse to
    child = find_child(n, key[depth]);
    if (child) {
        return recursive_insert(shmt, *child, child, key, key_len, value,
                                depth + 1, old);
    }

    // No child, node goes within us
    l = make_leaf(shmt, key, key_len, value);
    add_child(shmt, n, ref, key[depth], SET_LEAF(l));
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
art_insert(SHMTREE *shmt, const uint8 *key, int key_len, void *value)
{
    int old_val = 0;
    art_tree *t = shmt->tree;
    void *old = recursive_insert(shmt, t->root, &t->root, key, key_len, value, 0,
                                 &old_val);
    return old;
}

static void
remove_child256(SHMTREE *shmt, art_node256 *n, art_node **ref, uint8 c)
{
    n->children[c] = NULL;
    n->n.num_children--;

    // Resize to a node48 on underflow, not immediately to prevent
    // trashing if we sit on the 48/49 boundary
    if (n->n.num_children == NODE256_MIN) {
        int i, pos = 0;
        art_node48 *new_node = (art_node48 *) alloc_node(shmt, NODE48);
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
        dealloc_node(shmt, (art_node *) n);
    }
}

static void
remove_child48(SHMTREE *shmt, art_node48 *n, art_node **ref, uint8 c)
{
    int pos = n->keys[c];
    n->keys[c] = 0;
    n->children[pos - 1] = NULL;
    n->n.num_children--;

    if (n->n.num_children == NODE48_MIN) {
        int i, child = 0;
        art_node16 *new_node = (art_node16 *) alloc_node(shmt, NODE16);
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
        dealloc_node(shmt, (art_node *) n);
    }
}

static void
remove_child16(SHMTREE *shmt, art_node16 *n, art_node **ref, art_node **l)
{
    int pos = l - n->children;
    memmove(n->keys + pos, n->keys + pos + 1, n->n.num_children - 1 - pos);
    memmove(n->children + pos, n->children + pos + 1,
            (n->n.num_children - 1 - pos) * sizeof(void *));
    n->n.num_children--;

    if (n->n.num_children == NODE16_MIN) {
        art_node4 *new_node = (art_node4 *) alloc_node(shmt, NODE4);
        *ref = (art_node *) new_node;
        copy_header((art_node *) new_node, (art_node *) n);
        memcpy(new_node->keys, n->keys, 4);
        memcpy(new_node->children, n->children, 4 * sizeof(void *));
        // pfree(n);
        dealloc_node(shmt, (art_node *) n);
    }
}

static void
remove_child4(SHMTREE *shmt, art_node4 *n, art_node **ref, art_node **l)
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
        dealloc_node(shmt, (art_node *) n);
    }
}

static void
remove_child(SHMTREE *shmt, art_node *n, art_node **ref, uint8 c, art_node **l)
{
    switch (n->type) {
    case NODE4:
        return remove_child4(shmt, (art_node4 *) n, ref, l);
    case NODE16:
        return remove_child16(shmt, (art_node16 *) n, ref, l);
    case NODE48:
        return remove_child48(shmt, (art_node48 *) n, ref, c);
    case NODE256:
        return remove_child256(shmt, (art_node256 *) n, ref, c);
    default:
        elog(ERROR, "remove_child: unknown art_node type");
    }
}

static art_leaf *
recursive_delete(SHMTREE *shmt, art_node *n, art_node **ref, const uint8 *key,
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
            remove_child(shmt, n, ref, key[depth], child);
            return l;
        }
        return NULL;
    } else {
        return recursive_delete(shmt, *child, child, key, key_len, depth + 1);
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
art_delete(SHMTREE *shmt, const uint8 *key, int key_len)
{
    art_tree *t = shmt->tree;
    art_leaf *l = recursive_delete(shmt, t->root, &t->root, key, key_len, 0);
    if (l) {
        void *old = l->value;
        // pfree(l);
        dealloc_leaf(shmt, l);
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
