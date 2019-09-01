//
// Kernel dynamic memory allocator
//
// The design of this kernel dynamic memory allocator mostly follows
// Bonwick's original paper on slab allocator:
//
// Bonwick, Jeff. "The Slab Allocator: An Object-Caching Kernel Memory
// Allocator." USENIX summer. Vol. 16. 1994.
//

#include <kernel/kmem.h>

#include <kernel/align.h>
#include <kernel/errno.h>
#include <kernel/page-alloc.h>
#include <kernel/printf.h>

#include <stdbool.h>
#include <string.h>

static struct kmem_cache kmem_cache_cache;
static struct kmem_cache kmem_slab_cache;

static struct kmem_bufctl *kmem_object_to_bufctl(struct kmem_cache *cache, void *obj)
{
	return obj + cache->bufctl;
}

static struct kmem_slab *kmem_slab_create(struct kmem_cache *cache)
{
	void *base = page_alloc_small();
	if (!base) {
		return NULL;
	}
	size_t slab_size = PAGE_SIZE_SMALL;
	struct kmem_slab *slab;
	if (cache->size < PAGE_SIZE_SMALL / 8) {
		slab = base + PAGE_SIZE_SMALL - sizeof(*slab);
		slab_size -= sizeof(*slab);
	} else {
		slab = kmem_cache_alloc(&kmem_slab_cache);
		if (!slab) {
			goto error_free_page;
		}
	}
	slab->cache = cache;
	slab->base = base;
	slab->head = kmem_object_to_bufctl(cache, base);
	slab->next = NULL;
	slab->nr_free = 0;
	slab->capacity = 0;
	size_t buffer_size = align_up(cache->size, cache->align);
	for (size_t offset = 0; offset + buffer_size <= slab_size; offset += buffer_size) {
		void *addr = base + offset;
		struct kmem_bufctl *bufctl = kmem_object_to_bufctl(cache, addr);
		size_t next_offset = offset + buffer_size;
		if (next_offset + buffer_size <= slab_size) {
			bufctl->next = kmem_object_to_bufctl(cache, base + next_offset);
		} else {
			bufctl->next = NULL;
		}
		bufctl->addr = addr;
		bufctl->slab = slab;
		slab->capacity++;
		slab->nr_free++;
	}
	return slab;
error_free_page:
	page_free_small(base);
	return NULL;
}

static void kmem_slab_destroy(struct kmem_slab *slab)
{
	page_free_small(slab->base);
}

static void *kmem_slab_alloc_object(struct kmem_slab *slab)
{
	struct kmem_bufctl *bufctl = slab->head;
	if (!bufctl) {
		return NULL;
	}
	slab->head = bufctl->next;
	slab->nr_free--;
	return bufctl->addr;
}

static bool kmem_slab_is_full(struct kmem_slab *slab)
{
	return slab->nr_free == slab->capacity;
}

static void kmem_slab_free_object(struct kmem_slab *slab, void *obj)
{
	struct kmem_bufctl *bufctl = kmem_object_to_bufctl(slab->cache, obj);
	bufctl->next = slab->head;
	bufctl->addr = obj;
	bufctl->slab = slab;
	slab->head = bufctl;
	slab->nr_free++;
}

static int kmem_cache_init(struct kmem_cache *cache, const char *name, size_t size, size_t align)
{
	if (align_up(size, align) < sizeof(struct kmem_bufctl)) {
		return -EINVAL;
	}
	strlcpy(cache->name, name, KMEM_NAME_MAX_LEN);
	cache->size = size;
	cache->align = align;
	cache->bufctl = align_up(size, align) - sizeof(struct kmem_bufctl);
	cache->slab = kmem_slab_create(cache);
	return 0;
}

struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align)
{
	struct kmem_cache *cache = kmem_cache_alloc(&kmem_cache_cache);
	if (cache) {
		if (kmem_cache_init(cache, name, size, align) < 0) {
			kmem_cache_free(&kmem_cache_cache, cache);
			return NULL;
		}
	}
	return cache;
}

void kmem_cache_destroy(struct kmem_cache *cache)
{
	struct kmem_slab *slab = cache->slab;
	for (;;) {
		struct kmem_slab *next = slab->next;
		kmem_slab_destroy(slab);
		if (!next) {
			break;
		}
		slab = next;
	}
	kmem_cache_free(&kmem_cache_cache, cache);
}

void *kmem_cache_alloc(struct kmem_cache *cache)
{
	for (;;) {
		void *obj = kmem_slab_alloc_object(cache->slab);
		if (obj) {
			return obj;
		}
		struct kmem_slab *slab = kmem_slab_create(cache);
		if (!slab) {
			return NULL;
		}
		slab->next = cache->slab;
		cache->slab = slab;
	}
}

void kmem_cache_free(struct kmem_cache *cache, void *obj)
{
	kmem_slab_free_object(cache->slab, obj);

	if (!kmem_slab_is_full(cache->slab)) {
		return;
	}
	struct kmem_slab *slab = cache->slab;
	if (slab->next) {
		cache->slab = slab->next;
		kmem_slab_destroy(slab);
	}
}

static size_t kmem_alloc_sizes[] = {
    32, 64, 128, 256, 512, 1024, 2048, 4096,
};

static struct kmem_cache kmalloc_caches[ARRAY_SIZE(kmem_alloc_sizes)];

static inline size_t kmem_cache_index(size_t size)
{
	if (size <= 32)
		return 0;
	if (size <= 64)
		return 1;
	if (size <= 128)
		return 2;
	if (size <= 256)
		return 3;
	if (size <= 512)
		return 4;
	if (size <= 1024)
		return 5;
	if (size <= 2048)
		return 6;
	if (size <= 4096)
		return 7;
	return ~0ULL;
}

static inline struct kmem_cache *kmem_size_to_cache(size_t size)
{
	size_t idx = kmem_cache_index(size);
	if (idx >= ARRAY_SIZE(kmem_alloc_sizes)) {
		return NULL;
	}
	return &kmalloc_caches[idx];
}

void *kmem_alloc(size_t size)
{
	struct kmem_cache *cache = kmem_size_to_cache(size);
	if (!cache) {
		return NULL;
	}
	return kmem_cache_alloc(cache);
}

void *kmem_zalloc(size_t size)
{
	void *p = kmem_alloc(size);
	if (!p) {
		return NULL;
	}
	memset(p, 0, size);
	return p;
}

void kmem_free(void *ptr, size_t size)
{
	struct kmem_cache *cache = kmem_size_to_cache(size);
	if (!cache) {
		return;
	}
	kmem_cache_free(cache, ptr);
}

int kmem_init(void)
{
	int err;
	err = kmem_cache_init(&kmem_cache_cache, "kmem_cache_cache", sizeof(struct kmem_cache), KMEM_DEFAULT_ALIGN);
	if (err) {
		return err;
	}
	err = kmem_cache_init(&kmem_slab_cache, "kmem_slab_cache", sizeof(struct kmem_slab), KMEM_DEFAULT_ALIGN);
	if (err) {
		return err;
	}
	for (unsigned int i = 0; i < ARRAY_SIZE(kmem_alloc_sizes); i++) {
		char cache_name[KMEM_NAME_MAX_LEN];
		size_t size = kmem_alloc_sizes[i];
		snprintf(cache_name, KMEM_NAME_MAX_LEN, "kmalloc-%lu", size);
		err = kmem_cache_init(&kmalloc_caches[i], cache_name, size, KMEM_DEFAULT_ALIGN);
		if (err) {
			return err;
		}
	}
	return 0;
}

static boolean_t
kmem_slab_is_reclaimable(kmem_cache_t *cp, kmem_slab_t *sp, int flags)
{
	long refcnt = sp->slab_refcnt;

	ASSERT(cp->cache_defrag != NULL);

	/*
	 * For code coverage we want to be able to move an object within the
	 * same slab (the only partial slab) even if allocating the destination
	 * buffer resulted in a completely allocated slab.
	 */
	if (flags & KMM_DEBUG) {
		return ((flags & KMM_DESPERATE) ||
		    ((sp->slab_flags & KMEM_SLAB_NOMOVE) == 0));
	}

	/* If we're desperate, we don't care if the client said NO. */
	if (flags & KMM_DESPERATE) {
		return (refcnt < sp->slab_chunks); /* any partial */
	}

	if (sp->slab_flags & KMEM_SLAB_NOMOVE) {
		return (B_FALSE);
	}

	if ((refcnt == 1) || kmem_move_any_partial) {
		return (refcnt < sp->slab_chunks);
	}

	/*
	 * The reclaim threshold is adjusted at each kmem_cache_scan() so that
	 * slabs with a progressively higher percentage of used buffers can be
	 * reclaimed until the cache as a whole is no longer fragmented.
	 *
	 *	sp->slab_refcnt   kmd_reclaim_numer
	 *	--------------- < ------------------
	 *	sp->slab_chunks   KMEM_VOID_FRACTION
	 */
	return ((refcnt * KMEM_VOID_FRACTION) <
	    (sp->slab_chunks * cp->cache_defrag->kmd_reclaim_numer));
}


static int
kmem_move_buffers(kmem_cache_t *cp, size_t max_scan, size_t max_slabs,
    int flags)
{
	kmem_slab_t *sp;
	void *buf;
	int i, j; /* slab index, buffer index */
	int s; /* reclaimable slabs */
	int b; /* allocated (movable) buffers on reclaimable slab */
	boolean_t success;
	int refcnt;
	int nomove;

	ASSERT(taskq_member(kmem_taskq, curthread));
	ASSERT(MUTEX_HELD(&cp->cache_lock));
	ASSERT(kmem_move_cache != NULL);
	ASSERT(cp->cache_move != NULL && cp->cache_defrag != NULL);
	ASSERT((flags & KMM_DEBUG) ? !avl_is_empty(&cp->cache_partial_slabs) :
	    avl_numnodes(&cp->cache_partial_slabs) > 1);

	if (kmem_move_blocked) {
		return (0);
	}

	if (kmem_move_fulltilt) {
		flags |= KMM_DESPERATE;
	}

	if (max_scan == 0 || (flags & KMM_DESPERATE)) {
		/*
		 * Scan as many slabs as needed to find the desired number of
		 * candidate slabs.
		 */
		max_scan = (size_t)-1;
	}

	if (max_slabs == 0 || (flags & KMM_DESPERATE)) {
		/* Find as many candidate slabs as possible. */
		max_slabs = (size_t)-1;
	}

	sp = avl_last(&cp->cache_partial_slabs);
	ASSERT(KMEM_SLAB_IS_PARTIAL(sp));
	for (i = 0, s = 0; (i < max_scan) && (s < max_slabs) && (sp != NULL) &&
	    ((sp != avl_first(&cp->cache_partial_slabs)) ||
	    (flags & KMM_DEBUG));
	    sp = AVL_PREV(&cp->cache_partial_slabs, sp), i++) {

		if (!kmem_slab_is_reclaimable(cp, sp, flags)) {
			continue;
		}
		s++;

		/* Look for allocated buffers to move. */
		for (j = 0, b = 0, buf = sp->slab_base;
		    (j < sp->slab_chunks) && (b < sp->slab_refcnt);
		    buf = (((char *)buf) + cp->cache_chunksize), j++) {

			if (kmem_slab_allocated(cp, sp, buf) == NULL) {
				continue;
			}

			b++;

			/*
			 * Prevent the slab from being destroyed while we drop
			 * cache_lock and while the pending move is not yet
			 * registered. Flag the pending move while
			 * kmd_moves_pending may still be empty, since we can't
			 * yet rely on a non-zero pending move count to prevent
			 * the slab from being destroyed.
			 */
			ASSERT(!(sp->slab_flags & KMEM_SLAB_MOVE_PENDING));
			sp->slab_flags |= KMEM_SLAB_MOVE_PENDING;
			/*
			 * Recheck refcnt and nomove after reacquiring the lock,
			 * since these control the order of partial slabs, and
			 * we want to know if we can pick up the scan where we
			 * left off.
			 */
			refcnt = sp->slab_refcnt;
			nomove = (sp->slab_flags & KMEM_SLAB_NOMOVE);
			mutex_exit(&cp->cache_lock);

			success = kmem_move_begin(cp, sp, buf, flags);

			/*
			 * Now, before the lock is reacquired, kmem could
			 * process all pending move requests and purge the
			 * deadlist, so that upon reacquiring the lock, sp has
			 * been remapped. Or, the client may free all the
			 * objects on the slab while the pending moves are still
			 * on the taskq. Therefore, the KMEM_SLAB_MOVE_PENDING
			 * flag causes the slab to be put at the end of the
			 * deadlist and prevents it from being destroyed, since
			 * we plan to destroy it here after reacquiring the
			 * lock.
			 */
			mutex_enter(&cp->cache_lock);
			ASSERT(sp->slab_flags & KMEM_SLAB_MOVE_PENDING);
			sp->slab_flags &= ~KMEM_SLAB_MOVE_PENDING;

			if (sp->slab_refcnt == 0) {
				list_t *deadlist =
				    &cp->cache_defrag->kmd_deadlist;
				list_remove(deadlist, sp);

				if (!avl_is_empty(
				    &cp->cache_defrag->kmd_moves_pending)) {
					/*
					 * A pending move makes it unsafe to
					 * destroy the slab, because even though
					 * the move is no longer needed, the
					 * context where that is determined
					 * requires the slab to exist.
					 * Fortunately, a pending move also
					 * means we don't need to destroy the
					 * slab here, since it will get
					 * destroyed along with any other slabs
					 * on the deadlist after the last
					 * pending move completes.
					 */
					list_insert_head(deadlist, sp);
					return (-1);
				}

				/*
				 * Destroy the slab now if it was completely
				 * freed while we dropped cache_lock and there
				 * are no pending moves. Since slab_refcnt
				 * cannot change once it reaches zero, no new
				 * pending moves from that slab are possible.
				 */
				cp->cache_defrag->kmd_deadcount--;
				cp->cache_slab_destroy++;
				mutex_exit(&cp->cache_lock);
				kmem_slab_destroy(cp, sp);
				mutex_enter(&cp->cache_lock);
				/*
				 * Since we can't pick up the scan where we left
				 * off, abort the scan and say nothing about the
				 * number of reclaimable slabs.
				 */
				return (-1);
			}

			if (!success) {
				/*
				 * Abort the scan if there is not enough memory
				 * for the request and say nothing about the
				 * number of reclaimable slabs.
				 */
				return (-1);
			}

			/*
			 * The slab's position changed while the lock was
			 * dropped, so we don't know where we are in the
			 * sequence any more.
			 */
			if (sp->slab_refcnt != refcnt) {
				/*
				 * If this is a KMM_DEBUG move, the slab_refcnt
				 * may have changed because we allocated a
				 * destination buffer on the same slab. In that
				 * case, we're not interested in counting it.
				 */
				return (-1);
			}
			if ((sp->slab_flags & KMEM_SLAB_NOMOVE) != nomove)
				return (-1);

			/*
			 * Generating a move request allocates a destination
			 * buffer from the slab layer, bumping the first partial
			 * slab if it is completely allocated. If the current
			 * slab becomes the first partial slab as a result, we
			 * can't continue to scan backwards.
			 *
			 * If this is a KMM_DEBUG move and we allocated the
			 * destination buffer from the last partial slab, then
			 * the buffer we're moving is on the same slab and our
			 * slab_refcnt has changed, causing us to return before
			 * reaching here if there are no partial slabs left.
			 */
			ASSERT(!avl_is_empty(&cp->cache_partial_slabs));
			if (sp == avl_first(&cp->cache_partial_slabs)) {
				/*
				 * We're not interested in a second KMM_DEBUG
				 * move.
				 */
				goto end_scan;
			}
		}
	}
end_scan:

	return (s);
}
