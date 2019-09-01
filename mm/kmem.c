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

#ifndef P2ALIGN
#define P2ALIGN(_x, _a)		((_x) & -(_a))
#endif

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

void *
kmem_cache_alloc(kmem_cache_t *cp, int kmflag)
{
	kmem_cpu_cache_t *ccp = KMEM_CPU_CACHE(cp);
	kmem_magazine_t *fmp;
	void *buf;

	mutex_enter(&ccp->cc_lock);
	for (;;) {
		/*
		 * If there's an object available in the current CPU's
		 * loaded magazine, just take it and return.
		 */
		if (ccp->cc_rounds > 0) {
			buf = ccp->cc_loaded->mag_round[--ccp->cc_rounds];
			ccp->cc_alloc++;
			mutex_exit(&ccp->cc_lock);
			if (ccp->cc_flags & (KMF_BUFTAG | KMF_DUMPUNSAFE)) {
				if (ccp->cc_flags & KMF_DUMPUNSAFE) {
					ASSERT(!(ccp->cc_flags &
					    KMF_DUMPDIVERT));
					cp->cache_dump.kd_unsafe++;
				}
				if ((ccp->cc_flags & KMF_BUFTAG) &&
				    kmem_cache_alloc_debug(cp, buf, kmflag, 0,
				    caller()) != 0) {
					if (kmflag & KM_NOSLEEP)
						return (NULL);
					mutex_enter(&ccp->cc_lock);
					continue;
				}
			}
			return (buf);
		}

		/*
		 * The loaded magazine is empty.  If the previously loaded
		 * magazine was full, exchange them and try again.
		 */
		if (ccp->cc_prounds > 0) {
			kmem_cpu_reload(ccp, ccp->cc_ploaded, ccp->cc_prounds);
			continue;
		}

		/*
		 * Return an alternate buffer at dump time to preserve
		 * the heap.
		 */
		if (ccp->cc_flags & (KMF_DUMPDIVERT | KMF_DUMPUNSAFE)) {
			if (ccp->cc_flags & KMF_DUMPUNSAFE) {
				ASSERT(!(ccp->cc_flags & KMF_DUMPDIVERT));
				/* log it so that we can warn about it */
				cp->cache_dump.kd_unsafe++;
			} else {
				if ((buf = kmem_cache_alloc_dump(cp, kmflag)) !=
				    NULL) {
					mutex_exit(&ccp->cc_lock);
					return (buf);
				}
				break;		/* fall back to slab layer */
			}
		}

		/*
		 * If the magazine layer is disabled, break out now.
		 */
		if (ccp->cc_magsize == 0)
			break;

		/*
		 * Try to get a full magazine from the depot.
		 */
		fmp = kmem_depot_alloc(cp, &cp->cache_full);
		if (fmp != NULL) {
			if (ccp->cc_ploaded != NULL)
				kmem_depot_free(cp, &cp->cache_empty,
				    ccp->cc_ploaded);
			kmem_cpu_reload(ccp, fmp, ccp->cc_magsize);
			continue;
		}

		/*
		 * There are no full magazines in the depot,
		 * so fall through to the slab layer.
		 */
		break;
	}
	mutex_exit(&ccp->cc_lock);

	/*
	 * We couldn't allocate a constructed object from the magazine layer,
	 * so get a raw buffer from the slab layer and apply its constructor.
	 */
	buf = kmem_slab_alloc(cp, kmflag);

	if (buf == NULL)
		return (NULL);

	if (cp->cache_flags & KMF_BUFTAG) {
		/*
		 * Make kmem_cache_alloc_debug() apply the constructor for us.
		 */
		int rc = kmem_cache_alloc_debug(cp, buf, kmflag, 1, caller());
		if (rc != 0) {
			if (kmflag & KM_NOSLEEP)
				return (NULL);
			/*
			 * kmem_cache_alloc_debug() detected corruption
			 * but didn't panic (kmem_panic <= 0). We should not be
			 * here because the constructor failed (indicated by a
			 * return code of 1). Try again.
			 */
			ASSERT(rc == -1);
			return (kmem_cache_alloc(cp, kmflag));
		}
		return (buf);
	}

	if (cp->cache_constructor != NULL &&
	    cp->cache_constructor(buf, cp->cache_private, kmflag) != 0) {
		atomic_inc_64(&cp->cache_alloc_fail);
		kmem_slab_free(cp, buf);
		return (NULL);
	}

	return (buf);
}

/*
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
*/
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
    1 * 8,
    2 * 8,
    3 * 8,
    4 * 8, 5 * 8, 6 * 8, 7 * 8,
    4 * 16, 5 * 16, 6 * 16, 7 * 16,
    4 * 32, 5 * 32, 6 * 32, 7 * 32,
    4 * 64, 5 * 64, 6 * 64, 7 * 64,
    4 * 128, 5 * 128, 6 * 128, 7 * 128,
    P2ALIGN(8192 / 7, 64),
    P2ALIGN(8192 / 6, 64),
    P2ALIGN(8192 / 5, 64),
    P2ALIGN(8192 / 4, 64),
    P2ALIGN(8192 / 3, 64),
    P2ALIGN(8192 / 2, 64),
};

static const int kmem_big_alloc_sizes[] = {
	2 * 4096,	3 * 4096,
	2 * 8192,	3 * 8192,
	4 * 8192,	5 * 8192,	6 * 8192,	7 * 8192,
	8 * 8192,	9 * 8192,	10 * 8192,	11 * 8192,
	12 * 8192,	13 * 8192,	14 * 8192,	15 * 8192,
	16 * 8192
};

#define	KMEM_MAXBUF		4096
#define	KMEM_BIG_MAXBUF_32BIT	32768
#define	KMEM_BIG_MAXBUF		131072

#define	KMEM_BIG_MULTIPLE	4096	/* big_alloc_sizes must be a multiple */
#define	KMEM_BIG_SHIFT		12	/* lg(KMEM_BIG_MULTIPLE) */

static kmem_cache_t *kmem_alloc_table[KMEM_MAXBUF >> KMEM_ALIGN_SHIFT];
static kmem_cache_t *kmem_big_alloc_table[KMEM_BIG_MAXBUF >> KMEM_BIG_SHIFT];

#define	KMEM_ALLOC_TABLE_MAX	(KMEM_MAXBUF >> KMEM_ALIGN_SHIFT)
static size_t kmem_big_alloc_table_max = 0;	/* # of filled elements */

static kmem_magtype_t kmem_magtype[] = {
	{ 1,	8,	3200,	65536	},
	{ 3,	16,	256,	32768	},
	{ 7,	32,	64,	16384	},
	{ 15,	64,	0,	8192	},
	{ 31,	64,	0,	4096	},
	{ 47,	64,	0,	2048	},
	{ 63,	64,	0,	1024	},
	{ 95,	64,	0,	512	},
	{ 143,	64,	0,	0	},
};

static kmem_cache_t	*kmem_slab_cache;
static kmem_cache_t	*kmem_bufctl_cache;
static kmem_cache_t	*kmem_bufctl_audit_cache;

static kmutex_t		kmem_cache_lock;	/* inter-cache linkage only */
static list_t		kmem_caches;

static taskq_t		*kmem_taskq;
static kmutex_t		kmem_flags_lock;
static vmem_t		*kmem_metadata_arena;
static vmem_t		*kmem_msb_arena;	/* arena for metadata caches */
static vmem_t		*kmem_cache_arena;
static vmem_t		*kmem_hash_arena;
static vmem_t		*kmem_log_arena;
static vmem_t		*kmem_oversize_arena;
static vmem_t		*kmem_va_arena;
static vmem_t		*kmem_default_arena;

static struct kmem_cache kmalloc_caches[ARRAY_SIZE(kmem_alloc_sizes)];

/*
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
*/
static inline struct kmem_cache *kmem_size_to_cache(size_t size)
{
	size_t idx = kmem_cache_index(size);
	if (idx >= ARRAY_SIZE(kmem_alloc_sizes)) {
		return NULL;
	}
	return &kmalloc_caches[idx];
}

void *
kmem_alloc(size_t size, int kmflag)
{
	size_t index;
	kmem_cache_t *cp;
	void *buf;

	if ((index = ((size - 1) >> KMEM_ALIGN_SHIFT)) < KMEM_ALLOC_TABLE_MAX) {
		cp = kmem_alloc_table[index];
		/* fall through to kmem_cache_alloc() */

	} else if ((index = ((size - 1) >> KMEM_BIG_SHIFT)) <
	    kmem_big_alloc_table_max) {
		cp = kmem_big_alloc_table[index];
		/* fall through to kmem_cache_alloc() */

	} else {
		if (size == 0) {
			if (kmflag != KM_SLEEP && !(kmflag & KM_PANIC))
				return (NULL);

			if (kmem_panic && kmem_panic_zerosized)
				panic("attempted to kmem_alloc() size of 0");

			if (kmem_warn_zerosized) {
				cmn_err(CE_WARN, "kmem_alloc(): sleeping "
				    "allocation with size of 0; "
				    "see kmem_zerosized_log for details");
			}

			kmem_log_event(kmem_zerosized_log, NULL, NULL, NULL);

			return (NULL);
		}

		buf = vmem_alloc(kmem_oversize_arena, size,
		    kmflag & KM_VMFLAGS);
		if (buf == NULL)
			kmem_log_event(kmem_failure_log, NULL, NULL,
			    (void *)size);
		else if (KMEM_DUMP(kmem_slab_cache)) {
			/* stats for dump intercept */
			kmem_dump_oversize_allocs++;
			if (size > kmem_dump_oversize_max)
				kmem_dump_oversize_max = size;
		}
		return (buf);
	}

	buf = kmem_cache_alloc(cp, kmflag);
	if ((cp->cache_flags & KMF_BUFTAG) && !KMEM_DUMP(cp) && buf != NULL) {
		kmem_buftag_t *btp = KMEM_BUFTAG(cp, buf);
		((uint8_t *)buf)[size] = KMEM_REDZONE_BYTE;
		((uint32_t *)btp)[1] = KMEM_SIZE_ENCODE(size);

		if (cp->cache_flags & KMF_LITE) {
			KMEM_BUFTAG_LITE_ENTER(btp, kmem_lite_count, caller());
		}
	}
	return (buf);
}

/*
void *kmem_alloc(size_t size)
{
	struct kmem_cache *cache = kmem_size_to_cache(size);
	if (!cache) {
		return NULL;
	}
	return kmem_cache_alloc(cache);
}
*/
void *kmem_zalloc(size_t size)
{
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
