// SPDX-License-Identifier: GPL-2.0-or-later
/* LKM backends required by kernel/base/hook.c. */
#include <linux/errno.h>
#include <linux/list.h>
// hlist definitions included via linux/list.h
#include <linux/hash.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>

#include "../include/kp_lkm.h"
#include <hook.h>
#include "../infra/patch_memory.h"
#include "../infra/symbol_resolver.h"

/* Hash table configuration */
#define KP_HOOK_HASH_BITS 6
#define KP_HOOK_HASH_SIZE (1 << KP_HOOK_HASH_BITS)  /* 64 buckets */

/* Maximum size for kmalloc (avoids page allocation overhead) */
#define KP_HOOK_KMALLOC_MAX (PAGE_SIZE / 2)

struct kp_hook_mem {
	struct hlist_node hash_node;  /* Hash table node */
	struct list_head list;        /* Maintenance list (for cleanup) */
	uintptr_t origin;
	enum hook_type type;
	void *region;
	size_t size;                  /* Actual allocated size for precise checking */
	bool use_vmalloc;             /* Track allocation method for precise free */
	union {
		hook_t hook;
		hook_chain_t chain;
		fp_hook_chain_t fp_chain;
	} *payload;
};

static LIST_HEAD(kp_hook_mems);
static DEFINE_MUTEX(kp_hook_lock);
static struct hlist_head kp_hook_hash[KP_HOOK_HASH_SIZE];  /* Hash table for fast lookup */
/* Executable-memory allocators. module_alloc exists through 6.10 (__weak in
 * 6.6); 6.11+ replaced it with execmem_alloc() (EXECMEM_MODULE_TEXT).
 * vmalloc is the universal last resort (still needs set_memory_x to be
 * executable on arm64). On 6.11+ the execmem typedef must use the kernel's
 * enum execmem_type so the kCFI type-hash at the indirect call matches. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
#include <linux/execmem.h>
static void *(*kp_hook_execmem_alloc)(enum execmem_type type, size_t size);
static void (*kp_hook_execmem_free)(void *ptr);
#else
static void *(*kp_hook_execmem_alloc)(int type, size_t size);
static void (*kp_hook_execmem_free)(void *ptr);
#endif
static void *(*kp_hook_module_alloc)(unsigned long size);
static void (*kp_hook_module_memfree)(void *region);
static void (*kp_hook_flush_icache_all)(void);
static int (*kp_hook_set_memory_x)(unsigned long addr, int numpages);

/* noinline: these are raw resolved function pointers; if inlined into a
 * CFI-instrumented caller, the compiler emits a kCFI type-hash load of
 * [fnptr - 4] that dereferences NULL when the allocator is absent (6.10+ has
 * no module_alloc) and panics. no_sanitize keeps the indirect calls unchecked. */
__attribute__((no_sanitize("cfi"), __noinline__))
static void *kp_hook_exec_alloc(unsigned long size)
{
	void *p = NULL;
	unsigned long pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	if (kp_hook_module_alloc)
		p = kp_hook_module_alloc(size);
	else if (kp_hook_execmem_alloc)
		p = kp_hook_execmem_alloc(0 /* EXECMEM_MODULE_TEXT */, size);
	else
		p = vmalloc(size);
	/* GKI module_alloc returns PAGE_KERNEL (PXN set, NX); vmalloc too. Hook
	 * trampolines live here and must be executable. */
	if (p && kp_hook_set_memory_x)
		kp_hook_set_memory_x((unsigned long)p, pages);
	return p;
}

__attribute__((no_sanitize("cfi"), __noinline__))
static void kp_hook_exec_free(void *region)
{
	if (kp_hook_module_memfree)
		kp_hook_module_memfree(region);
	else if (kp_hook_execmem_free)
		kp_hook_execmem_free(region);
	else
		vfree(region);
}

__attribute__((no_sanitize("cfi")))
static void kp_hook_flush_all(void)
{
	if (kp_hook_flush_icache_all)
		kp_hook_flush_icache_all();
}

/* Hash function for hook address lookup */
static inline int kp_hook_hash_addr(unsigned long addr)
{
	return hash_long(addr, KP_HOOK_HASH_BITS) % KP_HOOK_HASH_SIZE;
}

/* Check if @addr falls within any hook memory region.
 * Uses hash table for O(1) average lookup with precise size-based checking.
 */
bool kp_hook_addr_in_region(unsigned long addr)
{
	struct kp_hook_mem *mem;
	int bucket = kp_hook_hash_addr(addr);

	mutex_lock(&kp_hook_lock);
	hlist_for_each_entry(mem, &kp_hook_hash[bucket], hash_node) {
		unsigned long start = (unsigned long)mem->region;
		unsigned long end = start + mem->size;

		if (mem->region && addr >= start && addr < end) {
			mutex_unlock(&kp_hook_lock);
			return true;
		}
	}
	mutex_unlock(&kp_hook_lock);
	return false;
}

int kp_hook_runtime_init(void)
{
	/* Initialize hash table buckets */
	for (int i = 0; i < KP_HOOK_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&kp_hook_hash[i]);
	}

	kp_hook_module_alloc = (void *)kp_resolve_symbol("module_alloc");
	kp_hook_module_memfree = (void *)kp_resolve_symbol("module_memfree");
	kp_hook_execmem_alloc = (void *)kp_resolve_symbol("execmem_alloc");
	kp_hook_execmem_free = (void *)kp_resolve_symbol("execmem_free");
	kp_hook_flush_icache_all = (void *)kp_resolve_symbol("flush_icache_all");
	kp_hook_set_memory_x = (int (*)(unsigned long, int))kp_resolve_symbol("set_memory_x");
	if (!kp_hook_module_alloc)
		logkw("module_alloc not found; using execmem_alloc/vmalloc for hook memory\n");
	if (!kp_hook_set_memory_x && !kp_hook_execmem_alloc) {
		logke("no executable-memory path (set_memory_x/execmem_alloc missing)\n");
		return -ENOSYS;
	}
	logki("KPM hook runtime ready (module_alloc=%px execmem_alloc=%px set_memory_x=%px)\n",
	      kp_hook_module_alloc, kp_hook_execmem_alloc, kp_hook_set_memory_x);
	return 0;
}

void *hook_mem_zalloc(uintptr_t origin, enum hook_type type)
{
	struct kp_hook_mem *mem;
	size_t size;

	switch (type) {
	case INLINE:
		size = sizeof(hook_t);
		break;
	case INLINE_CHAIN:
		size = sizeof(hook_chain_t);
		break;
	case FUNCTION_POINTER_CHAIN:
		size = sizeof(fp_hook_chain_t);
		break;
	default:
		return NULL;
	}

	mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return NULL;

	/* Adaptive allocation: kmalloc for small, module_alloc for large */
	if (size <= KP_HOOK_KMALLOC_MAX) {
		/* Small allocation: use kmalloc (page-aligned internally) */
		mem->region = kmalloc(size, GFP_KERNEL | __GFP_NOWARN);
		if (!mem->region) {
			/* Fallback to vmalloc if kmalloc fails */
			mem->region = vmalloc(size);
			if (!mem->region) {
				kfree(mem);
				return NULL;
			}
			mem->use_vmalloc = true;
		} else {
			mem->use_vmalloc = false;
		}
	} else {
		/* Large allocation: use module_alloc + set_memory_x */
		mem->region = kp_hook_exec_alloc(size);
		if (!mem->region) {
			kfree(mem);
			return NULL;
		}
		mem->use_vmalloc = false;
	}

	memset(mem->region, 0, size);
	mem->payload = mem->region;
	mem->origin = origin;
	mem->type = type;
	mem->size = size;  /* Store actual size for precise checking */

	mutex_lock(&kp_hook_lock);
	list_add_tail(&mem->list, &kp_hook_mems);

	/* Insert into hash table for fast lookup */
	int bucket = kp_hook_hash_addr((unsigned long)mem->region);
	hlist_add_head(&mem->hash_node, &kp_hook_hash[bucket]);

	mutex_unlock(&kp_hook_lock);
	return mem->payload;
}

void *hook_get_mem_from_origin(uint64_t origin)
{
	struct kp_hook_mem *mem;
	void *result = NULL;

	mutex_lock(&kp_hook_lock);
	list_for_each_entry(mem, &kp_hook_mems, list) {
		if (mem->origin == origin) {
			result = mem->payload;
			break;
		}
	}
	mutex_unlock(&kp_hook_lock);
	return result;
}

void hook_mem_free(void *payload)
{
	struct kp_hook_mem *mem, *tmp;

	mutex_lock(&kp_hook_lock);
	list_for_each_entry_safe(mem, tmp, &kp_hook_mems, list) {
		if (mem->payload == payload) {
			list_del(&mem->list);
			hlist_del(&mem->hash_node);  /* Remove from hash table */

			/* Must free memory while holding lock to prevent UAF in kp_hook_addr_in_region */
			if (mem->use_vmalloc) {
				vfree(mem->region);
			} else if (mem->size <= KP_HOOK_KMALLOC_MAX) {
				kfree(mem->region);
			} else {
				kp_hook_exec_free(mem->region);
			}
			kfree(mem);
			mutex_unlock(&kp_hook_lock);
			return;
		}
	}
	mutex_unlock(&kp_hook_lock);
}

int hotpatch(void *addrs[], uint32_t values[], int count)
{
	int i, start, rc;

	for (start = 0; start < count; start = i) {
		for (i = start + 1; i < count; i++) {
			if ((char *)addrs[i] != (char *)addrs[start] +
						 (i - start) * sizeof(values[0]))
				break;
		}
		rc = kp_patch_text(addrs[start], &values[start],
				   (i - start) * sizeof(values[0]),
				   KP_PATCH_TEXT_FLUSH_DCACHE | KP_PATCH_TEXT_FLUSH_ICACHE);
		if (rc)
			return rc;
	}
	return 0;
}

void flush_icache_all(void)
{
	kp_hook_flush_all();
}
