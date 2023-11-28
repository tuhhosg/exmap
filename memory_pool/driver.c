#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "memory_pool.h"
#include "ksyms.h"

unsigned active_memory_pools;
static struct memory_pool_ctx* MEMORY_POOLS[64];

#define TAG_BITS (6ULL)
#define TAG_LIMIT (1ULL << TAG_BITS)
#define TAG_MASK (TAG_LIMIT - 1)

static inline unsigned get_tag(struct page* page) {
	return ((uintptr_t) page) & TAG_MASK;
}

/** @return the correctly aligned pagep with zeroes in the first bits */
static inline struct page* get_without_tag(struct page* page) {
	return (struct page*) ((uintptr_t) page & ~TAG_MASK);
}

static inline struct page* construct_with_tag(struct page* page, unsigned tag) {
	struct page* clean;

	if (!page)
		return NULL;

	clean = get_without_tag(page);
	return (struct page*) ((uintptr_t) clean | (tag % TAG_LIMIT));
}

static bool bundle_list_push(struct page *new_first, struct bundle_list_head *head)
{
	struct page *first;

	/* pages coming in must not have a tag set */
	BUG_ON(new_first != get_without_tag(new_first));

	do {
		/* there may be a tag left over from the previous loop iteration */
		new_first = get_without_tag(new_first);

		/* current first list entry */
		first = READ_ONCE(head->first);
		/* the next-pointer of the new first list entry */
		new_first->mapping = (struct address_space*) get_without_tag(first);

		/* new first entry keeps tag of previous first */
		new_first = construct_with_tag(new_first, get_tag(first));
	} while (cmpxchg(&head->first, first, new_first) != first);

	return !first;
}

static struct page *bundle_list_pop(struct bundle_list_head *head)
{
	struct page *entry, *old_entry, *next;

	entry = smp_load_acquire(&head->first);
	for (;;) {
		if (entry == NULL)
			return NULL;

		old_entry = entry;
		next = (struct page*) READ_ONCE(get_without_tag(entry)->mapping);
		/* next / new first entry has tag of previous first + 1 */
		next = construct_with_tag(next, get_tag(old_entry) + 1);

		entry = cmpxchg(&head->first, old_entry, next);
		if (entry == old_entry)
			break;
	}

	return get_without_tag(entry);
}

static inline struct page *bundle_list_del_all(struct bundle_list_head *head)
{
	return get_without_tag(xchg(&head->first, NULL));
}

void push_bundle(struct page_bundle bundle, struct memory_pool_ctx* ctx) {
	BUG_ON(bundle.count != 512);

	preempt_disable();
	bundle_list_push(bundle.stack, &ctx->bundle_list);
	preempt_enable();
}

struct page_bundle pop_bundle(struct memory_pool_ctx* ctx) {
	struct page* page;
	struct page_bundle ret;

	preempt_disable();
	page = bundle_list_pop(&ctx->bundle_list);
	preempt_enable();

	if (!page) {
		ret.stack = NULL;
		ret.count = 0;
		return ret;
	}

	ret.stack = page;
	ret.count = 512;
	return ret;
}


void push_page(struct page* page, struct page_bundle* bundle, struct memory_pool_ctx* ctx) {
	void* stack_page_virt;

	BUG_ON(!page);

	if (!bundle->stack) {
		bundle->stack = page;
		return;
	}
	stack_page_virt = page_to_virt(bundle->stack);
	((struct page**) stack_page_virt)[bundle->count++] = page;

	if (bundle->count == 512) {
		push_bundle(*bundle, ctx);
		bundle->count = 0;
		bundle->stack = NULL;
	}
}
EXPORT_SYMBOL(push_page);

struct page* pop_page(struct page_bundle* bundle, struct memory_pool_ctx* ctx) {
	do {
		if (bundle->count > 0) {
			void* stack_page_virt = page_to_virt(bundle->stack);
			struct page* page = ((struct page**) stack_page_virt)[--bundle->count];
			page->mapping = NULL;
			return page;
		}
		if (bundle->stack) {
			struct page* page = bundle->stack;
			bundle->stack = NULL;
			page->mapping = NULL;
			return page;
		}

		*bundle = pop_bundle(ctx);
		if (bundle->count == 0) {
			goto failed;
		}
	} while (1);

failed:
	return NULL;
}
EXPORT_SYMBOL(pop_page);



static inline void memory_pool_unaccount_mem(struct memory_pool_ctx *ctx,
									   unsigned long nr_pages) {
	/* TODO fix */
	pr_warn("memory_pool: accounting unimplemented!\n");
	return;

	/* // Account for locked memory */
	/* atomic_long_sub(nr_pages, &ctx->user->locked_vm); */

	/* // Also un-account the memory at the process */
	/* atomic64_sub(nr_pages, &ctx->mm_account->pinned_vm); */
}

static inline int memory_pool_account_mem(struct memory_pool_ctx *ctx,
									unsigned long nr_pages)
{
	/* TODO fix */
	pr_warn("memory_pool: accounting unimplemented!\n");
	return -1;

	/* unsigned long page_limit, cur_pages, new_pages; */

	/* /\* Don't allow more pages than we can safely lock *\/ */
	/* page_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT; */
	/* pr_info("page_limit: %ld/%ld (alloc: %lu)\n", */
	/* 		atomic_long_read(&ctx->user->locked_vm), */
	/* 		page_limit, nr_pages); */

	/* do { */
	/* 	cur_pages = atomic_long_read(&ctx->user->locked_vm); */
	/* 	new_pages = cur_pages + nr_pages; */
	/* 	if (new_pages > page_limit) */
	/* 		return -ENOMEM; */
	/* } while (atomic_long_cmpxchg(&ctx->user->locked_vm, cur_pages, */
	/* 							 new_pages) != cur_pages); */

	/* atomic64_add(nr_pages, &ctx->mm_account->pinned_vm); */

	/* return 0; */
}

void free_page_system(struct page * page) {
//	current->rss_stat.count[mm_counter_file(page)] -= 1;
	ClearPageReserved(page);
	__free_pages(page, 0);
}

struct page* alloc_page_system(void) {
	struct page *page = alloc_pages(GFP_NOIO | __GFP_ZERO,  0);
	SetPageReserved(page);
//	current->rss_stat.count[mm_counter_file(page)] += 1;
	return page;
}


unsigned free_page_bundle(struct page* bundle_page, unsigned count) {
	void* stack_page_virt;
	unsigned freed_pages = 0;

	/* interface-local free pages bundle can temporarily be NULL until the next page gets pushed */
	if (!bundle_page)
		return 0;

	stack_page_virt = page_to_virt(bundle_page);
	while (count > 0) {
		struct page* page = ((struct page**) stack_page_virt)[--count];
		/* pr_info("bundle: free page %lx, %d remaining, stack %lx (virt %lx)", page, count, stack, stack_page_virt); */
		BUG_ON(!page);
		page->mapping = NULL;
		free_page_system(page);
		freed_pages++;
	}
	/* pr_info("bundle: free stack page %lx itself", stack); */
	bundle_page->mapping = NULL;
	free_page_system(bundle_page);
	freed_pages++;

	return freed_pages;
}
EXPORT_SYMBOL(free_page_bundle);

struct memory_pool_ctx* memory_pool_create(struct memory_pool_setup* setup) {
	struct memory_pool_ctx* ctx = vmalloc(sizeof(struct memory_pool_ctx));

	size_t alloc_count = 0;

	pr_info("memory_pool: init size (4K pages) = %ld (flags = %u)\n", setup->pool_size, setup->flags);

	/* TODO: checks? */
	ctx->pool_size = setup->pool_size;

	ctx->flags = setup->flags;

	// // Account for the locked memory
	// rc = pool_account_mem(ctx, pool_size);
	// if (rc < 0) {
	// 	pr_info("pool: cannot account for memory, rlimit exceeded\n");
	//     return rc;
	// }
	/* ctx->buffer_size += setup.buffer_size; */
	/* atomic_set(&ctx->alloc_count, 0); */

	ctx->bundle_list.first = NULL;

	/* // Allocate Memory from the system */
	/* add_mm_counter(current->mm, MM_FILEPAGES, ctx->buffer_size); */

	if (setup->flags & BACKING_VM_CONTIGUOUS) {
		struct page* pages;
		unsigned long start, end, addr;
		pages = alloc_contig_pages(ctx->pool_size, GFP_KERNEL, first_online_node, NULL);
		if (!pages) {
			pr_err("failed to allocate %lx contiguous pages\n", ctx->pool_size);
			return NULL;
		}

		start = (unsigned long) page_to_virt(pages);
		ctx->start = start;
		end = start + PAGE_SIZE * ctx->pool_size;
		pr_info("memory_pool: contiguous mem %lx..%lx with %lu pages\n",
				start, end, ctx->pool_size);

		for (addr = start; addr < end; addr += PAGE_SIZE) {
			struct page* page = virt_to_page(addr);
			if (!page) {
				pr_err("contig pre alloc failed at addr %lx (range %lx..%lx, first pagep %lx)\n",
					   addr, start, end, (unsigned long) pages);
				break;
			}
			push_page(page, &ctx->pool_bundle, ctx);
			alloc_count++;
		}
	} else {
		while (alloc_count < ctx->pool_size) {
			struct page* page = alloc_page_system();
			if (!page) {
				pr_err("pre alloc failed at count %lu of %lu\n",
						alloc_count, ctx->pool_size);
				break;
			}
			push_page(page, &ctx->pool_bundle, ctx);
			alloc_count++;
		}
	}

	/* TODO: add huge page support flag (and say it's unimplemented) */
	/* exmap_flags = EXMAP_FLAGS_ACTIVE; */
	/* // The pagefault handler is currently broken in global free mode */
	/* if (setup.flags & EXMAP_PAGEFAULT_ALLOC) */
	/* 	return -EINVAL; */
	/* if (setup.flags & EXMAP_PAGEFAULT_ALLOC) */
	/* 	exmap_flags |= EXMAP_FLAGS_PAGEFAULT_ALLOC; */
	/* atomic_set(&ctx->flags, exmap_flags); */

	/* TODO: return pool handle */
	MEMORY_POOLS[active_memory_pools++] = ctx;
	return ctx;
}
EXPORT_SYMBOL(memory_pool_create);

void memory_pool_destroy(struct memory_pool_ctx* ctx) {
	struct page* node;
	unsigned long freed_pages = 0;

	freed_pages += free_page_bundle(ctx->pool_bundle.stack, ctx->pool_bundle.count);

	node = bundle_list_del_all(&ctx->bundle_list);
	while (node) {
		struct page* stack = node;
		node = get_without_tag((struct page*) node->mapping);

		freed_pages += free_page_bundle(stack, 512);

		/* When this gets triggered, the global list is corrupted */
		if (node && node == get_without_tag((struct page*) node->mapping)) {
			pr_err("pool_destroy: circular global list node (%lx) == node->next", (unsigned long) node);
			break;
		}
	}

	/* add_mm_counter(vma->vm_mm, MM_FILEPAGES, -1 * ctx->pool_size); */

/* 	// Raise the locked_vm_pages again */
/* 	// exmap_unaccount_mem(ctx, ctx->buffer_size); */

	MEMORY_POOLS[active_memory_pools] = NULL;
	active_memory_pools--;

	pr_info("memory_pool: destroyed %d, freed %lu pages\n", active_memory_pools + 1, freed_pages);

	vfree(ctx);
}
EXPORT_SYMBOL(memory_pool_destroy);

static int memory_pool_init_module(void) {
	active_memory_pools = 0;

	acquire_ksyms();

	pr_info("memory_pool module loaded\n");

	return 0;
}

static void memory_pool_cleanup_module(void) {
	int i;
	
	for (i = 0; i < active_memory_pools; i++)
		memory_pool_destroy(MEMORY_POOLS[i]);

	active_memory_pools = 0;

	pr_info("memory_pool module unloaded\n");
}

module_init(memory_pool_init_module)
module_exit(memory_pool_cleanup_module)
MODULE_LICENSE("GPL");
