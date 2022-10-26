#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/init.h>
#include <linux/kernel.h> /* min */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h> /* copy_from_user, copy_to_user */
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/mman.h>
#include <linux/sched/mm.h>
#include <linux/cdev.h>
#include <linux/random.h>
#include <linux/mmu_notifier.h>

#include <linux/pgtable.h>
#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>


#include <asm/tlbflush.h>

#include <linux/version.h>

#include "linux/exmap.h"
#include "driver.h"
#include "ksyms.h"
#include "config.h"


static dev_t first;
static struct cdev cdev;
static struct class *cl; // Global variable for the device class

struct exmap_interface;
struct exmap_ctx {
	size_t buffer_size;
	size_t alloc_count;

	/* Only used for accounting purposes */
	struct user_struct		*user;
	struct mm_struct		*mm_account;

	/* The main buffer is located here */
	struct vm_area_struct *exmap_vma;

	/* The backing storage */
	struct file *file_backend;
	struct block_device *bdev;

	/* Interfaces are memory mapped areas where the kernel can communicate with the user */
	int    max_interfaces;
	struct exmap_interface *interfaces;

	/* @buffer_size contiguous pages */
	struct page* contig_pages;
	unsigned contig_counter;
	size_t contig_size;
	spinlock_t contig_lock;

	/* exmap-local singly-linked list of free pages */
	struct llist_head global_free_list;
	spinlock_t free_list_lock;

	struct mmu_notifier mmu_notifier;
};

void push_bundle(struct page_bundle bundle, struct exmap_ctx* ctx) {
	BUG_ON(bundle.count != 512);
	/* pr_info("push_bundle: add %lx ([0]=%lx, [511]=%lx)", bundle.stack, */
	/* 		((struct page**) page_to_virt(bundle.stack))[0], */
	/* 		((struct page**) page_to_virt(bundle.stack))[511] */
	/* 	); */
	llist_add((struct llist_node*) &bundle.stack->mapping, &ctx->global_free_list);
}

struct page_bundle pop_bundle(struct exmap_ctx* ctx) {
	struct llist_node* first;
	spin_lock(&ctx->free_list_lock);
	first = llist_del_first(&ctx->global_free_list);
	spin_unlock(&ctx->free_list_lock);
	if (!first) {
		struct page_bundle ret = {
			.stack = NULL,
			.count = 0};
		/* pr_info("pop_bundle: global free list empty"); */
		return ret;
	}

	struct page* page = container_of((struct address_space**) first, struct page, mapping);
	struct page_bundle ret = {
		.stack = page,
		.count = 512,
	};
	/* pr_info("pop_bundle: get %lx ([0]=%lx, [511]=%lx), first was %lx, now %lx", ret.stack, */
	/* 		((struct page**) page_to_virt(ret.stack))[0], */
	/* 		((struct page**) page_to_virt(ret.stack))[511], */
	/* 		first, ctx->global_free_list.first */
	/* 	); */
	return ret;
}


void push_page(struct page* page, struct page_bundle* bundle, struct exmap_ctx* ctx) {
	/* pr_info("push_page: %lx, bundle %lx, count %lu, global %lx", page, bundle, bundle->count, global_free_list); */

	if (!bundle->stack) {
		bundle->stack = page;
		return;
	}
	void* stack_page_virt = page_to_virt(bundle->stack);
	((struct page**) stack_page_virt)[bundle->count++] = page;
	/* pr_info("set entry %lu of virt %lx: %lx", bundle->count-1, stack_page_virt, page); */

	if (bundle->count == 512) {
		push_bundle(*bundle, ctx);
		bundle->count = 0;
		bundle->stack = NULL;
	}
}

struct page* pop_page(struct page_bundle* bundle, struct exmap_ctx* ctx) {
again:
	/* pr_info("pop_page: bundle %lx, count %lu, global %lx", bundle, bundle->count, global_free_list); */
	if (bundle->count > 0) {
		void* stack_page_virt = page_to_virt(bundle->stack);
		struct page* page = ((struct page**) stack_page_virt)[--bundle->count];
		/* pr_info("get entry %lu of virt %lx: %lx", bundle->count, stack_page_virt, page); */
		return page;
	}
	if (bundle->stack) {
		struct page* page = bundle->stack;
		bundle->stack = NULL;
		return page;
	}

	*bundle = pop_bundle(ctx);
	goto again;
}


ssize_t exmap_read_iter(struct kiocb* kiocb, struct iov_iter *iter);



static inline void exmap_unaccount_mem(struct exmap_ctx *ctx,
									   unsigned long nr_pages) {
	// Account for locked memory
	atomic_long_sub(nr_pages, &ctx->user->locked_vm);

	// Also un-account the memory at the process
	atomic64_sub(nr_pages, &ctx->mm_account->pinned_vm);
}

static inline int exmap_account_mem(struct exmap_ctx *ctx,
									unsigned long nr_pages)
{
	unsigned long page_limit, cur_pages, new_pages;

	/* Don't allow more pages than we can safely lock */
	page_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	pr_info("page_limit: %ld/%ld (alloc: %lu)\n",
			atomic_long_read(&ctx->user->locked_vm),
			page_limit, nr_pages);

	do {
		cur_pages = atomic_long_read(&ctx->user->locked_vm);
		new_pages = cur_pages + nr_pages;
		if (new_pages > page_limit)
			return -ENOMEM;
	} while (atomic_long_cmpxchg(&ctx->user->locked_vm, cur_pages,
								 new_pages) != cur_pages);

	atomic64_add(nr_pages, &ctx->mm_account->pinned_vm);

	return 0;
}

void exmap_free_page_system(struct page * page) {
//	current->rss_stat.count[mm_counter_file(page)] -= 1;
	ClearPageReserved(page);
	__free_pages(page, 0);
}

struct page* exmap_alloc_page_system(void) {
	struct page *page = alloc_pages(GFP_NOIO | __GFP_ZERO,  0);
	SetPageReserved(page);
//	current->rss_stat.count[mm_counter_file(page)] += 1;
	return page;
}

struct page* exmap_alloc_page_contig(struct exmap_ctx* ctx) {
	/* BUG_ON(ctx->contig_counter >= ctx->contig_size); */
	if (ctx->contig_counter >= ctx->contig_size)
		return NULL;

	/* NOTE: beware of pointer arithmetic, this adds counter*sizeof(struct page) each time */
	/* TODO: lock needed? */
	spin_lock(&ctx->contig_lock);
	struct page* page = ctx->contig_pages + ctx->contig_counter++;
	ctx->alloc_count++;
	spin_unlock(&ctx->contig_lock);
	/* pr_info("alloc_contig: got page %lx (virt %lx), counter now %u\n", page, page_to_virt(page), ctx->contig_counter); */
	SetPageReserved(page);
//	current->rss_stat.count[mm_counter_file(page)] += 1;
	return page;
}

void exmap_free_stack(struct page* stack, unsigned count) {
	/* interface-local free pages stack can temporarily be NULL until the next page gets pushed */
	if (!stack)
		return;

	void* stack_page_virt = page_to_virt(stack);
	while (count > 0) {
		struct page* page = ((struct page**) stack_page_virt)[--count];
		/* pr_info("bundle: free page %lx, %d remaining, stack %lx (virt %lx)", page, count, stack, stack_page_virt); */
		BUG_ON(!page);
		page->mapping = NULL;
		exmap_free_page_system(page);
	}
	/* pr_info("bundle: free stack page %lx itself", stack); */
	stack->mapping = NULL;
	exmap_free_page_system(stack);
}

static void vm_close(struct vm_area_struct *vma) {
	struct exmap_ctx *ctx = vma->vm_private_data;
	unsigned long freed_pages = 0, unlocked_pages = 0;
	int idx;

	if (!ctx->interfaces)
		return;

#ifdef USE_CONTIG_ALLOC
	/* free all (contiguous) pages allocated from the system */
	unsigned i;
	for (i = 0; i < ctx->contig_size; i++) {
		struct page* page = ctx->contig_pages + i;
		page->mapping = NULL;
		ClearPageReserved(page);
	}
	free_contig_range(page_to_pfn(ctx->contig_pages), ctx->contig_size);
	freed_pages += ctx->contig_size;

	unlocked_pages = ctx->contig_counter;
#else
	// Free all pages in our interfaces
	for (idx = 0; idx < ctx->max_interfaces; idx++) {
		struct exmap_interface *interface = &ctx->interfaces[idx];
		exmap_free_stack(interface->local_pages.stack, interface->local_pages.count);
		freed_pages += interface->local_pages.count + 1;
	}

	/* free remaining global list entries */
	pr_info("vm_close: free global list entries");

	spin_lock(&ctx->free_list_lock);
	struct llist_node* node = llist_del_all(&ctx->global_free_list);
	spin_unlock(&ctx->free_list_lock);
	while (node) {
		struct page* stack = container_of((struct address_space**) node, struct page, mapping);
		exmap_free_stack(stack, 512);
		freed_pages += 513;

		/* When this gets triggered, the global list is corrupted */
		if (node == node->next) {
			pr_err("vm_close: circular global list node (%lx) == node->next", node);
			BUG_ON(node == node->next);
			break;
		}

		node = node->next;
	}
	unlocked_pages = ctx->buffer_size;
#endif

	/* add_mm_counter(vma->vm_mm, MM_FILEPAGES, -1 * ctx->contig_counter); */

	// Raise the locked_vm_pages again
	// exmap_unaccount_mem(ctx, ctx->buffer_size);

	pr_info("vm_close:  freed: %lu, unlock=%lu\n",
			freed_pages, unlocked_pages);
}

/* First page access. */
static vm_fault_t vm_fault(struct vm_fault *vmf) {
#ifndef HANDLE_PAGE_FAULT // The default
	pr_info("vm_fault: off=%ld\n", vmf->pgoff);
	// We forbid the implicit page fault interface
	return VM_FAULT_SIGSEGV;
#else
	int rc;
	struct vm_area_struct *vma = vmf->vma;
	struct exmap_ctx *ctx = vma->vm_private_data;
	struct exmap_interface *interface = &ctx->interfaces[0];

	struct exmap_pages_ctx pages_ctx = {
		.ctx = ctx,
		.interface = interface,
		.pages_count = 1,
	};

	rc = exmap_insert_pages(vma, (uintptr_t) vmf->address,
							1, &pages_ctx, NULL,NULL);
	if (rc < 0) return VM_FAULT_SIGSEGV;

	return VM_FAULT_NOPAGE;
#endif
}

/* After mmap. TODO vs mmap, when can this happen at a different time than mmap? */
static void vm_open(struct vm_area_struct *vma)
{
	pr_info("vm_open\n");
}

static struct vm_operations_struct vm_ops =
{
	.close = vm_close,
	.open = vm_open,
	.fault = vm_fault,
};

static inline struct exmap_ctx *mmu_notifier_to_exmap(struct mmu_notifier *mn)
{
	return container_of(mn, struct exmap_ctx, mmu_notifier);
}

static void exmap_notifier_release(struct mmu_notifier *mn,
								   struct mm_struct *mm) {
	int rc, unmapped_pages;
	struct exmap_ctx *ctx = mmu_notifier_to_exmap(mn);

	if (ctx->interfaces && ctx->exmap_vma) {
		struct vm_area_struct *vma = ctx->exmap_vma;
		unsigned long pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

		struct exmap_pages_ctx pages_ctx = {
			.ctx = ctx,
			.interface = &ctx->interfaces[0],
			.pages_count = 0,
		};
		rc = exmap_unmap_pages(vma, vma->vm_start, pages, &pages_ctx);
		BUG_ON(rc != 0);

		unmapped_pages = pages_ctx.pages_count;

		printk("notifier_release: purged %d pages\n", unmapped_pages);
	}
}

static const struct mmu_notifier_ops mn_opts = {
	.release                = exmap_notifier_release,
};

static int exmap_mmu_notifier(struct exmap_ctx *ctx)
{
	ctx->mmu_notifier.ops = &mn_opts;
	return mmu_notifier_register(&ctx->mmu_notifier, current->mm);
}

static int exmap_mmap(struct file *file, struct vm_area_struct *vma) {
	struct exmap_ctx *ctx = file->private_data;
	loff_t offset = vma->vm_pgoff << PAGE_SHIFT;
	size_t sz = vma->vm_end - vma->vm_start;
	unsigned long pfn;

	if (offset == EXMAP_OFF_EXMAP) {
		// The exmap itself can only be mapped once.
		if (ctx->exmap_vma) {
			return -EBUSY;
		}

		ctx->exmap_vma = vma;
		vma->vm_ops   = &vm_ops;
		vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP | VM_NOHUGEPAGE | VM_DONTCOPY;
		vma->vm_flags |= VM_MIXEDMAP; // required for vm_insert_page
		vma->vm_private_data = ctx;
		vm_open(vma);
	} else if (offset >= EXMAP_OFF_INTERFACE_BASE && offset <= EXMAP_OFF_INTERFACE_MAX) {
		int idx = (offset - EXMAP_OFF_INTERFACE_BASE) >> PAGE_SHIFT;
		struct exmap_interface *interface;

		if (!ctx->interfaces || idx > ctx->max_interfaces || idx < 0)
			return -ENXIO;

		if (sz != PAGE_SIZE)
			return -EINVAL;

		interface = (&ctx->interfaces[idx]);
		// pr_info("mmap interface[%d]: 0x%lx size=%d\n", idx, interface->usermem, sz);


		// Map the struct exmap_user_interface into the userspace
		pfn = virt_to_phys(interface->usermem) >> PAGE_SHIFT;
		return remap_pfn_range(vma, vma->vm_start, pfn, sz, vma->vm_page_prot);
	} else {
		return -EINVAL;
	}
	return 0;
}

static void exmap_mem_free(void *ptr, size_t size) {
	struct page *page;
	page = virt_to_head_page(ptr);
	__free_pages(page, get_order(size));
}

static void *exmap_mem_alloc(size_t size)
{
	gfp_t gfp_flags = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP | __GFP_NORETRY;

	return (void *) __get_free_pages(gfp_flags, get_order(size));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
/*
 * commit 3a3bae50af5d73fab5da20484029de77ca67bb2e:
 * fs: Remove aops ->set_page_dirty
 * With all implementations converted to ->dirty_folio, we can stop calling
 * this fallback method and remove it entirely.
 *
 * TODO: verify whether this new ops struct is correct
 */
bool my_noop_dirty_folio(struct address_space *mapping, struct folio *folio) {
	pr_info("dirty folio, doing nothing\n");
	return 0;
}
void my_noop_invalidate_folio(struct folio *folio, size_t offset, size_t len) {
	pr_info("invalidate folio, doing nothing\n");
}
static const struct address_space_operations dev_exmap_aops = {
	.dirty_folio			= my_noop_dirty_folio,
	.invalidate_folio		= my_noop_invalidate_folio,
	.direct_IO				= exmap_read_iter,
};
#else
static const struct address_space_operations dev_exmap_aops = {
	.set_page_dirty		= __set_page_dirty_no_writeback,
	.invalidatepage		= noop_invalidatepage,
	.direct_IO			= exmap_read_iter,
};
#endif


static int open(struct inode *inode, struct file *filp) {
	int rc = 0;
	// Open does always
	struct exmap_ctx *ctx;
	ctx = kmalloc(sizeof(struct exmap_ctx), GFP_KERNEL);
	memset(ctx, 0, sizeof(struct exmap_ctx));

	// Get mmstruct and current user for accounting purposes
	mmgrab(current->mm);

	rc = exmap_mmu_notifier(ctx);
	if (rc) goto free_ctx;

	ctx->mm_account = current->mm;
	ctx->user = get_uid(current_user());

	ctx->max_interfaces = 0;
	ctx->interfaces = NULL;

	ctx->global_free_list.first = NULL;

	filp->private_data = ctx;

	// Make the character device O_DIRECT
	inode->i_mapping->a_ops = &dev_exmap_aops;
	filp->f_flags |= O_DIRECT | O_NONBLOCK;
	return 0;

free_ctx:
	kfree(ctx);

	return rc;
}

/* FIXME: something here(?) causes bad page state for threads >= 32 (with 16 cores) */
static int release(struct inode *inode, struct file *filp) {
	struct exmap_ctx *ctx = filp->private_data;

	if (ctx->mm_account) {
		mmdrop(ctx->mm_account);
		ctx->mm_account = NULL;
	}

	if (ctx->interfaces) {
		int idx;

		for (idx = 0; idx < ctx->max_interfaces; idx++) {
			// Remove all memory from the free_pages
			exmap_mem_free(ctx->interfaces[idx].usermem,
						   sizeof(struct exmap_user_interface));
		}
		kvfree(ctx->interfaces);
	}

	pr_info("release\n");


	kfree(ctx);
	filp->private_data = NULL;
	return 0;
}

struct exmap_alloc_ctx {
	struct exmap_ctx *ctx;
	struct exmap_interface *interface;

	// From command
	enum exmap_flags flags;
	struct exmap_iov *iov_cur;

	struct bio *bio;
	unsigned long bio_next_offset;

	int bio_count;
	int bio_vec_count;
};

struct exmap_bio_ret {
	atomic_t	      remaining;
	struct completion event;
	int error;
};

static void exmap_submit_endio(struct bio *bio)
{
	struct exmap_bio_ret *ret = bio->bi_private;

	if (blk_status_to_errno(bio->bi_status))
		ret->error = blk_status_to_errno(bio->bi_status);

//	pr_info("completed: %p %d\n", bio, ret->error);

	if (atomic_dec_and_test(&ret->remaining)) {
		complete(&ret->event);
	}

	// IO on the page is now complete and it can be evicted
	ClearPageUnevictable(bio_first_page_all(bio));
}


int exmap_submit_and_wait(struct exmap_alloc_ctx *ctx) {
	unsigned int idx;

	struct exmap_bio_ret data;
	init_completion(&data.event);
	atomic_set(&data.remaining, ctx->bio_count);
	data.error = 0;

	// TODO: Submit the bios
	for (idx = 0; idx < ctx->bio_count; idx++) {
		struct bio *bio = &ctx->interface->bio[idx];
		bio->bi_private = &data;
		bio->bi_end_io = exmap_submit_endio;
		submit_bio(bio);
	}

	// Wait here
	wait_for_completion_io(&data.event);

	// Unitilialize.
	for (idx = 0; idx < ctx->bio_count; idx++) {
		struct bio *bio = &ctx->interface->bio[idx];
		// FIXME: Unpin struct pages after IO has completed
		bio_uninit(bio);
	}
	ctx->bio_count = 0;
	ctx->bio_vec_count = 0;

	return data.error;
}

/**
 * bio_full - check if the bio is full
 * @bio:	bio to check
 * @len:	length of one segment to be added
 *
 * Return true if @bio is full and one segment with @len bytes can't be
 * added to the bio, otherwise return false
 */
static inline bool bio_full(struct bio *bio, unsigned len)
{
	if (bio->bi_vcnt >= bio->bi_max_vecs)
		return true;
	if (bio->bi_iter.bi_size > UINT_MAX - len)
		return true;
	return false;
}


int
exmap_alloc(struct exmap_ctx *ctx, struct exmap_action_params *params) {
	int iface = params->interface;
	struct exmap_interface *interface  = &(ctx->interfaces[iface]);
	struct vm_area_struct  *vma       = ctx->exmap_vma;
	unsigned int  iov_len             = params->iov_len;
	unsigned long nr_pages_alloced    = 0;
	int idx, rc = 0, failed = 0;
	struct exmap_alloc_ctx alloc_ctx = {
		.ctx = ctx,
		.interface = interface,
		.flags = params->flags,
	};

	if (iov_len == 0)
		return failed;

	/* allocate pages from the system if possible */
	unsigned num_pages = iov_len;
	while (unlikely(ctx->alloc_count < ctx->buffer_size) && num_pages > 0) {
#ifdef USE_CONTIG_ALLOC
		struct page* page = exmap_alloc_page_contig(ctx);
#else
		struct page* page = exmap_alloc_page_system();
		ctx->alloc_count++;
#endif
		if (!page) {
			pr_warn("exmap_alloc: no page, alloc=%lu, alloc_max=%lu, contig=%lu, contig_max=%lu\n",
				ctx->alloc_count, ctx->buffer_size, ctx->contig_counter, ctx->contig_size);
			break;
		}
		/* pr_info("exmap_alloc: push %lx on %d", page, iface); */
		push_page(page, &interface->local_pages, ctx);
		num_pages--;
	}

	/* add_mm_counter(current->mm, MM_FILEPAGES, iov_len - num_pages); */


	// Do we really need this lock?
	mmap_read_lock(vma->vm_mm);

	struct exmap_pages_ctx pages_ctx = {
		.ctx = ctx,
		.interface = interface,
		.pages_count = iov_len,
	};

	for (idx = 0; idx < iov_len; idx++) {
		unsigned long uaddr;
		struct exmap_iov ret, vec;
		unsigned free_pages_before;

		vec = READ_ONCE(interface->usermem->iov[idx]);
		uaddr = vma->vm_start + (vec.page << PAGE_SHIFT);
		alloc_ctx.iov_cur = &vec;

		// pr_info("alloc[%d]: off=%llu, len=%d", iface, (uint64_t) vec.page, (int) vec.len);

		free_pages_before = pages_ctx.pages_count;
		rc = exmap_insert_pages(vma, uaddr, vec.len, &pages_ctx,
								NULL, &alloc_ctx);
		if (rc < 0) failed++;

		ret.res = rc;
		ret.pages = (int)(free_pages_before - pages_ctx.pages_count);
		nr_pages_alloced += ret.pages;

		exmap_debug("alloc: %llu+%d => rc=%d, used=%d",
					(uint64_t) vec.page, (int)vec.len,
					(int)ret.res, (int) ret.pages);

		WRITE_ONCE(interface->usermem->iov[idx], ret);
	}

	if (alloc_ctx.bio_count > 0)
		exmap_submit_and_wait(&alloc_ctx);

	// Update the RSS counter once!
	// add_mm_counter(vma->vm_mm, MM_FILEPAGES, nr_pages_alloced);

	mmap_read_unlock(vma->vm_mm);

	return failed;
}

int
exmap_free(struct exmap_ctx *ctx, struct exmap_action_params *params) {
	int iface = params->interface;
	struct exmap_interface *interface = &(ctx->interfaces[iface]);
	struct vm_area_struct  *vma       = ctx->exmap_vma;
	unsigned int  iov_len             = params->iov_len;
	int idx, rc = 0, failed = 0;
	/* FREE_PAGES(free_pages); */

	if (iov_len == 0)
		return failed;

	// Do we really need this lock?
	mmap_read_lock(vma->vm_mm);

	struct exmap_pages_ctx pages_ctx = {
		.ctx = ctx,
		.interface = interface,
		.pages_count = 0,
	};

	for (idx = 0; idx < iov_len; idx++) {
		struct exmap_iov vec = READ_ONCE(interface->usermem->iov[idx]);
		unsigned long uaddr = vma->vm_start + (vec.page << PAGE_SHIFT);
		unsigned long old_free_count = pages_ctx.pages_count;

		/* FIXME what if vec.len == 0 */
		/* if (vec.len == 0) */
		/* 	continue; */


		rc = exmap_unmap_pages(vma, uaddr, (int) vec.len, &pages_ctx);

		exmap_debug("free[%d]: off=%llu, len=%d, freed: %lu",
				iface,
					(uint64_t) vec.page, (int) vec.len,
					pages_ctx.pages_count - old_free_count);

		if (rc < 0) failed++;
		vec.res = rc;
		vec.pages = pages_ctx.pages_count - old_free_count;

		interface->count.e += vec.pages;

		WRITE_ONCE(interface->usermem->iov[idx], vec);

#ifndef BATCH_TLB_FLUSH
		flush_tlb_mm(vma->vm_mm);
#endif
	}

	// Flush the TLB of this CPU!
	// __flush_tlb_all(); 	// Please note: This is no shootdown!
#ifdef BATCH_TLB_FLUSH
	flush_tlb_mm(vma->vm_mm);
#endif

	// Update the RSS counter once!
	// add_mm_counter(vma->vm_mm, MM_FILEPAGES, -1 * free_pages.count);

	mmap_read_unlock(vma->vm_mm);

	return failed;
}

typedef int (*exmap_action_fptr)(struct exmap_ctx *, struct exmap_action_params *);

static exmap_action_fptr exmap_action_array[] = {
	[EXMAP_OP_ALLOC] = &exmap_alloc,
	[EXMAP_OP_FREE]  = &exmap_free,
};

static long exmap_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
	struct exmap_ioctl_setup  setup;
	struct exmap_action_params action;
	struct exmap_ctx *ctx;
	struct exmap_interface *interface;
	int rc = 0, idx;
	gfp_t gfp_flags;

	ctx = (struct exmap_ctx*) file->private_data;

	switch(cmd) {
	case EXMAP_IOCTL_SETUP:
		if( copy_from_user(&setup, (struct exmap_ioctl_setup *) arg,
						   sizeof(struct exmap_ioctl_setup)) )
			return -EFAULT;

		/* process data and execute command */
		pr_info("setup.buffer_size = %ld", setup.buffer_size);

		// Interfaces can only be initialized once
		/* pr_info("setup.interfaces = %p", ctx->interfaces); */
		if (ctx->interfaces)
			return -EBUSY;

		if (setup.fd >= 0) {
			struct file *file = fget(setup.fd);
			struct inode *inode;

			if (!file) goto out_fput;

			if (!(file->f_flags & O_DIRECT)) {
				pr_err("Please give an O_DIRECT fd");
				goto out_fput;
			}

			if (!(file->f_mode & FMODE_READ)) {
				pr_err("Please give a readable fd");
				goto out_fput;
			}

			inode = file_inode(file);
			if (!S_ISBLK(inode->i_mode)) {
				pr_err("Only support for block devices at the moment");
				goto out_fput;
			}

			ctx->file_backend = file;
			ctx->bdev = I_BDEV(file->f_mapping->host);

			pr_info("setup.fd: %d (bdev=%p)", setup.fd, ctx->bdev);

			if (false) {
			out_fput:
				fput(file);
				return -EBADF;

			}
		}

		// // Account for the locked memory
		// rc = exmap_account_mem(ctx, (setup.buffer_size - ctx->buffer_size));
		// if (rc < 0) {
		// 	pr_info("Cannot account for memory. rlimit exceeded");
		//     return rc;
		// }
		ctx->buffer_size += setup.buffer_size;
		ctx->alloc_count = 0;

		if (setup.max_interfaces > 256)
			return -EINVAL;

		ctx->max_interfaces = setup.max_interfaces;
		/* warn if more interfaces are created than there are CPUs */
		if (num_online_cpus() < setup.max_interfaces) {
			pr_warn("exmap: More interfaces (%u) than CPUs (%u)\n", setup.max_interfaces, num_online_cpus());
		}

		/*
		 * kvmalloc in combination with __GFP_COMP leads to "bad page state" errors
		 * when freeing the memory again. This is probably due to VM_ALLOW_HUGE_VMAP
		 * being set in kvmalloc_node (see 3b8000ae185cb068adbda5f966a3835053c85fd4).
		 *
		 * We have two options to fix this, either by using __vmalloc derivatives, or
		 * by removing the __GFP_COMP flag.
		 */
		gfp_flags = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP | __GFP_NORETRY;
		ctx->interfaces = __vmalloc_array(setup.max_interfaces, sizeof(struct exmap_interface), gfp_flags);
		if (!ctx->interfaces) {
			pr_info("interfaces failed");
			return -ENOMEM;
		}


#ifdef USE_CONTIG_ALLOC
		/* @buffer_size + one page for the bundle/stack for each interface */
		ctx->contig_size = setup.buffer_size + setup.max_interfaces;
		ctx->contig_pages = alloc_contig_pages(ctx->contig_size, GFP_NOIO | __GFP_ZERO,
												first_online_node, NULL);
		if (!ctx->contig_pages) {
			pr_info("allocation of %lu contiguous pages failed", setup.buffer_size);
			return -ENOMEM;
		}
		ctx->contig_counter = 0;
		spin_lock_init(&ctx->contig_lock);
		exmap_debug("allocated %lu+%lu contiguous pages at %lx\n",
				setup.buffer_size, setup.max_interfaces, ctx->contig_pages);

#endif

		ctx->global_free_list.first = NULL;
		spin_lock_init(&ctx->free_list_lock);

		for (idx = 0; idx < ctx->max_interfaces; idx++) {
			interface = &ctx->interfaces[idx];

			// Allocate user facing memory
			interface->usermem = exmap_mem_alloc(sizeof(struct exmap_user_interface));
			if (!interface->usermem) {
				// BUG_ON(!interface->usermem); // Lost Memory....
				pr_info("usermem failed");
				ctx->interfaces = NULL;
				return -ENOMEM;
			}

			/* initialize counters */
			interface->count.a = 0;
			interface->count.e = 0;
			interface->count.r = 0;

			mutex_init(&interface->interface_lock);

			interface->local_pages.count = 0;
#ifdef USE_CONTIG_ALLOC
			interface->local_pages.stack = exmap_alloc_page_contig(ctx);
#else
			interface->local_pages.stack = exmap_alloc_page_system();
			ctx->alloc_count++;
#endif
		}

		break;

	case EXMAP_IOCTL_ACTION:
		if (unlikely(ctx->interfaces == NULL))
			return -EBADF;

		if( copy_from_user(&action, (struct exmap_action_params *) arg,
						   sizeof(struct exmap_action_params)) )
			return -EFAULT;

		if (unlikely(action.interface >= ctx->max_interfaces))
			return -EINVAL;

		if (action.opcode > ARRAY_SIZE(exmap_action_array)
			|| !exmap_action_array[action.opcode])
			return -EINVAL;

		mutex_lock(&(ctx->interfaces[action.interface].interface_lock));
		rc = exmap_action_array[action.opcode](ctx, &action);
		mutex_unlock(&(ctx->interfaces[action.interface].interface_lock));
		break;
	default:
		return -EINVAL;
	}

	return rc;
}

ssize_t exmap_alloc_iter(struct exmap_ctx *ctx, struct exmap_interface *interface, struct iov_iter *iter) {
	ssize_t total_nr_pages = iov_iter_count(iter) >> PAGE_SHIFT;
	struct iov_iter_state iter_state;
	int rc, rc_all = 0;

	iov_iter_save_state(iter, &iter_state);
	while (iov_iter_count(iter)) {
		struct iovec iovec = iov_iter_iovec(iter);
		char __user* addr = iovec.iov_base;
		ssize_t size = iovec.iov_len;

		struct exmap_pages_ctx pages_ctx = {
			.ctx = ctx,
			.interface = interface,
			.pages_count = size,
		};

		//if (iovec.iov_len != iov_iter_count(iter)) {
		//	pr_info("exmap: BUG we currently support only iovectors of length 1\n");
		//	return -EINVAL;
		//}
		// pr_info("iov: %lx + %ld (of %ld)\n", (uintptr_t)addr, size >> PAGE_SHIFT, iov_iter_count(iter));

		if (ctx->exmap_vma->vm_start > (uintptr_t) addr) {
			pr_info("vmstart");
			return -EINVAL;
		}
		if (ctx->exmap_vma->vm_end < (uintptr_t) addr) {
			pr_info("vmend");
			return -EINVAL;
		}
		if (((uintptr_t) addr) & ~PAGE_MASK) // Not aligned start
		{
			pr_info("addr");
			return -EINVAL;
		}
		if (((uintptr_t) size) & ~PAGE_MASK) { // Not aligned end
			pr_info("size");
			return -EINVAL;
		}

		rc = exmap_insert_pages(ctx->exmap_vma, (uintptr_t) addr,
								(size >> PAGE_SHIFT),
								&pages_ctx, NULL,NULL);
		if (rc < 0) return rc;
		rc_all += rc;

		iov_iter_advance(iter, iovec.iov_len);
	}

	iov_iter_restore(iter, &iter_state);

	return rc_all;
}


ssize_t exmap_read_iter(struct kiocb* kiocb, struct iov_iter *iter) {
	struct file *file = kiocb->ki_filp;
	struct exmap_ctx *ctx = (struct exmap_ctx *) file->private_data;
	unsigned int iface_id = kiocb->ki_pos & 0xff;
	unsigned int action = (kiocb->ki_pos >> 8) & 0xff;
	struct exmap_interface *interface;

	int rc, rc_all = 0;

	if (action != EXMAP_OP_READ && action != EXMAP_OP_ALLOC) {
		return -EINVAL;
	}

	if (iface_id >= ctx->max_interfaces) {
		pr_info("max");
		return -EINVAL;
	}
	interface = &ctx->interfaces[iface_id];

	// Allocate Memory in Area
	rc = exmap_alloc_iter(ctx, interface, iter);
	if (rc < 0) return rc;

	// EXMAP_OP_READ == 0
	if (action != EXMAP_OP_READ) {
		return rc;
	} else {
		if (!(ctx->file_backend && ctx->file_backend->f_op->read_iter)){
			pr_info("nofile");
			return -EINVAL;
		}
	}

	while (iov_iter_count(iter)) {
		struct iovec iovec = iov_iter_iovec(iter);
		char __user* addr = iovec.iov_base;
		ssize_t size = iovec.iov_len;
		loff_t  disk_offset = (uintptr_t)addr - ctx->exmap_vma->vm_start;
		struct iov_iter_state iter_state;

		// pr_info("exmap: read  @ interface %d: %lu+%lu\n", iface_id, disk_offset, size);

		kiocb->ki_pos = disk_offset;
		kiocb->ki_filp = ctx->file_backend;

		iov_iter_save_state(iter, &iter_state);
		iov_iter_truncate(iter, size);
		rc = call_read_iter(ctx->file_backend, kiocb, iter);
		iov_iter_restore(iter, &iter_state);

		if (rc < 0) return rc;

		rc_all += rc;

		iov_iter_advance(iter, iovec.iov_len);
	}

	return rc_all;
}

static const struct file_operations fops = {
	.mmap = exmap_mmap,
	.open = open,
	.read_iter = exmap_read_iter,
	.release = release,
	.unlocked_ioctl = exmap_ioctl
};

static int dev_uevent_perms(struct device *dev, struct kobj_uevent_env *env) {
	return add_uevent_var(env, "DEVMODE=%#o", 0666);
}

static int exmap_init_module(void) {
	if (exmap_acquire_ksyms())
		goto out;

	if (alloc_chrdev_region(&first, 0, 1, "exmap") < 0)
		goto out;
	if ((cl = class_create(THIS_MODULE, "exmap")) == NULL)
		goto out_unregister_chrdev_region;
	cl->dev_uevent = dev_uevent_perms;
	if (device_create(cl, NULL, first, NULL, "exmap") == NULL)
		goto out_class_destroy;

	cdev_init(&cdev, &fops);
	if (cdev_add(&cdev, first, 1) == -1)
		goto out_device_destroy;

	printk(KERN_INFO "exmap registered");

	return 0;

 out_device_destroy:
	device_destroy(cl, first);
 out_class_destroy:
	class_destroy(cl);
 out_unregister_chrdev_region:
	unregister_chrdev_region(first, 1);
 out:
	return -1;
}

static void exmap_cleanup_module(void) {
	cdev_del(&cdev);
	device_destroy(cl, first);
	class_destroy(cl);
	unregister_chrdev_region(first, 1);
	printk(KERN_INFO "exmap unregistered");
}

module_init(exmap_init_module)
module_exit(exmap_cleanup_module)
MODULE_LICENSE("GPL");
