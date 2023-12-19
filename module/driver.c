#include <linux/version.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/init.h>
#include <linux/kernel.h> /* min */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/hugetlb.h>
#include <asm/pgtable.h>
#include <linux/uaccess.h> /* copy_from_user, copy_to_user */
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/mman.h>
#include <linux/sched/mm.h>
#include <linux/cdev.h>
#include <linux/random.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include <linux/io_uring.h>
#include <linux/io_uring_types.h>
#endif

#include <linux/pgtable.h>
#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>


#include <asm/tlbflush.h>



#include "linux/exmap.h"
#include "driver.h"
#include "ksyms.h"

static dev_t first;
static struct cdev cdev;
static struct class *cl; // Global variable for the device class

#define EXMAP_FLAGS_ACTIVE (1 << 0) // Is the exmap still active or in a state of decay/tear down.
#define EXMAP_FLAGS_PAGEFAULT_ALLOC (1 << 1) // Alloc new memory on a page fault
#define EXMAP_FLAGS_STEAL (1 << 2) // Alloc new memory on a page fault

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define pte_offset_map pte_offset_kernel
#endif


static inline
struct exmap_ctx * exmap_from_file(struct file *file) {
	struct exmap_ctx *ctx = file->private_data;
	if (ctx->clone_of != NULL)
		ctx = ctx->clone_of;
	return ctx;
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


////////////////////////////////////////////////////////////////
// Page Table Export

/* First page access. */
static vm_fault_t pt_export_vm_fault(struct vm_fault *vmf) {
	int ret = VM_FAULT_SIGSEGV;
	struct vm_area_struct *vma = vmf->vma;
	struct exmap_ctx *ctx = vma->vm_private_data;
	unsigned long pfn = (vmf->real_address - vma->vm_start) / sizeof(pteval_t);
	unsigned long exmap_addr    = ctx->exmap_vma->vm_start + pfn * PAGE_SIZE;


	// Ask for the page table
	pmd_t *pmd = exmap_walk_to_pmd(ctx->exmap_vma, exmap_addr);
	if (pmd && pmd_present(*pmd) && !pmd_huge(*pmd)) {
		int rc;
		pte_t *pte = pte_offset_map(pmd, exmap_addr);
		struct page* ptable = virt_to_page(pte);
		FREE_PAGES(free_pages);

		//pr_info("ptexport/vm_fault: addr=%lx, pn: %d, ptable: %lx\n", vmf->address, pfn, ptable);
		//pr_info("ptexport/vm_fault: pte: %lx, %lx\n", pte, page_to_virt(ptable));
		//pr_info("ptexport/vm_fault: pteval: %lx\n", pte_val(*pte));

		//pmd_t *ptexport_pmd = exmap_walk_to_pmd(ctx->ptexport_vma, vmf->address);
		//pte_t *ptexport_pte = pte_offset_map(ptexport_pmd, vmf->address);

		// This is an uggly hack to insert the page without validation
		struct page_bundle temp = {
			.stack = ptable,
			.count = 0,
		};
		free_pages.ctx = ctx;
		free_pages.bundle = &temp;
		free_pages.count++;
		rc = exmap_insert_pages(vma, vmf->address, 1, &free_pages, NULL,NULL);
		BUG_ON(rc != 0);

		//pr_info("ptexport/vm_fault: ptexport: %lx\n", pte_val(*ptexport_pte));
		ret = VM_FAULT_NOPAGE;
	}
	return ret;
}

static struct vm_operations_struct pt_export_vm_ops = {
	.fault = pt_export_vm_fault,
};

static void ptexport_vma_cleanup(struct exmap_ctx *ctx) {
	unsigned long rc;
	struct vm_area_struct *vma = ctx->ptexport_vma;
	unsigned pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	pr_info("ptexport_vma_cleanup!");
	rc = exmap_unmap_pages(vma, vma->vm_start, pages, NULL);
	BUG_ON(rc != 0);
}


static int pt_export_mmap(struct exmap_ctx *ctx, struct vm_area_struct *vma) {
	unsigned long ex_start_pfn, ex_end_pfn, pt_export_max;

	// ExMap Mapping must be created beforehand
	if (!ctx->exmap_vma)
		return -EPROTO;

	ex_start_pfn = ctx->exmap_vma->vm_start >> PAGE_SHIFT;
	ex_end_pfn   = ctx->exmap_vma->vm_end   >> PAGE_SHIFT;

	// Are all exported page table only filled with PTEs from our
	// exmap_vma? Otherwise: Information leakage
	if ((ex_start_pfn & (PTRS_PER_PTE - 1)) != 0)
		return -EFAULT;

	if ((ex_end_pfn & (PTRS_PER_PTE - 1)) != 0)
		return -EFAULT;


	// Next, check that Our VMA is not larger than the exmap
	pt_export_max = (ex_end_pfn - ex_start_pfn) * sizeof(pteval_t);
	if ((vma->vm_end - vma->vm_start) > pt_export_max)
		return -EOVERFLOW;

	pr_info("pt_export: exmap(%lx + %lx pages), will export %ld page tables\n",
			ctx->exmap_vma->vm_start, ex_end_pfn - ex_start_pfn,
			(vma->vm_end - vma->vm_start) >> PAGE_SHIFT);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	vm_flags_set(vma, VM_DONTEXPAND);
	vm_flags_set(vma, VM_DONTDUMP);
	vm_flags_set(vma, VM_NOHUGEPAGE);
	vm_flags_set(vma, VM_DONTCOPY);
	vm_flags_set(vma, VM_MIXEDMAP);
#else
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP | VM_NOHUGEPAGE | VM_DONTCOPY;
	vma->vm_flags |= VM_MIXEDMAP;
#endif
	vma->vm_private_data = ctx;
	vma->vm_ops = &pt_export_vm_ops;
	vma->vm_private_data = ctx;
	ctx->ptexport_vma = vma;

	return 0;
}

////////////////////////////////////////////////////////////////
// Exmap mmap()
static void vm_close(struct vm_area_struct *vma) {
	struct exmap_ctx *ctx = vma->vm_private_data;
	unsigned long freed_pages = 0;
	int idx;

	if (!ctx->interfaces)
		return;

	// Free all pages in our interfaces
	for (idx = 0; idx < ctx->max_interfaces; idx++) {
		struct exmap_interface *interface = &ctx->interfaces[idx];
		freed_pages += free_page_bundle(interface->local_pages.stack, interface->local_pages.count);
	}

	memory_pool_destroy(ctx->memory_pool);

	add_mm_counter(vma->vm_mm, MM_FILEPAGES, -1 * ctx->buffer_size);

	// Raise the locked_vm_pages again
	// exmap_unaccount_mem(ctx, ctx->buffer_size);

	ctx->exmap_vma = NULL;

	pr_info("vm_close:  freed: %lu, unlock=%ld\n",
			freed_pages, ctx->buffer_size);
}

/* First page access. */
static vm_fault_t exmap_vm_fault(struct vm_fault *vmf) {
	int rc, cpu, ret = VM_FAULT_SIGSEGV;
	FREE_PAGES(free_pages);
	struct vm_area_struct *vma = vmf->vma;
	struct exmap_ctx *ctx = vma->vm_private_data;
	struct exmap_interface *interface;
	if (atomic_read(&ctx->flags) & EXMAP_FLAGS_PAGEFAULT_ALLOC) {
		cpu = raw_smp_processor_id() % ctx->max_interfaces;
		// pr_info("fault: %d\n", cpu);

		interface = &ctx->interfaces[cpu];
		// mutex_lock(&interface->interface_lock);

		free_pages.ctx = ctx;
		free_pages.bundle = &interface->local_pages;
		free_pages.count = 1;

		rc = exmap_insert_pages(vma, (uintptr_t) vmf->address,
								1, &free_pages, NULL,NULL);
		if (rc < 0) {
			pr_info("insert failed: %d\n", rc);
			goto out;
		}


		// pr_info("fault ok: %d\n", cpu);

		ret = VM_FAULT_NOPAGE;
out:
		// mutex_unlock(&interface->interface_lock);
	} else {
		// We forbid the implicit page fault interface
		pr_info("vm_fault: off=%ld addr=%lx\n", vmf->pgoff, vmf->address);
	}
	return ret;
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
	.fault = exmap_vm_fault,
};

static inline struct exmap_ctx *mmu_notifier_to_exmap(struct mmu_notifier *mn)
{
	return container_of(mn, struct exmap_ctx, mmu_notifier);
}

static void exmap_vma_cleanup(struct exmap_ctx *ctx, unsigned long start, unsigned long end) {
	unsigned long rc, unmapped_pages;

	struct vm_area_struct *vma = ctx->exmap_vma;
	unsigned long pages = (end - start) >> PAGE_SHIFT;
    FREE_PAGES(free_pages);

	// Clear all flags and make the exmap inactive such that no new
	// operations are started from now on.
	int flags = atomic_xchg(&ctx->flags, 0);
	if (!(flags & EXMAP_FLAGS_ACTIVE)) {
		printk("cleanup already happened. skip it.\n");
		return;
	}

	// Sequentialize after all actions. We never unlock these
	// interfaces!
	for (unsigned idx = 0; idx < ctx->max_interfaces; idx++) {
		mutex_lock(&ctx->interfaces[idx].interface_lock);
	}

	free_pages.ctx = ctx;
	free_pages.bundle = &ctx->interfaces[0].local_pages;
	free_pages.count = 0;

    rc = exmap_unmap_pages(vma, vma->vm_start, pages, &free_pages);
    BUG_ON(rc != 0);

    unmapped_pages = free_pages.count;


    printk("notifier cleanup: purged %lu pages\n", unmapped_pages);

	for (unsigned idx = 0; idx < ctx->max_interfaces; idx++) {
		mutex_unlock(&ctx->interfaces[idx].interface_lock);
	}
	printk("notifier cleanup: unlocked all interfaces (%d)\n", ctx->max_interfaces);

}

static void exmap_notifier_release(struct mmu_notifier *mn,
								   struct mm_struct *mm) {
	struct exmap_ctx *ctx = mmu_notifier_to_exmap(mn);

	if (ctx->interfaces && ctx->exmap_vma) {
		exmap_vma_cleanup(ctx, ctx->exmap_vma->vm_start, ctx->exmap_vma->vm_end);
	}
	if (ctx->ptexport_vma) {
		ptexport_vma_cleanup(ctx);
	}
}

static int exmap_notifier_invalidate_range_start(struct mmu_notifier *mn, const struct mmu_notifier_range *range) {
	struct exmap_ctx *ctx = mmu_notifier_to_exmap(mn);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct vm_area_struct *vma;
	vma = find_vma_intersection(range->mm, range->start, range->end);
	if (ctx->interfaces && ctx->exmap_vma && ctx->exmap_vma == vma) {
		exmap_vma_cleanup(ctx, range->start, range->end);
	}
	if (ctx->ptexport_vma && ctx->ptexport_vma == vma) {
		ptexport_vma_cleanup(ctx);
	}
#else
	// Only cleanup the exmap_vma when it is the one being unmapped
	if (ctx->interfaces && ctx->exmap_vma && ctx->exmap_vma == range->vma) {
		exmap_vma_cleanup(ctx, range->start, range->end);
	}
	if (ctx->ptexport_vma && ctx->ptexport_vma == range->vma) {
		ptexport_vma_cleanup(ctx);
	}
#endif
	return 0;
}

static const struct mmu_notifier_ops mn_opts = {
	.release                = exmap_notifier_release,
	.invalidate_range_start = exmap_notifier_invalidate_range_start,
};

static int exmap_mmu_notifier(struct exmap_ctx *ctx)
{
	ctx->mmu_notifier.ops = &mn_opts;
	return mmu_notifier_register(&ctx->mmu_notifier, current->mm);
}

static void exmap_mmu_notifier_unregister(struct exmap_ctx *ctx)
{
	if (current->mm && ctx->mmu_notifier.ops) {
		mmu_notifier_unregister(&ctx->mmu_notifier, current->mm);
		ctx->mmu_notifier.ops = NULL;
	}
}

static int exmap_mmap(struct file *file, struct vm_area_struct *vma) {
	struct exmap_ctx *ctx = exmap_from_file(file);
	loff_t offset = vma->vm_pgoff << PAGE_SHIFT;
	size_t sz = vma->vm_end - vma->vm_start;
	unsigned long pfn;

	if (offset == EXMAP_OFF_EXMAP) {
		// The exmap itsel can only be mapped once.
		if (ctx->exmap_vma) {
			return -EBUSY;
		}

		vma->vm_ops   = &vm_ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	vm_flags_set(vma, VM_DONTEXPAND);
	vm_flags_set(vma, VM_DONTDUMP);
	vm_flags_set(vma, VM_NOHUGEPAGE);
	vm_flags_set(vma, VM_DONTCOPY);
	vm_flags_set(vma, VM_MIXEDMAP);
#else
		vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP | VM_NOHUGEPAGE | VM_DONTCOPY;
		vma->vm_flags |= VM_MIXEDMAP; // required for vm_insert_page
#endif
		vma->vm_private_data = ctx;
		vm_open(vma);
		ctx->exmap_vma = vma;
	} else if (offset == EXMAP_OFF_PTEXPORT) {
		if (ctx->ptexport_vma) return -EBUSY;
		return pt_export_mmap(ctx, vma);
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
	gfp_t gfp_flags = GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP |
		__GFP_NORETRY | __GFP_ACCOUNT;

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
 * */
static const struct address_space_operations dev_exmap_aops = {
	.dirty_folio		= noop_dirty_folio,
	.invalidate_folio		= folio_invalidate,
	.direct_IO              = exmap_read_iter,
};
#else
static const struct address_space_operations dev_exmap_aops = {
	.set_page_dirty		= __set_page_dirty_no_writeback,
	.invalidatepage		= noop_invalidatepage,
	.direct_IO              = exmap_read_iter,
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

	filp->private_data = ctx;

	// Make the character device O_DIRECT
	inode->i_mapping->a_ops = &dev_exmap_aops;
	filp->f_flags |= O_DIRECT | O_NONBLOCK;

	// Disable fs notify for the proxy file descriptor as this is
	// a major bottlneck for accessing files.
	filp->f_mode |= FMODE_NONOTIFY;
	return 0;

free_ctx:
	kfree(ctx);

	return rc;
}

static int release(struct inode *inode, struct file *filp) {
	struct exmap_ctx *ctx = filp->private_data;
	if (ctx->clone_of)
		goto free_private_data;

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

	exmap_mmu_notifier_unregister(ctx);

	pr_info("release\n");

 free_private_data:
	kfree(filp->private_data);
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
exmap_alloc_from_ivec(struct exmap_ctx *ctx, struct exmap_interface* interface,
					  struct exmap_iov *ivec, unsigned int ivec_len,
					  unsigned flags) {
	struct vm_area_struct  *vma       = ctx->exmap_vma;
	unsigned long nr_pages_alloced    = 0;
	FREE_PAGES(free_pages);
	int idx, rc = 0, failed = 0;
	struct exmap_alloc_ctx alloc_ctx = {
		.ctx = ctx,
		.interface = interface,
		.flags = flags,
	};

	if (ivec_len == 0)
		return failed;

	free_pages.ctx = ctx;
	free_pages.bundle = &interface->local_pages;
	free_pages.count = 0;

	// pr_info("First Alloc: %d\n", free_pages.count);

	// Do we really need this lock?
	//	mmap_read_lock(vma->vm_mm);

	for (idx = 0; idx < ivec_len; idx++) {
		unsigned long uaddr;
		struct exmap_iov ret, vec;
		unsigned free_pages_before;

		vec = READ_ONCE(ivec[idx]);
		uaddr = vma->vm_start + (vec.page << PAGE_SHIFT);
		alloc_ctx.iov_cur = &vec;

		// pr_info("alloc[%d]: off=%llu, len=%d", iface, (uint64_t) vec.page, (int) vec.len);

		/* assume there are enough free pages in the local or global list */
		free_pages.count += vec.len;

		free_pages_before = free_pages.count;
		rc = exmap_insert_pages(vma, uaddr, vec.len, &free_pages,
								NULL, &alloc_ctx);
		if (rc == -ENOMEM) {
			for (; idx < ivec_len; idx++) {
				ret.res = -ENOMEM;
				ret.pages = 0;
				WRITE_ONCE(ivec[idx], ret);
			}
			break;
		}
		if (rc < 0) failed++;

		ret.res = rc;
		ret.pages = (int)(free_pages_before - free_pages.count);
		nr_pages_alloced += ret.pages;

		exmap_debug("alloc[%d]: %llu+%d => rc=%d, used=%d",
					interface - ctx->interfaces,
					(uint64_t) vec.page, (int)vec.len,
					(int)ret.res, (int) ret.pages);

		WRITE_ONCE(ivec[idx], ret);
	}

	if (alloc_ctx.bio_count > 0)
		exmap_submit_and_wait(&alloc_ctx);

	// Update the RSS counter once!
	// add_mm_counter(vma->vm_mm, MM_FILEPAGES, nr_pages_alloced);

	// mmap_read_unlock(vma->vm_mm);

	return failed;
}

int
exmap_alloc(struct exmap_ctx *ctx, struct exmap_action_params *params) {
	int iface = params->interface;
	struct exmap_interface *interface  = &(ctx->interfaces[iface]);
	struct exmap_iov *iov = interface->usermem->iov;

	return exmap_alloc_from_ivec(ctx, interface, iov, params->iov_len, params->flags);
}

int
exmap_free(struct exmap_ctx *ctx, struct exmap_action_params *params) {
	int iface = params->interface;
	struct exmap_interface *interface = &(ctx->interfaces[iface]);
	struct vm_area_struct  *vma       = ctx->exmap_vma;
	unsigned int  iov_len             = params->iov_len;
	int idx, rc = 0, failed = 0;
	FREE_PAGES(free_pages);

	if (iov_len == 0)
		return failed;

	// Do we really need this lock?
	mmap_read_lock(vma->vm_mm);

	free_pages.ctx = ctx;
	free_pages.bundle = &interface->local_pages;
	free_pages.count = 0;

	for (idx = 0; idx < iov_len; idx++) {
		struct exmap_iov vec = READ_ONCE(interface->usermem->iov[idx]);
		unsigned long uaddr = vma->vm_start + (vec.page << PAGE_SHIFT);
		unsigned long old_free_count = free_pages.count;

		/* FIXME what if vec.len == 0 */
		/* if (vec.len == 0) */
		/* 	continue; */

		rc = exmap_unmap_pages(vma, uaddr, (int) vec.len, &free_pages);

		exmap_debug("free[%d]: %llu+%d, => rc=%d freed: %lu",
					iface, (uint64_t) vec.page, (int) vec.len,
					rc, free_pages.count - old_free_count);

		if (rc < 0) failed++;
		vec.res = rc;
		vec.pages = free_pages.count - old_free_count;

		interface->count.e += vec.pages;

		WRITE_ONCE(interface->usermem->iov[idx], vec);

	}

	// Flush the TLB of this CPU!
	// __flush_tlb_all(); 	// Please note: This is no shootdown!
	flush_tlb_mm(vma->vm_mm);

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

static long exmap_stats(struct exmap_ioctl_stats *dst, struct exmap_ctx *ctx) {
	struct exmap_ioctl_stats ret = {0};

	ret.flags = atomic_read(&ctx->flags);
	ret.max_interfaces = ctx->max_interfaces;
	ret.buffer_size = ctx->buffer_size;
	ret.alloc_count = atomic_read(&ctx->alloc_count);
	if( copy_to_user(dst, &ret, sizeof(ret)))
		return -EFAULT;
	return 0;
}

static long exmap_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
	struct memory_pool_setup pool_setup;
	struct memory_pool_ctx* pool_ctx;
	struct exmap_ioctl_setup setup;
	struct exmap_action_params action;
	struct exmap_ctx *ctx = exmap_from_file(file);
	struct exmap_interface *interface;
	int rc = 0, idx, exmap_flags;
	gfp_t gfp_flags;

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
		atomic_set(&ctx->alloc_count, 0);

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
			interface->local_pages.stack = NULL;
		}

		// 2. Allocate Memory from the system
		add_mm_counter(current->mm, MM_FILEPAGES, ctx->buffer_size);

		pool_setup.pool_size = ctx->buffer_size;
		pool_ctx = memory_pool_create(&pool_setup);
		ctx->memory_pool = pool_ctx;


		exmap_flags = EXMAP_FLAGS_ACTIVE;
		// The pagefault handler is currently broken in global free mode
		if (setup.flags & EXMAP_PAGEFAULT_ALLOC)
			return -EINVAL;
		if (setup.flags & EXMAP_PAGEFAULT_ALLOC)
			exmap_flags |= EXMAP_FLAGS_PAGEFAULT_ALLOC;
		atomic_set(&ctx->flags, exmap_flags);

		break;
	case EXMAP_IOCTL_CLONE:
		struct file *other_file = fget(arg);
		struct exmap_ctx *other_ctx;
		if (!other_file) return -EBADFD;

		if (file->f_op != other_file->f_op) {
			fput(other_file);
			return -EINVAL; // Other file is not an exmap
		}

		other_ctx = other_file->private_data;
		if (other_ctx->clone_of != NULL) {
			fput(other_file);
			return -EINVAL;
		}

		ctx->clone_of = other_ctx;
		fput(other_file);
		return 0;
	case EXMAP_IOCTL_STATS:
		return exmap_stats((struct exmap_ioctl_stats *)arg, ctx);
	case EXMAP_IOCTL_ACTION:
		if (unlikely(ctx->interfaces == NULL))
			return -EBADF;

		if (unlikely(!(atomic_read(&ctx->flags) & EXMAP_FLAGS_ACTIVE)))
			return -EPROTO;

		if( copy_from_user(&action, (struct exmap_action_params *) arg,
						   sizeof(struct exmap_action_params)) )
			return -EFAULT;

		if (unlikely(action.interface >= ctx->max_interfaces))
			return -EINVAL;

		if (action.opcode > ARRAY_SIZE(exmap_action_array)
			|| !exmap_action_array[action.opcode])
			return -EINVAL;

		mutex_lock(&(ctx->interfaces[action.interface].interface_lock));
		if (atomic_read(&ctx->flags) & EXMAP_FLAGS_ACTIVE)
			rc = exmap_action_array[action.opcode](ctx, &action);
		else
			rc = -EPROTO;
		mutex_unlock(&(ctx->interfaces[action.interface].interface_lock));
		break;
	default:
		return -EINVAL;
	}

	return rc;
}

static bool validate_surface(struct exmap_ctx *ctx, char __user* addr, ssize_t size) {
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
	return 0;
}

ssize_t exmap_read_iter(struct kiocb* kiocb, struct iov_iter *iter) {
	struct file *file = kiocb->ki_filp;
	struct exmap_ctx *ctx = exmap_from_file(file);
	unsigned int iface_id = kiocb->ki_pos & 0xff;
	unsigned int action   = (kiocb->ki_pos >> 8) & 0xff;
	struct exmap_interface *interface;
	ssize_t total_nr_pages;
	FREE_PAGES(free_pages);

	int rc = 0, rc_all = 0;

	if (action != EXMAP_OP_READ && action != EXMAP_OP_ALLOC) {
		pr_info("invalid action: id:%d action:%d (%llx)", iface_id, action, kiocb->ki_pos);
		return -EINVAL;
	}

	if (iface_id >= ctx->max_interfaces) {
		pr_info("max interfaces");
		return -EINVAL;
	}

	interface = &ctx->interfaces[iface_id];
	mutex_lock(&(interface->interface_lock));
	if (!(atomic_read(&ctx->flags) & EXMAP_FLAGS_ACTIVE)) {
		rc_all = -EPROTO;
		goto out;
	}

	if (action == EXMAP_OP_READ) {
		if (!ctx->file_backend) {
			pr_info("file backend??");
			rc_all = -EINVAL; goto out;
		}
		if (!ctx->file_backend->f_op) {
			pr_info("f_op iter??");
			rc_all = -EINVAL; goto out;
		}
		if (!ctx->file_backend->f_op->read_iter) {
			pr_info("read iter??");
			rc_all = -EINVAL; goto out;
		}
	}

	// Iterate over IO Vector. Allocate and then read
	kiocb->ki_filp = ctx->file_backend;

	total_nr_pages = iov_iter_count(iter) >> PAGE_SHIFT;

	free_pages.ctx = ctx;
	free_pages.bundle = &interface->local_pages;
	/* assume we have enough free pages somewhere */
	free_pages.count = total_nr_pages;
	while (iov_iter_count(iter)) {
		char __user *addr; ssize_t size;
		loff_t  disk_offset;
		unsigned pages_before, pages_after, pages_should;
		struct iov_iter_state iter_state;
		if (iter_is_ubuf(iter)) {
			addr = iter->ubuf;
			size = iov_iter_count(iter);
		} else {
			BUG_ON(!iter_is_iovec(iter));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
			addr = iter_iov_addr(iter);
			size = iter_iov_len(iter);
#else
			struct iovec iovec;
			iovec = iov_iter_iovec(iter);
			addr = iovec.iov_base;
			size = iovec.iov_len;
#endif
		}

		disk_offset = (uintptr_t)addr - ctx->exmap_vma->vm_start;
		pages_should = size >> PAGE_SHIFT;

		//pr_info("exmap: read  @ interface %d: %lu+%lu pages\n", interface - ctx->interfaces,
		//		disk_offset, pages_should);

		// Validate that the IO Vector is in our exmap range
		rc = validate_surface(ctx, addr, size);
		if (rc < 0) { rc_all = rc; goto out; }

		BUG_ON(free_pages.count < pages_should);

		// Insert memory in that range
		pages_before = free_pages.count;
		rc = exmap_insert_pages(ctx->exmap_vma, (uintptr_t) addr,
								pages_should, &free_pages, NULL,NULL);
		pages_after = free_pages.count;
		if (rc < 0) {
			pr_info("exmap: insert failed with: %d\n", rc);
			break;
		}

		if ((pages_before - pages_after) != pages_should) {
			//pr_info("error: did not insert new pages at %d\n",
			//	disk_offset >> PAGE_SHIFT);
			break;
		}

		if (action == EXMAP_OP_READ) {
			kiocb->ki_pos = disk_offset;
			iov_iter_save_state(iter, &iter_state);
			iov_iter_truncate(iter, size);
			rc = call_read_iter(ctx->file_backend, kiocb, iter);
			iov_iter_restore(iter, &iter_state);
			if (rc == -EIOCBQUEUED) {
				rc_all = rc;
				break;
			} else if (rc < 0) {
				pr_info("exmap: read failed with: %d (%lld)\n", rc,
						disk_offset >> PAGE_SHIFT);
				rc = exmap_unmap_pages(ctx->exmap_vma, (uintptr_t) addr, size, &free_pages);
				if (rc < 0) rc_all = rc;
				break;
			}
		} else { // Only allocate memory
			rc = size;
		}

		// rc is the (positive) number of bytes;
		rc_all += rc;

		iov_iter_advance(iter, size);
	}

out:

	// Restore kiocb (FIXME: This was necessary at some point, but it provokes weirdest bugs)
	// kiocb->ki_filp = file;
	mutex_unlock(&(interface->interface_lock));

	return rc_all;
}
// We require at least 6.1 as we want uring cmds with fixed buffer
// support.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
int exmap_uring_cmd(struct io_uring_cmd *ioucmd, unsigned int issue_flags) {
	int rc = -EINVAL;
	struct file *file = ioucmd->file;
	struct exmap_ctx *ctx = exmap_from_file(file);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	struct exmap_uring_cmd *cmd = (struct exmap_uring_cmd *)io_uring_sqe_cmd(ioucmd->sqe);
#else
	struct exmap_uring_cmd *cmd = (struct exmap_uring_cmd *)ioucmd->cmd;
#endif
	unsigned int iface_id = ioucmd->cmd_op & 0xff;
	unsigned int action = (ioucmd->cmd_op >> 8) & 0xff;
	struct exmap_interface *interface = &(ctx->interfaces[iface_id]);
	struct exmap_iov *ivec, ivec_stack;

	unsigned ivec_len = 0;

	if (iface_id >= ctx->max_interfaces) {
		pr_info("max: %d", iface_id);
		return -EINVAL;
	}

	if (ioucmd->flags & IORING_URING_CMD_FIXED) {
		struct iov_iter iter;
		const struct bio_vec *bvec;
		rc = io_uring_cmd_import_fixed((u64)cmd->iov.iov_base, cmd->iov.iov_len, true, &iter, ioucmd);
		if (rc < 0) {
			pr_info("import_fixed failed: iov: %lx-%ld rc=%d", (uintptr_t)cmd->iov.iov_base, cmd->iov.iov_len,
					rc);
			return rc;
		}
		BUG_ON(!iov_iter_is_bvec(&iter));
		if (iter.nr_segs > 1) {
			pr_info("nr_segs: %d", iface_id);
			return -EINVAL;
		}
		bvec = &(iter.bvec[0]);
		ivec = page_to_virt(bvec->bv_page) + bvec->bv_offset;
		ivec_len = bvec->bv_len / sizeof(struct exmap_iov);
	} else {
		rc = validate_surface(ctx, cmd->iov.iov_base, cmd->iov.iov_len);
		if (rc < 0) return rc;

		ivec_stack.page = (uintptr_t)(cmd->iov.iov_base - ctx->exmap_vma->vm_start) >> PAGE_SHIFT;
		ivec_stack.len  = cmd->iov.iov_len >> PAGE_SHIFT;
		ivec = &ivec_stack;
		ivec_len = 1;
	}

	if (action == EXMAP_OP_ALLOC) {
		mutex_lock(&(interface->interface_lock));
		if (atomic_read(&ctx->flags) & EXMAP_FLAGS_ACTIVE)
			rc = exmap_alloc_from_ivec(ctx, interface, ivec, ivec_len, 0);
		else
			rc = -EPROTO;
		mutex_unlock(&(interface->interface_lock));
	}

	if (ivec == &ivec_stack) {
		if (ivec_stack.res < 0)
			rc = ivec_stack.res;
		else
			rc = ivec_stack.pages * PAGE_SIZE;
	}


	return rc;
}
#endif

static const struct file_operations exmap_fops = {
	.mmap = exmap_mmap,
	.open = open,
	.read_iter = exmap_read_iter,
	.release = release,
	.unlocked_ioctl = exmap_ioctl,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	.uring_cmd = exmap_uring_cmd
#endif
};


asmlinkage ssize_t sys_exmap_action(struct pt_regs *regs) {
	int rc = -EBADFD;
	int exmap_fd = regs->di;
	int opcode   = regs->si;
	int iface_id = regs->dx;
	int len      = regs->r10;
	struct file *file;
	struct exmap_ctx *ctx;
	struct exmap_action_params action;

	file = fget(exmap_fd);
	if (unlikely(!file))
		goto out_return;

	if (unlikely(file->f_op != &exmap_fops))
		goto out_fput;

	rc = -EINVAL;
	ctx = exmap_from_file(file);
	if (unlikely(!ctx || ctx->interfaces == NULL))
		goto out_fput;

	if (unlikely(iface_id >= ctx->max_interfaces))
		goto out_fput;

	if (unlikely(opcode > ARRAY_SIZE(exmap_action_array)
				 || !exmap_action_array[opcode]))
		goto out_fput;

	mutex_lock(&(ctx->interfaces[iface_id].interface_lock));
	action.interface = iface_id;
	action.iov_len   = len;
	action.opcode    = opcode;
	if (atomic_read(&ctx->flags) & EXMAP_FLAGS_ACTIVE)
		rc = exmap_action_array[opcode](ctx, &action);
	else
		rc = -EPROTO;
	mutex_unlock(&(ctx->interfaces[iface_id].interface_lock));

 out_fput:
	fput(file);

 out_return:
	return rc;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
static int dev_uevent_perms(const struct device *dev, struct kobj_uevent_env *env) {
	return add_uevent_var(env, "DEVMODE=%#o", 0666);
}
#else
static int dev_uevent_perms(struct device *dev, struct kobj_uevent_env *env) {
	return add_uevent_var(env, "DEVMODE=%#o", 0666);
}
#endif

static uintptr_t orig_syscall_400;


/* bit 16 (for the CR0 register) */
#define WP_MASK 0x10000
static inline void custom_write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");
}

static int exmap_init_module(void) {
	unsigned long cr0;

	if (exmap_acquire_ksyms())
		goto out;

	if (alloc_chrdev_region(&first, 0, 1, "exmap") < 0)
		goto out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	if ((cl = class_create("exmap")) == NULL)
		goto out_unregister_chrdev_region;
#else
	if ((cl = class_create(THIS_MODULE, "exmap")) == NULL)
		goto out_unregister_chrdev_region;
#endif
	cl->dev_uevent = dev_uevent_perms;
	if (device_create(cl, NULL, first, NULL, "exmap") == NULL)
		goto out_class_destroy;

	cdev_init(&cdev, &exmap_fops);
	if (cdev_add(&cdev, first, 1) == -1)
		goto out_device_destroy;

	/* disable write protection */
    cr0 = read_cr0();
    custom_write_cr0(cr0 & ~WP_MASK);

	orig_syscall_400 = sys_call_table_ptr[SYS_EXMAP_ACTION];
	sys_call_table_ptr[SYS_EXMAP_ACTION] = (uintptr_t) &sys_exmap_action;

	/* re-enable write protection */
    custom_write_cr0(cr0);

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
	unsigned long cr0;

	cdev_del(&cdev);
	device_destroy(cl, first);
	class_destroy(cl);
	unregister_chrdev_region(first, 1);

	/* disable write protection */
    cr0 = read_cr0();
    custom_write_cr0(cr0 & ~WP_MASK);

	// Restore syscall
	if (orig_syscall_400 && sys_call_table_ptr)
		sys_call_table_ptr[SYS_EXMAP_ACTION] = orig_syscall_400;

	/* re-enable write protection */
    custom_write_cr0(cr0);

	printk(KERN_INFO "exmap unregistered");
}

module_init(exmap_init_module)
module_exit(exmap_cleanup_module)
MODULE_LICENSE("GPL");
