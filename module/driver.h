#pragma once

#include <linux/mm.h>
#include <linux/list.h>
#include <linux/mmu_notifier.h>

#include "config.h"
#include "linux/exmap.h"
#include "../memory_pool/memory_pool.h"


struct iface_count {
	unsigned a; // alloc
	unsigned r; // read
	unsigned e; // evict
#ifndef USE_GLOBAL_FREE_LIST
	unsigned s; // steal
	unsigned p; // steal (pages)
#endif
};

struct exmap_ctx {
	struct exmap_ctx *clone_of;

	size_t buffer_size;
	atomic_t alloc_count;

	/* Only used for accounting purposes */
	struct user_struct		*user;
	struct mm_struct		*mm_account;

	/* Here is the main buffer located */
	struct vm_area_struct *exmap_vma;

	/* Here is the ptexport buffer located */
	struct vm_area_struct *ptexport_vma;

	/* The baking storage */
	struct file *file_backend;
	struct block_device *bdev;

	/* Interfaces are memory mapped areas where the kernel can communicate with the user */
	atomic_t    flags;
	int    max_interfaces;
	struct exmap_interface *interfaces;

/* #ifdef USE_GLOBAL_FREE_LIST */
/* 	struct exmap_llist_head global_free_list; */
/* #endif */
	struct memory_pool_ctx* memory_pool;

	struct mmu_notifier mmu_notifier;
};
#ifdef USE_GLOBAL_FREE_LIST
struct free_pages {
	struct exmap_ctx *ctx;
	/* struct exmap_interface *interface; */
	struct page_bundle* bundle;
	long count;
};
#define FREE_PAGES_INIT(name) {.ctx = NULL, .bundle = NULL, .count = 0}

/* struct page_bundle { */
/* 	struct page* stack; */
/* 	unsigned long count; */
/* }; */
/* void push_page(struct page* page, struct page_bundle* bundle, struct exmap_ctx* ctx); */
/* struct page* pop_page(struct page_bundle* bundle, struct exmap_ctx* ctx); */

#else
struct free_pages {
	spinlock_t       lock;
	struct list_head list;
	unsigned long    count;
};

#define FREE_PAGES_INIT(name) {.list = LIST_HEAD_INIT(name.list), .count = 0}
static inline void free_pages_init(struct free_pages *fp) {
	spin_lock_init(&fp->lock);
	fp->count = 0;
	INIT_LIST_HEAD(&fp->list);
}
#endif

#define FREE_PAGES(name)							\
	struct free_pages name = FREE_PAGES_INIT(name)
struct exmap_interface {
	struct mutex		interface_lock;

	/* alloc/read/evict/.. counters */
	struct iface_count count;

	// Page(s) that are shared with userspace
	struct exmap_user_interface *usermem;

#ifdef USE_GLOBAL_FREE_LIST
	// Interface-local bundle of free pages
	struct page_bundle local_pages;
#else
	/* default page steal target (interface) */
	unsigned int steal_target;
	// Interface-local free page lock
	struct free_pages free_pages;
#endif

	// Temporary storage used during operations
	union {
		struct {
			// We pre-allocate as many bios, as we would have
			// exmap_iovs to support scattered single-read pages
			struct bio     bio[EXMAP_USER_INTERFACE_PAGES];
			// We pre-allocate as many bio_vecs as one exmap_iov has in length.
			// Please note: that we would need EXMAP_PAGE_MAX_PAGES/2 structs bio
			//              to read one sparsely populated area of pages
			struct bio_vec bio_vecs[EXMAP_PAGE_MAX_PAGES];
		};
	};
};


struct exmap_alloc_ctx;

typedef int (*exmap_insert_callback)(struct exmap_alloc_ctx *, unsigned long, struct page *);

struct page* exmap_alloc_page_system(void);

int exmap_insert_pages(struct vm_area_struct *vma,
					   unsigned long addr, unsigned long num_pages,
					   struct free_pages *pages,
					   exmap_insert_callback cb, struct exmap_alloc_ctx *data);

int exmap_unmap_pages(struct vm_area_struct *vma,
					  unsigned long addr, unsigned long num_pages,
					  struct free_pages *pages);

pmd_t * exmap_walk_to_pmd(struct vm_area_struct *vma,
						  unsigned long addr);

// #define exmap_debug(...) pr_info("exmap:" __VA_ARGS__)
#define exmap_debug(...) 

