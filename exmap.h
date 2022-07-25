#pragma once

#include <linux/mm.h>
#include <linux/list.h>

#include "exmap_common.h"

/* struct free_pages { */
/* 	spinlock_t       lock; */
/* 	struct list_head list; */
/* 	unsigned long    count; */
/* }; */

/* #define FREE_PAGES_INIT(name) {.list = LIST_HEAD_INIT(name.list), .count = 0} */
/* #define FREE_PAGES(name)							\ */
/* 	struct free_pages name = FREE_PAGES_INIT(name) */

/* static inline void free_pages_init(struct free_pages *fp) { */
/* 	spin_lock_init(&fp->lock); */
/* 	fp->count = 0; */
/* 	INIT_LIST_HEAD(&fp->list); */
/* } */

struct page_bundle {
	struct page* stack;
	unsigned long count;
};

struct iface_count {
	unsigned a; // alloc
	unsigned r; // read
	unsigned e; // evict
	unsigned s; // steal
	unsigned p; // steal (pages)
};


struct exmap_interface {
	struct mutex		interface_lock;

	/* alloc/read/evict/.. counters */
	struct iface_count count;
	/* default page steal target (interface) */
	unsigned int steal_target;

	// Page(s) that are shared with userspace
	struct exmap_user_interface *usermem;

	// Interface-local free page lock
	/* struct free_pages free_pages; */
	struct page_bundle local_pages;

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
struct exmap_ctx;

struct exmap_TODORENAME_ctx {
	struct exmap_ctx *ctx;
	struct exmap_interface *interface;
	unsigned long pages_count;
};

void push_page(struct page* page, struct page_bundle* bundle, struct exmap_ctx* ctx);
struct page* pop_page(struct page_bundle* bundle, struct exmap_ctx* ctx);

struct exmap_alloc_ctx;

typedef int (*exmap_insert_callback)(struct exmap_alloc_ctx *, unsigned long, struct page *);

int exmap_insert_pages(struct vm_area_struct *vma,
					   unsigned long addr, unsigned long num_pages,
					   struct exmap_TODORENAME_ctx* ctx,
					   /* struct free_pages *pages, */
					   exmap_insert_callback cb, struct exmap_alloc_ctx *data);

struct exmap_interface;
int exmap_unmap_pages(struct vm_area_struct *vma,
					  unsigned long addr, unsigned long num_pages,
					  struct exmap_TODORENAME_ctx* ctx);
					  /* struct free_pages *pages); */

// #define exmap_debug(...) pr_info("exmap:" __VA_ARGS__)
#define exmap_debug(...) 

