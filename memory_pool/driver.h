#pragma once

#include <linux/mm.h>
#include <linux/list.h>

#include "config.h"
#include "../memory_pool/memory_pool.h"


/* struct iface_count { */
/* 	unsigned a; // alloc */
/* 	unsigned r; // read */
/* 	unsigned e; // evict */
/* }; */

struct free_pages {
	struct exmap_ctx *ctx;
	/* struct exmap_interface *interface; */
	struct page_bundle* bundle;
	long count;
};
#define FREE_PAGES_INIT(name) {.ctx = NULL, .bundle = NULL, .count = 0}

/* void push_page(struct page* page, struct page_bundle* bundle, struct memory_pool_ctx* ctx); */
/* struct page* pop_page(struct page_bundle* bundle, struct exmap_ctx* ctx); */


/* #define FREE_PAGES(name)							\ */
/* 	struct free_pages name = FREE_PAGES_INIT(name) */
/* struct exmap_interface { */
/* 	struct mutex		interface_lock; */

/* 	/\* alloc/read/evict/.. counters *\/ */
/* 	struct iface_count count; */

/* 	// Page(s) that are shared with userspace */
/* 	struct exmap_user_interface *usermem; */

/* 	// Interface-local bundle of free pages */
/* 	struct page_bundle local_pages; */

/* 	// Temporary storage used during operations */
/* 	union { */
/* 		struct { */
/* 			// We pre-allocate as many bios, as we would have */
/* 			// exmap_iovs to support scattered single-read pages */
/* 			struct bio     bio[EXMAP_USER_INTERFACE_PAGES]; */
/* 			// We pre-allocate as many bio_vecs as one exmap_iov has in length. */
/* 			// Please note: that we would need EXMAP_PAGE_MAX_PAGES/2 structs bio */
/* 			//              to read one sparsely populated area of pages */
/* 			struct bio_vec bio_vecs[EXMAP_PAGE_MAX_PAGES]; */
/* 		}; */
/* 	}; */
/* }; */


/* struct exmap_alloc_ctx; */

/* typedef int (*exmap_insert_callback)(struct exmap_alloc_ctx *, unsigned long, struct page *); */

struct page* exmap_alloc_page_system(void);

/* int exmap_insert_pages(struct vm_area_struct *vma, */
/* 					   unsigned long addr, unsigned long num_pages, */
/* 					   struct free_pages *pages, */
/* 					   exmap_insert_callback cb, struct exmap_alloc_ctx *data); */

/* int exmap_unmap_pages(struct vm_area_struct *vma, */
/* 					  unsigned long addr, unsigned long num_pages, */
/* 					  struct free_pages *pages); */

/* pmd_t * exmap_walk_to_pmd(struct vm_area_struct *vma, */
/* 						  unsigned long addr); */

// #define exmap_debug(...) pr_info("exmap:" __VA_ARGS__)
#define exmap_debug(...) 

