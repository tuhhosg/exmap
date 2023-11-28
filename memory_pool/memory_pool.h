#pragma once
#include <asm/ioctl.h>
#include <linux/types.h>


struct page_bundle {
	struct page* stack;
	unsigned long count;
};

enum memory_pool_flags {
	BACKING_VM_CONTIGUOUS = (1 << 0),
};
typedef enum memory_pool_flags memory_pool_flags;
struct memory_pool_setup {
	size_t pool_size;
	memory_pool_flags flags;
};

struct bundle_list_head {
	struct page *first;
};

struct memory_pool_ctx {
	size_t pool_size;

	memory_pool_flags flags;
	/* start address, for contiguous pools */
	unsigned long start;

	/*
	 * One "helper" bundle to push pages into
	 * when full. The contents of this bundle are moved
	 * to the pool bundle_list
	 */
	struct page_bundle pool_bundle;

	/*
	 * The bundle list contains, as the name implies,
	 * bundles of free pages.
	 * Specifically, it contains single struct page*s, whose underlying
	 * memory is sequentially filled with 512 addresses of further free pages.
	 * See also: <struct page_bundle>
	 */
	struct bundle_list_head bundle_list;

	/* Only used for accounting purposes */
	struct user_struct		*user;
	struct mm_struct		*mm_account;
};

struct memory_pool_ctx* memory_pool_create(struct memory_pool_setup* setup);
void memory_pool_destroy(struct memory_pool_ctx* ctx);

struct page* pop_page(struct page_bundle* bundle, struct memory_pool_ctx* ctx);
void push_page(struct page* page, struct page_bundle* bundle, struct memory_pool_ctx* ctx);

unsigned free_page_bundle(struct page* bundle_page, unsigned count);
