#ifndef COMMON_H_
#define COMMON_H_

#include "linux/types.h"


#define STATIC_ASSERT(COND,MSG) typedef char static_assertion_##MSG[(!!(COND))*2-1]

// Maximum Range of exmap_page.len
#define EXMAP_PAGE_LEN_BITS 12
#define EXMAP_PAGE_MAX_PAGES (1 << EXMAP_PAGE_LEN_BITS)

#define EXMAP_USER_INTERFACE_PAGES 512

struct exmap_iov {
	union {
		uint64_t value;
		struct {
			uint64_t page   : 64 - EXMAP_PAGE_LEN_BITS;
			uint64_t len    : EXMAP_PAGE_LEN_BITS;
		};
		struct {
			int32_t   res;
			int16_t   pages;
		};
		struct {
			int16_t victim;
			int16_t robber;
			uint32_t count;
		};
	};
};

STATIC_ASSERT(sizeof(struct exmap_iov) == 8, exmap_iov);
struct exmap_user_interface {
	union {
		struct exmap_iov iov[EXMAP_USER_INTERFACE_PAGES];
	};
};


STATIC_ASSERT(sizeof(struct exmap_user_interface) == 4096, exmap_user_interface);
#endif // COMMON_H_
