#pragma once
#include <asm/ioctl.h>

#include "../exmap_common.h"

struct exmap_ioctl_setup {
	int    fd;
	int    max_interfaces;
	size_t buffer_size;
	uint64_t flags;
};

#define EXMAP_IOCTL_SETUP _IOC(_IOC_WRITE, 'k', 1, sizeof(struct exmap_ioctl_setup))





enum exmap_opcode {
	EXMAP_OP_READ   = 0,
	EXMAP_OP_ALLOC  = 1,
	EXMAP_OP_FREE   = 2,
	EXMAP_OP_WRITE  = 3,
};

enum exmap_flags {
	// When allocating memory, we only look at the first element, and
	// if that is currently mapped, we skip that exmap_iov
	EXMAP_ALLOC_PROBE  = 1, // Not implemented yet(!); If the first page of a vector is mapped, return immediately
};
typedef enum exmap_flags exmap_flags;

struct exmap_action_params {
	uint16_t interface;
	uint16_t iov_len;
	uint16_t opcode; // exmap_opcode
	uint64_t flags;  // exmap_flags
};

#define EXMAP_IOCTL_ACTION _IOC(_IOC_WRITE, 'k', 2, sizeof(struct exmap_action_params))


#define EXMAP_OFF_EXMAP       0x0000
#define EXMAP_OFF_INTERFACE_BASE 0xe000000000000000UL
#define EXMAP_OFF_INTERFACE_MAX  0xf000000000000000UL
#define EXMAP_OFF_INTERFACE(n) (EXMAP_OFF_INTERFACE_BASE | (n << 12LL))

#ifndef EXMAP_IN_KERNEL

#include <sys/ioctl.h>

int exmap_action(int fd, struct exmap_action_params *params) {
	return ioctl(fd, EXMAP_IOCTL_ACTION, params);
}

#endif
