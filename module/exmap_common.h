#pragma once

#include <linux/types.h>

struct exmap_action_params {
	uint16_t interface;
	uint16_t iov_len;
	uint16_t opcode; // exmap_opcode
	uint64_t flags;  // exmap_flags
};

#define EXMAP_IOCTL_ACTION _IOC(_IOC_WRITE, 'k', 2, sizeof(struct exmap_action_params))
