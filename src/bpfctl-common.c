// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpfctl-internal.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

int ca_bpf_pin_path(char *buf, size_t len, const char *name)
{
	int ret = snprintf(buf, len, "%s/%s", CA_PIN_ROOT, name);

	return ret < 0 || (size_t)ret >= len ? -ENAMETOOLONG : 0;
}

int ca_bpf_open_map(const char *name)
{
	char path[PATH_MAX];

	if (ca_bpf_pin_path(path, sizeof(path), name))
		return -1;
	return bpf_obj_get(path);
}

int ca_bpf_lookup_config(int fd, struct ca_config *config)
{
	__u32 zero = 0;

	/* ca_config contains a top-level bpf_spin_lock. BPF_F_LOCK is mandatory
	 * for userspace lookups so every controller command observes the same
	 * coherent record used by the packet datapath.
	 */
	return bpf_map_lookup_elem_flags(fd, &zero, config, BPF_F_LOCK);
}

int ca_bpf_update_lock(void)
{
	int fd = open(CA_BPF_UPDATE_LOCK, O_CREAT | O_CLOEXEC | O_RDWR, 0600);

	if (fd < 0 || flock(fd, LOCK_EX)) {
		fprintf(stderr, "unable to lock application BPF state: %s\n",
			strerror(errno));
		if (fd >= 0)
			close(fd);
		return -1;
	}
	return fd;
}

