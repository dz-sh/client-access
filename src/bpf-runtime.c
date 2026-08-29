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

int ca_bpf_backend_disable_unlocked(void)
{
	struct ca_config config = {};
	__u32 zero = 0;
	int fd;
	int ret = 0;

	fd = ca_bpf_open_map("ca_config");
	if (fd < 0)
		ret = errno == ENOENT ? 0 : 1;
	if (fd < 0)
		goto out;
	if (ca_bpf_lookup_config(fd, &config)) {
		if (errno != ENOENT)
			ret = 1;
	}
	else {
		config.enabled = 0;
		if (bpf_map_update_elem(fd, &zero, &config, BPF_ANY | BPF_F_LOCK))
			ret = 1;
	}
	if (ret)
		fprintf(stderr, "unable to disable application BPF state: %s\n", strerror(errno));
out:
	if (fd >= 0)
		close(fd);
	return ret;
}

int ca_bpf_backend_disable(void)
{
	int lock_fd = ca_bpf_update_lock();
	int ret;

	if (lock_fd < 0)
		return 1;
	ret = ca_bpf_backend_disable_unlocked();
	close(lock_fd);
	return ret;
}

int ca_bpf_print_generations(void)
{
	struct ca_config config = {};
	int fd = ca_bpf_open_map("ca_config");

	if (fd < 0 || ca_bpf_lookup_config(fd, &config)) {
		if (fd >= 0)
			close(fd);
		fprintf(stderr, "application BPF config map is unavailable\n");
		return 1;
	}
	close(fd);
	printf("%u %u\n", config.app_policy_generation,
	       config.classifier_generation);
	return 0;
}

int ca_bpf_gc_flows(unsigned long idle_seconds)
{
	struct ca_flow_key key, next;
	struct ca_flow_state state;
	struct timespec now;
	int fd, removed = 0;
	__u64 cutoff;

	fd = ca_bpf_open_map("ca_flows");
	if (fd < 0) {
		fprintf(stderr, "flow map is unavailable: %s\n", strerror(errno));
		return 1;
	}
	if (clock_gettime(CLOCK_MONOTONIC, &now)) {
		fprintf(stderr, "unable to read monotonic clock: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	cutoff = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec;
	cutoff = cutoff > idle_seconds * 1000000000ULL
		? cutoff - idle_seconds * 1000000000ULL : 0;
	if (bpf_map_get_next_key(fd, NULL, &key))
		goto done;
	for (;;) {
		bool have_next = !bpf_map_get_next_key(fd, &key, &next);

		if (!bpf_map_lookup_elem(fd, &key, &state) && state.last_seen_ns < cutoff) {
			if (!bpf_map_delete_elem(fd, &key))
				removed++;
		}
		if (!have_next)
			break;
		key = next;
	}
done:
	close(fd);
	printf("{\"removed\":%d}\n", removed);
	return 0;
}


