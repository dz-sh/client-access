// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpfctl-internal.h"

static void usage(FILE *out)
{
	fprintf(out,
		"usage: client-access-bpfctl COMMAND [ARGS]\\n"
		"  ensure [object]        load and pin the datapath if absent\\n"
		"  load [object]          replace the pinned datapath\\n"
		"  disable                make every attached instance pass packets\\n"
		"  unload                 remove this application's pinned objects\\n"
		"  attach IFNAME          attach the pinned program at TC ingress\\n"
		"  detach IFNAME          detach this application's TC ingress filter\\n"
		"  prune [IFNAME ...]     keep owned filters only on listed interfaces\\n"
		"  sync                   validate stdin snapshot and atomically publish it\\n"
		"  gc [IDLE_SECONDS]      expire idle cached flows\\n"
		"  generations            print policy and classifier generation floors\\n"
		"  health POLICY CLASSIFIER IFNAME [IFNAME ...]\\n"
		"                         verify enabled generations and attachments\\n"
		"  status                 print runtime state and counters as JSON\\n");
}

static int parse_u32_argument(const char *text, __u32 *value)
{
	char *end;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || *end || parsed > UINT32_MAX)
		return -1;
	*value = (__u32)parsed;
	return 0;
}

static int with_object_lock(const char *path, bool replace)
{
	int lock_fd = ca_bpf_update_lock();
	int ret;

	if (lock_fd < 0)
		return 1;
	ret = ca_bpf_object_load(path, replace);
	close(lock_fd);
	return ret;
}

static int unload_backend(void)
{
	int lock_fd = ca_bpf_update_lock();
	int ret;

	if (lock_fd < 0)
		return 1;
	ret = ca_bpf_backend_disable_unlocked();
	if (!ret)
		ret = ca_bpf_tc_detach_all();
	if (!ret)
		ca_bpf_object_unlink();
	close(lock_fd);
	return ret;
}

static int with_tc_lock(const char *ifname, bool attach)
{
	int lock_fd = ca_bpf_update_lock();
	int ret;

	if (lock_fd < 0)
		return 1;
	ret = ca_bpf_tc_action(ifname, attach);
	close(lock_fd);
	return ret;
}

static int prune_with_lock(int keep_count, char **keep_names)
{
	int lock_fd = ca_bpf_update_lock();
	int ret;

	if (lock_fd < 0)
		return 1;
	ret = ca_bpf_tc_prune(keep_count, keep_names);
	close(lock_fd);
	return ret;
}

static int health_with_lock(__u32 policy_generation, __u32 classifier_generation,
			    int interface_count, char **interfaces)
{
	int lock_fd = ca_bpf_update_lock();
	int ret;

	if (lock_fd < 0)
		return 1;
	ret = ca_bpf_verify_health(policy_generation, classifier_generation,
				   interface_count, interfaces);
	if (!ret)
		ret = ca_bpf_print_status();
	close(lock_fd);
	return ret;
}

static int simple_with_lock(int (*operation)(void))
{
	int lock_fd = ca_bpf_update_lock();
	int ret;

	if (lock_fd < 0)
		return 1;
	ret = operation();
	close(lock_fd);
	return ret;
}

static int gc_with_lock(unsigned long idle)
{
	int lock_fd = ca_bpf_update_lock();
	int ret;

	if (lock_fd < 0)
		return 1;
	ret = ca_bpf_gc_flows(idle);
	close(lock_fd);
	return ret;
}

int main(int argc, char **argv)
{
	const char *object = argc > 2 ? argv[2] : CA_BPF_DEFAULT_OBJECT;
	unsigned long idle = 300;

	if (argc < 2) {
		usage(stderr);
		return 2;
	}
	if (!strcmp(argv[1], "ensure")) {
		ca_bpf_raise_memlock_limit();
		return with_object_lock(object, false);
	}
	if (!strcmp(argv[1], "load")) {
		ca_bpf_raise_memlock_limit();
		return with_object_lock(object, true);
	}
	if (!strcmp(argv[1], "disable") && argc == 2)
		return ca_bpf_backend_disable();
	if (!strcmp(argv[1], "unload"))
		return unload_backend();
	if (!strcmp(argv[1], "attach") && argc == 3)
		return with_tc_lock(argv[2], true);
	if (!strcmp(argv[1], "detach") && argc == 3)
		return with_tc_lock(argv[2], false);
	if (!strcmp(argv[1], "prune"))
		return prune_with_lock(argc - 2, argv + 2);
	if (!strcmp(argv[1], "sync") && argc == 2)
		return ca_bpf_snapshot_sync();
	if (!strcmp(argv[1], "generations") && argc == 2)
		return simple_with_lock(ca_bpf_print_generations);
	if (!strcmp(argv[1], "health") && argc >= 5) {
		__u32 policy_generation, classifier_generation;

		if (parse_u32_argument(argv[2], &policy_generation) ||
		    parse_u32_argument(argv[3], &classifier_generation)) {
			fprintf(stderr, "health generations must be unsigned 32-bit integers\\n");
			return 2;
		}
		return health_with_lock(policy_generation, classifier_generation,
					argc - 4, argv + 4);
	}
	if (!strcmp(argv[1], "status") && argc == 2)
		return simple_with_lock(ca_bpf_print_status);
	if (!strcmp(argv[1], "gc")) {
		if (argc == 3) {
			char *end;

			errno = 0;
			idle = strtoul(argv[2], &end, 10);
			if (errno || *end || idle < 1 || idle > 86400) {
				fprintf(stderr, "IDLE_SECONDS must be from 1 to 86400\\n");
				return 2;
			}
		}
		else if (argc != 2)
			return 2;
		return gc_with_lock(idle);
	}
	usage(stderr);
	return 2;
}
