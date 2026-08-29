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

static const char *const map_names[] = {
	"ca_config", "ca_mark_schema", "ca_subject_a", "ca_subject_b", "ca_policy_a",
	"ca_policy_b", "ca_port_a", "ca_port_b", "ca_ipv4_a", "ca_ipv4_b",
	"ca_ipv6_a", "ca_ipv6_b", "ca_flows",
	"ca_global_rate", "ca_subject_rates", "ca_runtime", "ca_stats",
};

bool ca_bpf_object_available(void)
{
	__u32 zero = 0, schema = 0;
	int fd = bpf_obj_get(CA_PROGRAM_PIN);

	if (fd < 0)
		return false;
	close(fd);
	fd = ca_bpf_open_map("ca_mark_schema");
	if (fd < 0)
		return false;
	if (bpf_map_lookup_elem(fd, &zero, &schema) ||
	    schema != CA_BPF_SCHEMA_VERSION) {
		close(fd);
		return false;
	}
	close(fd);
	for (size_t i = 0; i < ARRAY_SIZE(map_names); i++) {
		fd = ca_bpf_open_map(map_names[i]);
		if (fd < 0)
			return false;
		close(fd);
	}
	return true;
}

void ca_bpf_raise_memlock_limit(void)
{
	const struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &limit) && errno != EPERM)
		fprintf(stderr, "unable to raise memlock limit: %s\n", strerror(errno));
}

void ca_bpf_object_unlink(void)
{
	char path[PATH_MAX];

	unlink(CA_PROGRAM_PIN);
	for (size_t i = 0; i < ARRAY_SIZE(map_names); i++) {
		if (!ca_bpf_pin_path(path, sizeof(path), map_names[i]))
			unlink(path);
	}
}

static int ensure_pin_root(void)
{
	if (!mkdir(CA_PIN_ROOT, 0755) || errno == EEXIST)
		return 0;
	fprintf(stderr, "unable to create %s: %s\n", CA_PIN_ROOT, strerror(errno));
	return -1;
}

int ca_bpf_object_load(const char *path, bool replace)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts,
		.pin_root_path = CA_PIN_ROOT,
	);
	struct bpf_program *program;
	struct bpf_map *schema_map;
	struct bpf_object *object;
	bool available = ca_bpf_object_available();
	__u32 zero = 0, schema = CA_BPF_SCHEMA_VERSION;
	int err;

	if (!replace && available)
		return 0;
	if (ensure_pin_root())
		return 1;
	if (ca_bpf_tc_detach_all()) {
		fprintf(stderr, "refusing to replace BPF state while an owned TC filter remains attached\n");
		return 1;
	}
	/* Recover an unusable pin set by loading one complete current object. */
	ca_bpf_object_unlink();

	object = bpf_object__open_file(path, &open_opts);
	err = libbpf_get_error(object);
	if (err) {
		fprintf(stderr, "unable to open BPF object %s: %s\n", path, strerror(-err));
		return 1;
	}
	program = bpf_object__find_program_by_name(object, "ca_ingress");
	if (!program) {
		fprintf(stderr, "BPF object has no ca_ingress program\n");
		bpf_object__close(object);
		return 1;
	}
	bpf_program__set_type(program, BPF_PROG_TYPE_SCHED_CLS);
	err = bpf_object__load(object);
	if (err) {
		fprintf(stderr, "unable to load BPF object: %s\n", strerror(-err));
		bpf_object__close(object);
		return 1;
	}
	schema_map = bpf_object__find_map_by_name(object, "ca_mark_schema");
	if (!schema_map || bpf_map_update_elem(bpf_map__fd(schema_map), &zero,
					       &schema, BPF_ANY)) {
		fprintf(stderr, "unable to publish BPF schema version: %s\n",
			strerror(errno));
		bpf_object__close(object);
		ca_bpf_object_unlink();
		return 1;
	}
	unlink(CA_PROGRAM_PIN);
	err = bpf_program__pin(program, CA_PROGRAM_PIN);
	if (err)
		fprintf(stderr, "unable to pin BPF program: %s\n", strerror(-err));
	bpf_object__close(object);
	if (err)
		ca_bpf_object_unlink();
	return err ? 1 : 0;
}


