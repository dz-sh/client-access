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

int ca_bpf_program_id_from_fd(int fd, __u32 *id)
{
	struct bpf_prog_info info = {};
	__u32 size = sizeof(info);

	if (bpf_prog_get_info_by_fd(fd, &info, &size))
		return -errno;
	*id = info.id;
	return 0;
}

int ca_bpf_tc_query_program(unsigned int ifindex, __u32 handle, __u32 priority,
			    __u32 *program_id)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
		.ifindex = ifindex,
		.attach_point = BPF_TC_INGRESS,
	);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
		.handle = handle,
		.priority = priority,
	);
	int err = bpf_tc_query(&hook, &opts);

	if (!err)
		*program_id = opts.prog_id;
	return err;
}

static bool tc_query_absent(int err)
{
	/* Some kernels report a missing TC filter chain as EINVAL rather than
	 * ENOENT. The hook and coordinates passed by this controller are fixed and
	 * valid, so both results mean that our coordinate is currently empty.
	 */
	return err == -ENOENT || err == -EINVAL;
}

static bool keep_interface(const char *ifname, int keep_count, char **keep_names)
{
	for (int i = 0; i < keep_count; i++)
		if (!strcmp(ifname, keep_names[i]))
			return true;
	return false;
}

int ca_bpf_tc_verify_program_interfaces(__u32 program_id, int keep_count,
				     char **keep_names)
{
	static const struct {
		__u32 handle;
		__u32 priority;
	} coordinates[] = {
		{ CA_TC_HANDLE, CA_TC_PRIORITY },
		{ 1, 1 },
	};
	struct if_nameindex *interfaces = if_nameindex();
	int ret = 1;

	if (!interfaces) {
		fprintf(stderr, "unable to enumerate interfaces: %s\n", strerror(errno));
		return 1;
	}
	for (struct if_nameindex *entry = interfaces; entry->if_index; entry++) {
		for (size_t i = 0; i < ARRAY_SIZE(coordinates); i++) {
			__u32 attached_id = 0;
			int err = ca_bpf_tc_query_program(entry->if_index, coordinates[i].handle,
						   coordinates[i].priority, &attached_id);

			if (tc_query_absent(err))
				continue;
			if (err) {
				fprintf(stderr, "unable to inspect TC attachment on %s: %s\n",
					entry->if_name, strerror(-err));
				goto out;
			}
			if (attached_id != program_id)
				continue;
			if (i == 0 && keep_interface(entry->if_name, keep_count, keep_names))
				continue;
			fprintf(stderr, "unexpected owned TC attachment on %s\n",
				entry->if_name);
			goto out;
		}
	}
	ret = 0;
out:
	if_freenameindex(interfaces);
	return ret;
}

static int detach_program_from_interfaces(__u32 program_id, int keep_count,
					  char **keep_names)
{
	static const struct {
		__u32 handle;
		__u32 priority;
	} coordinates[] = {
		{ CA_TC_HANDLE, CA_TC_PRIORITY },
		/* Remove filters left by the pre-schema-version implementation. */
		{ 1, 1 },
	};
	struct if_nameindex *interfaces = if_nameindex();
	int failures = 0;

	if (!interfaces) {
		fprintf(stderr, "unable to enumerate interfaces: %s\n", strerror(errno));
		return 1;
	}
	for (struct if_nameindex *entry = interfaces; entry->if_index; entry++) {
		for (size_t i = 0; i < ARRAY_SIZE(coordinates); i++) {
			DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
				.ifindex = entry->if_index,
				.attach_point = BPF_TC_INGRESS,
			);
			DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
				.handle = coordinates[i].handle,
				.priority = coordinates[i].priority,
			);
			__u32 attached_id = 0;
			int err = ca_bpf_tc_query_program(entry->if_index, opts.handle,
						   opts.priority, &attached_id);

			if (tc_query_absent(err))
				continue;
			if (err) {
				fprintf(stderr, "unable to inspect TC attachment on %s: %s\n",
					entry->if_name, strerror(-err));
				failures++;
				continue;
			}
			if (attached_id != program_id)
				continue;
			if (coordinates[i].handle == CA_TC_HANDLE &&
			    coordinates[i].priority == CA_TC_PRIORITY &&
			    keep_interface(entry->if_name, keep_count, keep_names))
				continue;
			err = bpf_tc_detach(&hook, &opts);
			if (err && err != -ENOENT) {
				fprintf(stderr, "unable to detach owned TC program from %s: %s\n",
					entry->if_name, strerror(-err));
				failures++;
			}
		}
	}
	if_freenameindex(interfaces);
	return failures ? 1 : 0;
}

int ca_bpf_tc_prune(int keep_count, char **keep_names)
{
	__u32 program_id;
	int fd = bpf_obj_get(CA_PROGRAM_PIN);
	int ret;

	for (int i = 0; i < keep_count; i++) {
		if (!if_nametoindex(keep_names[i])) {
			fprintf(stderr, "unknown keep interface %s\n", keep_names[i]);
			return 1;
		}
	}
	if (fd < 0)
		return errno == ENOENT ? 0 : 1;
	ret = ca_bpf_program_id_from_fd(fd, &program_id);
	close(fd);
	if (ret) {
		fprintf(stderr, "unable to identify pinned BPF program: %s\n",
			strerror(-ret));
		return 1;
	}
	return detach_program_from_interfaces(program_id, keep_count, keep_names);
}

int ca_bpf_tc_detach_all(void)
{
	return ca_bpf_tc_prune(0, NULL);
}

int ca_bpf_tc_action(const char *ifname, bool attach)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
		.attach_point = BPF_TC_INGRESS,
	);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
		.handle = CA_TC_HANDLE,
		.priority = CA_TC_PRIORITY,
	);
	__u32 attached_id = 0, program_id = 0;
	int program_fd, err;

	hook.ifindex = if_nametoindex(ifname);
	if (!hook.ifindex) {
		fprintf(stderr, "unknown interface %s\n", ifname);
		return 1;
	}
	program_fd = bpf_obj_get(CA_PROGRAM_PIN);
	if (program_fd < 0) {
		fprintf(stderr, "pinned BPF program is unavailable: %s\n", strerror(errno));
		return 1;
	}
	err = ca_bpf_program_id_from_fd(program_fd, &program_id);
	if (err) {
		fprintf(stderr, "unable to identify pinned BPF program: %s\n",
			strerror(-err));
		close(program_fd);
		return 1;
	}
	if (!attach) {
		err = ca_bpf_tc_query_program(hook.ifindex, opts.handle, opts.priority,
				       &attached_id);
		if (tc_query_absent(err)) {
			close(program_fd);
			return 0;
		}
		if (err) {
			fprintf(stderr, "unable to query TC program on %s: %s\n",
				ifname, strerror(-err));
			close(program_fd);
			return 1;
		}
		if (attached_id != program_id) {
			fprintf(stderr, "refusing to detach an unowned TC program from %s\n",
				ifname);
			close(program_fd);
			return 1;
		}
		err = bpf_tc_detach(&hook, &opts);
		if (err && err != -ENOENT)
			fprintf(stderr, "unable to detach TC program from %s: %s\n",
				ifname, strerror(-err));
		close(program_fd);
		return err && err != -ENOENT ? 1 : 0;
	}
	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "unable to create clsact on %s: %s\n", ifname, strerror(-err));
		close(program_fd);
		return 1;
	}
	attached_id = 0;
	err = ca_bpf_tc_query_program(hook.ifindex, opts.handle, opts.priority, &attached_id);
	if (!err) {
		if (attached_id == program_id) {
			close(program_fd);
			return 0;
		}
		fprintf(stderr, "TC coordinate %u/%u on %s is owned by another program\n",
			opts.handle, opts.priority, ifname);
		close(program_fd);
		return 1;
	}
	if (!tc_query_absent(err)) {
		fprintf(stderr, "unable to query TC coordinate on %s: %s\n",
			ifname, strerror(-err));
		close(program_fd);
		return 1;
	}
	opts.prog_fd = program_fd;
	opts.flags = 0;
	err = bpf_tc_attach(&hook, &opts);
	if (err == -EEXIST) {
		attached_id = 0;
		if (!ca_bpf_tc_query_program(hook.ifindex, opts.handle, opts.priority,
				      &attached_id) && attached_id == program_id)
			err = 0;
	}
	if (err)
		fprintf(stderr, "unable to attach TC program to %s: %s\n", ifname, strerror(-err));
	close(program_fd);
	return err ? 1 : 0;
}


