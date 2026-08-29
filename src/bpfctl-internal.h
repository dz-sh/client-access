// SPDX-License-Identifier: Apache-2.0
#ifndef CLIENT_ACCESS_BPFCTL_INTERNAL_H
#define CLIENT_ACCESS_BPFCTL_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <linux/types.h>

#include "client-access-bpf.h"

#define CA_BPF_DEFAULT_OBJECT "/usr/lib/bpf/client-access-bpf.o"
#define CA_BPF_UPDATE_LOCK "/var/run/client-access-bpfctl.lock"

int ca_bpf_pin_path(char *buf, size_t len, const char *name);
int ca_bpf_open_map(const char *name);
int ca_bpf_lookup_config(int fd, struct ca_config *config);
int ca_bpf_update_lock(void);
int ca_bpf_program_id_from_fd(int fd, __u32 *id);
int ca_bpf_tc_query_program(unsigned int ifindex, __u32 handle, __u32 priority,
			   __u32 *program_id);
int ca_bpf_tc_verify_program_interfaces(__u32 program_id, int keep_count,
					char **keep_names);
int ca_bpf_tc_prune(int keep_count, char **keep_names);
int ca_bpf_tc_detach_all(void);
int ca_bpf_tc_action(const char *ifname, bool attach);
bool ca_bpf_object_available(void);
void ca_bpf_raise_memlock_limit(void);
void ca_bpf_object_unlink(void);
int ca_bpf_object_load(const char *path, bool replace);
int ca_bpf_snapshot_sync(void);
int ca_bpf_backend_disable_unlocked(void);
int ca_bpf_backend_disable(void);
int ca_bpf_print_generations(void);
int ca_bpf_gc_flows(unsigned long idle_seconds);
int ca_bpf_verify_health(__u32 policy_generation, __u32 classifier_generation,
			 int interface_count, char **interfaces);
int ca_bpf_print_status(void);

#endif

