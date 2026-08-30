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

int ca_bpf_verify_health(__u32 policy_generation, __u32 classifier_generation,
			 int interface_count, char **interfaces)
{
	struct ca_config config = {};
	__u32 program_id = 0;
	int config_fd = -1, program_fd = -1;
	int ret = 1;

	if (!ca_bpf_object_available()) {
		fprintf(stderr, "application BPF pins or schema are incompatible\n");
		return 1;
	}
	config_fd = ca_bpf_open_map("ca_config");
	program_fd = bpf_obj_get(CA_PROGRAM_PIN);
	if (config_fd < 0 || program_fd < 0 ||
	    ca_bpf_lookup_config(config_fd, &config) ||
	    ca_bpf_program_id_from_fd(program_fd, &program_id)) {
		fprintf(stderr, "unable to inspect application BPF health\n");
		goto out;
	}
	if (!config.enabled || config.app_policy_generation != policy_generation ||
	    config.classifier_generation != classifier_generation) {
		fprintf(stderr,
			"application BPF generation mismatch: enabled=%u policy=%u classifier=%u\n",
			config.enabled, config.app_policy_generation,
			config.classifier_generation);
		goto out;
	}
	for (int i = 0; i < interface_count; i++) {
		__u32 attached_id = 0;
		unsigned int ifindex = if_nametoindex(interfaces[i]);
		int err;

		if (!ifindex) {
			fprintf(stderr, "unknown health interface %s\n", interfaces[i]);
			goto out;
		}
		err = ca_bpf_tc_query_program(ifindex, CA_TC_HANDLE, CA_TC_PRIORITY,
					       &attached_id);
		if (err || attached_id != program_id) {
			fprintf(stderr, "application BPF attachment mismatch on %s\n",
				interfaces[i]);
			goto out;
		}
	}
	if (ca_bpf_tc_verify_program_interfaces(program_id, interface_count, interfaces))
		goto out;
	ret = 0;
out:
	if (config_fd >= 0)
		close(config_fd);
	if (program_fd >= 0)
		close(program_fd);
	return ret;
}

static int count_map_entries(int fd, size_t key_size)
{
	unsigned char key[key_size], next[key_size];
	void *current = NULL;
	int count = 0;

	while (!bpf_map_get_next_key(fd, current, next)) {
		memcpy(key, next, key_size);
		current = key;
		count++;
	}
	return count;
}

static int count_unique_subjects(int fd)
{
	struct ca_mac_key key, next;
	__u32 values[CA_MAX_SUBJECTS];
	void *current = NULL;
	size_t count = 0;

	while (!bpf_map_get_next_key(fd, current, &next)) {
		__u32 subject_id;
		bool found = false;

		key = next;
		current = &key;
		if (bpf_map_lookup_elem(fd, &key, &subject_id))
			continue;
		for (size_t i = 0; i < count; i++)
			if (values[i] == subject_id) {
				found = true;
				break;
			}
		if (!found && count < ARRAY_SIZE(values))
			values[count++] = subject_id;
	}
	return count;
}

int ca_bpf_print_status(void)
{
	struct ca_config config = {};
	__u64 runtime = 0;
	__u32 zero = 0, schema = 0;
	int config_fd = -1, subject_fd = -1, policy_fd = -1;
	int port_fd = -1, ipv4_fd = -1, ipv6_fd = -1;
	int flow_fd = -1;
	int runtime_fd = -1, stats_fd = -1, schema_fd = -1;
	int cpus = libbpf_num_possible_cpus();
	uint64_t *percpu = NULL;
	uint64_t stats[CA_STATS_COUNT] = {};
	uint64_t flow_memory = (uint64_t)CA_MAX_FLOWS *
		(sizeof(struct ca_flow_key) + sizeof(struct ca_flow_state) + 72);
	int subject_entries, unique_subjects, policy_entries;
	int flow_entries;
	int port_entries, ipv4_entries, ipv6_entries;
	int ret = 1;

	config_fd = ca_bpf_open_map("ca_config");
	if (config_fd < 0 || ca_bpf_lookup_config(config_fd, &config)) {
		fprintf(stderr, "application BPF state is unavailable\n");
		goto out;
	}
	schema_fd = ca_bpf_open_map("ca_mark_schema");
	if (schema_fd < 0 || bpf_map_lookup_elem(schema_fd, &zero, &schema)) {
		fprintf(stderr, "application BPF schema is unavailable\n");
		goto out;
	}
	subject_fd = ca_bpf_open_map(config.active_slot ? "ca_subject_b" : "ca_subject_a");
	policy_fd = ca_bpf_open_map(config.active_slot ? "ca_policy_b" : "ca_policy_a");
	port_fd = ca_bpf_open_map(config.active_slot ? "ca_port_b" : "ca_port_a");
	ipv4_fd = ca_bpf_open_map(config.active_slot ? "ca_ipv4_b" : "ca_ipv4_a");
	ipv6_fd = ca_bpf_open_map(config.active_slot ? "ca_ipv6_b" : "ca_ipv6_a");
	flow_fd = ca_bpf_open_map("ca_flows");
	runtime_fd = ca_bpf_open_map("ca_runtime");
	stats_fd = ca_bpf_open_map("ca_stats");
	if (subject_fd < 0 || policy_fd < 0 || port_fd < 0 || ipv4_fd < 0 ||
	    ipv6_fd < 0 || flow_fd < 0 ||
	    runtime_fd < 0 || stats_fd < 0 || cpus <= 0) {
		fprintf(stderr, "one or more application BPF maps are unavailable\n");
		goto out;
	}
	bpf_map_lookup_elem(runtime_fd, &zero, &runtime);
	percpu = calloc(cpus, sizeof(*percpu));
	if (!percpu)
		goto out;
	for (__u32 id = 0; id < CA_STATS_COUNT; id++) {
		memset(percpu, 0, cpus * sizeof(*percpu));
		if (bpf_map_lookup_elem(stats_fd, &id, percpu))
			continue;
		for (int cpu = 0; cpu < cpus; cpu++)
			stats[id] += percpu[cpu];
	}
	subject_entries = count_map_entries(subject_fd, sizeof(struct ca_mac_key));
	unique_subjects = count_unique_subjects(subject_fd);
	policy_entries = count_map_entries(policy_fd, sizeof(struct ca_policy_key));
	port_entries = count_map_entries(port_fd, sizeof(struct ca_port_key));
	ipv4_entries = count_map_entries(ipv4_fd, sizeof(struct ca_ipv4_lpm_key));
	ipv6_entries = count_map_entries(ipv6_fd, sizeof(struct ca_ipv6_lpm_key));
	flow_entries = count_map_entries(flow_fd, sizeof(struct ca_flow_key));
	printf("{\"backend_mode\":\"V4_BPF_BASIC\"," 
	       "\"program_pinned\":true,\"maps_pinned\":true,"
	       "\"bpf_schema_version\":%u,"
	       "\"enabled\":%s,\"app_enforcement_enabled\":%s,\"active_slot\":%u,"
	       "\"app_policy_generation\":%u,\"classifier_generation\":%u,"
	       "\"subject_entries\":%d,\"subject_count\":%d,"
	       "\"app_policy_snapshot_entries\":%d,\"policy_entries\":%d,"
	       "\"port_hint_entries\":%d,\"ipv4_prefix_entries\":%d,"
	       "\"ipv6_prefix_entries\":%d,\"runtime_projection_entries\":%d,"
	       "\"flow_map_entries\":%d,\"flow_entries\":%d,"
	       "\"flow_capacity\":%u,\"estimated_flow_map_memory_bytes\":%" PRIu64 ","
	       "\"flows_total\":%" PRIu64 ",\"flows_pending\":%u,"
	       "\"flows_pending_peak\":%u,"
	       "\"flows_classified_exact\":%" PRIu64 ","
	       "\"flows_classified_category\":%" PRIu64 ","
	       "\"flows_unclassified\":%" PRIu64 ","
	       "\"flows_unclassified_budget\":%" PRIu64 ","
	       "\"flows_unclassified_load_shed\":%" PRIu64 ","
	       "\"flow_app_allow_verdicts\":%" PRIu64 ","
	       "\"flow_app_deny_verdicts\":%" PRIu64 ","
	       "\"classification_packets\":%" PRIu64 ","
	       "\"classification_bytes\":%" PRIu64 ","
	       "\"classification_admission_denied\":%" PRIu64 ","
	       "\"flow_map_evictions\":%" PRIu64 ","
	       "\"flow_readmissions\":%" PRIu64 ","
	       "\"parser_map_entries\":0,\"offload_excluded_subjects\":%d,"
	       "\"flow_map_full\":%" PRIu64 ",\"policy_reevaluations\":%" PRIu64 ","
	       "\"unknown_subject_packets\":%" PRIu64 ","
	       "\"parse_unsupported\":%" PRIu64 ","
	       "\"classifier_conflicts\":%" PRIu64 ","
	       "\"packet_app_allow_verdicts\":%" PRIu64 ","
	       "\"packet_app_deny_verdicts\":%" PRIu64 ","
	       "\"app_mark_mask\":%u,"
	       "\"max_packets_inspected\":%u,\"max_bytes_examined\":%u,"
	       "\"max_classification_age_ms\":%u,\"max_pending_entries\":%u,"
	       "\"max_new_classifications_per_second\":%u,"
	       "\"per_subject_new_classification_rate\":%u}\n",
	       schema, config.enabled ? "true" : "false",
	       config.app_enforcement_enabled ? "true" : "false",
	       config.active_slot,
	       config.app_policy_generation, config.classifier_generation,
	       subject_entries, unique_subjects,
	       policy_entries, policy_entries,
	       port_entries, ipv4_entries, ipv6_entries,
	       port_entries + ipv4_entries + ipv6_entries,
	       flow_entries, flow_entries, CA_MAX_FLOWS, flow_memory,
	       stats[CA_STAT_FLOWS_TOTAL], (__u32)runtime, (__u32)(runtime >> 32),
	       stats[CA_STAT_FLOWS_CLASSIFIED_EXACT],
	       stats[CA_STAT_FLOWS_CLASSIFIED_CATEGORY],
	       stats[CA_STAT_FLOWS_UNCLASSIFIED],
	       stats[CA_STAT_FLOWS_UNCLASSIFIED_BUDGET],
	       stats[CA_STAT_FLOWS_UNCLASSIFIED_LOAD_SHED],
	       stats[CA_STAT_FLOW_APP_ALLOW_VERDICTS],
	       stats[CA_STAT_FLOW_APP_DENY_VERDICTS],
	       stats[CA_STAT_CLASSIFICATION_PACKETS], stats[CA_STAT_CLASSIFICATION_BYTES],
	       stats[CA_STAT_CLASSIFICATION_ADMISSION_DENIED],
	       stats[CA_STAT_FLOW_MAP_EVICTIONS], stats[CA_STAT_FLOW_READMISSIONS],
	       config.enabled ? unique_subjects : 0,
	       stats[CA_STAT_FLOW_MAP_FULL], stats[CA_STAT_POLICY_REEVALUATIONS],
	       stats[CA_STAT_UNKNOWN_SUBJECT_PACKETS], stats[CA_STAT_PARSE_UNSUPPORTED],
	       stats[CA_STAT_CLASSIFIER_CONFLICTS],
	       stats[CA_STAT_PACKET_APP_ALLOW_VERDICTS],
	       stats[CA_STAT_PACKET_APP_DENY_VERDICTS], CA_APP_MARK_MASK,
	       config.max_packets_inspected, config.max_bytes_examined,
	       config.max_classification_age_ms, config.max_pending_entries,
	       config.max_new_classifications_per_second,
	       config.per_subject_new_classification_rate);
	ret = 0;
out:
	free(percpu);
	if (config_fd >= 0)
		close(config_fd);
	if (subject_fd >= 0)
		close(subject_fd);
	if (policy_fd >= 0)
		close(policy_fd);
	if (port_fd >= 0)
		close(port_fd);
	if (ipv4_fd >= 0)
		close(ipv4_fd);
	if (ipv6_fd >= 0)
		close(ipv6_fd);
	if (flow_fd >= 0)
		close(flow_fd);
	if (runtime_fd >= 0)
		close(runtime_fd);
	if (stats_fd >= 0)
		close(stats_fd);
	if (schema_fd >= 0)
		close(schema_fd);
	return ret;
}

