// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "client-access-bpf.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define DEFAULT_OBJECT "/usr/lib/bpf/client-access-bpf.o"

static const char *const map_names[] = {
	"ca_config", "ca_subject_a", "ca_subject_b", "ca_policy_a",
	"ca_policy_b", "ca_flows", "ca_stats",
};

struct subject_entry {
	struct ca_mac_key key;
	__u32 subject_id;
};

struct policy_entry {
	struct ca_policy_key key;
	__u8 verdict;
};

struct snapshot {
	struct ca_config config;
	bool have_config;
	struct subject_entry *subjects;
	size_t subject_count;
	struct policy_entry *policies;
	size_t policy_count;
};

static void usage(FILE *out)
{
	fprintf(out,
		"usage: client-access-bpfctl COMMAND [ARGS]\n"
		"  ensure [object]        load and pin the datapath if absent\n"
		"  load [object]          replace the pinned datapath\n"
		"  disable                make every attached instance pass packets\n"
		"  unload                 remove this application's pinned objects\n"
		"  attach IFNAME          attach the pinned program at TC ingress\n"
		"  detach IFNAME          detach this application's TC ingress filter\n"
		"  sync                   validate stdin snapshot and atomically publish it\n"
		"  gc [IDLE_SECONDS]      expire idle cached flows\n"
		"  status                 print runtime state and counters as JSON\n");
}

static int pin_path(char *buf, size_t len, const char *name)
{
	int ret = snprintf(buf, len, "%s/%s", CA_PIN_ROOT, name);

	return ret < 0 || (size_t)ret >= len ? -ENAMETOOLONG : 0;
}

static int open_map(const char *name)
{
	char path[PATH_MAX];

	if (pin_path(path, sizeof(path), name))
		return -1;
	return bpf_obj_get(path);
}

static bool pinned_backend_available(void)
{
	int fd = bpf_obj_get(CA_PROGRAM_PIN);

	if (fd < 0)
		return false;
	close(fd);
	for (size_t i = 0; i < ARRAY_SIZE(map_names); i++) {
		fd = open_map(map_names[i]);
		if (fd < 0)
			return false;
		close(fd);
	}
	return true;
}

static void raise_memlock_limit(void)
{
	const struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &limit) && errno != EPERM)
		fprintf(stderr, "unable to raise memlock limit: %s\n", strerror(errno));
}

static void unlink_pins(void)
{
	char path[PATH_MAX];

	unlink(CA_PROGRAM_PIN);
	for (size_t i = 0; i < ARRAY_SIZE(map_names); i++) {
		if (!pin_path(path, sizeof(path), map_names[i]))
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

static int load_object(const char *path, bool replace)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts,
		.pin_root_path = CA_PIN_ROOT,
	);
	struct bpf_program *program;
	struct bpf_object *object;
	int err;

	if (!replace && pinned_backend_available())
		return 0;
	if (ensure_pin_root())
		return 1;
	if (replace)
		unlink_pins();

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
	unlink(CA_PROGRAM_PIN);
	err = bpf_program__pin(program, CA_PROGRAM_PIN);
	if (err)
		fprintf(stderr, "unable to pin BPF program: %s\n", strerror(-err));
	bpf_object__close(object);
	return err ? 1 : 0;
}

static int tc_action(const char *ifname, bool attach)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
		.attach_point = BPF_TC_INGRESS,
	);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
		.handle = 1,
		.priority = 1,
	);
	int program_fd, err;

	hook.ifindex = if_nametoindex(ifname);
	if (!hook.ifindex) {
		fprintf(stderr, "unknown interface %s\n", ifname);
		return 1;
	}
	if (!attach) {
		err = bpf_tc_detach(&hook, &opts);
		if (err && err != -ENOENT)
			fprintf(stderr, "unable to detach TC program from %s: %s\n",
				ifname, strerror(-err));
		return err && err != -ENOENT ? 1 : 0;
	}

	program_fd = bpf_obj_get(CA_PROGRAM_PIN);
	if (program_fd < 0) {
		fprintf(stderr, "pinned BPF program is unavailable: %s\n", strerror(errno));
		return 1;
	}
	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "unable to create clsact on %s: %s\n", ifname, strerror(-err));
		close(program_fd);
		return 1;
	}
	opts.prog_fd = program_fd;
	opts.flags = 0;
	err = bpf_tc_attach(&hook, &opts);
	if (err == -EEXIST) {
		opts.flags = BPF_TC_F_REPLACE;
		err = bpf_tc_attach(&hook, &opts);
	}
	if (err)
		fprintf(stderr, "unable to attach TC program to %s: %s\n", ifname, strerror(-err));
	close(program_fd);
	return err ? 1 : 0;
}

static int parse_mac(const char *text, struct ca_mac_key *key)
{
	unsigned int b[6];

	if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x",
		   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
		return -1;
	for (size_t i = 0; i < 6; i++)
		key->addr[i] = b[i];
	return 0;
}

static int append_subject(struct snapshot *snapshot, const struct subject_entry *entry)
{
	void *items;

	if (snapshot->subject_count >= CA_MAX_SUBJECTS)
		return -E2BIG;
	items = realloc(snapshot->subjects,
			sizeof(*snapshot->subjects) * (snapshot->subject_count + 1));
	if (!items)
		return -ENOMEM;
	snapshot->subjects = items;
	snapshot->subjects[snapshot->subject_count++] = *entry;
	return 0;
}

static int append_policy(struct snapshot *snapshot, const struct policy_entry *entry)
{
	void *items;

	if (snapshot->policy_count >= CA_MAX_POLICY_ENTRIES)
		return -E2BIG;
	items = realloc(snapshot->policies,
			sizeof(*snapshot->policies) * (snapshot->policy_count + 1));
	if (!items)
		return -ENOMEM;
	snapshot->policies = items;
	snapshot->policies[snapshot->policy_count++] = *entry;
	return 0;
}

static int parse_snapshot(struct snapshot *snapshot)
{
	char *line = NULL;
	size_t capacity = 0;
	unsigned long line_number = 0;
	int ret = 0;

	while (getline(&line, &capacity, stdin) >= 0) {
		char command[16];

		line_number++;
		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (sscanf(line, "%15s", command) != 1)
			continue;
		if (!strcmp(command, "CONFIG")) {
			unsigned int enabled, generation, classifier_generation;
			unsigned int unknown, provisional;

			if (sscanf(line, "CONFIG %u %u %u %u %u",
				   &enabled, &generation, &classifier_generation,
				   &unknown, &provisional) != 5 ||
			    enabled > 1 || unknown > 1 || provisional > 1) {
				ret = -EINVAL;
				break;
			}
			snapshot->config.enabled = enabled;
			snapshot->config.app_policy_generation = generation;
			snapshot->config.classifier_generation = classifier_generation;
			snapshot->config.unknown_app_verdict = unknown;
			snapshot->config.provisional_app_verdict = provisional;
			snapshot->have_config = true;
		}
		else if (!strcmp(command, "SUBJECT")) {
			struct subject_entry entry = {};
			char mac[32];
			unsigned int subject_id;

			if (sscanf(line, "SUBJECT %31s %u", mac, &subject_id) != 2 ||
			    !subject_id || parse_mac(mac, &entry.key)) {
				ret = -EINVAL;
				break;
			}
			entry.subject_id = subject_id;
			ret = append_subject(snapshot, &entry);
			if (ret)
				break;
		}
		else if (!strcmp(command, "POLICY")) {
			struct policy_entry entry = {};
			unsigned int subject_id, class_id, verdict;

			if (sscanf(line, "POLICY %u %u %u", &subject_id, &class_id, &verdict) != 3 ||
			    !subject_id || class_id > UINT16_MAX || verdict > CA_VERDICT_DENY) {
				ret = -EINVAL;
				break;
			}
			entry.key.subject_id = subject_id;
			entry.key.class_id = class_id;
			entry.verdict = verdict;
			ret = append_policy(snapshot, &entry);
			if (ret)
				break;
		}
		else {
			ret = -EINVAL;
			break;
		}
	}
	free(line);
	if (!ret && !snapshot->have_config)
		ret = -EINVAL;
	if (ret)
		fprintf(stderr, "invalid snapshot at line %lu: %s\n",
			line_number, strerror(-ret));
	return ret;
}

static int clear_map(int fd, size_t key_size)
{
	unsigned char key[key_size];

	while (!bpf_map_get_next_key(fd, NULL, key)) {
		if (bpf_map_delete_elem(fd, key))
			return -errno;
	}
	return errno == ENOENT ? 0 : -errno;
}

static int sync_snapshot(void)
{
	struct snapshot snapshot = {};
	struct ca_config current = {};
	__u32 zero = 0;
	int config_fd = -1, subject_fd = -1, policy_fd = -1;
	int ret = 1;

	if (parse_snapshot(&snapshot))
		goto out;
	config_fd = open_map("ca_config");
	if (config_fd < 0) {
		fprintf(stderr, "application BPF config map is unavailable: %s\n", strerror(errno));
		goto out;
	}
	if (bpf_map_lookup_elem(config_fd, &zero, &current) && errno != ENOENT) {
		fprintf(stderr, "unable to read active application snapshot: %s\n", strerror(errno));
		goto out;
	}
	snapshot.config.active_slot = current.active_slot ? 0 : 1;
	subject_fd = open_map(snapshot.config.active_slot ? "ca_subject_b" : "ca_subject_a");
	policy_fd = open_map(snapshot.config.active_slot ? "ca_policy_b" : "ca_policy_a");
	if (subject_fd < 0 || policy_fd < 0) {
		fprintf(stderr, "inactive application snapshot maps are unavailable: %s\n", strerror(errno));
		goto out;
	}
	if (clear_map(subject_fd, sizeof(struct ca_mac_key)) ||
	    clear_map(policy_fd, sizeof(struct ca_policy_key))) {
		fprintf(stderr, "unable to clear inactive application snapshot\n");
		goto out;
	}
	for (size_t i = 0; i < snapshot.subject_count; i++) {
		if (bpf_map_update_elem(subject_fd, &snapshot.subjects[i].key,
					&snapshot.subjects[i].subject_id, BPF_NOEXIST)) {
			fprintf(stderr, "unable to populate subject snapshot: %s\n", strerror(errno));
			goto out;
		}
	}
	for (size_t i = 0; i < snapshot.policy_count; i++) {
		if (bpf_map_update_elem(policy_fd, &snapshot.policies[i].key,
					&snapshot.policies[i].verdict, BPF_NOEXIST)) {
			fprintf(stderr, "unable to populate policy snapshot: %s\n", strerror(errno));
			goto out;
		}
	}
	if (bpf_map_update_elem(config_fd, &zero, &snapshot.config, BPF_ANY)) {
		fprintf(stderr, "unable to publish application snapshot: %s\n", strerror(errno));
		goto out;
	}
	ret = 0;
out:
	if (config_fd >= 0)
		close(config_fd);
	if (subject_fd >= 0)
		close(subject_fd);
	if (policy_fd >= 0)
		close(policy_fd);
	free(snapshot.subjects);
	free(snapshot.policies);
	return ret;
}

static int disable_backend(void)
{
	struct ca_config config = {};
	__u32 zero = 0;
	int fd = open_map("ca_config");
	int ret = 0;

	if (fd < 0)
		return errno == ENOENT ? 0 : 1;
	if (bpf_map_lookup_elem(fd, &zero, &config)) {
		if (errno != ENOENT)
			ret = 1;
	}
	else {
		config.enabled = 0;
		if (bpf_map_update_elem(fd, &zero, &config, BPF_ANY))
			ret = 1;
	}
	if (ret)
		fprintf(stderr, "unable to disable application BPF state: %s\n", strerror(errno));
	close(fd);
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

static int gc_flows(unsigned long idle_seconds)
{
	struct ca_flow_key key, next;
	struct ca_flow_state state;
	struct timespec now;
	void *current = NULL;
	int fd, removed = 0;
	__u64 cutoff;

	fd = open_map("ca_flows");
	if (fd < 0) {
		fprintf(stderr, "flow map is unavailable: %s\n", strerror(errno));
		return 1;
	}
	clock_gettime(CLOCK_MONOTONIC, &now);
	cutoff = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec;
	cutoff = cutoff > idle_seconds * 1000000000ULL
		? cutoff - idle_seconds * 1000000000ULL : 0;
	while (!bpf_map_get_next_key(fd, current, &next)) {
		key = next;
		current = &key;
		if (!bpf_map_lookup_elem(fd, &key, &state) && state.last_seen_ns < cutoff) {
			if (!bpf_map_delete_elem(fd, &key)) {
				removed++;
				current = NULL;
			}
		}
	}
	close(fd);
	printf("{\"removed\":%d}\n", removed);
	return 0;
}

static int print_status(void)
{
	struct ca_config config = {};
	__u32 zero = 0;
	int config_fd = -1, subject_fd = -1, policy_fd = -1;
	int flow_fd = -1, stats_fd = -1;
	int cpus = libbpf_num_possible_cpus();
	uint64_t *percpu = NULL;
	uint64_t stats[CA_STATS_COUNT] = {};
	int ret = 1;

	config_fd = open_map("ca_config");
	if (config_fd < 0 || bpf_map_lookup_elem(config_fd, &zero, &config)) {
		fprintf(stderr, "application BPF state is unavailable\n");
		goto out;
	}
	subject_fd = open_map(config.active_slot ? "ca_subject_b" : "ca_subject_a");
	policy_fd = open_map(config.active_slot ? "ca_policy_b" : "ca_policy_a");
	flow_fd = open_map("ca_flows");
	stats_fd = open_map("ca_stats");
	if (subject_fd < 0 || policy_fd < 0 || flow_fd < 0 || stats_fd < 0 || cpus <= 0) {
		fprintf(stderr, "one or more application BPF maps are unavailable\n");
		goto out;
	}
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
	printf("{\"backend_mode\":\"V4_BPF_BASIC\","
	       "\"enabled\":%s,\"active_slot\":%u,"
	       "\"app_policy_generation\":%u,\"classifier_generation\":%u,"
	       "\"subject_entries\":%d,\"policy_entries\":%d,\"flow_entries\":%d,"
	       "\"flows_total\":%" PRIu64 ",\"flows_unclassified\":%" PRIu64 ","
	       "\"flows_allowed\":%" PRIu64 ",\"flows_denied\":%" PRIu64 ","
	       "\"flow_map_full\":%" PRIu64 ",\"policy_reevaluations\":%" PRIu64 ","
	       "\"unknown_subject_packets\":%" PRIu64 "}\n",
	       config.enabled ? "true" : "false", config.active_slot,
	       config.app_policy_generation, config.classifier_generation,
	       count_map_entries(subject_fd, sizeof(struct ca_mac_key)),
	       count_map_entries(policy_fd, sizeof(struct ca_policy_key)),
	       count_map_entries(flow_fd, sizeof(struct ca_flow_key)),
	       stats[CA_STAT_FLOWS_TOTAL], stats[CA_STAT_FLOWS_UNCLASSIFIED],
	       stats[CA_STAT_FLOWS_ALLOWED], stats[CA_STAT_FLOWS_DENIED],
	       stats[CA_STAT_FLOW_MAP_FULL], stats[CA_STAT_POLICY_REEVALUATIONS],
	       stats[CA_STAT_UNKNOWN_SUBJECT_PACKETS]);
	ret = 0;
out:
	free(percpu);
	if (config_fd >= 0)
		close(config_fd);
	if (subject_fd >= 0)
		close(subject_fd);
	if (policy_fd >= 0)
		close(policy_fd);
	if (flow_fd >= 0)
		close(flow_fd);
	if (stats_fd >= 0)
		close(stats_fd);
	return ret;
}

int main(int argc, char **argv)
{
	const char *object = argc > 2 ? argv[2] : DEFAULT_OBJECT;
	unsigned long idle = 300;

	if (argc < 2) {
		usage(stderr);
		return 2;
	}
	if (!strcmp(argv[1], "ensure")) {
		raise_memlock_limit();
		return load_object(object, false);
	}
	if (!strcmp(argv[1], "load")) {
		raise_memlock_limit();
		return load_object(object, true);
	}
	if (!strcmp(argv[1], "disable") && argc == 2)
		return disable_backend();
	if (!strcmp(argv[1], "unload")) {
		if (disable_backend())
			return 1;
		unlink_pins();
		return 0;
	}
	if (!strcmp(argv[1], "attach") && argc == 3)
		return tc_action(argv[2], true);
	if (!strcmp(argv[1], "detach") && argc == 3)
		return tc_action(argv[2], false);
	if (!strcmp(argv[1], "sync") && argc == 2)
		return sync_snapshot();
	if (!strcmp(argv[1], "status") && argc == 2)
		return print_status();
	if (!strcmp(argv[1], "gc")) {
		if (argc == 3)
			idle = strtoul(argv[2], NULL, 10);
		return gc_flows(idle);
	}
	usage(stderr);
	return 2;
}
