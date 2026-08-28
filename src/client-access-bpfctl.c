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

#include "client-access-bpf.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define DEFAULT_OBJECT "/usr/lib/bpf/client-access-bpf.o"
#define UPDATE_LOCK "/var/run/client-access-bpfctl.lock"

static const char *const map_names[] = {
	"ca_config", "ca_subject_a", "ca_subject_b",
	"ca_destination_a", "ca_destination_b", "ca_policy_a",
	"ca_policy_b", "ca_port_a", "ca_port_b", "ca_ipv4_a", "ca_ipv4_b",
	"ca_ipv6_a", "ca_ipv6_b", "ca_dns4", "ca_dns6", "ca_flows",
	"ca_global_rate", "ca_subject_rates", "ca_runtime", "ca_stats",
};

struct subject_entry {
	struct ca_mac_key key;
	__u32 subject_id;
};

struct destination_entry {
	__u32 ifindex;
	__u8 enabled;
};

struct policy_entry {
	struct ca_policy_key key;
	__u8 verdict;
};

struct port_entry {
	struct ca_port_key key;
	struct ca_class_hint hint;
};

struct ipv4_entry {
	struct ca_ipv4_lpm_key key;
	struct ca_class_hint hint;
};

struct ipv6_entry {
	struct ca_ipv6_lpm_key key;
	struct ca_class_hint hint;
};

struct snapshot {
	struct ca_config config;
	bool have_config;
	struct subject_entry *subjects;
	size_t subject_count;
	struct destination_entry *destinations;
	size_t destination_count;
	struct policy_entry *policies;
	size_t policy_count;
	struct port_entry *ports;
	size_t port_count;
	struct ipv4_entry *ipv4;
	size_t ipv4_count;
	struct ipv6_entry *ipv6;
	size_t ipv6_count;
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
		"  dns-sync               publish a bounded batch of DNS classification hints\n"
		"  gc [IDLE_SECONDS]      expire idle cached flows\n"
		"  generations            print policy and classifier generation floors\n"
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

static int acquire_update_lock(void)
{
	int fd = open(UPDATE_LOCK, O_CREAT | O_CLOEXEC | O_RDWR, 0600);

	if (fd < 0 || flock(fd, LOCK_EX)) {
		fprintf(stderr, "unable to lock application BPF state: %s\n",
			strerror(errno));
		if (fd >= 0)
			close(fd);
		return -1;
	}
	return fd;
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
	bool available = pinned_backend_available();
	int err;

	if (!replace && available)
		return 0;
	if (ensure_pin_root())
		return 1;
	/* Remove partial or schema-incompatible pins before loading this object. */
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

static int append_destination(struct snapshot *snapshot,
			      const struct destination_entry *entry)
{
	void *items;

	if (snapshot->destination_count >= CA_MAX_DESTINATIONS)
		return -E2BIG;
	items = realloc(snapshot->destinations,
			sizeof(*snapshot->destinations) * (snapshot->destination_count + 1));
	if (!items)
		return -ENOMEM;
	snapshot->destinations = items;
	snapshot->destinations[snapshot->destination_count++] = *entry;
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

static int append_port(struct snapshot *snapshot, const struct port_entry *entry)
{
	void *items;

	if (snapshot->port_count >= CA_MAX_PORT_HINTS)
		return -E2BIG;
	items = realloc(snapshot->ports,
			sizeof(*snapshot->ports) * (snapshot->port_count + 1));
	if (!items)
		return -ENOMEM;
	snapshot->ports = items;
	snapshot->ports[snapshot->port_count++] = *entry;
	return 0;
}

static int append_ipv4(struct snapshot *snapshot, const struct ipv4_entry *entry)
{
	void *items;

	if (snapshot->ipv4_count >= CA_MAX_IPV4_HINTS)
		return -E2BIG;
	items = realloc(snapshot->ipv4,
			sizeof(*snapshot->ipv4) * (snapshot->ipv4_count + 1));
	if (!items)
		return -ENOMEM;
	snapshot->ipv4 = items;
	snapshot->ipv4[snapshot->ipv4_count++] = *entry;
	return 0;
}

static int append_ipv6(struct snapshot *snapshot, const struct ipv6_entry *entry)
{
	void *items;

	if (snapshot->ipv6_count >= CA_MAX_IPV6_HINTS)
		return -E2BIG;
	items = realloc(snapshot->ipv6,
			sizeof(*snapshot->ipv6) * (snapshot->ipv6_count + 1));
	if (!items)
		return -ENOMEM;
	snapshot->ipv6 = items;
	snapshot->ipv6[snapshot->ipv6_count++] = *entry;
	return 0;
}

static int parse_hint(unsigned int class_id, unsigned int category_id,
			      unsigned int kind, struct ca_class_hint *hint)
{
	if (class_id <= CA_CLASS_UNCLASSIFIED || class_id > UINT16_MAX ||
	    category_id > UINT16_MAX ||
	    (kind != CA_CLASS_KIND_EXACT && kind != CA_CLASS_KIND_CATEGORY))
		return -EINVAL;
	if (kind == CA_CLASS_KIND_CATEGORY && category_id != class_id)
		return -EINVAL;
	hint->class_id = class_id;
	hint->category_id = category_id;
	hint->kind = kind;
	return 0;
}

static int parse_dns_hint(unsigned int class_id, unsigned int category_id,
				  unsigned int kind, struct ca_class_hint *hint)
{
	if (kind == CA_CLASS_KIND_NONE && class_id == CA_CLASS_UNCLASSIFIED &&
	    category_id == 0) {
		hint->class_id = class_id;
		return 0;
	}
	return parse_hint(class_id, category_id, kind, hint);
}

static int parse_prefix(const char *text, int family, void *address,
			unsigned int *prefixlen)
{
	char copy[INET6_ADDRSTRLEN + 4];
	char *slash, *end;
	unsigned long value;
	unsigned int maximum = family == AF_INET ? 32 : 128;

	if (strlen(text) >= sizeof(copy))
		return -EINVAL;
	strcpy(copy, text);
	slash = strchr(copy, '/');
	if (!slash)
		return -EINVAL;
	*slash++ = '\0';
	errno = 0;
	value = strtoul(slash, &end, 10);
	if (errno || *end || value > maximum || inet_pton(family, copy, address) != 1)
		return -EINVAL;
	*prefixlen = value;
	return 0;
}

static void canonicalize_prefix(int family, void *address, unsigned int prefixlen)
{
	if (family == AF_INET) {
		uint32_t value;
		uint32_t mask = prefixlen ? UINT32_MAX << (32 - prefixlen) : 0;

		memcpy(&value, address, sizeof(value));
		value = htonl(ntohl(value) & mask);
		memcpy(address, &value, sizeof(value));
		return;
	}

	unsigned char *bytes = address;
	unsigned int whole = prefixlen / 8;
	unsigned int remainder = prefixlen % 8;

	if (whole < 16 && remainder) {
		bytes[whole] &= 0xff << (8 - remainder);
		whole++;
	}
	for (unsigned int i = whole; i < 16; i++)
		bytes[i] = 0;
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
			unsigned int unknown, provisional, max_packets, max_bytes;
			unsigned int max_age, max_pending, max_new, per_subject;

			if (snapshot->have_config ||
			    sscanf(line, "CONFIG %u %u %u %u %u %u %u %u %u %u %u",
				   &enabled, &generation, &classifier_generation,
				   &unknown, &provisional, &max_packets, &max_bytes,
				   &max_age, &max_pending, &max_new, &per_subject) != 11 ||
			    enabled > 1 || unknown > 1 || provisional > 1 ||
			    max_packets != 1 ||
			    max_bytes < 64 || max_bytes > 8192 ||
			    max_age < 1 || max_age > 10000 ||
			    max_pending < 1 || max_pending > CA_MAX_FLOWS ||
			    max_new < 1 || max_new > 100000 ||
			    per_subject < 1 || per_subject > max_new) {
				ret = -EINVAL;
				break;
			}
			snapshot->config.enabled = enabled;
			snapshot->config.app_policy_generation = generation;
			snapshot->config.classifier_generation = classifier_generation;
			snapshot->config.unknown_subject_app_verdict = unknown;
			snapshot->config.provisional_app_verdict = provisional;
			snapshot->config.max_packets_inspected = max_packets;
			snapshot->config.max_bytes_examined = max_bytes;
			snapshot->config.max_classification_age_ms = max_age;
			snapshot->config.max_pending_entries = max_pending;
			snapshot->config.max_new_classifications_per_second = max_new;
			snapshot->config.per_subject_new_classification_rate = per_subject;
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
		else if (!strcmp(command, "DESTINATION")) {
			struct destination_entry entry = { .enabled = 1 };
			char ifname[IFNAMSIZ];

			if (sscanf(line, "DESTINATION %15s", ifname) != 1 ||
			    !(entry.ifindex = if_nametoindex(ifname))) {
				ret = -EINVAL;
				break;
			}
			ret = append_destination(snapshot, &entry);
			if (ret)
				break;
		}
		else if (!strcmp(command, "PORT")) {
			struct port_entry entry = {};
			unsigned int protocol, port, class_id, category_id, kind;

			if (sscanf(line, "PORT %u %u %u %u %u", &protocol, &port,
				   &class_id, &category_id, &kind) != 5 ||
			    (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) ||
			    port == 0 || port > UINT16_MAX ||
			    parse_hint(class_id, category_id, kind, &entry.hint)) {
				ret = -EINVAL;
				break;
			}
			entry.key.ip_proto = protocol;
			entry.key.dst_port = htons(port);
			ret = append_port(snapshot, &entry);
			if (ret)
				break;
		}
		else if (!strcmp(command, "PREFIX4")) {
			struct ipv4_entry entry = {};
			char prefix[INET_ADDRSTRLEN + 4];
			unsigned int class_id, category_id, kind;

			if (sscanf(line, "PREFIX4 %18s %u %u %u", prefix, &class_id,
				   &category_id, &kind) != 4 ||
			    parse_prefix(prefix, AF_INET, &entry.key.addr,
						 &entry.key.prefixlen) ||
			    parse_hint(class_id, category_id, kind, &entry.hint)) {
				ret = -EINVAL;
				break;
			}
			canonicalize_prefix(AF_INET, &entry.key.addr, entry.key.prefixlen);
			ret = append_ipv4(snapshot, &entry);
			if (ret)
				break;
		}
		else if (!strcmp(command, "PREFIX6")) {
			struct ipv6_entry entry = {};
			char prefix[INET6_ADDRSTRLEN + 4];
			unsigned int class_id, category_id, kind;

			if (sscanf(line, "PREFIX6 %49s %u %u %u", prefix, &class_id,
				   &category_id, &kind) != 4 ||
			    parse_prefix(prefix, AF_INET6, entry.key.addr,
						 &entry.key.prefixlen) ||
			    parse_hint(class_id, category_id, kind, &entry.hint)) {
				ret = -EINVAL;
				break;
			}
			canonicalize_prefix(AF_INET6, entry.key.addr, entry.key.prefixlen);
			ret = append_ipv6(snapshot, &entry);
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
	if (!ret && snapshot->config.enabled && !snapshot->destination_count)
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
	int config_fd = -1, subject_fd = -1, destination_fd = -1, policy_fd = -1;
	int port_fd = -1, ipv4_fd = -1, ipv6_fd = -1;
	int dns4_fd = -1, dns6_fd = -1, rate_fd = -1;
	int lock_fd = -1;
	int ret = 1;

	lock_fd = acquire_update_lock();
	if (lock_fd < 0)
		goto out;
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
	destination_fd = open_map(snapshot.config.active_slot
		? "ca_destination_b" : "ca_destination_a");
	policy_fd = open_map(snapshot.config.active_slot ? "ca_policy_b" : "ca_policy_a");
	port_fd = open_map(snapshot.config.active_slot ? "ca_port_b" : "ca_port_a");
	ipv4_fd = open_map(snapshot.config.active_slot ? "ca_ipv4_b" : "ca_ipv4_a");
	ipv6_fd = open_map(snapshot.config.active_slot ? "ca_ipv6_b" : "ca_ipv6_a");
	if (subject_fd < 0 || destination_fd < 0 || policy_fd < 0 || port_fd < 0 ||
	    ipv4_fd < 0 || ipv6_fd < 0) {
		fprintf(stderr, "inactive application snapshot maps are unavailable: %s\n", strerror(errno));
		goto out;
	}
	/* Retain the prior slot beyond the maximum expected TC invocation. */
	usleep(50000);
	if (clear_map(subject_fd, sizeof(struct ca_mac_key)) ||
	    clear_map(destination_fd, sizeof(__u32)) ||
	    clear_map(policy_fd, sizeof(struct ca_policy_key)) ||
	    clear_map(port_fd, sizeof(struct ca_port_key)) ||
	    clear_map(ipv4_fd, sizeof(struct ca_ipv4_lpm_key)) ||
	    clear_map(ipv6_fd, sizeof(struct ca_ipv6_lpm_key))) {
		fprintf(stderr, "unable to clear inactive application snapshot\n");
		goto out;
	}
	for (size_t i = 0; i < snapshot.destination_count; i++) {
		if (bpf_map_update_elem(destination_fd,
				&snapshot.destinations[i].ifindex,
				&snapshot.destinations[i].enabled, BPF_NOEXIST)) {
			fprintf(stderr, "unable to populate destination snapshot: %s\n",
				strerror(errno));
			goto out;
		}
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
	for (size_t i = 0; i < snapshot.port_count; i++) {
		if (bpf_map_update_elem(port_fd, &snapshot.ports[i].key,
					&snapshot.ports[i].hint, BPF_NOEXIST)) {
			fprintf(stderr, "unable to populate port classifier snapshot: %s\n",
				strerror(errno));
			goto out;
		}
	}
	for (size_t i = 0; i < snapshot.ipv4_count; i++) {
		if (bpf_map_update_elem(ipv4_fd, &snapshot.ipv4[i].key,
					&snapshot.ipv4[i].hint, BPF_NOEXIST)) {
			fprintf(stderr, "unable to populate IPv4 classifier snapshot: %s\n",
				strerror(errno));
			goto out;
		}
	}
	for (size_t i = 0; i < snapshot.ipv6_count; i++) {
		if (bpf_map_update_elem(ipv6_fd, &snapshot.ipv6[i].key,
					&snapshot.ipv6[i].hint, BPF_NOEXIST)) {
			fprintf(stderr, "unable to populate IPv6 classifier snapshot: %s\n",
				strerror(errno));
			goto out;
		}
	}
	if (snapshot.config.classifier_generation != current.classifier_generation) {
		dns4_fd = open_map("ca_dns4");
		dns6_fd = open_map("ca_dns6");
		rate_fd = open_map("ca_subject_rates");
		if (dns4_fd < 0 || dns6_fd < 0 || rate_fd < 0 ||
		    clear_map(rate_fd, sizeof(__u32))) {
			fprintf(stderr, "unable to reset generation-scoped classifier state\n");
			goto out;
		}
	}
	if (bpf_map_update_elem(config_fd, &zero, &snapshot.config, BPF_ANY)) {
		fprintf(stderr, "unable to publish application snapshot: %s\n", strerror(errno));
		goto out;
	}
	if (snapshot.config.classifier_generation != current.classifier_generation &&
	    (clear_map(dns4_fd, sizeof(__be32)) ||
	     clear_map(dns6_fd, sizeof(struct ca_ipv6_addr_key))))
		fprintf(stderr, "warning: stale DNS hints will expire lazily\n");
	ret = 0;
out:
	if (config_fd >= 0)
		close(config_fd);
	if (subject_fd >= 0)
		close(subject_fd);
	if (destination_fd >= 0)
		close(destination_fd);
	if (policy_fd >= 0)
		close(policy_fd);
	if (port_fd >= 0)
		close(port_fd);
	if (ipv4_fd >= 0)
		close(ipv4_fd);
	if (ipv6_fd >= 0)
		close(ipv6_fd);
	if (dns4_fd >= 0)
		close(dns4_fd);
	if (dns6_fd >= 0)
		close(dns6_fd);
	if (rate_fd >= 0)
		close(rate_fd);
	if (lock_fd >= 0)
		close(lock_fd);
	free(snapshot.subjects);
	free(snapshot.destinations);
	free(snapshot.policies);
	free(snapshot.ports);
	free(snapshot.ipv4);
	free(snapshot.ipv6);
	return ret;
}

#define CA_MAX_DNS_BATCH 256

struct dns4_publish_entry {
	__be32 address;
	struct ca_class_hint hint;
	unsigned int ttl;
};

struct dns6_publish_entry {
	struct ca_ipv6_addr_key address;
	struct ca_class_hint hint;
	unsigned int ttl;
};

static bool same_hint(const struct ca_class_hint *a,
			      const struct ca_class_hint *b)
{
	return a->class_id == b->class_id &&
	       a->category_id == b->category_id && a->kind == b->kind;
}

static int publish_dns_hint(int fd, const void *key, struct ca_dns_hint *value,
			    __u64 now_ns)
{
	struct ca_dns_hint current;

	if (!bpf_map_lookup_elem(fd, key, &current) &&
	    current.classifier_generation == value->classifier_generation &&
	    current.expires_ns > now_ns) {
		if (!same_hint(&current.hint, &value->hint)) {
			value->hint.class_id = CA_CLASS_UNCLASSIFIED;
			value->hint.category_id = 0;
			value->hint.kind = CA_CLASS_KIND_NONE;
		}
		if (current.expires_ns > value->expires_ns)
			value->expires_ns = current.expires_ns;
	}
	return bpf_map_update_elem(fd, key, value, BPF_ANY) ? -errno : 0;
}

static int sync_dns_hints(void)
{
	struct dns4_publish_entry entries4[CA_MAX_DNS_BATCH];
	struct dns6_publish_entry entries6[CA_MAX_DNS_BATCH];
	struct ca_config config = {};
	char *line = NULL;
	size_t capacity = 0, count4 = 0, count6 = 0;
	unsigned long line_number = 0;
	unsigned int generation = 0;
	bool have_generation = false;
	struct timespec now;
	__u64 now_ns;
	__u32 zero = 0;
	int config_fd = -1, dns4_fd = -1, dns6_fd = -1;
	int lock_fd = -1;
	int ret = 1;

	lock_fd = acquire_update_lock();
	if (lock_fd < 0)
		goto out;

	while (getline(&line, &capacity, stdin) >= 0) {
		char command[16], address[INET6_ADDRSTRLEN];
		unsigned int class_id, category_id, kind, ttl;

		line_number++;
		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (sscanf(line, "%15s", command) != 1)
			continue;
		if (!strcmp(command, "DNSGEN")) {
			if (have_generation || sscanf(line, "DNSGEN %u", &generation) != 1)
				goto invalid;
			have_generation = true;
			continue;
		}
		if (!have_generation || count4 + count6 >= CA_MAX_DNS_BATCH ||
		    sscanf(line, "%15s %45s %u %u %u %u", command, address,
			   &class_id, &category_id, &kind, &ttl) != 6 ||
		    ttl < 1 || ttl > 86400)
			goto invalid;
		if (!strcmp(command, "DNS4")) {
			struct dns4_publish_entry *entry;

			entry = &entries4[count4];
			if (inet_pton(AF_INET, address, &entry->address) != 1 ||
			    parse_dns_hint(class_id, category_id, kind, &entry->hint))
				goto invalid;
			entry->ttl = ttl;
			count4++;
		}
		else if (!strcmp(command, "DNS6")) {
			struct dns6_publish_entry *entry;

			entry = &entries6[count6];
			if (inet_pton(AF_INET6, address, entry->address.addr) != 1 ||
			    parse_dns_hint(class_id, category_id, kind, &entry->hint))
				goto invalid;
			entry->ttl = ttl;
			count6++;
		}
		else
			goto invalid;
	}
	if (!have_generation)
		goto invalid;
	free(line);
	line = NULL;

	config_fd = open_map("ca_config");
	if (config_fd < 0 || bpf_map_lookup_elem(config_fd, &zero, &config)) {
		fprintf(stderr, "application BPF config map is unavailable\n");
		goto out;
	}
	/* A queued DNS batch from an older taxonomy is intentionally discarded. */
	if (!config.enabled || config.classifier_generation != generation) {
		ret = 0;
		goto out;
	}
	dns4_fd = open_map("ca_dns4");
	dns6_fd = open_map("ca_dns6");
	if (dns4_fd < 0 || dns6_fd < 0) {
		fprintf(stderr, "DNS classifier maps are unavailable\n");
		goto out;
	}
	if (clock_gettime(CLOCK_MONOTONIC, &now)) {
		fprintf(stderr, "unable to read monotonic clock: %s\n", strerror(errno));
		goto out;
	}
	now_ns = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec;
	for (size_t i = 0; i < count4; i++) {
		struct ca_dns_hint value = {
			.expires_ns = now_ns + (__u64)entries4[i].ttl * 1000000000ULL,
			.classifier_generation = generation,
			.hint = entries4[i].hint,
		};

		if (publish_dns_hint(dns4_fd, &entries4[i].address, &value, now_ns)) {
			fprintf(stderr, "unable to publish IPv4 DNS hint: %s\n", strerror(errno));
			goto out;
		}
	}
	for (size_t i = 0; i < count6; i++) {
		struct ca_dns_hint value = {
			.expires_ns = now_ns + (__u64)entries6[i].ttl * 1000000000ULL,
			.classifier_generation = generation,
			.hint = entries6[i].hint,
		};

		if (publish_dns_hint(dns6_fd, &entries6[i].address, &value, now_ns)) {
			fprintf(stderr, "unable to publish IPv6 DNS hint: %s\n", strerror(errno));
			goto out;
		}
	}
	ret = 0;
	goto out;

invalid:
	fprintf(stderr, "invalid DNS hint batch at line %lu\n", line_number);
out:
	free(line);
	if (config_fd >= 0)
		close(config_fd);
	if (dns4_fd >= 0)
		close(dns4_fd);
	if (dns6_fd >= 0)
		close(dns6_fd);
	if (lock_fd >= 0)
		close(lock_fd);
	return ret;
}

static int disable_backend(void)
{
	struct ca_config config = {};
	__u32 zero = 0;
	int lock_fd = acquire_update_lock();
	int fd;
	int ret = 0;

	if (lock_fd < 0)
		return 1;
	fd = open_map("ca_config");
	if (fd < 0)
		ret = errno == ENOENT ? 0 : 1;
	if (fd < 0)
		goto out;
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
out:
	if (fd >= 0)
		close(fd);
	close(lock_fd);
	return ret;
}

static int print_generations(void)
{
	struct ca_config config = {};
	__u32 zero = 0;
	int fd = open_map("ca_config");

	if (fd < 0 || bpf_map_lookup_elem(fd, &zero, &config)) {
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

static int gc_flows(unsigned long idle_seconds)
{
	struct ca_flow_key key, next;
	struct ca_flow_state state;
	struct timespec now;
	int fd, removed = 0;
	__u64 cutoff;

	fd = open_map("ca_flows");
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

static int print_status(void)
{
	struct ca_config config = {};
	__u64 runtime = 0;
	__u32 zero = 0;
	int config_fd = -1, subject_fd = -1, destination_fd = -1, policy_fd = -1;
	int port_fd = -1, ipv4_fd = -1, ipv6_fd = -1;
	int dns4_fd = -1, dns6_fd = -1, flow_fd = -1;
	int runtime_fd = -1, stats_fd = -1;
	int cpus = libbpf_num_possible_cpus();
	uint64_t *percpu = NULL;
	uint64_t stats[CA_STATS_COUNT] = {};
	uint64_t flow_memory = (uint64_t)CA_MAX_FLOWS *
		(sizeof(struct ca_flow_key) + sizeof(struct ca_flow_state) + 72);
	int subject_entries, unique_subjects, destination_entries, policy_entries;
	int flow_entries;
	int port_entries, ipv4_entries, ipv6_entries, dns4_entries, dns6_entries;
	int ret = 1;

	config_fd = open_map("ca_config");
	if (config_fd < 0 || bpf_map_lookup_elem(config_fd, &zero, &config)) {
		fprintf(stderr, "application BPF state is unavailable\n");
		goto out;
	}
	subject_fd = open_map(config.active_slot ? "ca_subject_b" : "ca_subject_a");
	destination_fd = open_map(config.active_slot
		? "ca_destination_b" : "ca_destination_a");
	policy_fd = open_map(config.active_slot ? "ca_policy_b" : "ca_policy_a");
	port_fd = open_map(config.active_slot ? "ca_port_b" : "ca_port_a");
	ipv4_fd = open_map(config.active_slot ? "ca_ipv4_b" : "ca_ipv4_a");
	ipv6_fd = open_map(config.active_slot ? "ca_ipv6_b" : "ca_ipv6_a");
	dns4_fd = open_map("ca_dns4");
	dns6_fd = open_map("ca_dns6");
	flow_fd = open_map("ca_flows");
	runtime_fd = open_map("ca_runtime");
	stats_fd = open_map("ca_stats");
	if (subject_fd < 0 || destination_fd < 0 || policy_fd < 0 || port_fd < 0 || ipv4_fd < 0 ||
	    ipv6_fd < 0 || dns4_fd < 0 || dns6_fd < 0 || flow_fd < 0 ||
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
	destination_entries = count_map_entries(destination_fd, sizeof(__u32));
	policy_entries = count_map_entries(policy_fd, sizeof(struct ca_policy_key));
	port_entries = count_map_entries(port_fd, sizeof(struct ca_port_key));
	ipv4_entries = count_map_entries(ipv4_fd, sizeof(struct ca_ipv4_lpm_key));
	ipv6_entries = count_map_entries(ipv6_fd, sizeof(struct ca_ipv6_lpm_key));
	dns4_entries = count_map_entries(dns4_fd, sizeof(__be32));
	dns6_entries = count_map_entries(dns6_fd, 16);
	flow_entries = count_map_entries(flow_fd, sizeof(struct ca_flow_key));
	printf("{\"backend_mode\":\"V4_BPF_BASIC\"," 
	       "\"program_pinned\":true,\"maps_pinned\":true,"
	       "\"enabled\":%s,\"active_slot\":%u,"
	       "\"app_policy_generation\":%u,\"classifier_generation\":%u,"
	       "\"subject_entries\":%d,\"subject_count\":%d,"
	       "\"destination_entries\":%d,"
	       "\"app_policy_snapshot_entries\":%d,\"policy_entries\":%d,"
	       "\"port_hint_entries\":%d,\"ipv4_prefix_entries\":%d,"
	       "\"ipv6_prefix_entries\":%d,\"dns_hint_entries\":%d,"
	       "\"flow_map_entries\":%d,\"flow_entries\":%d,"
	       "\"flow_capacity\":%u,\"estimated_flow_map_memory_bytes\":%" PRIu64 ","
	       "\"flows_total\":%" PRIu64 ",\"flows_pending\":%u,"
	       "\"flows_pending_peak\":%u,"
	       "\"flows_classified_exact\":%" PRIu64 ","
	       "\"flows_classified_category\":%" PRIu64 ","
	       "\"flows_unclassified\":%" PRIu64 ","
	       "\"flows_unclassified_budget\":%" PRIu64 ","
	       "\"flows_unclassified_load_shed\":%" PRIu64 ","
	       "\"flows_allowed\":%" PRIu64 ",\"flows_denied\":%" PRIu64 ","
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
	       "\"dns_hint_expired\":%" PRIu64 ","
	       "\"forward_scope_lookup_failed\":%" PRIu64 ","
	       "\"packets_allowed\":%" PRIu64 ",\"packets_denied\":%" PRIu64 ","
	       "\"max_packets_inspected\":%u,\"max_bytes_examined\":%u,"
	       "\"max_classification_age_ms\":%u,\"max_pending_entries\":%u,"
	       "\"max_new_classifications_per_second\":%u,"
	       "\"per_subject_new_classification_rate\":%u}\n",
	       config.enabled ? "true" : "false", config.active_slot,
	       config.app_policy_generation, config.classifier_generation,
	       subject_entries, unique_subjects, destination_entries,
	       policy_entries, policy_entries,
	       port_entries, ipv4_entries, ipv6_entries, dns4_entries + dns6_entries,
	       flow_entries, flow_entries, CA_MAX_FLOWS, flow_memory,
	       stats[CA_STAT_FLOWS_TOTAL], (__u32)runtime, (__u32)(runtime >> 32),
	       stats[CA_STAT_FLOWS_CLASSIFIED_EXACT],
	       stats[CA_STAT_FLOWS_CLASSIFIED_CATEGORY],
	       stats[CA_STAT_FLOWS_UNCLASSIFIED],
	       stats[CA_STAT_FLOWS_UNCLASSIFIED_BUDGET],
	       stats[CA_STAT_FLOWS_UNCLASSIFIED_LOAD_SHED],
	       stats[CA_STAT_FLOWS_ALLOWED], stats[CA_STAT_FLOWS_DENIED],
	       stats[CA_STAT_CLASSIFICATION_PACKETS], stats[CA_STAT_CLASSIFICATION_BYTES],
	       stats[CA_STAT_CLASSIFICATION_ADMISSION_DENIED],
	       stats[CA_STAT_FLOW_MAP_EVICTIONS], stats[CA_STAT_FLOW_READMISSIONS],
	       config.enabled ? unique_subjects : 0,
	       stats[CA_STAT_FLOW_MAP_FULL], stats[CA_STAT_POLICY_REEVALUATIONS],
	       stats[CA_STAT_UNKNOWN_SUBJECT_PACKETS], stats[CA_STAT_PARSE_UNSUPPORTED],
	       stats[CA_STAT_CLASSIFIER_CONFLICTS], stats[CA_STAT_DNS_HINT_EXPIRED],
	       stats[CA_STAT_SCOPE_LOOKUP_FAILED], stats[CA_STAT_PACKETS_ALLOWED],
	       stats[CA_STAT_PACKETS_DENIED],
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
	if (destination_fd >= 0)
		close(destination_fd);
	if (policy_fd >= 0)
		close(policy_fd);
	if (port_fd >= 0)
		close(port_fd);
	if (ipv4_fd >= 0)
		close(ipv4_fd);
	if (ipv6_fd >= 0)
		close(ipv6_fd);
	if (dns4_fd >= 0)
		close(dns4_fd);
	if (dns6_fd >= 0)
		close(dns6_fd);
	if (flow_fd >= 0)
		close(flow_fd);
	if (runtime_fd >= 0)
		close(runtime_fd);
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
	if (!strcmp(argv[1], "dns-sync") && argc == 2)
		return sync_dns_hints();
	if (!strcmp(argv[1], "generations") && argc == 2)
		return print_generations();
	if (!strcmp(argv[1], "status") && argc == 2)
		return print_status();
	if (!strcmp(argv[1], "gc")) {
		if (argc == 3) {
			char *end;

			errno = 0;
			idle = strtoul(argv[2], &end, 10);
			if (errno || *end || idle < 1 || idle > 86400) {
				fprintf(stderr, "IDLE_SECONDS must be from 1 to 86400\n");
				return 2;
			}
		}
		else if (argc != 2)
			return 2;
		return gc_flows(idle);
	}
	usage(stderr);
	return 2;
}
