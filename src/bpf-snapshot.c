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

struct subject_entry {
	struct ca_mac_key key;
	__u32 subject_id;
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
	struct policy_entry *policies;
	size_t policy_count;
	struct port_entry *ports;
	size_t port_count;
	struct ipv4_entry *ipv4;
	size_t ipv4_count;
	struct ipv6_entry *ipv6;
	size_t ipv6_count;
};

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
	if (kind == CA_CLASS_KIND_UNCLASSIFIED &&
	    class_id == CA_CLASS_UNCLASSIFIED && category_id == 0) {
		hint->class_id = class_id;
		hint->category_id = 0;
		hint->kind = kind;
		return 0;
	}
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
			    per_subject < 1 || per_subject > 100000) {
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

int ca_bpf_snapshot_sync(void)
{
	struct snapshot snapshot = {};
	struct ca_config current = {};
	__u32 zero = 0;
	int config_fd = -1, subject_fd = -1, policy_fd = -1;
	int port_fd = -1, ipv4_fd = -1, ipv6_fd = -1;
	int rate_fd = -1;
	int lock_fd = -1;
	int ret = 1;

	lock_fd = ca_bpf_update_lock();
	if (lock_fd < 0)
		goto out;
	if (parse_snapshot(&snapshot))
		goto out;
	config_fd = ca_bpf_open_map("ca_config");
	if (config_fd < 0) {
		fprintf(stderr, "application BPF config map is unavailable: %s\n", strerror(errno));
		goto out;
	}
	if (ca_bpf_lookup_config(config_fd, &current) && errno != ENOENT) {
		fprintf(stderr, "unable to read active application snapshot: %s\n", strerror(errno));
		goto out;
	}
	snapshot.config.active_slot = current.active_slot ? 0 : 1;
	subject_fd = ca_bpf_open_map(snapshot.config.active_slot ? "ca_subject_b" : "ca_subject_a");
	policy_fd = ca_bpf_open_map(snapshot.config.active_slot ? "ca_policy_b" : "ca_policy_a");
	port_fd = ca_bpf_open_map(snapshot.config.active_slot ? "ca_port_b" : "ca_port_a");
	ipv4_fd = ca_bpf_open_map(snapshot.config.active_slot ? "ca_ipv4_b" : "ca_ipv4_a");
	ipv6_fd = ca_bpf_open_map(snapshot.config.active_slot ? "ca_ipv6_b" : "ca_ipv6_a");
	if (subject_fd < 0 || policy_fd < 0 || port_fd < 0 ||
	    ipv4_fd < 0 || ipv6_fd < 0) {
		fprintf(stderr, "inactive application snapshot maps are unavailable: %s\n", strerror(errno));
		goto out;
	}
	/* Retain the prior slot beyond the maximum expected TC invocation. */
	usleep(50000);
	if (clear_map(subject_fd, sizeof(struct ca_mac_key)) ||
	    clear_map(policy_fd, sizeof(struct ca_policy_key)) ||
	    clear_map(port_fd, sizeof(struct ca_port_key)) ||
	    clear_map(ipv4_fd, sizeof(struct ca_ipv4_lpm_key)) ||
	    clear_map(ipv6_fd, sizeof(struct ca_ipv6_lpm_key))) {
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
		rate_fd = ca_bpf_open_map("ca_subject_rates");
		if (rate_fd < 0 || clear_map(rate_fd, sizeof(__u32))) {
			fprintf(stderr, "unable to reset generation-scoped classifier state\n");
			goto out;
		}
	}
	if (bpf_map_update_elem(config_fd, &zero, &snapshot.config,
				BPF_ANY | BPF_F_LOCK)) {
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
	if (port_fd >= 0)
		close(port_fd);
	if (ipv4_fd >= 0)
		close(ipv4_fd);
	if (ipv6_fd >= 0)
		close(ipv6_fd);
	if (rate_fd >= 0)
		close(rate_fd);
	if (lock_fd >= 0)
		close(lock_fd);
	free(snapshot.subjects);
	free(snapshot.policies);
	free(snapshot.ports);
	free(snapshot.ipv4);
	free(snapshot.ipv6);
	return ret;
}


