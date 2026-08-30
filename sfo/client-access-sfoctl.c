// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "client-access-bpf.h"

#define CA_SFO_MAX_CANDIDATES 4096U
#define CA_SFO_MAX_CONNTRACK_SNAPSHOT 32768U
#define CA_SFO_MAX_VERIFICATION_PASSES 3U
#define CA_SFO_MAX_FALLBACK_EVICTIONS 4096U
#define CA_SFO_DEFAULT_DEADLINE_MS 2000U
#define CA_SFO_MAX_DEADLINE_MS 10000U
#define CA_SFO_RETRY_DELAY_MS 20U

struct ca_candidate {
	struct ca_flow_key key;
	struct ca_flow_state state;
	uint32_t next;
	bool present;
};

struct ca_candidates {
	struct ca_candidate *items;
	size_t count;
	size_t capacity;
	uint32_t *buckets;
	size_t bucket_count;
	bool overflow;
};

struct ca_ct_list {
	struct nf_conntrack **items;
	size_t count;
	size_t capacity;
	bool overflow;
};

struct ca_scan {
	struct ca_candidates *candidates;
	struct ca_ct_list *matches;
	uint32_t entries;
	uint32_t software_offloaded;
	uint32_t hardware_offloaded;
	bool snapshot_overflow;
	bool offloaded_only;
};

struct ca_result {
	const char *result;
	const char *correlation_health;
	uint32_t tracked_flows;
	uint32_t candidates;
	uint32_t conntrack_entries;
	uint32_t software_offloaded;
	uint32_t hardware_offloaded;
	uint32_t delete_attempts;
	uint32_t delete_successes;
	uint32_t already_absent;
	uint32_t verification_failures;
	uint32_t verification_passes;
	uint32_t remaining;
	uint32_t fallback_evictions;
	uint32_t gc_reclaimed;
	uint64_t latency_ms;
	bool deadline_exceeded;
	bool fallback_used;
};

static uint64_t monotonic_ms(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return (uint64_t)now.tv_sec * 1000U + now.tv_nsec / 1000000U;
}

static bool parse_u32(const char *text, uint32_t minimum, uint32_t maximum,
			  uint32_t *value)
{
	char *end;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || *end || parsed < minimum || parsed > maximum)
		return false;
	*value = (uint32_t)parsed;
	return true;
}

static bool supported_flow(const struct ca_flow_key *key)
{
	uint16_t family = ntohs(key->eth_proto);

	return (family == ETH_P_IP || family == ETH_P_IPV6) &&
		(key->ip_proto == IPPROTO_TCP || key->ip_proto == IPPROTO_UDP);
}

static uint32_t hash_bytes(uint32_t hash, const void *data, size_t length)
{
	const uint8_t *bytes = data;

	for (size_t i = 0; i < length; i++) {
		hash ^= bytes[i];
		hash *= 16777619U;
	}
	return hash;
}

static uint32_t candidate_hash(const struct ca_flow_key *key)
{
	uint32_t hash = 2166136261U;
	uint8_t family = ntohs(key->eth_proto) == ETH_P_IP ? 4 : 6;

	hash = hash_bytes(hash, &family, sizeof(family));
	hash = hash_bytes(hash, &key->ip_proto, sizeof(key->ip_proto));
	hash = hash_bytes(hash, &key->src_port, sizeof(key->src_port));
	hash = hash_bytes(hash, &key->dst_port, sizeof(key->dst_port));
	if (family == 4) {
		hash = hash_bytes(hash, &key->addr.v4.src, sizeof(key->addr.v4.src));
		hash = hash_bytes(hash, &key->addr.v4.dst, sizeof(key->addr.v4.dst));
	}
	else {
		hash = hash_bytes(hash, key->addr.v6.src, sizeof(key->addr.v6.src));
		hash = hash_bytes(hash, key->addr.v6.dst, sizeof(key->addr.v6.dst));
	}
	return hash;
}

static uint32_t conntrack_hash(const struct nf_conntrack *ct)
{
	uint32_t hash = 2166136261U;
	uint8_t family = nfct_get_attr_u8(ct, ATTR_L3PROTO) == AF_INET ? 4 : 6;
	uint8_t protocol = nfct_get_attr_u8(ct, ATTR_L4PROTO);
	uint16_t source_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
	uint16_t destination_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);

	hash = hash_bytes(hash, &family, sizeof(family));
	hash = hash_bytes(hash, &protocol, sizeof(protocol));
	hash = hash_bytes(hash, &source_port, sizeof(source_port));
	hash = hash_bytes(hash, &destination_port, sizeof(destination_port));
	if (family == 4) {
		uint32_t source = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
		uint32_t destination = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);

		hash = hash_bytes(hash, &source, sizeof(source));
		hash = hash_bytes(hash, &destination, sizeof(destination));
	}
	else {
		hash = hash_bytes(hash, nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC), 16);
		hash = hash_bytes(hash, nfct_get_attr(ct, ATTR_ORIG_IPV6_DST), 16);
	}
	return hash;
}

static int index_candidates(struct ca_candidates *set)
{
	size_t buckets = 1;

	while (buckets < set->capacity * 2U)
		buckets <<= 1;
	set->buckets = malloc(buckets * sizeof(*set->buckets));
	if (!set->buckets)
		return -1;
	set->bucket_count = buckets;
	for (size_t i = 0; i < buckets; i++)
		set->buckets[i] = UINT32_MAX;
	for (size_t i = 0; i < set->count; i++) {
		uint32_t bucket = candidate_hash(&set->items[i].key) & (buckets - 1U);

		set->items[i].next = set->buckets[bucket];
		set->buckets[bucket] = (uint32_t)i;
	}
	return 0;
}

static int collect_candidates(struct ca_candidates *set, bool have_subject,
			      uint32_t subject_id, bool have_class,
			      uint16_t class_id)
{
	struct ca_flow_key key, next;
	struct ca_flow_state state;
	int fd;

	fd = bpf_obj_get(CA_PIN_ROOT "/ca_flows");
	if (fd < 0)
		return -1;
	if (bpf_map_get_next_key(fd, NULL, &key)) {
		close(fd);
		return errno == ENOENT ? 0 : -1;
	}
	for (;;) {
		bool have_next = !bpf_map_get_next_key(fd, &key, &next);

		if (!bpf_map_lookup_elem(fd, &key, &state) &&
		    (!have_subject || key.subject_id == subject_id) &&
		    supported_flow(&key) &&
		    (!have_class || state.class_id == class_id)) {
			if (set->count >= set->capacity) {
				set->overflow = true;
				break;
			}
			set->items[set->count].key = key;
			set->items[set->count].state = state;
			set->count++;
		}
		if (!have_next)
			break;
		key = next;
	}
	close(fd);
	return set->overflow ? -E2BIG : index_candidates(set);
}

static bool ct_has(const struct nf_conntrack *ct, enum nf_conntrack_attr attr)
{
	return nfct_attr_is_set(ct, attr) > 0;
}

static bool tuple_matches(const struct ca_flow_key *key,
			  const struct nf_conntrack *ct)
{
	uint8_t family;

	if (!ct_has(ct, ATTR_L3PROTO) || !ct_has(ct, ATTR_L4PROTO) ||
	    !ct_has(ct, ATTR_ORIG_PORT_SRC) || !ct_has(ct, ATTR_ORIG_PORT_DST))
		return false;
	family = nfct_get_attr_u8(ct, ATTR_L3PROTO);
	if (nfct_get_attr_u8(ct, ATTR_L4PROTO) != key->ip_proto ||
	    nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) != key->src_port ||
	    nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST) != key->dst_port)
		return false;
	if (ntohs(key->eth_proto) == ETH_P_IP) {
		return family == AF_INET && ct_has(ct, ATTR_ORIG_IPV4_SRC) &&
			ct_has(ct, ATTR_ORIG_IPV4_DST) &&
			nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC) == key->addr.v4.src &&
			nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST) == key->addr.v4.dst;
	}
	return family == AF_INET6 && ct_has(ct, ATTR_ORIG_IPV6_SRC) &&
		ct_has(ct, ATTR_ORIG_IPV6_DST) &&
		!memcmp(nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC), key->addr.v6.src, 16) &&
		!memcmp(nfct_get_attr(ct, ATTR_ORIG_IPV6_DST), key->addr.v6.dst, 16);
}

static bool supported_conntrack_tuple(const struct nf_conntrack *ct)
{
	uint8_t family, protocol;

	if (!ct_has(ct, ATTR_L3PROTO) || !ct_has(ct, ATTR_L4PROTO) ||
	    !ct_has(ct, ATTR_ORIG_PORT_SRC) || !ct_has(ct, ATTR_ORIG_PORT_DST))
		return false;
	family = nfct_get_attr_u8(ct, ATTR_L3PROTO);
	protocol = nfct_get_attr_u8(ct, ATTR_L4PROTO);
	if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
		return false;
	return family == AF_INET
		? ct_has(ct, ATTR_ORIG_IPV4_SRC) && ct_has(ct, ATTR_ORIG_IPV4_DST)
		: family == AF_INET6 && ct_has(ct, ATTR_ORIG_IPV6_SRC) &&
			ct_has(ct, ATTR_ORIG_IPV6_DST);
}

static uint32_t ct_status(const struct nf_conntrack *ct)
{
	return ct_has(ct, ATTR_STATUS) ? nfct_get_attr_u32(ct, ATTR_STATUS) : 0;
}

static int append_ct(struct ca_ct_list *list, const struct nf_conntrack *ct)
{
	struct nf_conntrack *copy;

	if (list->count >= list->capacity) {
		list->overflow = true;
		return -1;
	}
	copy = nfct_clone(ct);
	if (!copy) {
		list->overflow = true;
		return -1;
	}
	list->items[list->count++] = copy;
	return 0;
}

static void free_ct_list(struct ca_ct_list *list)
{
	for (size_t i = 0; i < list->count; i++)
		nfct_destroy(list->items[i]);
	list->count = 0;
	list->overflow = false;
}

static int scan_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct,
		   void *data)
{
	struct ca_scan *scan = data;
	uint32_t status = ct_status(ct);

	(void)type;
	if (++scan->entries > CA_SFO_MAX_CONNTRACK_SNAPSHOT) {
		scan->snapshot_overflow = true;
		return NFCT_CB_STOP;
	}
	if (status & IPS_HW_OFFLOAD)
		scan->hardware_offloaded++;
	if (status & IPS_OFFLOAD)
		scan->software_offloaded++;

	if (scan->offloaded_only) {
		if ((status & IPS_OFFLOAD) && !(status & IPS_HW_OFFLOAD) && scan->matches)
			append_ct(scan->matches, ct);
		return scan->matches && scan->matches->overflow
			? NFCT_CB_STOP : NFCT_CB_CONTINUE;
	}
	if (!scan->candidates || !scan->candidates->count)
		return NFCT_CB_CONTINUE;
	if (!supported_conntrack_tuple(ct) || !scan->candidates->buckets)
		return NFCT_CB_CONTINUE;
	uint32_t bucket = conntrack_hash(ct) & (scan->candidates->bucket_count - 1U);
	bool matched = false;
	for (uint32_t i = scan->candidates->buckets[bucket]; i != UINT32_MAX;
	     i = scan->candidates->items[i].next) {
		if (!tuple_matches(&scan->candidates->items[i].key, ct))
			continue;
		scan->candidates->items[i].present = true;
		matched = true;
	}
	if (matched && scan->matches)
		append_ct(scan->matches, ct);
	return scan->matches && scan->matches->overflow
		? NFCT_CB_STOP : NFCT_CB_CONTINUE;
}

static int conntrack_scan(struct ca_scan *scan)
{
	struct nfct_handle *handle;
	uint32_t family = AF_UNSPEC;
	int ret;

	handle = nfct_open(CONNTRACK, 0);
	if (!handle)
		return -1;
	if (nfct_callback_register(handle, NFCT_T_ALL, scan_cb, scan)) {
		nfct_close(handle);
		return -1;
	}
	ret = nfct_query(handle, NFCT_Q_DUMP, &family);
	nfct_close(handle);
	return ret;
}

static int delete_conntracks(struct ca_ct_list *list, struct ca_result *result)
{
	struct nfct_handle *handle = nfct_open(CONNTRACK, 0);

	if (!handle)
		return -1;
	for (size_t i = 0; i < list->count; i++) {
		result->delete_attempts++;
		if (!nfct_query(handle, NFCT_Q_DESTROY, list->items[i]))
			result->delete_successes++;
		else if (errno == ENOENT)
			result->already_absent++;
		else {
			nfct_close(handle);
			return -1;
		}
	}
	nfct_close(handle);
	return 0;
}

static void print_result(const struct ca_result *result)
{
	printf("{\"result\":\"%s\",\"correlation_health\":\"%s\","
	       "\"tracked_flow_count\":%u,"
	       "\"candidate_count\":%u,\"conntrack_entries\":%u,"
	       "\"software_offloaded_flow_count\":%u,"
	       "\"hardware_offloaded_flow_count\":%u,"
	       "\"delete_attempts\":%u,\"delete_successes\":%u,"
	       "\"already_absent\":%u,\"verification_failures\":%u,"
	       "\"verification_passes\":%u,\"remaining\":%u,"
	       "\"fallback_used\":%s,\"fallback_evictions\":%u,"
	       "\"gc_reclaimed\":%u,"
	       "\"revocation_latency_ms\":%" PRIu64 ","
	       "\"deadline_exceeded\":%s,"
	       "\"limits\":{\"max_tracked_flow_records\":%u,"
	       "\"max_revocation_candidates\":%u,"
	       "\"max_verification_passes\":%u,"
	       "\"max_conntrack_snapshot\":%u,"
	       "\"max_revocation_deadline_ms\":%u,"
	       "\"max_broader_fallback_scope\":%u}}\n",
	       result->result, result->correlation_health, result->tracked_flows,
	       result->candidates,
	       result->conntrack_entries, result->software_offloaded,
	       result->hardware_offloaded, result->delete_attempts,
	       result->delete_successes, result->already_absent,
	       result->verification_failures, result->verification_passes,
	       result->remaining, result->fallback_used ? "true" : "false",
	       result->fallback_evictions, result->gc_reclaimed,
	       result->latency_ms,
	       result->deadline_exceeded ? "true" : "false", CA_MAX_FLOWS,
	       CA_SFO_MAX_CANDIDATES, CA_SFO_MAX_VERIFICATION_PASSES,
	       CA_SFO_MAX_CONNTRACK_SNAPSHOT, CA_SFO_MAX_DEADLINE_MS,
	       CA_SFO_MAX_FALLBACK_EVICTIONS);
}

static int run_status(void)
{
	struct ca_scan scan = {};
	struct ca_result result = {
		.result = "COMPLETE",
		.correlation_health = "HEALTHY",
	};
	struct ca_candidates flows = {
		.items = calloc(CA_MAX_FLOWS, sizeof(*flows.items)),
		.capacity = CA_MAX_FLOWS,
	};
	struct ca_flow_key key, next;
	struct ca_flow_state state;
	int fd;

	if (!flows.items)
		return 1;
	fd = bpf_obj_get(CA_PIN_ROOT "/ca_flows");
	if (fd < 0) {
		result.result = "FAILED";
		result.correlation_health = "UNKNOWN";
	}
	else if (!bpf_map_get_next_key(fd, NULL, &key)) {
		for (;;) {
			bool have_next = !bpf_map_get_next_key(fd, &key, &next);
			if (!bpf_map_lookup_elem(fd, &key, &state))
				flows.count++;
			if (!have_next)
				break;
			key = next;
		}
		close(fd);
	}
	else
		close(fd);
	result.candidates = flows.count;
	result.tracked_flows = flows.count;
	if (conntrack_scan(&scan) || scan.snapshot_overflow) {
		result.result = "FAILED";
		result.correlation_health = "DEGRADED";
		result.verification_failures++;
	}
	result.conntrack_entries = scan.entries;
	result.software_offloaded = scan.software_offloaded;
	result.hardware_offloaded = scan.hardware_offloaded;
	if (scan.hardware_offloaded) {
		result.result = "FAILED";
		result.correlation_health = "DEGRADED";
	}
	print_result(&result);
	free(flows.items);
	return strcmp(result.result, "COMPLETE") != 0;
}

static int run_revoke(uint32_t subject_id, bool have_class, uint16_t class_id,
		      uint32_t deadline_ms)
{
	struct ca_candidates candidates = {
		.items = calloc(CA_SFO_MAX_CANDIDATES, sizeof(*candidates.items)),
		.capacity = CA_SFO_MAX_CANDIDATES,
	};
	struct nf_conntrack **matches = calloc(CA_SFO_MAX_CANDIDATES,
					       sizeof(*matches));
	struct ca_result result = {
		.result = "FAILED",
		.correlation_health = "HEALTHY",
	};
	uint64_t start = monotonic_ms();

	if (!candidates.items || !matches ||
	    collect_candidates(&candidates, true, subject_id, have_class, class_id)) {
		result.correlation_health = "DEGRADED";
		result.verification_failures++;
		goto out;
	}
	result.candidates = candidates.count;
	for (uint32_t pass = 0; pass < CA_SFO_MAX_VERIFICATION_PASSES; pass++) {
		struct ca_ct_list list = {
			.items = matches,
			.capacity = CA_SFO_MAX_CANDIDATES,
		};
		struct ca_scan scan = {
			.candidates = &candidates,
			.matches = &list,
		};

		for (size_t i = 0; i < candidates.count; i++)
			candidates.items[i].present = false;
		result.verification_passes++;
		if (conntrack_scan(&scan) || scan.snapshot_overflow || list.overflow) {
			result.verification_failures++;
			result.correlation_health = "DEGRADED";
			free_ct_list(&list);
			break;
		}
		result.conntrack_entries = scan.entries;
		result.software_offloaded = scan.software_offloaded;
		result.hardware_offloaded = scan.hardware_offloaded;
		result.remaining = list.count;
		if (scan.hardware_offloaded) {
			result.correlation_health = "DEGRADED";
			free_ct_list(&list);
			break;
		}
		if (!list.count) {
			result.result = "COMPLETE";
			free_ct_list(&list);
			break;
		}
		if (delete_conntracks(&list, &result)) {
			result.verification_failures++;
			free_ct_list(&list);
			break;
		}
		free_ct_list(&list);
		if (monotonic_ms() - start >= deadline_ms)
			break;
		usleep(CA_SFO_RETRY_DELAY_MS * 1000U);
	}
	result.latency_ms = monotonic_ms() - start;
	result.deadline_exceeded = result.latency_ms > deadline_ms ||
		(strcmp(result.result, "COMPLETE") && result.remaining);
	if (result.deadline_exceeded) {
		result.result = "FAILED";
		result.correlation_health = "DEGRADED";
	}
out:
	if (!result.latency_ms)
		result.latency_ms = monotonic_ms() - start;
	print_result(&result);
	free(matches);
	free(candidates.buckets);
	free(candidates.items);
	return strcmp(result.result, "COMPLETE") != 0;
}

static int run_gc(uint32_t idle_seconds)
{
	struct ca_candidates candidates = {
		.items = calloc(CA_MAX_FLOWS, sizeof(*candidates.items)),
		.capacity = CA_MAX_FLOWS,
	};
	struct ca_result result = {
		.result = "FAILED",
		.correlation_health = "HEALTHY",
	};
	struct ca_scan scan = { .candidates = &candidates };
	struct timespec now;
	uint64_t cutoff;
	int fd = -1;

	if (!candidates.items ||
	    collect_candidates(&candidates, false, 0, false, 0) ||
	    clock_gettime(CLOCK_MONOTONIC, &now)) {
		result.correlation_health = "DEGRADED";
		result.verification_failures++;
		goto out;
	}
	result.candidates = candidates.count;
	result.tracked_flows = candidates.count;
	if (conntrack_scan(&scan) || scan.snapshot_overflow) {
		result.correlation_health = "DEGRADED";
		result.verification_failures++;
		goto out;
	}
	result.conntrack_entries = scan.entries;
	result.software_offloaded = scan.software_offloaded;
	result.hardware_offloaded = scan.hardware_offloaded;
	if (scan.hardware_offloaded) {
		result.correlation_health = "DEGRADED";
		goto out;
	}
	cutoff = (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
	cutoff = cutoff > (uint64_t)idle_seconds * 1000000000ULL
		? cutoff - (uint64_t)idle_seconds * 1000000000ULL : 0;
	fd = bpf_obj_get(CA_PIN_ROOT "/ca_flows");
	if (fd < 0) {
		result.correlation_health = "DEGRADED";
		result.verification_failures++;
		goto out;
	}
	for (size_t i = 0; i < candidates.count; i++) {
		if (candidates.items[i].present ||
		    candidates.items[i].state.last_seen_ns >= cutoff)
			continue;
		if (!bpf_map_delete_elem(fd, &candidates.items[i].key))
			result.gc_reclaimed++;
		else if (errno != ENOENT) {
			result.correlation_health = "DEGRADED";
			result.verification_failures++;
			goto out;
		}
	}
	result.result = "COMPLETE";
out:
	if (fd >= 0)
		close(fd);
	print_result(&result);
	free(candidates.buckets);
	free(candidates.items);
	return strcmp(result.result, "COMPLETE") != 0;
}

static int run_baseline(uint32_t deadline_ms)
{
	struct nf_conntrack **items = calloc(CA_SFO_MAX_FALLBACK_EVICTIONS,
					     sizeof(*items));
	struct ca_result result = {
		.result = "FAILED",
		.correlation_health = "HEALTHY",
		.fallback_used = true,
	};
	uint64_t start = monotonic_ms();

	if (!items)
		return 1;
	for (uint32_t pass = 0; pass < CA_SFO_MAX_VERIFICATION_PASSES; pass++) {
		struct ca_ct_list list = {
			.items = items,
			.capacity = CA_SFO_MAX_FALLBACK_EVICTIONS,
		};
		struct ca_scan scan = {
			.matches = &list,
			.offloaded_only = true,
		};

		result.verification_passes++;
		if (conntrack_scan(&scan) || scan.snapshot_overflow || list.overflow) {
			result.verification_failures++;
			result.correlation_health = "DEGRADED";
			free_ct_list(&list);
			break;
		}
		result.conntrack_entries = scan.entries;
		result.software_offloaded = scan.software_offloaded;
		result.hardware_offloaded = scan.hardware_offloaded;
		result.remaining = list.count;
		if (scan.hardware_offloaded) {
			result.correlation_health = "DEGRADED";
			free_ct_list(&list);
			break;
		}
		if (!list.count) {
			result.result = "COMPLETE";
			free_ct_list(&list);
			break;
		}
		result.fallback_evictions += list.count;
		if (delete_conntracks(&list, &result)) {
			result.verification_failures++;
			free_ct_list(&list);
			break;
		}
		free_ct_list(&list);
		if (monotonic_ms() - start >= deadline_ms)
			break;
		usleep(CA_SFO_RETRY_DELAY_MS * 1000U);
	}
	result.latency_ms = monotonic_ms() - start;
	result.deadline_exceeded = result.latency_ms > deadline_ms ||
		(strcmp(result.result, "COMPLETE") && result.remaining);
	if (result.deadline_exceeded) {
		result.result = "FAILED";
		result.correlation_health = "DEGRADED";
	}
	print_result(&result);
	free(items);
	return strcmp(result.result, "COMPLETE") != 0;
}

static void usage(FILE *out)
{
	fprintf(out,
		"usage: client-access-sfoctl status\n"
		"       client-access-sfoctl revoke SUBJECT_ID CLASS_ID|- [DEADLINE_MS]\n"
		"       client-access-sfoctl baseline [DEADLINE_MS]\n"
		"       client-access-sfoctl gc IDLE_SECONDS\n");
}

int main(int argc, char **argv)
{
	uint32_t subject_id, class_id = 0;
	uint32_t deadline_ms = CA_SFO_DEFAULT_DEADLINE_MS;
	bool have_class;

	if (argc == 2 && !strcmp(argv[1], "status"))
		return run_status();
	if ((argc == 2 || argc == 3) && !strcmp(argv[1], "baseline")) {
		if (argc == 3 && !parse_u32(argv[2], 1, CA_SFO_MAX_DEADLINE_MS,
					    &deadline_ms))
			goto invalid;
		return run_baseline(deadline_ms);
	}
	if (argc == 3 && !strcmp(argv[1], "gc")) {
		uint32_t idle_seconds;

		if (!parse_u32(argv[2], 1, 86400, &idle_seconds))
			goto invalid;
		return run_gc(idle_seconds);
	}
	if ((argc == 4 || argc == 5) && !strcmp(argv[1], "revoke")) {
		if (!parse_u32(argv[2], 1, UINT32_MAX, &subject_id))
			goto invalid;
		have_class = strcmp(argv[3], "-") != 0;
		if (have_class && !parse_u32(argv[3], 0, UINT16_MAX, &class_id))
			goto invalid;
		if (argc == 5 && !parse_u32(argv[4], 1, CA_SFO_MAX_DEADLINE_MS,
					    &deadline_ms))
			goto invalid;
		return run_revoke(subject_id, have_class, (uint16_t)class_id,
				  deadline_ms);
	}
invalid:
	usage(stderr);
	return 2;
}
