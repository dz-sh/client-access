// SPDX-License-Identifier: Apache-2.0
#define KBUILD_MODNAME "client_access"

#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "client-access-bpf.h"

struct ca_vlan_hdr {
	__be16 tci;
	__be16 encapsulated_proto;
};

#define CA_IPV4_FRAGMENT_MASK 0x3fff
#define CA_NEXTHDR_HOP 0
#define CA_NEXTHDR_ROUTING 43
#define CA_NEXTHDR_FRAGMENT 44
#define CA_NEXTHDR_ESP 50
#define CA_NEXTHDR_AUTH 51
#define CA_NEXTHDR_DEST 60
#define CA_RATE_WINDOW_NS 1000000000ULL
#define CA_CAS_ATTEMPTS 8

enum ca_parse_result {
	CA_PARSE_OK = 0,
	CA_PARSE_NO_ETHERNET = -1,
	CA_PARSE_UNSUPPORTED = 1,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ca_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_config SEC(".maps");

/* Presence of this pin distinguishes the mark-emitting backend schema. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_mark_schema SEC(".maps");

#define CA_SUBJECT_MAP(name) \
	struct { \
		__uint(type, BPF_MAP_TYPE_HASH); \
		__uint(max_entries, CA_MAX_SUBJECTS); \
		__uint(map_flags, BPF_F_NO_PREALLOC); \
		__type(key, struct ca_mac_key); \
		__type(value, __u32); \
		__uint(pinning, LIBBPF_PIN_BY_NAME); \
	} name SEC(".maps")

CA_SUBJECT_MAP(ca_subject_a);
CA_SUBJECT_MAP(ca_subject_b);

#define CA_POLICY_MAP(name) \
	struct { \
		__uint(type, BPF_MAP_TYPE_HASH); \
		__uint(max_entries, CA_MAX_POLICY_ENTRIES); \
		__uint(map_flags, BPF_F_NO_PREALLOC); \
		__type(key, struct ca_policy_key); \
		__type(value, __u8); \
		__uint(pinning, LIBBPF_PIN_BY_NAME); \
	} name SEC(".maps")

CA_POLICY_MAP(ca_policy_a);
CA_POLICY_MAP(ca_policy_b);

#define CA_PORT_MAP(name) \
	struct { \
		__uint(type, BPF_MAP_TYPE_HASH); \
		__uint(max_entries, CA_MAX_PORT_HINTS); \
		__uint(map_flags, BPF_F_NO_PREALLOC); \
		__type(key, struct ca_port_key); \
		__type(value, struct ca_class_hint); \
		__uint(pinning, LIBBPF_PIN_BY_NAME); \
	} name SEC(".maps")

CA_PORT_MAP(ca_port_a);
CA_PORT_MAP(ca_port_b);

#define CA_IPV4_MAP(name) \
	struct { \
		__uint(type, BPF_MAP_TYPE_LPM_TRIE); \
		__uint(max_entries, CA_MAX_IPV4_HINTS); \
		__uint(map_flags, BPF_F_NO_PREALLOC); \
		__type(key, struct ca_ipv4_lpm_key); \
		__type(value, struct ca_class_hint); \
		__uint(pinning, LIBBPF_PIN_BY_NAME); \
	} name SEC(".maps")

CA_IPV4_MAP(ca_ipv4_a);
CA_IPV4_MAP(ca_ipv4_b);

#define CA_IPV6_MAP(name) \
	struct { \
		__uint(type, BPF_MAP_TYPE_LPM_TRIE); \
		__uint(max_entries, CA_MAX_IPV6_HINTS); \
		__uint(map_flags, BPF_F_NO_PREALLOC); \
		__type(key, struct ca_ipv6_lpm_key); \
		__type(value, struct ca_class_hint); \
		__uint(pinning, LIBBPF_PIN_BY_NAME); \
	} name SEC(".maps")

CA_IPV6_MAP(ca_ipv6_a);
CA_IPV6_MAP(ca_ipv6_b);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CA_MAX_DNS4_HINTS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __be32);
	__type(value, struct ca_dns_hint);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_dns4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CA_MAX_DNS6_HINTS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ca_ipv6_addr_key);
	__type(value, struct ca_dns_hint);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_dns6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CA_MAX_FLOWS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ca_flow_key);
	__type(value, struct ca_flow_state);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_global_rate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CA_MAX_SUBJECTS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_subject_rates SEC(".maps");

/* Low 32 bits are current PENDING entries; high 32 bits are the peak. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_runtime SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CA_STATS_COUNT);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_stats SEC(".maps");

static __always_inline void ca_stat_add(__u32 id, __u64 amount)
{
	__u64 *value = bpf_map_lookup_elem(&ca_stats, &id);

	if (value)
		*value += amount;
}

static __always_inline void ca_stat_inc(__u32 id)
{
	ca_stat_add(id, 1);
}

static __always_inline __u32 *ca_subject_lookup(const struct ca_config *config,
						 const struct ca_mac_key *key)
{
	if (config->active_slot)
		return bpf_map_lookup_elem(&ca_subject_b, key);
	return bpf_map_lookup_elem(&ca_subject_a, key);
}

static __always_inline __u8 *ca_policy_lookup_map(const struct ca_config *config,
							 const struct ca_policy_key *key)
{
	if (config->active_slot)
		return bpf_map_lookup_elem(&ca_policy_b, key);
	return bpf_map_lookup_elem(&ca_policy_a, key);
}

static __always_inline struct ca_class_hint *
ca_port_lookup(const struct ca_config *config, const struct ca_port_key *key)
{
	if (config->active_slot)
		return bpf_map_lookup_elem(&ca_port_b, key);
	return bpf_map_lookup_elem(&ca_port_a, key);
}

static __always_inline struct ca_class_hint *
ca_ipv4_lookup(const struct ca_config *config, const struct ca_ipv4_lpm_key *key)
{
	if (config->active_slot)
		return bpf_map_lookup_elem(&ca_ipv4_b, key);
	return bpf_map_lookup_elem(&ca_ipv4_a, key);
}

static __always_inline struct ca_class_hint *
ca_ipv6_lookup(const struct ca_config *config, const struct ca_ipv6_lpm_key *key)
{
	if (config->active_slot)
		return bpf_map_lookup_elem(&ca_ipv6_b, key);
	return bpf_map_lookup_elem(&ca_ipv6_a, key);
}

static __always_inline __u8 ca_policy_verdict(const struct ca_config *config,
						__u32 subject_id, __u16 class_id)
{
	struct ca_policy_key key = {
		.subject_id = subject_id,
		.class_id = class_id,
	};
	__u8 *verdict = ca_policy_lookup_map(config, &key);

	if (verdict)
		return *verdict;
	key.class_id = CA_CLASS_DEFAULT;
	verdict = ca_policy_lookup_map(config, &key);
	return verdict ? *verdict : CA_VERDICT_ALLOW;
}

static __always_inline int ca_emit_app_verdict(struct __sk_buff *skb, __u8 verdict)
{
	__u32 mark = skb->mark & ~CA_APP_MARK_MASK;

	mark |= CA_APP_MARK_VALID;
	if (verdict == CA_VERDICT_DENY) {
		mark |= CA_APP_MARK_DENY;
		ca_stat_inc(CA_STAT_PACKET_APP_DENY_VERDICTS);
	}
	else
		ca_stat_inc(CA_STAT_PACKET_APP_ALLOW_VERDICTS);
	skb->mark = mark;
	return TC_ACT_UNSPEC;
}

static __always_inline bool ca_is_ipv6_extension(__u8 nexthdr)
{
	return nexthdr == CA_NEXTHDR_HOP || nexthdr == CA_NEXTHDR_ROUTING ||
	       nexthdr == CA_NEXTHDR_FRAGMENT || nexthdr == CA_NEXTHDR_ESP ||
	       nexthdr == CA_NEXTHDR_AUTH || nexthdr == CA_NEXTHDR_DEST;
}

static __always_inline int ca_parse_flow(void *data, void *data_end,
						 struct ca_flow_key *key,
						 struct ca_mac_key *mac,
						 __u32 *examined)
{
	struct ethhdr *eth = data;
	__u64 offset = sizeof(*eth);
	__be16 proto;

	if ((void *)(eth + 1) > data_end)
		return CA_PARSE_NO_ETHERNET;
	__builtin_memcpy(mac->addr, eth->h_source, sizeof(mac->addr));
	proto = eth->h_proto;

#pragma unroll
	for (int i = 0; i < 2; i++) {
		struct ca_vlan_hdr *vlan;

		if (proto != bpf_htons(ETH_P_8021Q) &&
		    proto != bpf_htons(ETH_P_8021AD))
			break;
		vlan = data + offset;
		if ((void *)(vlan + 1) > data_end)
			return CA_PARSE_UNSUPPORTED;
		proto = vlan->encapsulated_proto;
		offset += sizeof(*vlan);
	}

	key->eth_proto = proto;
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + offset;
		__u32 ihl;

		if ((void *)(ip + 1) > data_end || ip->version != 4)
			return CA_PARSE_UNSUPPORTED;
		ihl = ip->ihl * 4;
		if (ihl < sizeof(*ip) || data + offset + ihl > data_end)
			return CA_PARSE_UNSUPPORTED;
		key->ip_proto = ip->protocol;
		key->addr.v4.src = ip->saddr;
		key->addr.v4.dst = ip->daddr;
		if (ip->frag_off & bpf_htons(CA_IPV4_FRAGMENT_MASK))
			return CA_PARSE_UNSUPPORTED;
		offset += ihl;
	}
	else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + offset;

		if ((void *)(ip6 + 1) > data_end || ip6->version != 6)
			return CA_PARSE_UNSUPPORTED;
		key->ip_proto = ip6->nexthdr;
		__builtin_memcpy(key->addr.v6.src, &ip6->saddr, 16);
		__builtin_memcpy(key->addr.v6.dst, &ip6->daddr, 16);
		if (ca_is_ipv6_extension(ip6->nexthdr))
			return CA_PARSE_UNSUPPORTED;
		offset += sizeof(*ip6);
	}
	else {
		return CA_PARSE_UNSUPPORTED;
	}

	if (key->ip_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = data + offset;
		__u32 tcp_len;

		if ((void *)(tcp + 1) > data_end || tcp->doff < 5)
			return CA_PARSE_UNSUPPORTED;
		tcp_len = tcp->doff * 4;
		if (data + offset + tcp_len > data_end)
			return CA_PARSE_UNSUPPORTED;
		key->src_port = tcp->source;
		key->dst_port = tcp->dest;
		offset += tcp_len;
	}
	else if (key->ip_proto == IPPROTO_UDP) {
		struct udphdr *udp = data + offset;

		if ((void *)(udp + 1) > data_end)
			return CA_PARSE_UNSUPPORTED;
		key->src_port = udp->source;
		key->dst_port = udp->dest;
		offset += sizeof(*udp);
	}

	*examined = offset > 0xffffffffULL ? 0xffffffffU : (__u32)offset;
	return CA_PARSE_OK;
}

static __always_inline int ca_merge_hint(struct ca_class_hint *result,
						 const struct ca_class_hint *candidate)
{
	if (!candidate || candidate->kind == CA_CLASS_KIND_NONE)
		return 0;
	if (result->kind == CA_CLASS_KIND_NONE) {
		*result = *candidate;
		return 0;
	}
	if (result->kind == candidate->kind &&
	    result->class_id == candidate->class_id &&
	    result->category_id == candidate->category_id)
		return 0;
	if (result->kind == CA_CLASS_KIND_EXACT &&
	    candidate->kind == CA_CLASS_KIND_CATEGORY &&
	    result->category_id == candidate->class_id)
		return 0;
	if (result->kind == CA_CLASS_KIND_CATEGORY &&
	    candidate->kind == CA_CLASS_KIND_EXACT &&
	    candidate->category_id == result->class_id) {
		*result = *candidate;
		return 0;
	}
	return -1;
}

static __always_inline const struct ca_class_hint *
ca_dns4_lookup(__be32 address, __u32 generation, __u64 now)
{
	struct ca_dns_hint *entry = bpf_map_lookup_elem(&ca_dns4, &address);

	if (!entry)
		return NULL;
	if (entry->classifier_generation != generation) {
		bpf_map_delete_elem(&ca_dns4, &address);
		return NULL;
	}
	if (entry->expires_ns && entry->expires_ns <= now) {
		bpf_map_delete_elem(&ca_dns4, &address);
		ca_stat_inc(CA_STAT_DNS_HINT_EXPIRED);
		return NULL;
	}
	return &entry->hint;
}

static __always_inline const struct ca_class_hint *
ca_dns6_lookup(const __u8 address[16], __u32 generation, __u64 now)
{
	struct ca_ipv6_addr_key key = {};
	struct ca_dns_hint *entry;

	__builtin_memcpy(key.addr, address, sizeof(key.addr));
	entry = bpf_map_lookup_elem(&ca_dns6, &key);

	if (!entry)
		return NULL;
	if (entry->classifier_generation != generation) {
		bpf_map_delete_elem(&ca_dns6, &key);
		return NULL;
	}
	if (entry->expires_ns && entry->expires_ns <= now) {
		bpf_map_delete_elem(&ca_dns6, &key);
		ca_stat_inc(CA_STAT_DNS_HINT_EXPIRED);
		return NULL;
	}
	return &entry->hint;
}

static __always_inline void ca_classify(const struct ca_config *config,
						 const struct ca_flow_key *key, __u64 now,
						 __u16 *class_id, __u8 *class_kind)
{
	struct ca_class_hint result = {};
	const struct ca_class_hint *hint;
	int conflict = 0;

	if (key->eth_proto == bpf_htons(ETH_P_IP)) {
		struct ca_ipv4_lpm_key prefix = {
			.prefixlen = 32,
			.addr = key->addr.v4.dst,
		};

		hint = ca_dns4_lookup(key->addr.v4.dst,
						 config->classifier_generation, now);
		conflict |= ca_merge_hint(&result, hint);
		hint = ca_ipv4_lookup(config, &prefix);
		conflict |= ca_merge_hint(&result, hint);
	}
	else if (key->eth_proto == bpf_htons(ETH_P_IPV6)) {
		struct ca_ipv6_lpm_key prefix = { .prefixlen = 128 };

		__builtin_memcpy(prefix.addr, key->addr.v6.dst, 16);
		hint = ca_dns6_lookup(key->addr.v6.dst,
						 config->classifier_generation, now);
		conflict |= ca_merge_hint(&result, hint);
		hint = ca_ipv6_lookup(config, &prefix);
		conflict |= ca_merge_hint(&result, hint);
	}

	if (key->ip_proto == IPPROTO_TCP || key->ip_proto == IPPROTO_UDP) {
		struct ca_port_key port = {
			.ip_proto = key->ip_proto,
			.dst_port = key->dst_port,
		};

		hint = ca_port_lookup(config, &port);
		conflict |= ca_merge_hint(&result, hint);
	}

	if (conflict) {
		ca_stat_inc(CA_STAT_CLASSIFIER_CONFLICTS);
		*class_id = CA_CLASS_UNCLASSIFIED;
		*class_kind = CA_CLASS_KIND_NONE;
	}
	else if (result.kind != CA_CLASS_KIND_NONE) {
		*class_id = result.class_id;
		*class_kind = result.kind;
	}
	else {
		*class_id = CA_CLASS_UNCLASSIFIED;
		*class_kind = CA_CLASS_KIND_NONE;
	}
}

static __always_inline bool ca_rate_take(__u64 *state, __u64 now, __u32 limit)
{
	__u64 second = now / CA_RATE_WINDOW_NS;

#pragma unroll
	for (int i = 0; i < CA_CAS_ATTEMPTS; i++) {
		__u64 old = __sync_fetch_and_add(state, 0);
		__u32 old_second = old >> 32;
		__u32 count = old;
		__u64 next;

		if ((__u32)second != old_second)
			next = ((__u64)(__u32)second << 32) | 1;
		else {
			if (count >= limit)
				return false;
			next = old + 1;
		}
		if (__sync_val_compare_and_swap(state, old, next) == old)
			return true;
	}
	return false;
}

static __always_inline bool ca_admit_classification(const struct ca_config *config,
										 __u32 subject_id, __u64 now)
{
	__u32 zero = 0;
	__u64 initial = 0;
	__u64 *global = bpf_map_lookup_elem(&ca_global_rate, &zero);
	__u64 *subject;

	if (!global || !ca_rate_take(global, now,
				config->max_new_classifications_per_second))
		return false;
	subject = bpf_map_lookup_elem(&ca_subject_rates, &subject_id);
	if (!subject) {
		bpf_map_update_elem(&ca_subject_rates, &subject_id, &initial, BPF_NOEXIST);
		subject = bpf_map_lookup_elem(&ca_subject_rates, &subject_id);
	}
	return subject && ca_rate_take(subject, now,
								config->per_subject_new_classification_rate);
}

static __always_inline bool ca_pending_reserve(__u32 limit)
{
	__u32 zero = 0;
	__u64 *state = bpf_map_lookup_elem(&ca_runtime, &zero);

	if (!state)
		return false;
#pragma unroll
	for (int i = 0; i < CA_CAS_ATTEMPTS; i++) {
		__u64 old = __sync_fetch_and_add(state, 0);
		__u32 pending_count = old;
		__u32 peak = old >> 32;
		__u32 next_current;
		__u32 next_peak;
		__u64 next;

		if (pending_count >= limit)
			return false;
		next_current = pending_count + 1;
		next_peak = next_current > peak ? next_current : peak;
		next = ((__u64)next_peak << 32) | next_current;
		if (__sync_val_compare_and_swap(state, old, next) == old)
			return true;
	}
	return false;
}

static __always_inline void ca_pending_release(void)
{
	__u32 zero = 0;
	__u64 *state = bpf_map_lookup_elem(&ca_runtime, &zero);

	if (state)
		__sync_fetch_and_sub(state, 1);
}

static __always_inline void ca_record_terminal(const struct ca_flow_state *flow,
										bool budget)
{
	if (flow->classification_state == CA_FLOW_CLASSIFIED) {
		if (flow->class_kind == CA_CLASS_KIND_EXACT)
			ca_stat_inc(CA_STAT_FLOWS_CLASSIFIED_EXACT);
		else
			ca_stat_inc(CA_STAT_FLOWS_CLASSIFIED_CATEGORY);
	}
	else {
		ca_stat_inc(CA_STAT_FLOWS_UNCLASSIFIED);
		if (budget)
			ca_stat_inc(CA_STAT_FLOWS_UNCLASSIFIED_BUDGET);
	}
	if (flow->app_verdict == CA_VERDICT_DENY)
		ca_stat_inc(CA_STAT_FLOW_APP_DENY_VERDICTS);
	else
		ca_stat_inc(CA_STAT_FLOW_APP_ALLOW_VERDICTS);
}

static __always_inline bool ca_budget_exhausted(const struct ca_config *config,
									 const struct ca_flow_state *flow,
									 __u64 now)
{
	return config->max_packets_inspected != 1 ||
	       flow->packets_examined >= config->max_packets_inspected ||
	       flow->bytes_examined >= config->max_bytes_examined ||
	       now - flow->first_seen_ns >=
			(__u64)config->max_classification_age_ms * 1000000ULL;
}

static __always_inline bool ca_try_terminal(const struct ca_config *config,
								 struct ca_flow_state *flow,
								 const struct ca_flow_key *key,
								 __u32 subject_id, __u64 now)
{
	bool budget;

	ca_classify(config, key, now, &flow->class_id, &flow->class_kind);
	budget = ca_budget_exhausted(config, flow, now);
	if (flow->class_kind != CA_CLASS_KIND_NONE)
		flow->classification_state = CA_FLOW_CLASSIFIED;
	else if (budget) {
		flow->class_id = CA_CLASS_UNCLASSIFIED;
		flow->classification_state = CA_FLOW_UNCLASSIFIED_FINAL;
	}
	else
		return false;

	flow->app_verdict = ca_policy_verdict(config, subject_id, flow->class_id);
	flow->app_policy_generation = config->app_policy_generation;
	return true;
}

static __always_inline int ca_load_shed(struct __sk_buff *skb,
									 const struct ca_config *config,
									 const struct ca_flow_key *key,
									 __u32 subject_id, __u64 now)
{
	struct ca_flow_state terminal = {
		.first_seen_ns = now,
		.last_seen_ns = now,
		.app_policy_generation = config->app_policy_generation,
		.classifier_generation = config->classifier_generation,
		.class_id = CA_CLASS_UNCLASSIFIED,
		.classification_state = CA_FLOW_UNCLASSIFIED_FINAL,
	};
	struct ca_flow_state *existing;

	terminal.app_verdict = ca_policy_verdict(config, subject_id,
										   CA_CLASS_UNCLASSIFIED);
	ca_stat_inc(CA_STAT_CLASSIFICATION_ADMISSION_DENIED);
	if (!bpf_map_update_elem(&ca_flows, key, &terminal, BPF_NOEXIST)) {
		ca_stat_inc(CA_STAT_FLOWS_TOTAL);
		ca_stat_inc(CA_STAT_FLOWS_UNCLASSIFIED_LOAD_SHED);
		ca_record_terminal(&terminal, false);
		return ca_emit_app_verdict(skb, terminal.app_verdict);
	}

	/* A concurrent CPU may have admitted the same flow after our initial
	 * lookup. Reuse that state instead of misreporting a full map.
	 */
	existing = bpf_map_lookup_elem(&ca_flows, key);
	if (existing) {
		existing->last_seen_ns = now;
		if (existing->classification_state == CA_FLOW_PENDING)
			return ca_emit_app_verdict(skb, config->provisional_app_verdict);
		if (existing->app_policy_generation != config->app_policy_generation) {
			existing->app_verdict = ca_policy_verdict(config, subject_id,
											existing->class_id);
			existing->app_policy_generation = config->app_policy_generation;
			ca_stat_inc(CA_STAT_POLICY_REEVALUATIONS);
		}
		return ca_emit_app_verdict(skb, existing->app_verdict);
	}

	/* A fixed-capacity HASH map deliberately refuses new state instead of
	 * evicting an active terminal flow and reopening its leakage window.
	 */
	ca_stat_inc(CA_STAT_FLOW_MAP_FULL);
	return ca_emit_app_verdict(skb, terminal.app_verdict);
}

SEC("tc")
int ca_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ca_flow_key flow_key = {};
	struct ca_mac_key mac = {};
	struct ca_flow_state *flow;
	struct ca_config *config_map;
	struct ca_config config_snapshot;
	const struct ca_config *config = &config_snapshot;
	struct ca_flow_state initial = {};
	__u32 zero = 0;
	__u32 examined = 0;
	__u32 *subject_id;
	__u64 now;
	int parsed;

	/* The application workflow exclusively owns and rewrites these two bits. */
	skb->mark &= ~CA_APP_MARK_MASK;
	config_map = bpf_map_lookup_elem(&ca_config, &zero);
	if (!config_map)
		return TC_ACT_UNSPEC;
	/* Keep slot and generation reads coherent across one packet invocation. */
	config_snapshot = *config_map;
	if (!config->enabled)
		return TC_ACT_UNSPEC;
	ca_stat_inc(CA_STAT_PACKETS);

	parsed = ca_parse_flow(data, data_end, &flow_key, &mac, &examined);
	if (parsed == CA_PARSE_NO_ETHERNET)
		return TC_ACT_UNSPEC;
	subject_id = ca_subject_lookup(config, &mac);
	if (!subject_id) {
		ca_stat_inc(CA_STAT_UNKNOWN_SUBJECT_PACKETS);
		return ca_emit_app_verdict(skb, config->unknown_subject_app_verdict);
	}
	if (parsed != CA_PARSE_OK) {
		ca_stat_inc(CA_STAT_PARSE_UNSUPPORTED);
		return ca_emit_app_verdict(skb, ca_policy_verdict(config, *subject_id,
										 CA_CLASS_UNCLASSIFIED));
	}

	flow_key.subject_id = *subject_id;
	now = bpf_ktime_get_ns();
	flow = bpf_map_lookup_elem(&ca_flows, &flow_key);
	if (flow) {
		flow->last_seen_ns = now;
		if (flow->classification_state == CA_FLOW_PENDING)
			return ca_emit_app_verdict(skb, config->provisional_app_verdict);
		if (flow->app_policy_generation != config->app_policy_generation) {
			flow->app_verdict = ca_policy_verdict(config, *subject_id,
											 flow->class_id);
			flow->app_policy_generation = config->app_policy_generation;
			ca_stat_inc(CA_STAT_POLICY_REEVALUATIONS);
		}
		return ca_emit_app_verdict(skb, flow->app_verdict);
	}

	if (!ca_admit_classification(config, *subject_id, now) ||
	    !ca_pending_reserve(config->max_pending_entries))
		return ca_load_shed(skb, config, &flow_key, *subject_id, now);

	initial.first_seen_ns = now;
	initial.last_seen_ns = now;
	initial.app_policy_generation = config->app_policy_generation;
	initial.classifier_generation = config->classifier_generation;
	initial.packets_examined = 1;
	initial.bytes_examined = examined;
	initial.class_id = CA_CLASS_UNCLASSIFIED;
	initial.classification_state = CA_FLOW_PENDING;
	initial.app_verdict = config->provisional_app_verdict;
	if (bpf_map_update_elem(&ca_flows, &flow_key, &initial, BPF_NOEXIST)) {
		ca_pending_release();
		return ca_load_shed(skb, config, &flow_key, *subject_id, now);
	}
	ca_stat_inc(CA_STAT_FLOWS_TOTAL);
	ca_stat_inc(CA_STAT_FLOWS_PENDING);
	ca_stat_inc(CA_STAT_CLASSIFICATION_PACKETS);
	ca_stat_add(CA_STAT_CLASSIFICATION_BYTES, examined);

	bool terminal = ca_try_terminal(config, &initial, &flow_key, *subject_id, now);
	if (bpf_map_update_elem(&ca_flows, &flow_key, &initial, BPF_EXIST)) {
		ca_pending_release();
		bpf_map_delete_elem(&ca_flows, &flow_key);
		return ca_load_shed(skb, config, &flow_key, *subject_id, now);
	}
	if (terminal) {
		ca_pending_release();
		ca_record_terminal(&initial,
			initial.classification_state == CA_FLOW_UNCLASSIFIED_FINAL);
	}

	/* The first admitted packet uses the explicit optimistic V4.1 verdict. */
	return ca_emit_app_verdict(skb, config->provisional_app_verdict);
}

char LICENSE[] SEC("license") = "Apache-2.0";
