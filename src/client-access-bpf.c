// SPDX-License-Identifier: Apache-2.0
#define KBUILD_MODNAME "client_access"

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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ca_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_config SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CA_MAX_FLOWS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ca_flow_key);
	__type(value, struct ca_flow_state);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CA_STATS_COUNT);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ca_stats SEC(".maps");

static __always_inline void ca_stat_inc(__u32 id)
{
	__u64 *value = bpf_map_lookup_elem(&ca_stats, &id);

	if (value)
		(*value)++;
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

static __always_inline int ca_enforce(__u8 verdict)
{
	if (verdict == CA_VERDICT_DENY) {
		ca_stat_inc(CA_STAT_FLOWS_DENIED);
		return TC_ACT_SHOT;
	}
	ca_stat_inc(CA_STAT_FLOWS_ALLOWED);
	return TC_ACT_UNSPEC;
}

static __always_inline int ca_parse_flow(void *data, void *data_end,
						 struct ca_flow_key *key,
						 struct ca_mac_key *mac)
{
	struct ethhdr *eth = data;
	__u64 offset = sizeof(*eth);
	__be16 proto;

	if ((void *)(eth + 1) > data_end)
		return -1;
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
			return -1;
		proto = vlan->encapsulated_proto;
		offset += sizeof(*vlan);
	}

	key->eth_proto = proto;
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + offset;
		__u32 ihl;

		if ((void *)(ip + 1) > data_end || ip->version != 4)
			return -1;
		ihl = ip->ihl * 4;
		if (ihl < sizeof(*ip) || data + offset + ihl > data_end)
			return -1;
		if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))
			return -1;
		key->ip_proto = ip->protocol;
		key->addr.v4.src = ip->saddr;
		key->addr.v4.dst = ip->daddr;
		offset += ihl;
	}
	else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + offset;

		if ((void *)(ip6 + 1) > data_end || ip6->version != 6)
			return -1;
		key->ip_proto = ip6->nexthdr;
		__builtin_memcpy(key->addr.v6.src, &ip6->saddr, 16);
		__builtin_memcpy(key->addr.v6.dst, &ip6->daddr, 16);
		offset += sizeof(*ip6);
	}
	else {
		return -1;
	}

	if (key->ip_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = data + offset;

		if ((void *)(tcp + 1) > data_end)
			return -1;
		key->src_port = tcp->source;
		key->dst_port = tcp->dest;
	}
	else if (key->ip_proto == IPPROTO_UDP) {
		struct udphdr *udp = data + offset;

		if ((void *)(udp + 1) > data_end)
			return -1;
		key->src_port = udp->source;
		key->dst_port = udp->dest;
	}

	return 0;
}

SEC("tc")
int ca_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ca_flow_key flow_key = {};
	struct ca_mac_key mac = {};
	struct ca_flow_state *flow;
	struct ca_config *config;
	struct ca_flow_state initial = {};
	__u32 zero = 0;
	__u32 *subject_id;
	__u64 now;
	__u8 verdict;

	config = bpf_map_lookup_elem(&ca_config, &zero);
	if (!config || !config->enabled)
		return TC_ACT_UNSPEC;
	ca_stat_inc(CA_STAT_PACKETS);

	if (ca_parse_flow(data, data_end, &flow_key, &mac))
		return TC_ACT_UNSPEC;
	subject_id = ca_subject_lookup(config, &mac);
	if (!subject_id) {
		ca_stat_inc(CA_STAT_UNKNOWN_SUBJECT_PACKETS);
		return ca_enforce(config->unknown_app_verdict);
	}
	flow_key.subject_id = *subject_id;
	now = bpf_ktime_get_ns();

	flow = bpf_map_lookup_elem(&ca_flows, &flow_key);
	if (flow) {
		flow->last_seen_ns = now;
		if (flow->app_policy_generation != config->app_policy_generation) {
			flow->app_verdict = ca_policy_verdict(config, *subject_id,
										 flow->class_id);
			flow->app_policy_generation = config->app_policy_generation;
			ca_stat_inc(CA_STAT_POLICY_REEVALUATIONS);
		}
		return ca_enforce(flow->app_verdict);
	}

	verdict = ca_policy_verdict(config, *subject_id, CA_CLASS_UNCLASSIFIED);
	initial.first_seen_ns = now;
	initial.last_seen_ns = now;
	initial.app_policy_generation = config->app_policy_generation;
	initial.classifier_generation = config->classifier_generation;
	initial.class_id = CA_CLASS_UNCLASSIFIED;
	initial.classification_state = CA_FLOW_UNCLASSIFIED_FINAL;
	initial.app_verdict = verdict;
	if (bpf_map_update_elem(&ca_flows, &flow_key, &initial, BPF_NOEXIST))
		ca_stat_inc(CA_STAT_FLOW_MAP_FULL);
	else {
		ca_stat_inc(CA_STAT_FLOWS_TOTAL);
		ca_stat_inc(CA_STAT_FLOWS_UNCLASSIFIED);
	}

	return ca_enforce(verdict);
}

char LICENSE[] SEC("license") = "Apache-2.0";
