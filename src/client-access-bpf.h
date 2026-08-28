// SPDX-License-Identifier: Apache-2.0
#ifndef CLIENT_ACCESS_BPF_H
#define CLIENT_ACCESS_BPF_H

#include <linux/types.h>

#define CA_PIN_ROOT "/sys/fs/bpf/client_access"
#define CA_PROGRAM_PIN CA_PIN_ROOT "/ca_ingress"

#define CA_CLASS_DEFAULT 0
#define CA_CLASS_UNCLASSIFIED 1

/* Reserved skb mark namespace for the independent application workflow. */
#define CA_APP_MARK_DENY 0x20000000U
#define CA_APP_MARK_VALID 0x40000000U
#define CA_APP_MARK_MASK (CA_APP_MARK_DENY | CA_APP_MARK_VALID)

#define CA_MAX_SUBJECTS 1024
#define CA_MAX_POLICY_ENTRIES 8192
#define CA_MAX_FLOWS 16384
#define CA_MAX_PORT_HINTS 1024
#define CA_MAX_IPV4_HINTS 4096
#define CA_MAX_IPV6_HINTS 4096
#define CA_MAX_DNS4_HINTS 4096
#define CA_MAX_DNS6_HINTS 4096
#define CA_STATS_COUNT 32

#define CA_DEFAULT_MAX_PACKETS 1
#define CA_DEFAULT_MAX_BYTES 256
#define CA_DEFAULT_MAX_AGE_MS 200
#define CA_DEFAULT_MAX_PENDING 256
#define CA_DEFAULT_MAX_NEW_PER_SECOND 512
#define CA_DEFAULT_MAX_NEW_PER_SUBJECT_SECOND 64

enum ca_verdict {
	CA_VERDICT_ALLOW = 0,
	CA_VERDICT_DENY = 1,
};

enum ca_classification_state {
	CA_FLOW_PENDING = 0,
	CA_FLOW_CLASSIFIED = 1,
	CA_FLOW_UNCLASSIFIED_FINAL = 2,
};

enum ca_class_kind {
	CA_CLASS_KIND_NONE = 0,
	CA_CLASS_KIND_EXACT = 1,
	CA_CLASS_KIND_CATEGORY = 2,
};

enum ca_stat_id {
	CA_STAT_PACKETS = 0,
	CA_STAT_FLOWS_TOTAL = 1,
	CA_STAT_FLOWS_UNCLASSIFIED = 2,
	CA_STAT_FLOW_APP_ALLOW_VERDICTS = 3,
	CA_STAT_FLOW_APP_DENY_VERDICTS = 4,
	CA_STAT_FLOW_MAP_FULL = 5,
	CA_STAT_POLICY_REEVALUATIONS = 6,
	CA_STAT_UNKNOWN_SUBJECT_PACKETS = 7,
	CA_STAT_FLOWS_PENDING = 8,
	CA_STAT_FLOWS_CLASSIFIED_EXACT = 9,
	CA_STAT_FLOWS_CLASSIFIED_CATEGORY = 10,
	CA_STAT_FLOWS_UNCLASSIFIED_BUDGET = 11,
	CA_STAT_FLOWS_UNCLASSIFIED_LOAD_SHED = 12,
	CA_STAT_CLASSIFICATION_PACKETS = 13,
	CA_STAT_CLASSIFICATION_BYTES = 14,
	CA_STAT_CLASSIFICATION_ADMISSION_DENIED = 15,
	CA_STAT_PACKET_APP_ALLOW_VERDICTS = 16,
	CA_STAT_PACKET_APP_DENY_VERDICTS = 17,
	CA_STAT_FLOW_READMISSIONS = 18,
	CA_STAT_FLOW_MAP_EVICTIONS = 19,
	CA_STAT_PARSE_UNSUPPORTED = 20,
	CA_STAT_CLASSIFIER_CONFLICTS = 21,
	CA_STAT_DNS_HINT_EXPIRED = 22,
	CA_STAT_CLASSIFIER_RESTARTS = 23,
};

struct ca_config {
	__u32 enabled;
	__u32 active_slot;
	__u32 app_policy_generation;
	__u32 classifier_generation;
	__u8 unknown_subject_app_verdict;
	__u8 provisional_app_verdict;
	__u16 max_packets_inspected;
	__u32 max_bytes_examined;
	__u32 max_classification_age_ms;
	__u32 max_pending_entries;
	__u32 max_new_classifications_per_second;
	__u32 per_subject_new_classification_rate;
};

struct ca_mac_key {
	__u8 addr[6];
};

struct ca_policy_key {
	__u32 subject_id;
	__u16 class_id;
	__u16 reserved;
};

struct ca_class_hint {
	__u16 class_id;
	__u16 category_id;
	__u8 kind;
	__u8 reserved[3];
};

struct ca_port_key {
	__u8 ip_proto;
	__u8 reserved;
	__be16 dst_port;
};

struct ca_ipv4_lpm_key {
	__u32 prefixlen;
	__be32 addr;
};

struct ca_ipv6_lpm_key {
	__u32 prefixlen;
	__u8 addr[16];
};

struct ca_ipv6_addr_key {
	__u8 addr[16];
};

struct ca_dns_hint {
	__u64 expires_ns;
	__u32 classifier_generation;
	__u32 reserved;
	struct ca_class_hint hint;
};

struct ca_flow_key {
	__u32 subject_id;
	__u16 eth_proto;
	__u8 ip_proto;
	__u8 reserved;
	__u16 src_port;
	__u16 dst_port;
	union {
		struct {
			__u32 src;
			__u32 dst;
		} v4;
		struct {
			__u8 src[16];
			__u8 dst[16];
		} v6;
	} addr;
};

struct ca_flow_state {
	__u64 first_seen_ns;
	__u64 last_seen_ns;
	__u32 app_policy_generation;
	__u32 classifier_generation;
	__u32 packets_examined;
	__u32 bytes_examined;
	__u16 class_id;
	__u8 classification_state;
	__u8 app_verdict;
	__u8 class_kind;
	__u8 reserved[3];
};

#endif
