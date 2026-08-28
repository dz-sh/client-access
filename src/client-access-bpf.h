// SPDX-License-Identifier: Apache-2.0
#ifndef CLIENT_ACCESS_BPF_H
#define CLIENT_ACCESS_BPF_H

#include <linux/types.h>

#define CA_PIN_ROOT "/sys/fs/bpf/client_access"
#define CA_PROGRAM_PIN CA_PIN_ROOT "/ca_ingress"

#define CA_CLASS_DEFAULT 0
#define CA_CLASS_UNCLASSIFIED 1

#define CA_MAX_SUBJECTS 1024
#define CA_MAX_POLICY_ENTRIES 8192
#define CA_MAX_FLOWS 16384
#define CA_STATS_COUNT 16

enum ca_verdict {
	CA_VERDICT_ALLOW = 0,
	CA_VERDICT_DENY = 1,
};

enum ca_classification_state {
	CA_FLOW_PENDING = 0,
	CA_FLOW_CLASSIFIED = 1,
	CA_FLOW_UNCLASSIFIED_FINAL = 2,
};

enum ca_stat_id {
	CA_STAT_PACKETS = 0,
	CA_STAT_FLOWS_TOTAL = 1,
	CA_STAT_FLOWS_UNCLASSIFIED = 2,
	CA_STAT_FLOWS_ALLOWED = 3,
	CA_STAT_FLOWS_DENIED = 4,
	CA_STAT_FLOW_MAP_FULL = 5,
	CA_STAT_POLICY_REEVALUATIONS = 6,
	CA_STAT_UNKNOWN_SUBJECT_PACKETS = 7,
};

struct ca_config {
	__u32 enabled;
	__u32 active_slot;
	__u32 app_policy_generation;
	__u32 classifier_generation;
	__u8 unknown_app_verdict;
	__u8 provisional_app_verdict;
	__u8 reserved[6];
};

struct ca_mac_key {
	__u8 addr[6];
};

struct ca_policy_key {
	__u32 subject_id;
	__u16 class_id;
	__u16 reserved;
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
	__u16 class_id;
	__u8 classification_state;
	__u8 app_verdict;
};

#endif
