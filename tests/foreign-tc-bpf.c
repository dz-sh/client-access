// SPDX-License-Identifier: Apache-2.0
#define KBUILD_MODNAME "client_access_foreign_test"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

SEC("classifier")
int foreign_tc(struct __sk_buff *skb)
{
	(void)skb;
	return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "Apache-2.0";
