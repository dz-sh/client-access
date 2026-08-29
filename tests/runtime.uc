// SPDX-License-Identifier: Apache-2.0

import { offload_refusal } from 'client_access.runtime';

function assert_equal(actual, expected, message) {
	if (actual != expected) {
		warn(`FAIL: ${message}: expected ${expected}, got ${actual}\n`);
		exit(1);
	}
}

const disabled = { flow_offloading: false, flow_offloading_hw: false };

assert_equal(offload_refusal(disabled, true,
	'table inet fw4 { chain forward { counter accept } }'), null,
	'ordinary nftables ruleset permits activation');
assert_equal(offload_refusal(disabled, false, ''), 'unverifiable_ruleset',
	'unreadable active ruleset fails closed');
assert_equal(offload_refusal({ flow_offloading: true }, true, ''),
	'firewall_configuration', 'software flow offload refuses activation');
assert_equal(offload_refusal({ flow_offloading_hw: true }, true, ''),
	'firewall_configuration', 'hardware flow offload refuses activation');
assert_equal(offload_refusal(disabled, true,
	'type filter hook forward priority filter; ip protocol tcp flow add @ft'),
	'custom_flowtable', 'custom flow add rule refuses activation');
assert_equal(offload_refusal(disabled, true,
	'ip6 nexthdr tcp flow\n\toffload   @fastpath'),
	'custom_flowtable', 'custom flow offload rule refuses activation');

print('runtime policy tests passed\n');
