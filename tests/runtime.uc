// SPDX-License-Identifier: Apache-2.0

import { offload_capability } from 'client_access.runtime';

function assert_equal(actual, expected, message) {
	if (actual != expected) {
		warn(`FAIL: ${message}: expected ${expected}, got ${actual}\n`);
		exit(1);
	}
}

const disabled = { flow_offloading: false, flow_offloading_hw: false };
const software = { flow_offloading: true, flow_offloading_hw: false };
const hardware = { flow_offloading: true, flow_offloading_hw: true };
const canonical = `table inet fw4 {
flowtable ft {
hook ingress priority filter
devices = { "lan", "wan" }
counter
}
chain forward {
meta l4proto { tcp, udp } flow add @ft
}
}`;

assert_equal(offload_capability(disabled, true, '', false).mode,
	'NO_OFFLOAD', 'disabled offload preserves the normal datapath');
assert_equal(offload_capability(disabled, true, '', true).mode,
	'SFO_AVAILABLE', 'installed SFO remains optional while offload is disabled');
assert_equal(offload_capability(disabled, false, '', true).mode,
	'OFFLOAD_UNVERIFIABLE', 'unreadable ruleset is never trusted');
assert_equal(offload_capability(software, true, canonical, false).mode,
	'SFO_BACKEND_MISSING', 'canonical SFO requires its optional backend');
const active = offload_capability(software, true, canonical, true);
assert_equal(active.mode, 'SFO_ACTIVE', 'canonical fw4 SFO is supported');
assert_equal(active.tracking_required, true, 'active SFO requires semantic tracking');
assert_equal(offload_capability(hardware, true, canonical, true).mode,
	'HFO_UNSUPPORTED', 'hardware flow offload is explicitly unsupported');
assert_equal(offload_capability(software, true,
	replace(canonical, 'counter', 'flags offload'), true).mode,
	'HFO_UNSUPPORTED', 'runtime hardware flag is explicitly unsupported');
assert_equal(offload_capability(software, true,
	replace(canonical, /ft/g, 'fastpath'), true).mode,
	'CUSTOM_OFFLOAD_UNSUPPORTED', 'custom flowtable is unsupported');
assert_equal(offload_capability(disabled, true, canonical, true).mode,
	'CUSTOM_OFFLOAD_UNSUPPORTED', 'out-of-band offload is not trusted');
assert_equal(offload_capability(software, true, 'table inet fw4 { }', true).mode,
	'OFFLOAD_UNVERIFIABLE', 'missing canonical runtime topology is degraded');

print('runtime policy tests passed\n');
