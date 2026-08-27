#!/usr/bin/ucode
// SPDX-License-Identifier: Apache-2.0

import * as policy from 'client_access.policy';

let failures = 0;

function assert_equal(actual, expected, name) {
	if (sprintf('%J', actual) == sprintf('%J', expected)) {
		printf('ok - %s\n', name);
		return;
	}

	warn(`not ok - ${name}\n  expected: ${sprintf('%J', expected)}\n  actual:   ${sprintf('%J', actual)}\n`);
	failures++;
}

function epoch(year, mon, mday, hour, min, sec) {
	return timegm({ year, mon, mday, hour, min, sec: sec ?? 0 });
}

const monday_0900 = epoch(2026, 8, 24, 9, 0);
const monday_1000 = epoch(2026, 8, 24, 10, 0);
const tuesday_0100 = epoch(2026, 8, 25, 1, 0);
const tuesday_0700 = epoch(2026, 8, 25, 7, 0);

let result = policy.compile({ mode: 'blacklist', devices: [] }, monday_0900);
assert_equal(result.enabled, false, 'global enforcement is disabled by default');

result = policy.compile({
	enabled: '1',
	mode: 'blacklist',
	devices: [
		{ name: 'blocked', enabled: '1', mac: '02:00:00:00:00:01', policy: 'always_block' },
		{ name: 'allowed', enabled: '1', mac: '02:00:00:00:00:02', policy: 'always_allow' },
	],
}, monday_0900);
assert_equal(result.default_verdict, 'allow', 'blacklist default is allow');
assert_equal(result.exceptions, [ '02:00:00:00:00:01' ], 'blacklist set contains denied exceptions');

result = policy.compile({
	enabled: '1',
	mode: 'whitelist',
	devices: [
		{ name: 'allowed', enabled: '1', mac: '02:00:00:00:00:02', policy: 'always_allow' },
		{ name: 'blocked', enabled: '1', mac: '02:00:00:00:00:01', policy: 'always_block' },
	],
}, monday_0900);
assert_equal(result.default_verdict, 'deny', 'whitelist default is deny');
assert_equal(result.exceptions, [ '02:00:00:00:00:02' ], 'whitelist set contains allowed exceptions');

result = policy.compile({
	enabled: '1',
	mode: 'blacklist',
	devices: [ {
		name: 'school tablet',
		enabled: '1',
		mac: '02:00:00:00:00:03',
		policy: 'allow_during',
		schedule: 'mon@08:00-10:00',
	} ],
}, monday_0900);
assert_equal(result.clients[0].verdict, 'allow', 'allow-during is active inside the window');
assert_equal(result.next_transition, monday_1000, 'next global transition is the closing boundary');
assert_equal(policy.safety_delay_ms(result, monday_0900, 60), 60000,
	'safety wakeup wins when the next transition is far away');

result = policy.compile({
	enabled: '1',
	mode: 'blacklist',
	devices: [ {
		name: 'short boundary',
		enabled: '1',
		mac: '02:00:00:00:00:08',
		policy: 'allow_during',
		schedule: 'mon@08:00-09:01',
	} ],
}, epoch(2026, 8, 24, 9, 0, 30));
assert_equal(policy.safety_delay_ms(result, epoch(2026, 8, 24, 9, 0, 30), 60), 30000,
	'exact transition wakes the global timer before the safety interval');

result = policy.compile({
	enabled: '1',
	mode: 'blacklist',
	devices: [ {
		name: 'overnight device',
		enabled: '1',
		mac: '02:00:00:00:00:04',
		policy: 'block_during',
		schedule: 'mon@23:00-07:00',
	} ],
}, tuesday_0100);
assert_equal(result.clients[0].verdict, 'deny', 'cross-midnight block window remains active');
assert_equal(result.next_transition, tuesday_0700, 'cross-midnight window closes on the next day');

result = policy.compile({
	enabled: '1',
	mode: 'whitelist',
	devices: [
		{ name: 'first', enabled: '1', mac: '02:00:00:00:00:05', policy: 'always_allow' },
		{ name: 'second', enabled: '1', mac: '02:00:00:00:00:05', policy: 'always_block' },
	],
}, monday_0900);
assert_equal(result.exceptions, [], 'deny wins when duplicate MAC policies conflict');
assert_equal(length(result.warnings), 1, 'duplicate conflicting MAC emits a warning');

result = policy.compile({
	enabled: '1',
	mode: 'whitelist',
	devices: [
		{ name: 'allowed', enabled: '1', mac: '02:00:00:00:00:07', policy: 'always_allow' },
		{ name: 'disabled', enabled: '0', mac: '02:00:00:00:00:07', policy: 'always_block' },
		{ name: 'inherited', enabled: '1', mac: '02:00:00:00:00:07', policy: 'inherit' },
	],
}, monday_0900);
assert_equal(result.exceptions, [ '02:00:00:00:00:07' ], 'disabled and inherited entries do not override explicit policy');
assert_equal(result.warnings, [], 'inactive duplicate entries do not emit conflicts');

result = policy.compile({
	enabled: '1',
	mode: 'blacklist',
	devices: [ {
		name: 'scheduled device',
		enabled: '1',
		mac: '02:00:00:00:00:06',
		policy: 'allow_during',
		schedule: '*@00:00-23:59',
	} ],
}, 0);
assert_equal(result.clock_valid, false, 'pre-2020 clock is considered invalid');
assert_equal(result.clients[0].verdict, 'deny', 'scheduled policy fails closed with invalid clock');
assert_equal(result.exceptions, [ '02:00:00:00:00:06' ], 'fail-closed device is materialized in blacklist set');

assert_equal(policy.normalize_mac('AA:BB:CC:DD:EE:FF'), 'aa:bb:cc:dd:ee:ff', 'MAC addresses are normalized');
assert_equal(policy.normalize_mac('invalid'), null, 'invalid MAC is rejected');

if (failures)
	exit(1);

printf('1..%d\n', 20);
