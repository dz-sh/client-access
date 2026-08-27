#!/usr/bin/ucode
// SPDX-License-Identifier: Apache-2.0

import * as policy from 'client_access.policy';
import * as model from 'client_access.model';

let failures = 0, assertions = 0;

function assert_equal(actual, expected, name) {
	assertions++;
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

function config(mode, identities, enabled) {
	return {
		schema_version: '2',
		enabled: enabled ?? '1',
		mode,
		identities: identities ?? [],
	};
}

const monday_0900 = epoch(2026, 8, 24, 9, 0);
const monday_1000 = epoch(2026, 8, 24, 10, 0);
const tuesday_0100 = epoch(2026, 8, 25, 1, 0);
const tuesday_0700 = epoch(2026, 8, 25, 7, 0);
const saturday_1000 = epoch(2026, 8, 29, 10, 0);

let result = policy.compile(config('blacklist', [], '0'), monday_0900);
assert_equal(result.enabled, false, 'global enforcement is disabled by default');
assert_equal(result.default_verdict, 'allow', 'blacklist default is allow');
assert_equal(result.exception_verdict, 'deny', 'blacklist exception is deny');

result = policy.compile({ enabled: '1', mode: 'blacklist', identities: [] }, monday_0900);
assert_equal(result.schema_supported, false, 'missing schema is rejected');
assert_equal(result.enabled, false, 'unsupported schema deactivates enforcement');

result = policy.compile(config('blacklist', [
	{ id: 'blocked', name: 'Blocked', activation: 'always_active' },
	{ id: 'prepared', name: 'Prepared', activation: 'inactive' },
]), monday_0900);
assert_equal(result.identities[0].verdict, 'deny', 'always-active blacklist identity is denied');
assert_equal(result.identities[0].effective_active, true, 'always-active identity participates in projection');
assert_equal(result.identities[0].next_transition, null, 'always-active identity has no time boundary');
assert_equal(result.identities[1].verdict, 'allow', 'inactive identity follows blacklist default');

let projection = model.project(result, [
	{ section: 'b1', identity: 'blocked', type: 'mac', value: '02:00:00:00:00:01' },
	{ section: 'b2', identity: 'prepared', type: 'mac', value: '02:00:00:00:00:02' },
]);
assert_equal(projection.exceptions, [ '02:00:00:00:00:01' ], 'blacklist set contains always-active identity binding');

result = policy.compile(config('whitelist', [
	{ id: 'allowed', name: 'Allowed', activation: 'always_active' },
	{ id: 'prepared', name: 'Prepared', activation: 'inactive' },
]), monday_0900);
projection = model.project(result, [
	{ section: 'b1', identity: 'allowed', type: 'mac', value: '02:00:00:00:00:03' },
	{ section: 'b2', identity: 'prepared', type: 'mac', value: '02:00:00:00:00:04' },
]);
assert_equal(result.default_verdict, 'deny', 'whitelist default is deny');
assert_equal(result.exception_verdict, 'allow', 'whitelist exception is allow');
assert_equal(projection.exceptions, [ '02:00:00:00:00:03' ], 'whitelist set contains always-active identity binding');

result = policy.compile(config('blacklist', [ {
	id: 'daily',
	activation: 'active_during',
	schedule: '*@08:00-10:00',
} ]), monday_0900);
assert_equal(result.identities[0].effective_active, true, 'daily schedule matches on Monday');
assert_equal(result.identities[0].verdict, 'deny', 'active blacklist schedule selects exception verdict');
assert_equal(result.next_transition, monday_1000, 'daily schedule contributes its closing boundary');

result = policy.compile(config('whitelist', [ {
	id: 'weekly',
	activation: 'active_during',
	schedule: [
		'mon,tue,wed,thu,fri@08:00-09:00',
		'sat,sun@09:00-23:00',
	],
} ]), saturday_1000);
assert_equal(result.identities[0].effective_active, true, 'weekend-specific schedule matches');
assert_equal(result.identities[0].verdict, 'allow', 'active whitelist schedule selects exception verdict');

result = policy.compile(config('blacklist', [ {
	id: 'split_day',
	activation: 'active_during',
	schedule: [ 'mon@08:00-10:00', 'mon@14:00-20:00' ],
} ]), monday_0900);
assert_equal(result.identities[0].effective_active, true, 'multiple same-day windows are combined as a union');

result = policy.compile(config('blacklist', [ {
	id: 'overnight',
	activation: 'active_during',
	schedule: 'mon@23:00-07:00',
} ]), tuesday_0100);
assert_equal(result.identities[0].effective_active, true, 'cross-midnight schedule remains active on the next day');
assert_equal(result.next_transition, tuesday_0700, 'cross-midnight schedule closes on the next day');

result = policy.compile(config('blacklist', [ {
	id: 'short_boundary',
	activation: 'active_during',
	schedule: 'mon@08:00-09:01',
} ]), epoch(2026, 8, 24, 9, 0, 30));
assert_equal(policy.safety_delay_ms(result, epoch(2026, 8, 24, 9, 0, 30), 60), 30000,
	'exact boundary wakes the global timer before the safety interval');

result = policy.compile(config('blacklist', [ {
	id: 'bad_clock',
	activation: 'active_during',
	schedule: '*@00:00-23:59',
} ]), 0);
assert_equal(result.clock_valid, false, 'pre-2020 clock is considered invalid');
assert_equal(result.identities[0].verdict, 'deny', 'invalid clock fails closed');
projection = model.project(result, [
	{ identity: 'bad_clock', type: 'mac', value: '02:00:00:00:00:05' },
]);
assert_equal(projection.exceptions, [ '02:00:00:00:00:05' ], 'blacklist fail-closed result enters exception set');

result = policy.compile(config('whitelist', [ {
	id: 'bad_schedule',
	activation: 'active_during',
	schedule: 'not-a-window',
} ]), monday_0900);
assert_equal(result.identities[0].verdict, 'deny', 'invalid whitelist schedule fails closed');
projection = model.project(result, [
	{ identity: 'bad_schedule', type: 'mac', value: '02:00:00:00:00:06' },
]);
assert_equal(projection.exceptions, [], 'whitelist fail-closed result remains outside allow set');

result = policy.compile(config('blacklist', [
	{ id: 'first', activation: 'always_active' },
	{ id: 'second', activation: 'inactive' },
]), monday_0900);
projection = model.project(result, [
	{ section: 'b1', identity: 'first', type: 'mac', value: '02:00:00:00:00:07' },
	{ section: 'b2', identity: 'second', type: 'mac', value: '02:00:00:00:00:07' },
]);
assert_equal(length(projection.errors), 1, 'duplicate MAC ownership is reported');
assert_equal(projection.exceptions, [ '02:00:00:00:00:07' ], 'duplicate MAC ownership fails closed in blacklist mode');

result = policy.compile(config('blacklist', [
	{ id: 'multi_mac', activation: 'always_active' },
]), monday_0900);
projection = model.project(result, [
	{ identity: 'multi_mac', type: 'mac', value: '02:00:00:00:00:08' },
	{ identity: 'multi_mac', type: 'mac', value: '02:00:00:00:00:09' },
]);
assert_equal(projection.exceptions,
	[ '02:00:00:00:00:08', '02:00:00:00:00:09' ],
	'multiple bindings share one effective identity decision');

projection = model.project(result, [
	{ identity: 'missing', type: 'mac', value: '02:00:00:00:00:0a' },
]);
assert_equal(length(projection.errors), 1, 'dangling identity binding is reported');
assert_equal(projection.exceptions, [ '02:00:00:00:00:0a' ], 'dangling binding fails closed in blacklist mode');

assert_equal(model.normalize_mac('AA:BB:CC:DD:EE:FF'), 'aa:bb:cc:dd:ee:ff', 'MAC addresses are normalized');
assert_equal(model.normalize_mac('invalid'), null, 'invalid MAC is rejected');

if (failures)
	exit(1);

printf('1..%d\n', assertions);
