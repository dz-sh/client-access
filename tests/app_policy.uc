#!/usr/bin/ucode
// SPDX-License-Identifier: Apache-2.0

import * as nft_policy from 'client_access.policy';
import * as app_policy from 'client_access.app_policy';
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

function config(enabled, rules, identities) {
	return {
		schema_version: '4',
		app_filter_enabled: enabled ?? '1',
		unknown_app_verdict: 'allow',
		provisional_app_verdict: 'allow',
		identities: identities ?? [
			{ id: 'alice', name: 'Alice', subject_id: '1001' },
		],
		app_classes: [
			{ id: '10', name: 'Video', kind: 'category' },
			{ id: '100', name: 'YouTube', kind: 'application', parent_id: '10' },
			{ id: '101', name: 'TikTok', kind: 'application', parent_id: '10' },
		],
		app_rules: rules ?? [],
	};
}

function verdict(compiled, subject_id, class_id) {
	for (let policy in compiled.policies)
		if (policy.subject_id == subject_id && policy.class_id == class_id)
			return policy.verdict;
	return null;
}

const monday_0900 = epoch(2026, 8, 24, 9, 0);
const monday_1000 = epoch(2026, 8, 24, 10, 0);

let result = app_policy.compile(config('0'), monday_0900);
assert_equal(result.requested_enabled, false, 'application workflow is disabled independently');
assert_equal(result.enabled, false, 'disabled application workflow remains inactive');
assert_equal(result.unknown_app_verdict, 'allow', 'unknown subject has an independent neutral app verdict');
assert_equal(result.provisional_app_verdict, 'allow', 'V4.1 provisional app verdict is allow');

result = app_policy.compile(config('1'), monday_0900);
assert_equal(result.enabled, true, 'valid application workflow can be enabled');
assert_equal(verdict(result, 1001, 100), 'allow', 'missing app rule uses app-policy default allow');
assert_equal(verdict(result, 1001, 1), 'allow', 'unclassified traffic uses app-policy default allow');

result = app_policy.compile(config('1', [
	{ identity: 'alice', class: '10', verdict: 'deny', activation: 'always_active' },
	{ identity: 'alice', class: '100', verdict: 'allow', activation: 'always_active' },
]), monday_0900);
assert_equal(verdict(result, 1001, 100), 'allow', 'exact app allow overrides category deny');
assert_equal(verdict(result, 1001, 101), 'deny', 'category deny applies to app without exact rule');

result = app_policy.compile(config('1', [
	{ identity: 'alice', class: '100', verdict: 'allow', activation: 'always_active' },
	{ identity: 'alice', class: '100', verdict: 'deny', activation: 'always_active' },
]), monday_0900);
assert_equal(verdict(result, 1001, 100), 'deny', 'deny wins among active rules at equal specificity');

result = app_policy.compile(config('1', [
	{ identity: 'alice', class: 'default', verdict: 'deny', activation: 'always_active' },
	{ identity: 'alice', class: 'unclassified', verdict: 'allow', activation: 'always_active' },
]), monday_0900);
assert_equal(verdict(result, 1001, 101), 'deny', 'app-policy default applies to unmatched classified apps');
assert_equal(verdict(result, 1001, 1), 'allow', 'unclassified rule overrides app-policy default');

result = app_policy.compile(config('1', [
	{
		identity: 'alice',
		class: '100',
		verdict: 'deny',
		activation: 'active_during',
		schedule: 'mon@08:00-10:00',
	},
]), monday_0900);
assert_equal(verdict(result, 1001, 100), 'deny', 'scheduled app rule contributes its own deny verdict');
assert_equal(result.next_transition, monday_1000, 'app rule contributes a global scheduler boundary');

result = app_policy.compile(config('1', [
	{
		identity: 'alice',
		class: '100',
		verdict: 'allow',
		activation: 'active_during',
		schedule: 'invalid',
	},
]), monday_0900);
assert_equal(result.enabled, false, 'invalid scheduled app policy is not published');
assert_equal(verdict(result, 1001, 100), 'deny', 'invalid scheduled app rule compiles to fail-closed deny for preview');

result = app_policy.compile(config('1', [], [
	{ id: 'alice', subject_id: '1001' },
	{ id: 'bob', subject_id: '1001' },
]), monday_0900);
assert_equal(result.enabled, false, 'duplicate subject IDs prevent app-policy publication');
assert_equal(length(result.errors) > 0, true, 'duplicate subject IDs are reported');

result = app_policy.compile(config('1'), monday_0900);
let projection = model.project_subjects(result, [
	{ identity: 'alice', type: 'mac', value: '02:00:00:00:00:01' },
	{ identity: 'alice', type: 'mac', value: '02:00:00:00:00:02' },
]);
assert_equal(projection.selectors, [
	{ mac: '02:00:00:00:00:01', subject_id: 1001 },
	{ mac: '02:00:00:00:00:02', subject_id: 1001 },
], 'multiple MAC bindings project to one stable subject ID');

const nft = nft_policy.compile({
	schema_version: '4',
	enabled: '1',
	mode: 'blacklist',
	identities: [ { id: 'alice', activation: 'always_active' } ],
}, monday_0900);
result = app_policy.compile(config('1', [
	{ identity: 'alice', class: '100', verdict: 'allow', activation: 'always_active' },
]), monday_0900);
const diagnostics = app_policy.consistency(nft, result);
assert_equal(length(diagnostics.warnings) > 0, true,
	'cross-workflow consistency analysis warns without changing either verdict');
assert_equal(nft.identities[0].verdict, 'deny', 'consistency analysis does not rewrite nft verdict');
assert_equal(verdict(result, 1001, 100), 'allow', 'consistency analysis does not rewrite app verdict');

if (failures)
	exit(1);

printf('1..%d\n', assertions);
