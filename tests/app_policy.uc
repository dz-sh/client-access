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
		unknown_subject_app_verdict: 'allow',
		provisional_app_verdict: 'allow',
		identities: identities ?? [
			{ id: 'alice', name: 'Alice', subject_id: '1001' },
		],
		app_classes: [
			{ id: '10', name: 'Video', kind: 'category', tcp_ports: [ '443' ] },
			{
				id: '100', name: 'YouTube', kind: 'application', parent_id: '10',
				domains: [ '*.youtube.example' ],
				ipv4_prefixes: [ '192.0.2.0/24' ],
			},
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
assert_equal(result.unknown_subject_app_verdict, 'allow', 'unknown subject has an independent neutral app verdict');
assert_equal(result.provisional_app_verdict, 'allow', 'V4.1 provisional app verdict is allow');

result = app_policy.compile(config('1'), monday_0900);
assert_equal(result.enabled, true, 'valid application workflow can be enabled');
assert_equal(verdict(result, 1001, 100), 'allow', 'missing app rule uses app-policy default allow');
assert_equal(verdict(result, 1001, 1), 'allow', 'unclassified traffic uses app-policy default allow');
assert_equal(result.resource_limits, {
	max_packets_inspected: 1,
	max_bytes_examined: 256,
	max_classification_age_ms: 200,
	max_pending_entries: 256,
	max_new_classifications_per_second: 512,
	per_subject_new_classification_rate: 64,
	signature_table_memory_limit: 262144,
}, 'V4.1 compiles explicit bounded resource defaults');
assert_equal(result.classifier.ports, [ {
	protocol: 6,
	port: 443,
	hint: { class_id: 10, category_id: 10, kind: 2 },
} ], 'port-only evidence compiles to a category hint');
assert_equal(result.classifier.ipv4_prefixes, [ {
	prefix: '192.0.2.0/24',
	hint: { class_id: 100, category_id: 10, kind: 1 },
} ], 'static prefix evidence can identify an exact application');
assert_equal(result.classifier.domains, [ {
	pattern: '*.youtube.example',
	hint: { class_id: 100, category_id: 10, kind: 1 },
} ], 'domain evidence compiles for bounded DNS correlation');
assert_equal(result.classifier.signature_memory_bytes, 433,
	'signature admission accounts for map overhead and domain storage');

let independent_limits = config('1');
independent_limits.max_new_classifications_per_second = '1';
independent_limits.per_subject_new_classification_rate = '100';
result = app_policy.compile(independent_limits, monday_0900);
assert_equal(result.enabled, true,
	'per-subject classification rate is independent of the global rate');
assert_equal(result.resource_limits.per_subject_new_classification_rate, 100,
	'compiler preserves a per-subject rate above the global aggregate rate');

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

let conflicting = config('1');
push(conflicting.app_classes, {
	id: '20', name: 'Social', kind: 'category', tcp_ports: [ '443' ],
});
result = app_policy.compile(conflicting, monday_0900);
assert_equal(result.enabled, false, 'conflicting classifier evidence prevents publication');
assert_equal(length(result.errors) > 0, true, 'classifier conflicts are diagnosed');

let invalid_limits = config('1');
invalid_limits.max_packets_inspected = '2';
result = app_policy.compile(invalid_limits, monday_0900);
assert_equal(result.enabled, false, 'V4.1 rejects multi-packet inspection configuration');

let oversized_signatures = config('1');
oversized_signatures.signature_table_memory_limit = '4096';
oversized_signatures.app_classes[1].domains = [];
for (let i = 0; i < 32; i++)
	push(oversized_signatures.app_classes[1].domains, `host-${i}.youtube.example`);
result = app_policy.compile(oversized_signatures, monday_0900);
assert_equal(result.enabled, false,
	'signature table exceeding its explicit memory budget is not published');
assert_equal(result.classifier.signature_memory_bytes > 4096, true,
	'signature memory estimate reports the rejected footprint');

let invalid_domain = config('1');
invalid_domain.app_classes[1].domains = [ 'video*.example' ];
result = app_policy.compile(invalid_domain, monday_0900);
assert_equal(result.enabled, false,
	'embedded domain wildcards rejected by the UI are also rejected by the compiler');

if (failures)
	exit(1);

printf('1..%d\n', assertions);
