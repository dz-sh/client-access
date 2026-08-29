#!/usr/bin/ucode
// SPDX-License-Identifier: Apache-2.0

import * as classification from 'client_access.classification';

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

function limits(memory) {
	return { signature_table_memory_limit: memory ?? 262144 };
}

function profile(id, class_id, name, kind, parent_id, evidence) {
	return {
		profile_id: id,
		profile_schema_version: '1',
		profile_source: 'native',
		profile_license: 'Apache-2.0',
		profile_provenance: `test:${id}`,
		id: '' + class_id,
		name,
		kind,
		parent_id: parent_id == null ? null : '' + parent_id,
		...(evidence ?? {}),
	};
}

const profiles = [
	profile('video', 10, 'Video', 'category', null, {
		tcp_ports: [ '443' ],
	}),
	profile('youtube', 100, 'YouTube', 'application', 10, {
		domains: [ '*.youtube.example' ],
	}),
	profile('tiktok', 101, 'TikTok', 'application', 10, {
		domains: [ 'api.tiktok.example' ],
	}),
];

/* V42-TEST-001: normalization and Profile metadata are deterministic. */
const model_a = classification.compile_profiles(profiles);
const model_b = classification.compile_profiles([ profiles[2], profiles[0], profiles[1] ]);
assert_equal(model_a.errors, [], 'supported Profiles normalize without errors');
assert_equal(model_a.signature, model_b.signature,
	'equivalent Profile inputs produce deterministic Classification IR');
assert_equal(model_a.profiles[0], {
	id: 'tiktok',
	class_id: 101,
	display_name: 'TikTok',
	kind: 'application',
	parent_category_id: 10,
	schema_version: '1',
	source: 'native',
	license: 'Apache-2.0',
	provenance: 'test:tiktok',
	expressions: [ { primitive: 'domain_exact', value: 'api.tiktok.example' } ],
}, 'Profile retains the required stable metadata and declarative expressions');

/* V42-TEST-002: incompatible static knowledge cannot be published. */
const static_conflict = classification.compile_profiles([
	profile('video', 10, 'Video', 'category', null, { tcp_ports: [ '443' ] }),
	profile('social', 20, 'Social', 'category', null, { tcp_ports: [ '443' ] }),
]);
assert_equal(length(static_conflict.errors) > 0, true,
	'incompatible static Profile knowledge is rejected deterministically');

/* V42-TEST-003: dnsmasq data crosses one normalized Observation contract. */
const normalized = classification.normalize_dns_observation({
	type: 'A',
	name: 'www.youtube.example.',
	address: '198.51.100.7',
	ttl: '60',
}, 7, 1000);
assert_equal(normalized, {
	valid: true,
	observation: {
		provider_id: 'dnsmasq',
		observation_type: 'dns_address',
		observation_key: 'www.youtube.example',
		observed_value: { address_type: 'ipv4', address: '198.51.100.7' },
		expires_at: 1060,
		generation: 7,
		authority: 'dns-answer',
		specificity: 19,
		id: 'dnsmasq/dns_address/www.youtube.example/ipv4/198.51.100.7',
	},
	errors: [],
}, 'dnsmasq result normalizes into provider-neutral Observation fields');
const malformed = classification.normalize_dns_observation({
	type: 'A', name: 'www.youtube.example', address: '999.1.1.1', ttl: '60',
}, 7, 1000);
assert_equal(malformed.valid, false,
	'malformed Provider data is rejected before it can mutate classification state');

/* V42-TEST-004 and 007: Profile + Observation -> Semantic State -> Projection. */
let resolved = classification.resolve(model_a, [ normalized.observation ],
	1001, 7, limits());
let correlated = null;
for (let entry in resolved.semantic_state.entries)
	if (entry.key.value == '198.51.100.7/32')
		correlated = entry;
assert_equal(correlated, {
	key: { type: 'ipv4_prefix', value: '198.51.100.7/32' },
	result: { class_id: 100, category_id: 10, kind: 'exact', kind_id: 1 },
	explanation: {
		profile_ids: [ 'youtube' ],
		provider_ids: [ 'dnsmasq' ],
		observation_types: [ 'dns_address' ],
	},
}, 'cross-source correlation produces explainable semantic exact knowledge');
assert_equal(resolved.runtime_projection.ipv4_prefixes, [ {
	prefix: '198.51.100.7/32',
	hint: { class_id: 100, category_id: 10, kind: 1 },
} ], 'Semantic State lowers to a compact precomputed prefix projection');
assert_equal(!!match(sprintf('%J', resolved.runtime_projection),
	/profile|provider|license|provenance|dnsmasq/), false,
	'Runtime Projection exposes no Profile or Provider representation');

/* A second Provider changes explanations, never the datapath lookup shape. */
const second_provider = {
	...normalized.observation,
	id: 'secondary/dns_address/www.youtube.example/ipv4/198.51.100.7',
	provider_id: 'secondary',
};
const multi_provider = classification.resolve(model_a,
	[ normalized.observation, second_provider ], 1001, 7, limits());
assert_equal(multi_provider.runtime_projection.signature,
	resolved.runtime_projection.signature,
	'adding a compatible Provider does not add a corresponding datapath lookup');
assert_equal(multi_provider.semantic_state.provider_ids,
	[ 'dnsmasq', 'native', 'secondary' ],
	'Provider contributions remain visible only in userspace diagnostics');

/* Extra domain-only Profiles without evidence do not alter BPF projection. */
const expanded_model = classification.compile_profiles([
	...profiles,
	profile('music', 102, 'Music', 'application', 10, {
		domains: [ '*.music.example' ],
	}),
]);
const base_static = classification.resolve(model_a, [], 1001, 7, limits());
const expanded_static = classification.resolve(expanded_model, [], 1001, 7, limits());
assert_equal(expanded_static.runtime_projection.signature,
	base_static.runtime_projection.signature,
	'installed Profile count does not add per-Profile datapath work');

/* V42-TEST-005: expired and stale-generation evidence cannot contribute. */
resolved = classification.resolve(model_a, [ normalized.observation ], 1060, 7, limits());
assert_equal(length(resolved.runtime_projection.ipv4_prefixes), 0,
	'expired observations do not enter a newly generated projection');
assert_equal(resolved.semantic_state.expired_observation_count, 1,
	'expired evidence is visible to diagnostics');
resolved = classification.resolve(model_a, [ normalized.observation ], 1001, 8, limits());
assert_equal(length(resolved.runtime_projection.ipv4_prefixes), 0,
	'incompatible observation generations cannot become active evidence');
assert_equal(resolved.semantic_state.stale_observation_count, 1,
	'stale evidence is visible to diagnostics');

/* V42-TEST-006: incompatible exact claims are UNCLASSIFIED, not last-writer-wins. */
const tiktok_observation = classification.normalize_dns_observation({
	type: 'A', name: 'api.tiktok.example', address: '198.51.100.7', ttl: '60',
}, 7, 1000).observation;
resolved = classification.resolve(model_a,
	[ normalized.observation, tiktok_observation ], 1001, 7, limits());
assert_equal(resolved.runtime_projection.ipv4_prefixes, [ {
	prefix: '198.51.100.7/32',
	hint: { class_id: 1, category_id: 0, kind: 3 },
} ], 'incompatible exact evidence lowers to an explicit UNCLASSIFIED hint');
assert_equal(resolved.semantic_state.conflict_count, 1,
	'classification conflict is retained as diagnostic semantic state');

/* Compatible exact and parent-category evidence preserves the exact result. */
const compatible_model = classification.compile_profiles([
	profile('video', 10, 'Video', 'category', null, {
		ipv4_prefixes: [ '198.51.100.7/32' ],
	}),
	profile('youtube', 100, 'YouTube', 'application', 10, {
		domains: [ '*.youtube.example' ],
	}),
]);
resolved = classification.resolve(compatible_model, [ normalized.observation ],
	1001, 7, limits());
assert_equal(resolved.runtime_projection.ipv4_prefixes[0].hint,
	{ class_id: 100, category_id: 10, kind: 1 },
	'compatible exact evidence wins over its parent category');

/* V42-TEST-008 build half: a bounded projection fails as a whole. */
resolved = classification.resolve(model_a, [ normalized.observation ],
	1001, 7, limits(1));
assert_equal(length(resolved.errors) > 0, true,
	'projection exceeding its resource budget fails before publication');

if (failures)
	exit(1);

printf('1..%d\n', assertions);
