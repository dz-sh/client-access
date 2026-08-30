// SPDX-License-Identifier: Apache-2.0

import * as manager from 'client_access.sfo_manager';

function fail(message) {
	warn(`FAIL: ${message}\n`);
	exit(1);
}

function assert_true(value, message) {
	if (!value)
		fail(message);
}

function response(ok, extra) {
	return {
		code: ok ? 0 : 1,
		value: {
			result: ok ? 'COMPLETE' : 'FAILED',
			correlation_health: ok ? 'HEALTHY' : 'DEGRADED',
			tracked_flow_count: 7,
			software_offloaded_flow_count: 2,
			revocation_latency_ms: ok ? 4 : 2001,
			...(extra ?? {}),
		},
	};
}

function backend(options) {
	let calls = [];
	return {
		calls,
		present: function() { push(calls, [ 'present' ]); return true; },
		status: function() { push(calls, [ 'status' ]); return response(true); },
		baseline: function(deadline) {
			push(calls, [ 'baseline', deadline ]);
			return response(options?.baseline_ok ?? true, { fallback_used: true });
		},
		revoke: function(subject, class_id, deadline) {
			push(calls, [ 'revoke', subject, class_id, deadline ]);
			return response(options?.revoke_ok ?? true);
		},
		gc: function(idle) {
			push(calls, [ 'gc', idle ]);
			return response(options?.gc_ok ?? true, { gc_reclaimed: 3 });
		},
	};
}

const no_offload = {
	mode: 'SFO_AVAILABLE', offload_present: false,
	runtime_ruleset_verified: true, hardware_offload_detected: false,
};
const active = {
	mode: 'SFO_ACTIVE', offload_present: true,
	runtime_ruleset_verified: true, hardware_offload_detected: false,
};

let fake = backend();
let state = manager.reconcile(manager.create(), no_offload, false, '2000', fake);
assert_true(state.mode == 'SFO_AVAILABLE' && length(fake.calls) == 1,
	'no-offload mode must not activate the revocation backend');

fake = backend();
state = manager.reconcile(manager.create(), active, true, '2000', fake);
assert_true(state.mode == 'SFO_ACTIVE' && !state.baseline_required &&
	state.fallback_revocations == 1 && state.tracked_flow_count == 7,
	'first SFO activation must establish and verify a clean baseline');
state = manager.reconcile_gc(state, active, true, fake);
assert_true(state.flow_gc_reclaimed == 3 && state.mode == 'SFO_ACTIVE',
	'offload-aware GC must preserve healthy state');

let transitions = manager.revoke_transitions(state, [ {
	scope: 'application', subject_id: 42, class_id: 10,
	restrictive: true, policy_published: true,
} ], active, fake);
assert_true(transitions[0].revocation_state == 'complete' &&
	transitions[0].revocation_backend == 'sfo_targeted',
	'exact application revocation must complete through the targeted backend');
const last = fake.calls[length(fake.calls) - 1];
assert_true(last[0] == 'revoke' && last[1] == 42 && last[2] == 10,
	'the revocation manager must preserve subject and class semantics');

fake = backend();
state = manager.reconcile(manager.create(), active, true, '2000', fake);
const calls_before_global = length(fake.calls);
transitions = manager.revoke_transitions(state, [ {
	scope: 'access', subject_id: null,
	restrictive: true, policy_published: true,
}, {
	scope: 'access', subject_id: 42,
	restrictive: true, policy_published: true,
} ], active, fake);
assert_true(transitions[0].revocation_backend == 'sfo_fallback' &&
	transitions[1].revocation_backend == 'sfo_fallback' &&
	length(fake.calls) == calls_before_global + 1 &&
	fake.calls[length(fake.calls) - 1][0] == 'baseline',
	'a restrictive global default must use one visible broader eviction');

fake = backend({ revoke_ok: false });
state = manager.reconcile(manager.create(), active, true, '2000', fake);
transitions = manager.revoke_transitions(state, [ {
	scope: 'access', subject_id: 42,
	restrictive: true, policy_published: true,
} ], active, fake);
assert_true(transitions[0].revocation_state == 'complete' &&
	transitions[0].revocation_backend == 'sfo_fallback' &&
	state.fallback_revocations == 2,
	'failed exact correlation must use a visible broader fallback');

fake = backend({ revoke_ok: false, baseline_ok: false });
state = manager.create();
state.baseline_required = false;
state.mode = 'SFO_ACTIVE';
transitions = manager.revoke_transitions(state, [ {
	scope: 'access', subject_id: 42,
	restrictive: true, policy_published: true,
} ], active, fake);
assert_true(transitions[0].revocation_state == 'failed' &&
	state.mode == 'SFO_DEGRADED' && state.baseline_required,
	'a stale flow surviving targeted and fallback revocation must degrade SFO');

fake = backend();
state = manager.reconcile(manager.create(), active, false, '2000', fake);
assert_true(state.mode == 'SFO_DEGRADED' &&
	state.correlation_health == 'DEGRADED',
	'SFO cannot be healthy without semantic flow correlation');

print('SFO manager tests passed.\n');
