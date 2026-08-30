// SPDX-License-Identifier: Apache-2.0

import * as status from 'client_access.status';

function fail(message) {
	warn(`FAIL: ${message}\n`);
	exit(1);
}

function assert_true(value, message) {
	if (!value)
		fail(message);
}

function assert_shape(value, expected, message) {
	let actual = keys(value);
	sort(actual);
	sort(expected);
	assert_true(sprintf('%J', actual) == sprintf('%J', expected),
		`${message}: ${sprintf('%J', actual)}`);
}

const committed = {
	access: { generation: 4, signature: 'access-a', applied: true },
	health: { last_attempt: 101, last_success: 100, last_error: null },
	acceleration: { mode: 'NO_OFFLOAD', correlation_health: 'UNKNOWN' },
};
const desired = {
	access: {
		ready: true,
		compiled: {
			enabled: true, requested_enabled: true, schema_supported: true,
			clock_valid: true, mode: 'blacklist', deny_action: 'reject',
			default_verdict: 'allow', exception_verdict: 'deny',
			next_transition: 200, identities: [ { effective_active: true } ],
		},
		projection: { binding_count: 2, exceptions: [ { mac: '02:00:00:00:00:42' } ] },
	},
	application: {
		compiled: {
			requested_enabled: true, identities: [ { id: 'alice' } ],
			policies: [ { subject_id: 42, class_id: 10 } ],
			classification_model: { profile_count: 1, ir_entry_count: 2 },
			resource_limits: { max_packets_inspected: 8 },
			next_transition: 210,
		},
		classification: {
			runtime_projection: {
				signature_count: 2, signature_memory_bytes: 64,
			},
			semantic_state: {
				entries: [ {}, {} ], provider_ids: [ 'native' ], conflict_count: 1,
			},
		},
		subject_projection: { preview_selectors: [ { mac: '02:00:00:00:00:42' } ] },
	},
	acceleration: { offload_present: false },
};
const plan = {
	attempt: { reason: 'schedule_transition', attempt_id: 9 },
	actions: {
		access: { id: 'access.publish' },
		application: { id: 'application.publish' },
		acceleration: { id: 'acceleration.reconcile' },
	},
};
const execution = {
	ok: true,
	actions: {
		'access.publish': { status: 'SUCCEEDED' },
		'application.publish': { status: 'SUCCEEDED' },
		'acceleration.reconcile': { status: 'SUCCEEDED' },
	},
	transitions: [],
	application_result: {
		ok: true, backend_mode: 'V4_BPF_BASIC', enabled: true,
		tracking_enabled: true, degraded: false,
		retained_previous_snapshot: false, available: true,
		generation: 7, classifier_generation: 3, errors: [], warnings: [],
	},
	application_runtime: { available: true, status_json: '{"ok":true}' },
	sfo_ready: true,
	errors: [],
	warnings: [],
};
const projected = status.project({
	committed,
	desired,
	plan,
	execution,
	outcome: { synchronized: true, application_ok: true },
	observed: {
		topology: {
			source: { interfaces: [ 'lan0' ] },
			destination: { interfaces: [ 'wan0' ] },
		},
	},
	leases: {
		database: { leases: [ { id: 'lease-1' } ] }, capacity: 256,
		next_expiry: 300, journal_available: true,
		latest_transitions: [], errors: [],
	},
	diagnostics: {
		dns_subscribed: true, observation_entries: 3,
		observation_generation: 2, observations_expired: 1,
		observations_stale: 0, dns_events_accepted: 4,
		dns_events_dropped: 1, projection_publish_errors: 0,
	},
});

assert_shape(projected, [
	'active_identity_count', 'app_filter', 'applied',
	'authorization_convergence', 'binding_count', 'clock_valid',
	'default_verdict', 'deny_action', 'destination_interfaces', 'enabled',
	'errors', 'exception_count', 'exception_verdict', 'generation',
	'identity_count', 'last_attempt', 'last_error', 'last_reason',
	'last_reconcile_attempt_id', 'last_reconcile_result', 'last_success',
	'mode', 'next_transition', 'plane_status', 'policy_publication',
	'requested_enabled', 'running', 'schema_supported', 'software_offload',
	'source_interfaces', 'temporary_approvals', 'warnings',
], 'public status top-level shape changed');
assert_shape(projected.app_filter, [
	'app_policy_generation', 'applied', 'available', 'backend_mode',
	'classification_conflicts', 'classification_ir_entry_count',
	'classifier_generation', 'classifier_signature_count',
	'classifier_signature_memory_bytes', 'degraded', 'dns_events_accepted',
	'dns_events_dropped', 'dns_subscribed', 'enabled', 'errors',
	'next_transition', 'observation_entries', 'observation_generation',
	'observations_expired', 'observations_stale', 'policy_entry_count',
	'profile_count', 'projection_publish_errors', 'provider_count',
	'requested_enabled', 'resource_limits', 'retained_previous_snapshot',
	'runtime_available', 'runtime_projection_entry_count',
	'runtime_status_json', 'selector_count', 'semantic_entry_count',
	'subject_count', 'tracking_enabled', 'warnings',
], 'public application status shape changed');
assert_true(projected.applied && projected.generation == 4 &&
	projected.policy_publication.access == 'CURRENT' &&
	projected.policy_publication.application == 'CURRENT' &&
	projected.app_filter.app_policy_generation == 7 &&
	projected.app_filter.classifier_generation == 3 &&
	projected.temporary_approvals.active_count == 1,
	'public status values no longer reflect reconciliation evidence');

const refreshed = status.snapshot(projected, {
	dns_subscribed: false, observation_entries: 5,
	dns_events_accepted: 6, dns_events_dropped: 2,
	projection_publish_errors: 1,
});
assert_true(!refreshed.app_filter.dns_subscribed &&
	refreshed.app_filter.observation_entries == 5 &&
	refreshed.app_filter.dns_events_accepted == 6 &&
	refreshed.app_filter.projection_publish_errors == 1,
	'read-only status refresh lost live diagnostics');

print('status projection regression tests passed.\n');
