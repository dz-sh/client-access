// SPDX-License-Identifier: Apache-2.0

/* Pure projection of reconciliation state and evidence onto the stable public
 * status API. This module owns no runtime adapters or mutable daemon state.
 */

function active_identity_count(identities) {
	let count = 0;
	for (let identity in identities)
		if (identity.effective_active)
			count++;
	return count;
}

function authorization_convergence(actions, transitions, action_id, scope) {
	if (actions[action_id]?.status != 'SUCCEEDED')
		return 'FAILED';
	for (let transition in transitions)
		if (transition.scope == scope && transition.restrictive &&
		    actions[`transition.${transition.id}`]?.status != 'SUCCEEDED')
			return 'FAILED';
	return 'CONVERGED';
}

export function initial(committed, approval_capacity) {
	return {
		running: true,
		applied: false,
		generation: 0,
		last_reason: 'startup',
		last_attempt: null,
		last_success: null,
		last_error: null,
		next_transition: null,
		clock_valid: false,
		mode: null,
		default_verdict: null,
		exception_verdict: null,
		identity_count: 0,
		active_identity_count: 0,
		binding_count: 0,
		exception_count: 0,
		source_interfaces: [],
		destination_interfaces: [],
		errors: [],
		warnings: [],
		temporary_approvals: {
			active_count: 0,
			capacity: approval_capacity,
			next_expiry: null,
			journal_available: true,
			latest_transitions: [],
			errors: [],
		},
		app_filter: {
			backend_mode: 'V3_NFT_ONLY',
			requested_enabled: false,
			enabled: false,
			available: false,
			degraded: false,
			retained_previous_snapshot: false,
			app_policy_generation: 0,
			classifier_generation: 0,
			dns_subscribed: false,
			dns_events_accepted: 0,
			dns_events_dropped: 0,
			classification_conflicts: 0,
			projection_publish_errors: 0,
			next_transition: null,
			errors: [],
			warnings: [],
		},
		software_offload: { ...committed.acceleration },
	};
}

export function project(input) {
	const committed = input.committed;
	const desired = input.desired;
	const plan = input.plan;
	const execution = input.execution;
	const outcome = input.outcome;
	const observed = input.observed;
	const leases = input.leases;
	const diagnostics = input.diagnostics;
	const compiled = desired.access.compiled;
	const projection = desired.access.projection;
	const app_compiled = desired.application.compiled;
	const classification_state = desired.application.classification;
	const subject_projection = desired.application.subject_projection;
	const app_apply = execution.application_result;
	const app_runtime = execution.application_runtime;
	const actions = execution.actions;
	const access_action = actions[plan.actions.access.id];
	const application_action = actions[plan.actions.application.id];
	const acceleration_action = actions[plan.actions.acceleration.id];
	const access_ok = access_action.status == 'SUCCEEDED';
	const access_convergence = authorization_convergence(actions,
		execution.transitions, plan.actions.access.id, 'access');
	const application_convergence = authorization_convergence(actions,
		execution.transitions, plan.actions.application.id, 'application');
	const acceleration_convergence = acceleration_action.status == 'SUCCEEDED'
		? 'CONVERGED' : 'FAILED';

	return {
		running: true,
		applied: outcome.synchronized,
		enabled: compiled.enabled,
		requested_enabled: compiled.requested_enabled,
		schema_supported: compiled.schema_supported,
		generation: committed.access.generation,
		last_reason: plan.attempt.reason,
		last_reconcile_attempt_id: plan.attempt.attempt_id,
		last_reconcile_result: execution.ok ? 'SUCCEEDED' : 'FAILED',
		last_attempt: committed.health.last_attempt,
		last_success: committed.health.last_success,
		last_error: committed.health.last_error,
		next_transition: compiled.next_transition,
		clock_valid: compiled.clock_valid,
		mode: compiled.mode,
		deny_action: compiled.deny_action,
		default_verdict: compiled.default_verdict,
		exception_verdict: compiled.exception_verdict,
		identity_count: length(compiled.identities),
		active_identity_count: active_identity_count(compiled.identities),
		binding_count: projection.binding_count,
		exception_count: compiled.enabled ? length(projection.exceptions) : 0,
		source_interfaces: observed.topology.source.interfaces,
		destination_interfaces: observed.topology.destination.interfaces,
		policy_publication: {
			access: access_ok ? 'CURRENT' : 'STALE',
			application: outcome.application_ok ? 'CURRENT' : 'STALE',
		},
		authorization_convergence: {
			access: access_convergence,
			application: application_convergence,
			acceleration: acceleration_convergence,
		},
		plane_status: {
			access: {
				execution: access_action.status,
				publication: access_ok ? 'CURRENT' : 'STALE',
				convergence: access_convergence,
				health: access_ok && desired.access.ready
					? 'HEALTHY' : 'DEGRADED',
			},
			application: {
				execution: application_action.status,
				publication: outcome.application_ok ? 'CURRENT' : 'STALE',
				convergence: application_convergence,
				health: app_apply.degraded ? 'DEGRADED'
					: (app_apply.tracking_enabled ? 'HEALTHY' : 'UNKNOWN'),
			},
			acceleration: {
				execution: acceleration_action.status,
				publication: 'NOT_REQUIRED',
				convergence: acceleration_convergence,
				health: desired.acceleration.offload_present
					? (execution.sfo_ready ? 'HEALTHY' : 'DEGRADED')
					: 'UNKNOWN',
			},
		},
		errors: execution.errors,
		warnings: execution.warnings,
		temporary_approvals: {
			active_count: length(leases.database.leases),
			capacity: leases.capacity,
			next_expiry: leases.next_expiry,
			journal_available: leases.journal_available,
			latest_transitions: leases.latest_transitions,
			errors: leases.errors,
		},
		app_filter: {
			backend_mode: app_apply.backend_mode,
			requested_enabled: app_compiled.requested_enabled,
			enabled: app_apply.enabled,
			tracking_enabled: app_apply.tracking_enabled,
			degraded: app_apply.degraded,
			retained_previous_snapshot: app_apply.retained_previous_snapshot,
			available: app_apply.available,
			applied: app_apply.ok,
			app_policy_generation: app_apply.generation,
			classifier_generation: app_apply.classifier_generation,
			classifier_signature_count:
				classification_state.runtime_projection.signature_count,
			classifier_signature_memory_bytes:
				classification_state.runtime_projection.signature_memory_bytes,
			profile_count: app_compiled.classification_model.profile_count,
			classification_ir_entry_count:
				app_compiled.classification_model.ir_entry_count,
			semantic_entry_count:
				length(classification_state.semantic_state.entries),
			runtime_projection_entry_count:
				classification_state.runtime_projection.signature_count,
			provider_count:
				length(classification_state.semantic_state.provider_ids),
			resource_limits: app_compiled.resource_limits,
			runtime_available: app_runtime.available,
			runtime_status_json: app_runtime.status_json,
			dns_subscribed: diagnostics.dns_subscribed,
			observation_entries: diagnostics.observation_entries,
			observation_generation: diagnostics.observation_generation,
			observations_expired: diagnostics.observations_expired,
			observations_stale: diagnostics.observations_stale,
			dns_events_accepted: diagnostics.dns_events_accepted,
			dns_events_dropped: diagnostics.dns_events_dropped,
			classification_conflicts:
				classification_state.semantic_state.conflict_count,
			projection_publish_errors: diagnostics.projection_publish_errors,
			next_transition: app_compiled.next_transition,
			subject_count: length(app_compiled.identities),
			selector_count: length(subject_projection.preview_selectors),
			policy_entry_count: length(app_compiled.policies),
			errors: app_apply.errors,
			warnings: app_apply.warnings,
		},
		software_offload: { ...committed.acceleration },
	};
}

export function snapshot(state, diagnostics) {
	let result = { ...state, app_filter: { ...(state.app_filter ?? {}) } };
	result.app_filter.dns_subscribed = diagnostics.dns_subscribed;
	result.app_filter.observation_entries = diagnostics.observation_entries;
	result.app_filter.dns_events_accepted = diagnostics.dns_events_accepted;
	result.app_filter.dns_events_dropped = diagnostics.dns_events_dropped;
	result.app_filter.projection_publish_errors = diagnostics.projection_publish_errors;
	return result;
}
