// SPDX-License-Identifier: Apache-2.0

/* V4.6 transition-to-runtime coordinator. Policy determines semantic scope;
 * this module owns only bounded backend convergence and diagnostics.
 */

import * as state_schema from 'client_access.state_schema';

const DEFAULT_DEADLINE_MS = 2000;
const MAX_DEADLINE_MS = 10000;

function parse_deadline(value) {
	const text = trim('' + (value ?? ''));
	if (!match(text, /^(0|[1-9][0-9]*)$/))
		return DEFAULT_DEADLINE_MS;
	const number = +text;
	return number >= 1 && number <= MAX_DEADLINE_MS
		? number : DEFAULT_DEADLINE_MS;
}

export function create() {
	return state_schema.acceleration();
}

function backend_ok(result) {
	return result && result.code == 0 && result.value &&
		result.value.result == 'COMPLETE' && !result.value.deadline_exceeded;
}

function absorb(state, result) {
	const value = result?.value ?? {};
	state.correlation_health = value.correlation_health ??
		(result?.code == 0 ? 'HEALTHY' : 'DEGRADED');
	state.tracked_flow_count = value.tracked_flow_count ?? state.tracked_flow_count;
	state.software_offloaded_flow_count = value.software_offloaded_flow_count ??
		state.software_offloaded_flow_count;
	state.hardware_offloaded_flow_count = value.hardware_offloaded_flow_count ??
		state.hardware_offloaded_flow_count;
	if (state.hardware_offloaded_flow_count > 0)
		state.hardware_offload_detected = true;
	state.last_revocation_latency_ms = value.revocation_latency_ms ?? 0;
}

export function reconcile_gc(state, capability, tracking_healthy, backend) {
	if (!backend)
		return state;
	if (capability.mode != 'SFO_ACTIVE' || state.mode != 'SFO_ACTIVE' ||
	    !tracking_healthy)
		return state;
	const result = backend.gc(300);
	absorb(state, result);
	if (!backend_ok(result)) {
		state.mode = 'SFO_DEGRADED';
		state.correlation_health = 'DEGRADED';
		state.flow_gc_failures++;
		state.baseline_required = true;
		push(state.errors, 'Offload-aware semantic flow reconciliation failed');
	}
	else
		state.flow_gc_reclaimed += result.value.gc_reclaimed ?? 0;
	return state;
}

export function reconcile(state, capability, tracking_healthy, configured_deadline,
		backend) {
	const previous_mode = state.mode;
	state.mode = capability.mode;
	state.backend_available = !!backend && backend.present();
	state.runtime_ruleset_verified = capability.runtime_ruleset_verified;
	state.hardware_offload_detected = capability.hardware_offload_detected;
	state.revocation_deadline_ms = parse_deadline(configured_deadline);
	state.errors = [];

	if (capability.mode != 'SFO_ACTIVE') {
		state.correlation_health = capability.offload_present ? 'UNKNOWN' : 'HEALTHY';
		state.baseline_required = true;
		if (capability.reason)
			push(state.errors, capability.reason);
		return state;
	}
	if (!backend) {
		state.mode = 'SFO_BACKEND_MISSING';
		state.correlation_health = 'DEGRADED';
		state.baseline_required = true;
		push(state.errors, 'Structured conntrack runtime backend is unavailable');
		return state;
	}
	if (!tracking_healthy) {
		state.mode = 'SFO_DEGRADED';
		state.correlation_health = 'DEGRADED';
		state.baseline_required = true;
		push(state.errors, 'BPF semantic flow correlation is unavailable');
		return state;
	}

	if (previous_mode != 'SFO_ACTIVE' || state.baseline_required) {
		const baseline = backend.baseline(state.revocation_deadline_ms);
		absorb(state, baseline);
		if (!backend_ok(baseline)) {
			state.mode = 'SFO_DEGRADED';
			state.correlation_health = 'DEGRADED';
			state.revocation_failures++;
			push(state.errors, 'Unable to establish a clean software-offload baseline');
			return state;
		}
		state.fallback_revocations++;
		state.baseline_required = false;
	}

	const health = backend.status();
	absorb(state, health);
	if (!backend_ok(health) || state.hardware_offload_detected) {
		state.mode = 'SFO_DEGRADED';
		state.correlation_health = 'DEGRADED';
		push(state.errors, 'Structured conntrack runtime health is unavailable');
	}
	return state;
}

export function revoke_transitions(state, transitions, capability, backend) {
	let published = [], broad_required = false, broad_result = null;
	for (let transition in transitions)
		if (transition.restrictive && transition.policy_published &&
		    transition.subject_id == null)
			broad_required = true;
	if (backend && broad_required && capability.offload_present &&
	    capability.mode == 'SFO_ACTIVE' && state.mode == 'SFO_ACTIVE') {
		broad_result = backend.baseline(state.revocation_deadline_ms);
		state.fallback_revocations++;
		absorb(state, broad_result);
		if (!backend_ok(broad_result)) {
			state.mode = 'SFO_DEGRADED';
			state.correlation_health = 'DEGRADED';
			state.baseline_required = true;
		}
	}
	for (let transition in transitions) {
		if (!transition.restrictive) {
			push(published, { ...transition, revocation_backend: 'not_required',
				revocation_state: 'not_required' });
			continue;
		}
		if (!transition.policy_published) {
			push(published, { ...transition, revocation_backend: 'none',
				revocation_state: 'failed' });
			state.revocation_failures++;
			continue;
		}
		if (!capability.offload_present) {
			push(published, { ...transition,
				revocation_backend: 'normal_datapath',
				revocation_state: 'complete' });
			continue;
		}
		state.revocation_generation++;
		if (!backend || capability.mode != 'SFO_ACTIVE' ||
		    (state.mode != 'SFO_ACTIVE' && broad_result == null)) {
			state.last_revocation_result = 'FAILED';
			state.revocation_failures++;
			push(published, { ...transition, revocation_backend: 'sfo',
				revocation_state: 'failed' });
			continue;
		}

		let result, fallback = broad_result != null;
		if (fallback)
			result = broad_result;
		else {
			result = backend.revoke(transition.subject_id,
				transition.scope == 'application' ? transition.class_id : null,
				state.revocation_deadline_ms);
			state.targeted_revocations++;
		}
		absorb(state, result);
		if (!backend_ok(result)) {
			if (!fallback) {
				result = backend.baseline(state.revocation_deadline_ms);
				state.fallback_revocations++;
				fallback = true;
				absorb(state, result);
			}
		}
		const complete = backend_ok(result);
		state.last_revocation_result = complete ? 'COMPLETE' : 'FAILED';
		if (!complete) {
			state.mode = 'SFO_DEGRADED';
			state.correlation_health = 'DEGRADED';
			state.revocation_failures++;
			state.baseline_required = true;
			push(state.errors,
				'Restrictive transition exceeded bounded SFO revocation guarantees');
		}
		push(published, { ...transition,
			revocation_backend: fallback ? 'sfo_fallback' : 'sfo_targeted',
			revocation_state: complete ? 'complete' : 'failed',
			revocation_latency_ms: state.last_revocation_latency_ms });
	}
	return published;
}

export const constants = {
	DEFAULT_DEADLINE_MS,
	MAX_DEADLINE_MS,
	parse_deadline,
};
