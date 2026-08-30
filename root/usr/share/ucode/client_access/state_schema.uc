// SPDX-License-Identifier: Apache-2.0

/* Pure constructors for daemon-owned runtime state. Keeping these shapes in
 * one module prevents adapters and the evidence-based commit layer drifting.
 */

export function application() {
	return {
		policy_generation: 0,
		classifier_generation: 0,
		applied_signature: null,
		classifier_signature: null,
		applied_sources: [],
		applied_destinations: [],
		attached_interfaces: [],
		applied_enforcement: false,
	};
}

export function acceleration() {
	return {
		mode: 'NO_OFFLOAD',
		backend_available: false,
		runtime_ruleset_verified: false,
		hardware_offload_detected: false,
		hardware_offloaded_flow_count: 0,
		correlation_health: 'UNKNOWN',
		tracked_flow_count: 0,
		software_offloaded_flow_count: 0,
		revocation_generation: 0,
		last_revocation_result: 'NOT_REQUIRED',
		last_revocation_latency_ms: 0,
		revocation_deadline_ms: 2000,
		targeted_revocations: 0,
		fallback_revocations: 0,
		revocation_failures: 0,
		flow_gc_reclaimed: 0,
		flow_gc_failures: 0,
		packet_guard_enabled: false,
		packet_guard_healthy: false,
		baseline_required: true,
		errors: [],
	};
}
