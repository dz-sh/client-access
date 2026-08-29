// SPDX-License-Identifier: Apache-2.0

/* Deterministic desired-state comparison helpers for the composition root. */

export function access_signature(compiled, projection, sources, destinations) {
	if (!compiled.enabled)
		return sprintf('%J', { enabled: false });
	return sprintf('%J', {
		enabled: true,
		mode: compiled.mode,
		deny_action: compiled.deny_action,
		exceptions: projection.exceptions,
		sources,
		destinations,
	});
}

export function application_signature(app_compiled, subject_projection,
		sources, destinations) {
	let policies = [];
	for (let entry in app_compiled.policies)
		push(policies, {
			identity_id: entry.identity_id,
			subject_id: entry.subject_id,
			class_id: entry.class_id,
			verdict: entry.verdict,
		});
	return sprintf('%J', {
		enabled: app_compiled.enabled,
		unknown_subject_app_verdict: app_compiled.unknown_subject_app_verdict,
		provisional_app_verdict: app_compiled.provisional_app_verdict,
		selectors: subject_projection.selectors,
		policies,
		resource_limits: app_compiled.resource_limits,
		sources,
		destinations,
	});
}

export function classifier_signature(runtime_projection) {
	return runtime_projection.signature;
}

export function active_identity_count(identities) {
	let count = 0;
	for (let identity in identities)
		if (identity.effective_active)
			count++;
	return count;
}

export function transition_reason(reason, lease_state) {
	return lease_state.expired_count > 0 ? 'lease_expired'
		: (lease_state.invalid_count > 0 ? 'lease_invalidated'
			: (reason == 'timer' ? 'schedule_transition' : (reason ?? 'unknown')));
}
