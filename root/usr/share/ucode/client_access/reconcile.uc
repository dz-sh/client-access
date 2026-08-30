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

export function attempt_context(reason, repair, attempt_id) {
	return {
		reason: reason ?? 'unknown',
		repair: !!repair,
		attempt_id: attempt_id ?? 0,
	};
}

function transition_id(transition, generation) {
	return sprintf('%s/%s/%s/%s/%s/g%d', transition.scope,
		transition.identity_id ?? '__default__',
		transition.class_id ?? '-', transition.old_verdict,
		transition.new_verdict, generation);
}

function set_difference(first, second) {
	let result = [], present = {};
	for (let value in second)
		present[value] = true;
	for (let value in first)
		if (!present[value])
			push(result, value);
	return result;
}

export function plan(committed, observed, desired, transitions, attempt) {
	const access_changed = desired.access.signature != committed.access.signature;
	const access_repair = attempt.repair ||
		(observed.access.publication_observable &&
		 observed.access.runtime_signature != committed.access.signature);
	const app_state = committed.application;
	const policy_floor = observed.application.generations_known
		? observed.application.policy_generation : app_state.policy_generation;
	const classifier_floor = observed.application.generations_known
		? observed.application.classifier_generation : app_state.classifier_generation;
	const base_policy_generation = policy_floor > app_state.policy_generation
		? policy_floor : app_state.policy_generation;
	const base_classifier_generation = classifier_floor > app_state.classifier_generation
		? classifier_floor : app_state.classifier_generation;
	const app_changed = desired.application.policy_signature !=
		app_state.applied_signature;
	const classifier_changed = desired.application.classifier_signature !=
		app_state.classifier_signature;
	const desired_interfaces = desired.application.source_interfaces;
	const current_interfaces = app_state.attached_interfaces ?? [];
	const interfaces_to_attach = set_difference(desired_interfaces,
		current_interfaces);
	const interfaces_to_keep = set_difference(desired_interfaces,
		interfaces_to_attach);
	const interfaces_to_detach = set_difference(current_interfaces,
		desired_interfaces);
	const access_generation = access_changed
		? committed.access.generation + 1 : committed.access.generation;
	const application_generation = app_changed
		? base_policy_generation + 1 : base_policy_generation;
	let planned_transitions = [];
	for (let transition in transitions) {
		const generation = transition.scope == 'access'
			? access_generation : application_generation;
		push(planned_transitions, {
			...transition,
			id: transition_id(transition, generation),
			publication_action_id: transition.scope == 'access'
				? 'access.publish' : 'application.publish',
		});
	}

	return {
		attempt,
		actions: {
			access: {
				id: 'access.publish',
				plane: 'access',
				operation: access_changed || access_repair ? 'publish' : 'noop',
				semantic_changed: access_changed,
				candidate_generation: access_generation,
				prerequisites: [],
			},
			application: {
				id: 'application.publish',
				plane: 'application',
				operation: 'reconcile',
				repair: attempt.repair,
				semantic_changed: app_changed,
				classifier_changed,
				policy_signature: desired.application.policy_signature,
				classifier_signature:
					desired.application.classifier_signature,
				candidate_policy_generation: application_generation,
				candidate_classifier_generation: classifier_changed
					? base_classifier_generation + 1 : base_classifier_generation,
				interfaces_to_attach,
				interfaces_to_keep,
				interfaces_to_detach,
				interfaces_to_ensure: attempt.repair
					? [ ...desired_interfaces ] : [ ...interfaces_to_attach ],
				prerequisites: [],
			},
			acceleration: {
				id: 'acceleration.reconcile',
				plane: 'acceleration',
				operation: 'reconcile',
				prerequisites: [],
			},
		},
		transitions: planned_transitions,
	};
}
