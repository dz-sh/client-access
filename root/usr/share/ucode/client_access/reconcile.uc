// SPDX-License-Identifier: Apache-2.0

/* Deterministic planning over desired, observed, and committed state. */

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

export function plan(committed, observed, desired, transitions, attempt) {
	const access_changed = desired.access.signature != committed.access.signature;
	const access_repair = attempt.repair;
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
				target_interfaces: [ ...desired_interfaces ],
			},
			acceleration: {
				id: 'acceleration.reconcile',
				plane: 'acceleration',
				operation: 'reconcile',
			},
		},
		transitions: planned_transitions,
	};
}
