// SPDX-License-Identifier: Apache-2.0

/* Pure evidence-based advancement of daemon-owned committed state. */

import * as state_schema from 'client_access.state_schema';

export function create() {
	return {
		access: { generation: 0, signature: null, applied: false },
		application: state_schema.application(),
		authorization: { snapshot: null },
		acceleration: state_schema.acceleration(),
		health: {
			last_attempt: null,
			last_success: null,
			last_error: null,
		},
	};
}

function advance_authorization(previous, desired, access_ok, application_ok) {
	let next = { ...(previous ?? {}) };
	for (let key, entry in desired) {
		if ((entry.scope == 'access' && access_ok) ||
		    (entry.scope == 'application' && application_ok))
			next[key] = entry;
	}
	return next;
}

export function apply(current, desired, plan, execution) {
	let access = { ...current.access };
	const access_result = execution.actions[plan.actions.access.id];
	if (access_result.status == 'SUCCEEDED') {
		access.applied = true;
		access.signature = desired.access.signature;
		if (plan.actions.access.semantic_changed)
			access.generation = plan.actions.access.candidate_generation;
	}

	const application_result = execution.actions[plan.actions.application.id];
	const application_ok = application_result.status == 'SUCCEEDED' &&
		execution.application_result.ok &&
		(!desired.application.requested || execution.application_result.enabled);
	const authorization = advance_authorization(
		current.authorization.snapshot,
		desired.authorization.snapshot,
		access_result.status == 'SUCCEEDED', application_ok);

	const synchronized = access_result.status == 'SUCCEEDED' &&
		desired.access.ready && execution.sfo_ready;
	const last_error = execution.error ??
		(!desired.access.ready
			? 'Internet-access policy is not publishable' : null);
	return {
		state: {
			access,
			application: execution.application_state,
			authorization: { snapshot: authorization },
			acceleration: execution.acceleration_state,
			health: {
				last_attempt: desired.epoch,
				last_success: synchronized
					? desired.epoch : current.health.last_success,
				last_error,
			},
		},
		application_ok,
		synchronized,
		transitions: execution.transitions,
	};
}
