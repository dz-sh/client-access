// SPDX-License-Identifier: Apache-2.0

/* Pure construction of one complete semantic desired-state snapshot. The
 * caller owns configuration, journal, observation, clock, and runtime reads.
 */

import * as reconciliation from 'client_access.reconcile';

export function build(input, observed) {
	const runtime = input.runtime;
	const compiled = runtime.compiled;
	const app_compiled = runtime.app_compiled;
	const sources = observed.topology.source.interfaces;
	const destinations = observed.topology.destination.interfaces;
	let access_readiness = compiled.enabled
		? [ ...observed.topology.source.errors,
			...observed.topology.destination.errors ] : [];
	if (compiled.enabled && !length(sources))
		push(access_readiness,
			'No source interfaces resolved; enforcement is inactive');
	if (compiled.enabled && !length(destinations))
		push(access_readiness,
			'No destination interfaces resolved; enforcement is inactive');

	const access_signature = reconciliation.access_signature(compiled,
		runtime.projection, sources, destinations);
	const application_signature = sprintf('%s|tracking=%d|enforcement=%d',
		reconciliation.application_signature(app_compiled,
			runtime.subject_projection, sources, destinations),
		observed.acceleration.capability.tracking_required ? 1 : 0,
		app_compiled.requested_enabled ? 1 : 0);
	const classifier_signature = reconciliation.classifier_signature(
		runtime.classification_state.runtime_projection);

	return {
			desired: {
				epoch: input.epoch,
			access: {
				compiled,
				projection: runtime.projection,
				source_interfaces: sources,
				destination_interfaces: destinations,
				signature: access_signature,
				ready: compiled.schema_supported && compiled.mode_valid &&
					!length(access_readiness),
			},
			application: {
				compiled: app_compiled,
				classification: runtime.classification_state,
				subject_projection: runtime.subject_projection,
				source_interfaces: sources,
				destination_interfaces: destinations,
				policy_signature: application_signature,
				classifier_signature,
				requested: app_compiled.requested_enabled,
				ready: app_compiled.enabled && !length([
					...runtime.subject_projection.errors,
					...observed.topology.source.errors,
					...observed.topology.destination.errors,
				]),
			},
				acceleration: {
					...observed.acceleration.capability,
					revocation_deadline_ms:
						input.config.sfo_revocation_deadline_ms,
				},
			authorization: { snapshot: input.authorization_snapshot },
			approvals: {
				database: input.lease_database,
				next_expiry: input.next_approval_expiry,
			},
			timing: {
				next_transition: compiled.next_transition,
				next_application_transition: app_compiled.next_transition,
				next_classification_expiry:
					runtime.classification_state.next_expiry,
			},
		},
		diagnostics: {
			access_errors: [ ...compiled.errors, ...runtime.projection.errors,
				...access_readiness ],
			access_warnings: [ ...compiled.warnings,
				...runtime.projection.warnings ],
			application_warnings: [ ...runtime.consistency.warnings ],
			access_readiness,
		},
	};
}
