// SPDX-License-Identifier: Apache-2.0

/* Side-effect execution for an already-planned reconciliation attempt. This
 * module returns bounded evidence and does not compile policy, re-plan
 * generations, or advance daemon-global committed state.
 */

import * as firewall from 'client_access.firewall';
import * as bpf_runtime from 'client_access.bpf_runtime';
import * as application_reconcile from 'client_access.application_reconcile';
import * as sfo_manager from 'client_access.sfo_manager';

function clone(value) {
	return json(sprintf('%J', value));
}

function action(status, evidence, error) {
	return { status, evidence: evidence ?? {}, error: error ?? null };
}

function application_published(desired, result) {
	return !desired.application.requested ||
		(result.ok && result.enabled);
}

export function neutralize_startup() {
	let evidence = { bpf_disabled: true, nft_scope_disabled: false };
	if (bpf_runtime.present())
		evidence.bpf_disabled = bpf_runtime.disable().code == 0;
	const scope = firewall.apply_application_scope(false, [], []);
	evidence.nft_scope_disabled = scope.ok;
	return {
		ok: evidence.bpf_disabled && evidence.nft_scope_disabled,
		evidence,
		error: scope.ok ? null : scope.error,
	};
}

export function execute(plan, desired, committed, handles) {
	let actions = {}, errors = [ ...handles.diagnostics.access_errors ];
	let warnings = [ ...handles.diagnostics.access_warnings ];
	const access_plan = plan.actions.access;
	let access_result = { ok: true, error: null };
	if (!desired.access.ready)
		access_result = {
			ok: false,
			error: handles.diagnostics.access_errors[0] ??
				'Internet-access policy is not publishable',
		};
	else if (access_plan.operation == 'publish')
		access_result = firewall.apply_access(desired.access.compiled,
			desired.access.projection, desired.access.source_interfaces,
			desired.access.destination_interfaces);
	if (!access_result.ok)
		push(errors, access_result.error);
	actions[access_plan.id] = access_result.ok
		? action('SUCCEEDED', {
			published: access_plan.operation == 'publish',
			semantic_changed: access_plan.semantic_changed,
			candidate_generation: access_plan.candidate_generation,
		})
		: action('FAILED', {}, access_result.error);

	const application_plan = plan.actions.application;
	let application_state = clone(committed.application);
	const policy_floor = application_plan.semantic_changed
		? application_plan.candidate_policy_generation - 1
		: application_plan.candidate_policy_generation;
	const classifier_floor = application_plan.classifier_changed
		? application_plan.candidate_classifier_generation - 1
		: application_plan.candidate_classifier_generation;
	if (policy_floor > application_state.policy_generation)
		application_state.policy_generation = policy_floor;
	if (classifier_floor > application_state.classifier_generation)
		application_state.classifier_generation = classifier_floor;
	const previous_app_enforcement = application_state.applied_enforcement;
	let application_result = application_reconcile.apply(application_state,
		desired.application.compiled,
		desired.application.classification,
		desired.application.subject_projection,
		desired.application.source_interfaces,
		desired.application.destination_interfaces,
		[ ...handles.observed.topology.source.errors,
			...handles.observed.topology.destination.errors ],
		application_plan, handles.observation_runtime,
		desired.acceleration);
	let application_runtime = application_reconcile.runtime_snapshot(
		application_state, application_result.tracking_enabled,
		application_result.generation,
		application_result.classifier_generation);
	if (application_result.tracking_enabled && !application_runtime.available) {
		push(application_result.errors, application_runtime.error ??
			'Application-filter runtime state became unavailable');
		application_reconcile.neutralize(application_state,
			application_result.errors);
		application_result = {
			...application_result,
			ok: false,
			available: false,
			enabled: false,
			degraded: true,
			retained_previous_snapshot: false,
			backend_mode: 'V3_NFT_ONLY',
			tracking_enabled: false,
		};
	}
	else if (application_runtime.error)
		push(application_result.warnings, application_runtime.error);
	for (let warning in handles.diagnostics.application_warnings)
		push(application_result.warnings, warning);
	const app_published = application_published(desired, application_result);
	actions[application_plan.id] = app_published
		? action('SUCCEEDED', {
			policy_generation: application_result.generation,
			classifier_generation: application_result.classifier_generation,
			retained_previous_snapshot:
				application_result.retained_previous_snapshot,
		})
		: action('FAILED', {}, join('; ', application_result.errors));

	let broad_revocation = false;
	for (let transition in plan.transitions)
		if (transition.restrictive && transition.subject_id == null)
			broad_revocation = true;
	let acceleration_state = clone(committed.acceleration);
	if (desired.acceleration.mode == 'SFO_ACTIVE' &&
	    !previous_app_enforcement && application_result.enabled &&
	    !broad_revocation)
		acceleration_state.baseline_required = true;
	const correlation_healthy = application_result.tracking_enabled &&
		application_runtime.available && application_runtime.correlation_healthy;
	acceleration_state = sfo_manager.reconcile(acceleration_state,
		desired.acceleration, correlation_healthy,
		desired.acceleration.revocation_deadline_ms, handles.sfo_runtime);
	if (desired.acceleration.mode == 'SFO_ACTIVE')
		acceleration_state = sfo_manager.reconcile_gc(acceleration_state,
			desired.acceleration, correlation_healthy, handles.sfo_runtime);
	else if (application_result.tracking_enabled && application_runtime.available)
		bpf_runtime.gc(300);
	const acceleration_plan = plan.actions.acceleration;
	const acceleration_ok = !desired.acceleration.offload_present ||
		acceleration_state.mode == 'SFO_ACTIVE';
	actions[acceleration_plan.id] = !acceleration_ok
		? action('FAILED', {}, join('; ', acceleration_state.errors))
		: action('SUCCEEDED', { mode: acceleration_state.mode });

	let transition_candidates = [];
	for (let transition in plan.transitions) {
		const prerequisite = actions[transition.publication_action_id];
		const published = prerequisite?.status == 'SUCCEEDED';
		push(transition_candidates, {
			...transition,
			policy_generation: transition.scope == 'access'
				? access_plan.candidate_generation
				: application_result.generation,
			policy_published: published,
		});
		if (transition.restrictive && !published)
			push(errors,
				`Restrictive ${transition.scope} authorization transition could not be published`);
	}
	const transitions = sfo_manager.revoke_transitions(acceleration_state,
		transition_candidates, desired.acceleration, handles.sfo_runtime);
	for (let transition in transitions) {
		actions[`transition.${transition.id}`] =
			transition.policy_published
				? (transition.revocation_state == 'failed'
					? action('FAILED', transition,
						'Accelerated-flow revocation did not converge')
					: action('SUCCEEDED', transition))
				: action('SKIPPED_PREREQUISITE', transition,
					'Policy publication prerequisite failed');
		if (transition.restrictive && transition.revocation_state == 'failed')
			push(errors,
				`Restrictive ${transition.scope} transition did not revoke stale accelerated state`);
	}

	const sfo_ready = !desired.acceleration.offload_present ||
		acceleration_state.mode == 'SFO_ACTIVE';
	if (!sfo_ready)
		actions[acceleration_plan.id] = action('FAILED', {},
			join('; ', acceleration_state.errors));
	let ok = true;
	for (let id, value in actions)
		if (value.status == 'FAILED' ||
		    value.status == 'SKIPPED_PREREQUISITE') {
			ok = false;
			break;
		}
	return {
		attempt_id: plan.attempt.attempt_id,
		ok,
		actions,
		application_state,
		application_result,
		application_runtime,
		acceleration_state,
		transitions,
		sfo_ready,
		errors,
		warnings,
		error: access_result.error ??
			(!sfo_ready ? join('; ', acceleration_state.errors) : null),
	};
}
