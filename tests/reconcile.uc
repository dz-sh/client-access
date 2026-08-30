// SPDX-License-Identifier: Apache-2.0

import * as reconciliation from 'client_access.reconcile';
import * as committed_state from 'client_access.commit';

function fail(message) {
	warn(`FAIL: ${message}\n`);
	exit(1);
}

function assert_true(value, message) {
	if (!value)
		fail(message);
}

function contains(values, expected) {
	for (let value in values)
		if (value == expected)
			return true;
	return false;
}

function observed(policy_generation, classifier_generation) {
	return {
		application: {
			generations_known: true,
			policy_generation,
			classifier_generation,
		},
	};
}

function desired(access_signature, policy_signature, classifier_signature,
		interfaces) {
	return {
		access: { signature: access_signature },
		application: {
			policy_signature,
			classifier_signature,
			source_interfaces: interfaces ?? [ 'lan0', 'lan1' ],
		},
	};
}

let committed = committed_state.create();
let plan = reconciliation.plan(committed, observed(0, 0),
	desired('access-a', 'app-a', 'classifier-a'), [],
	reconciliation.attempt_context('startup', false, 1));
assert_true(plan.actions.access.operation == 'publish' &&
	plan.actions.access.candidate_generation == 1,
	'initial access publication must allocate semantic generation 1');
assert_true(plan.actions.application.candidate_policy_generation == 1 &&
	plan.actions.application.candidate_classifier_generation == 1,
	'initial application and classifier snapshots need independent generations');
assert_true(sprintf('%J', plan.actions.application.target_interfaces) ==
		'["lan0","lan1"]' &&
	!contains(keys(plan.actions.application), 'interfaces_to_attach') &&
	!contains(keys(plan.actions.application), 'interfaces_to_detach') &&
	!contains(keys(plan.actions.application), 'interfaces_to_keep'),
	'planner must expose target interfaces without backend TC deltas');

committed.access = { generation: 5, signature: 'access-a', applied: true };
committed.application.policy_generation = 7;
committed.application.classifier_generation = 3;
committed.application.applied_signature = 'app-a';
committed.application.classifier_signature = 'classifier-a';
committed.application.attached_interfaces = [ 'lan0' ];
plan = reconciliation.plan(committed, observed(7, 3),
	desired('access-a', 'app-a', 'classifier-a'), [],
	reconciliation.attempt_context('fw4-reload', true, 2));
assert_true(plan.actions.access.operation == 'publish' &&
	plan.actions.access.candidate_generation == 5,
	'repair publication must not advance access semantic generation');
assert_true(plan.actions.application.candidate_policy_generation == 7 &&
	plan.actions.application.candidate_classifier_generation == 3,
	'forced reconciliation must not advance unchanged application generations');
assert_true(sprintf('%J', plan.actions.application.target_interfaces) ==
		'["lan0","lan1"]' && plan.actions.application.repair,
	'repair must preserve the semantic target without exposing attach operations');

plan = reconciliation.plan(committed, observed(10, 8),
	desired('access-b', 'app-b', 'classifier-b'), [ {
		scope: 'application', identity_id: 'alice', class_id: 10,
		old_verdict: 'ALLOW', new_verdict: 'DENY', restrictive: true,
	} ], reconciliation.attempt_context('policy-change', false, 3));
assert_true(plan.actions.access.candidate_generation == 6,
	'access generation is independent from observed BPF generation floors');
assert_true(plan.actions.application.candidate_policy_generation == 11 &&
	plan.actions.application.candidate_classifier_generation == 9,
	'new BPF generations must be allocated above observed runtime floors');
assert_true(plan.transitions[0].publication_action_id == 'application.publish' &&
	length(plan.transitions[0].id),
	'a restrictive transition must name its plane publication prerequisite');

plan = reconciliation.plan(committed, observed(11, 9),
	desired('access-b', 'app-b', 'classifier-b', [ 'lan1' ]), [],
	reconciliation.attempt_context('interface-remove', false, 4));
assert_true(sprintf('%J', plan.actions.application.target_interfaces) ==
		'["lan1"]',
	'interface removal must be represented only as a new target set');

plan = reconciliation.plan(committed, observed(12, 10),
	desired('access-b', 'app-b', 'classifier-b', [ 'lan0', 'lan1', 'lan2' ]), [],
	reconciliation.attempt_context('interface-add', false, 5));
assert_true(sprintf('%J', plan.actions.application.target_interfaces) ==
		'["lan0","lan1","lan2"]',
	'interface addition must be represented only as a new target set');

print('reconciliation planner tests passed.\n');
