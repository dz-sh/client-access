// SPDX-License-Identifier: Apache-2.0

import * as commit from 'client_access.commit';

function fail(message) {
	warn(`FAIL: ${message}\n`);
	exit(1);
}

function assert_true(value, message) {
	if (!value)
		fail(message);
}

const desired = {
	epoch: 100,
	access: { signature: 'access-a', ready: true },
	application: { requested: true },
	authorization: { snapshot: {
		'access/alice': { scope: 'access', verdict: 'DENY' },
		'application/alice/10': {
			scope: 'application', verdict: 'DENY',
		},
	} },
};
const plan = { actions: {
	access: {
		id: 'access.publish', semantic_changed: true,
		candidate_generation: 1,
	},
	application: { id: 'application.publish' },
} };

let current = commit.create();
let consumed_application = { ...current.application,
	policy_generation: 1, classifier_generation: 1 };
let execution = {
	actions: {
		'access.publish': { status: 'SUCCEEDED' },
		'application.publish': { status: 'FAILED' },
	},
	application_state: consumed_application,
	application_result: { ok: false, enabled: false },
	acceleration_state: current.acceleration,
	sfo_ready: true,
	transitions: [],
	error: 'application publication failed',
};
let result = commit.apply(current, desired, plan, execution);
assert_true(result.state.access.generation == 1 &&
	result.state.access.signature == 'access-a',
	'successful access evidence must commit independently');
assert_true(result.state.application.policy_generation == 1,
	'a consumed BPF generation must not be reusable after later failure');
assert_true(result.state.authorization.snapshot['access/alice'] != null &&
	result.state.authorization.snapshot['application/alice/10'] == null,
	'authorization snapshots must advance only for the successful policy plane');

current = commit.create();
const successful_application = { ...current.application,
	policy_generation: 1, classifier_generation: 1,
	applied_signature: 'app-a', classifier_signature: 'classifier-a' };
execution = {
	actions: {
		'access.publish': { status: 'FAILED' },
		'application.publish': { status: 'SUCCEEDED' },
	},
	application_state: successful_application,
	application_result: { ok: true, enabled: true },
	acceleration_state: current.acceleration,
	sfo_ready: true,
	transitions: [],
	error: 'access publication failed',
};
result = commit.apply(current, desired, plan, execution);
assert_true(result.state.access.generation == 0 &&
	result.state.access.signature == null,
	'failed access publication must not advance committed access state');
assert_true(result.application_ok &&
	result.state.authorization.snapshot['application/alice/10'] != null &&
	result.state.authorization.snapshot['access/alice'] == null,
	'successful application evidence must commit independently');

print('evidence-based commit tests passed.\n');
