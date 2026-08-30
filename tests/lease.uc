#!/usr/bin/ucode
// SPDX-License-Identifier: Apache-2.0

import * as lease from 'client_access.lease';

let failures = 0, assertions = 0;

function assert_equal(actual, expected, name) {
	assertions++;
	if (sprintf('%J', actual) == sprintf('%J', expected)) {
		printf('ok - %s\n', name);
		return;
	}
	warn(`not ok - ${name}\n  expected: ${sprintf('%J', expected)}\n  actual:   ${sprintf('%J', actual)}\n`);
	failures++;
}

const EPOCH = 1704067200;
const MONOTONIC = [ 1000, 0 ];
const context = {
	identities: [
		{ id: 'alice', subject_id: 42 },
		{ id: 'bob', subject_id: 43 },
	],
	classes: {
		'0': { id: 0, kind: 'default', parent_id: null },
		'1': { id: 1, kind: 'unclassified', parent_id: null },
		'10': { id: 10, kind: 'category', parent_id: null },
		'100': { id: 100, kind: 'application', parent_id: 10 },
		'101': { id: 101, kind: 'application', parent_id: 10 },
	},
};

let database = lease.empty_database();

/* V44-TEST-001, 004 and 009: bounded duration and same-target replacement. */
let created = lease.create(database, {
	scope: 'access', identity_id: 'alice', duration: 'one_hour',
}, context, EPOCH, MONOTONIC);
assert_equal(created.ok, true, 'one-hour Access Lease is accepted with a valid clock');
assert_equal(created.lease.expires_at, EPOCH + 3600,
	'one-hour approval expires exactly 3600 seconds after creation');
assert_equal(created.lease.monotonic_deadline, 4600,
	'one-hour approval also has a monotonic deadline');
database = created.database;

created = lease.create(database, {
	scope: 'access', identity_id: 'alice', duration: 'today',
}, context, EPOCH + 60, [ 1060, 0 ]);
assert_equal(created.ok, true, 'end-of-day replacement is accepted');
assert_equal(created.replacing, true, 'same target replaces rather than accumulates');
assert_equal(length(created.database.leases), 1,
	'same-target replacement leaves one active lease');
assert_equal(created.lease.expires_at, EPOCH + 86400,
	'end-of-day approval expires at the next local midnight in UTC test time');
database = created.database;

/* V44-TEST-011: invalid wall clock cannot create ALLOW. */
assert_equal(lease.create(database, {
	scope: 'access', identity_id: 'bob', duration: 'one_hour',
}, context, 100, [ 10, 0 ]).ok, false,
	'invalid clock rejects Temporary Approval');
assert_equal(lease.create(database, {
	scope: 'access', identity_id: 'bob', duration: 'one_hour',
}, context, EPOCH, {}).ok, false,
	'unavailable monotonic clock rejects Temporary Approval');

/* V44-TEST-005 and 007: independent access/application overlays. */
const application = lease.create(database, {
	scope: 'application', identity_id: 'alice', class_id: 10,
	duration: 'one_hour',
}, context, EPOCH + 120, [ 1120, 0 ]);
assert_equal(application.ok, true, 'category Application Lease is accepted');
database = application.database;

const base_access = {
	identities: [
		{ id: 'alice', verdict: 'deny' },
		{ id: 'bob', verdict: 'allow' },
	],
	next_transition: null,
};
const access_effective = lease.overlay_access(base_access, database);
assert_equal(access_effective.identities[0].verdict, 'allow',
	'Access Lease overlays a base DENY with ALLOW');
assert_equal(access_effective.identities[0].base_verdict, 'deny',
	'Access overlay retains the independently explainable base verdict');

const base_app = {
	identities: context.identities,
	classes: context.classes,
	policies: [
		{ identity_id: 'alice', subject_id: 42, class_id: 0, verdict: 'allow' },
		{ identity_id: 'alice', subject_id: 42, class_id: 1, verdict: 'deny' },
		{ identity_id: 'alice', subject_id: 42, class_id: 10, verdict: 'deny' },
		{ identity_id: 'alice', subject_id: 42, class_id: 100, verdict: 'deny' },
		{ identity_id: 'alice', subject_id: 42, class_id: 101, verdict: 'deny' },
	],
	next_transition: null,
};
const app_effective = lease.overlay_application(base_app, database);
assert_equal(app_effective.policies[0].verdict, 'allow',
	'Application Lease never changes CLASS_DEFAULT');
assert_equal(app_effective.policies[1].verdict, 'deny',
	'Application Lease never changes UNCLASSIFIED');
assert_equal(app_effective.policies[2].verdict, 'allow',
	'category lease temporarily allows the category');
assert_equal(app_effective.policies[3].verdict, 'allow',
	'category lease temporarily allows a child exact application');
assert_equal(app_effective.policies[4].verdict, 'allow',
	'category lease applies consistently to every child application');
assert_equal(access_effective.identities[0].verdict, 'allow',
	'Application overlay does not consume or replace the independent Access Lease');
let application_leases = [];
for (let entry in database.leases)
	if (entry.scope == 'application')
		push(application_leases, entry);
const app_only_access = lease.overlay_access(base_access,
	{ ...database, leases: application_leases });
assert_equal(app_only_access.identities[0].verdict, 'deny',
	'Application Lease cannot override subject-wide Access DENY');

assert_equal(lease.create(database, {
	scope: 'application', identity_id: 'alice', class_id: 1,
	duration: 'one_hour',
}, context, EPOCH, MONOTONIC).ok, false,
	'reserved UNCLASSIFIED cannot receive a Temporary Approval');

/* V44-TEST-008 and 020: only effective changes transition. */
const previous = lease.effective_snapshot(base_access, base_app, true);
const current = lease.effective_snapshot(access_effective, app_effective, true);
const transitions = lease.plan_transitions(previous, current, 'lease_created');
assert_equal(length(transitions) > 0, true,
	'effective DENY to ALLOW changes produce authorization transitions');
const no_op_access = lease.overlay_access({
	identities: [ { id: 'alice', verdict: 'allow' } ], next_transition: null,
}, database);
assert_equal(lease.plan_transitions(
	lease.effective_snapshot({ identities: [ { id: 'alice', verdict: 'allow' } ] },
		{ identities: [], policies: [] }, true),
	lease.effective_snapshot(no_op_access, { identities: [], policies: [] }, true),
	'lease_created'), [],
	'base ALLOW plus lease ALLOW does not create a transition');

const revoked = lease.revoke(database, application.lease.id);
assert_equal(revoked.ok, true, 'manual revocation removes the selected lease');
const after_revoke = lease.overlay_application(base_app, revoked.database);
const restrictive = lease.plan_transitions(
	lease.effective_snapshot(access_effective, app_effective, true),
	lease.effective_snapshot(access_effective, after_revoke, true), 'lease_revoked');
assert_equal(restrictive[0].ordering, [
	'restrict_admission', 'publish_restrictive_policy', 'revoke_bypass_state',
], 'ALLOW to DENY transition freezes safe future revocation ordering');
assert_equal(restrictive[0].revocation_state, 'pending_publication',
	'restrictive transition is not complete before policy publication');

const global_default_transition = lease.plan_transitions(
	lease.effective_snapshot({ enabled: false, identities: [] },
		{ identities: [], policies: [] }, false),
	lease.effective_snapshot({ enabled: true, default_verdict: 'deny', identities: [] },
		{ identities: [], policies: [] }, false), 'policy_changed');
assert_equal(global_default_transition[0].subject_id, null,
	'a restrictive unknown-client default is represented without inventing an identity');
assert_equal(global_default_transition[0].restrictive, true,
	'a restrictive unknown-client default requests broader runtime revocation');

/* V44-TEST-012, 013 and 015: journal parsing is volatile and fail closed. */
const reloaded = lease.parse_database(database, context, EPOCH + 180, [ 1180, 0 ]);
assert_equal(length(reloaded.database.leases), 2,
	'valid volatile journal survives daemon restart with original leases');
assert_equal(lease.parse_database(null, context, EPOCH, MONOTONIC).database,
	lease.empty_database(), 'missing or corrupt journal broadens no authorization');
assert_equal(lease.parse_database(lease.empty_database(), context, EPOCH,
	MONOTONIC).database.leases, [],
	'router reboot empty volatile state restores base policy');

const monotonic_expired = lease.parse_database(database, context,
	EPOCH + 200, [ 999999, 0 ]);
assert_equal(length(monotonic_expired.database.leases), 0,
	'monotonic expiry prevents wall-clock rollback from extending ALLOW');
const wall_expired = lease.parse_database(database, context,
	EPOCH + 86401, [ 87401, 0 ]);
const expired_access = lease.overlay_access(base_access, wall_expired.database);
assert_equal(expired_access.identities[0].verdict, 'deny',
	'expiry automatically restores the base Access verdict');
assert_equal(lease.plan_transitions(
	lease.effective_snapshot(access_effective, app_effective, true),
	lease.effective_snapshot(expired_access,
		lease.overlay_application(base_app, wall_expired.database), true),
	'lease_expired')[0].restrictive, true,
	'lease expiry is represented as a restrictive authorization transition');

const missing_monotonic = { ...database,
	leases: [ { ...database.leases[0], monotonic_deadline: null } ] };
assert_equal(length(lease.parse_database(missing_monotonic, context,
	EPOCH + 180, [ 1180, 0 ]).database.leases), 0,
	'journal entry without a monotonic bound cannot broaden authorization');

/* V44-TEST-014: explicit capacity rejection without eviction. */
let full = lease.empty_database();
for (let i = 0; i < lease.constants.MAX_ACTIVE_LEASES; i++)
	push(full.leases, {
		id: `lease-${EPOCH}-${i + 1}`,
		scope: 'access', identity_id: `identity-${i}`, subject_id: i + 1,
		target_key: `access/identity-${i}`, created_at: EPOCH,
		expires_at: EPOCH + 3600, monotonic_deadline: 4600,
		duration: 'one_hour',
	});
const capacity_context = { identities: [ ...context.identities ], classes: context.classes };
for (let i = 0; i < lease.constants.MAX_ACTIVE_LEASES; i++)
	push(capacity_context.identities, { id: `identity-${i}`, subject_id: i + 1 });
const exhausted = lease.create(full, {
	scope: 'access', identity_id: 'alice', duration: 'one_hour',
}, capacity_context, EPOCH, MONOTONIC);
assert_equal(exhausted.ok, false, 'lease capacity exhaustion fails explicitly');
assert_equal(length(exhausted.database.leases), lease.constants.MAX_ACTIVE_LEASES,
	'capacity failure silently evicts no existing approval');

if (failures)
	exit(1);

printf('1..%d\n', assertions);
