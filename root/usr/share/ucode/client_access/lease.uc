// SPDX-License-Identifier: Apache-2.0

/*
 * V4.4 bounded Temporary Approval model.
 *
 * Lease objects exist only in userspace. These helpers overlay active ALLOW
 * leases onto already-compiled V3/V4 base policy and emit only effective
 * policy plus authorization transitions for datapath publication.
 */

const SCHEMA_VERSION = 1;
const MAX_ACTIVE_LEASES = 256;
const CLOCK_VALID_AFTER = 1577836800;
const CLASS_DEFAULT = 0;
const CLASS_UNCLASSIFIED = 1;

function parse_uint(value, maximum) {
	const text = trim('' + (value ?? ''));
	if (!match(text, /^(0|[1-9][0-9]*)$/))
		return null;
	const number = +text;
	return number >= 0 && number <= maximum ? number : null;
}

function monotonic_second(value) {
	if (type(value) == 'array')
		return value[0];
	if (type(value) == 'int' || type(value) == 'double')
		return value;
	return null;
}

function target_key(scope, identity_id, class_id) {
	return scope == 'access'
		? `access/${identity_id}`
		: `application/${identity_id}/${class_id}`;
}

function identity_map(context) {
	let result = {};
	for (let identity in ((context && context.identities) ?? []))
		if (identity.id != null)
			result[identity.id] = identity;
	return result;
}

function class_is_ancestor(classes, ancestor_id, class_id) {
	let current = classes['' + class_id], seen = {};
	while (current && !seen[current.id]) {
		seen[current.id] = true;
		if (current.id == ancestor_id && current.kind == 'category')
			return true;
		current = current.parent_id != null ? classes['' + current.parent_id] : null;
	}
	return false;
}

function lease_matches_class(lease, class_id, classes) {
	return lease.class_id == class_id ||
		class_is_ancestor(classes, lease.class_id, class_id);
}

function lease_status(lease, context, epoch, monotonic_now, errors) {
	if (type(lease) != 'object') {
		push(errors, 'Ignored non-object lease entry');
		return 'invalid';
	}
	if (!match('' + (lease.id ?? ''), /^lease-[0-9]+-[0-9]+$/)) {
		push(errors, `Ignored lease with invalid ID '${lease.id ?? 'missing'}'`);
		return 'invalid';
	}
	if (lease.scope != 'access' && lease.scope != 'application') {
		push(errors, `${lease.id}: unsupported scope '${lease.scope ?? 'missing'}'`);
		return 'invalid';
	}
	const identities = identity_map(context);
	const identity = identities[lease.identity_id];
	if (!identity || identity.subject_id == null) {
		push(errors, `${lease.id}: unknown Identity '${lease.identity_id ?? 'missing'}'`);
		return 'invalid';
	}
	if (lease.subject_id != identity.subject_id) {
		push(errors, `${lease.id}: subject does not match Identity '${lease.identity_id}'`);
		return 'invalid';
	}
	if (lease.scope == 'application') {
		const class_id = parse_uint(lease.class_id, 65535);
		const class_info = context && context.classes
			? context.classes['' + class_id] : null;
		if (class_id == null || class_id <= CLASS_UNCLASSIFIED || !class_info ||
		    (class_info.kind != 'application' && class_info.kind != 'category')) {
			push(errors, `${lease.id}: unknown or reserved application class '${lease.class_id ?? 'missing'}'`);
			return 'invalid';
		}
	}
	if (parse_uint(lease.created_at, 4294967295) == null ||
	    parse_uint(lease.expires_at, 4294967295) == null ||
	    lease.expires_at <= lease.created_at) {
		push(errors, `${lease.id}: invalid lease timestamps`);
		return 'invalid';
	}
	if ((lease.duration == 'one_hour' &&
	     lease.expires_at - lease.created_at != 3600) ||
	    (lease.duration == 'today' &&
	     lease.expires_at != end_of_today(lease.created_at)) ||
	    (lease.duration != 'one_hour' && lease.duration != 'today')) {
		push(errors, `${lease.id}: invalid lease duration`);
		return 'invalid';
	}
	if (parse_uint(lease.monotonic_deadline, 4294967295) == null) {
		push(errors, `${lease.id}: missing monotonic deadline`);
		return 'invalid';
	}
	if (epoch < CLOCK_VALID_AFTER) {
		push(errors, `${lease.id}: clock is invalid; lease was ignored`);
		return 'invalid';
	}
	const current = monotonic_second(monotonic_now);
	if (current == null) {
		push(errors, `${lease.id}: monotonic clock is unavailable; lease was ignored`);
		return 'invalid';
	}
	return lease.expires_at <= epoch || lease.monotonic_deadline <= current
		? 'expired' : 'active';
}

export function empty_database() {
	return { schema_version: SCHEMA_VERSION, next_id: 1, leases: [] };
}

export function parse_database(value, context, epoch, monotonic_now) {
	epoch ??= clock()[0];
	monotonic_now ??= clock(true);
	if (type(value) != 'object' || value.schema_version != SCHEMA_VERSION ||
	    type(value.leases) != 'array') {
		return {
			database: empty_database(),
			valid: false,
			errors: [ 'Temporary Approval journal is invalid and was ignored' ],
			expired_count: 0,
			invalid_count: 1,
		};
	}
	if (length(value.leases) > MAX_ACTIVE_LEASES) {
		return {
			database: empty_database(),
			valid: false,
			errors: [ `Temporary Approval journal exceeds ${MAX_ACTIVE_LEASES} leases and was ignored` ],
			expired_count: 0,
			invalid_count: length(value.leases),
		};
	}

	let errors = [], candidates = [], ids = {}, targets = {};
	let expired_count = 0, invalid_count = 0;
	for (let lease in value.leases) {
		const status = lease_status(lease, context, epoch, monotonic_now, errors);
		if (status != 'active') {
			if (status == 'expired')
				expired_count++;
			else
				invalid_count++;
			continue;
		}
		const key = target_key(lease.scope, lease.identity_id, lease.class_id);
		ids[lease.id] = (ids[lease.id] ?? 0) + 1;
		targets[key] = (targets[key] ?? 0) + 1;
		push(candidates, { ...lease, target_key: key });
	}

	let leases = [];
	for (let lease in candidates) {
		if (ids[lease.id] != 1 || targets[lease.target_key] != 1) {
			push(errors, `${lease.id}: duplicate lease ID or target was ignored`);
			continue;
		}
		push(leases, lease);
	}
	sort(leases, (a, b) => a.target_key < b.target_key ? -1 :
		(a.target_key > b.target_key ? 1 : 0));
	const next_id = parse_uint(value.next_id, 4294967295) ?? 1;
	return {
		database: { schema_version: SCHEMA_VERSION, next_id, leases },
		valid: !length(errors),
		errors,
		expired_count,
		invalid_count,
	};
}

function end_of_today(epoch) {
	const tm = localtime(epoch);
	return timelocal({
		year: tm.year,
		mon: tm.mon,
		mday: tm.mday + 1,
		hour: 0,
		min: 0,
		sec: 0,
		isdst: -1,
	});
}

export function create(database, request, context, epoch, monotonic_now) {
	epoch ??= clock()[0];
	monotonic_now ??= clock(true);
	let errors = [];
	if (epoch < CLOCK_VALID_AFTER)
		push(errors, 'Clock is not valid; Temporary Approval was not created');
	const scope = request ? request.scope : null;
	if (scope != 'access' && scope != 'application')
		push(errors, `Unsupported approval scope '${scope ?? 'missing'}'`);
	const identity_id = trim('' + ((request ? request.identity_id : null) ?? ''));
	const identity = identity_map(context)[identity_id];
	if (!identity || identity.subject_id == null)
		push(errors, `Unknown Identity '${identity_id}'`);

	let class_id = null;
	if (scope == 'application') {
		class_id = parse_uint(request ? request.class_id : null, 65535);
		const class_info = context && context.classes
			? context.classes['' + class_id] : null;
		if (class_id == null || class_id <= CLASS_UNCLASSIFIED || !class_info ||
		    (class_info.kind != 'application' && class_info.kind != 'category'))
			push(errors, `Unknown or reserved application class '${(request ? request.class_id : null) ?? 'missing'}'`);
	}
	const duration = request ? request.duration : null;
	let expires_at = null;
	if (duration == 'one_hour')
		expires_at = epoch + 3600;
	else if (duration == 'today')
		expires_at = end_of_today(epoch);
	else
		push(errors, `Unsupported approval duration '${duration ?? 'missing'}'`);
	if (expires_at == null || expires_at <= epoch)
		push(errors, 'Temporary Approval expiry is not in the future');
	const monotonic_current = monotonic_second(monotonic_now);
	if (monotonic_current == null)
		push(errors, 'Monotonic clock is unavailable; Temporary Approval was not created');

	const key = target_key(scope, identity_id, class_id);
	let retained = [], replacing = false;
	for (let lease in ((database && database.leases) ?? [])) {
		if (lease.target_key == key)
			replacing = true;
		else
			push(retained, lease);
	}
	if (!replacing && length(retained) >= MAX_ACTIVE_LEASES)
		push(errors, `Temporary Approval capacity ${MAX_ACTIVE_LEASES} is exhausted`);
	if (length(errors))
		return { ok: false, database, lease: null, replacing, errors };

	const sequence = parse_uint(database ? database.next_id : null, 4294967295) ?? 1;
	const lease = {
		id: `lease-${epoch}-${sequence}`,
		scope,
		identity_id,
		subject_id: identity.subject_id,
		...(scope == 'application' ? { class_id } : {}),
		target_key: key,
		created_at: epoch,
		expires_at,
		monotonic_deadline: monotonic_current + (expires_at - epoch),
		duration,
	};
	push(retained, lease);
	sort(retained, (a, b) => a.target_key < b.target_key ? -1 :
		(a.target_key > b.target_key ? 1 : 0));
	return {
		ok: true,
		database: {
			schema_version: SCHEMA_VERSION,
			next_id: sequence == 4294967295 ? 1 : sequence + 1,
			leases: retained,
		},
		lease,
		replacing,
		errors,
	};
}

export function revoke(database, lease_id) {
	let leases = [], removed = null;
	for (let lease in ((database && database.leases) ?? [])) {
		if (lease.id == lease_id)
			removed = lease;
		else
			push(leases, lease);
	}
	return removed == null
		? { ok: false, database, lease: null,
			errors: [ `Unknown Temporary Approval '${lease_id}'` ] }
		: { ok: true, database: { ...database, leases }, lease: removed, errors: [] };
}

export function inspect(database, lease_id, epoch, monotonic_now) {
	epoch ??= clock()[0];
	monotonic_now ??= clock(true);
	for (let lease in ((database && database.leases) ?? [])) {
		if (lease.id != lease_id)
			continue;
		const monotonic_current = monotonic_second(monotonic_now);
		let remaining = lease.expires_at - epoch;
		if (lease.monotonic_deadline != null && monotonic_current != null &&
		    lease.monotonic_deadline - monotonic_current < remaining)
			remaining = lease.monotonic_deadline - monotonic_current;
		return { ...lease, active: remaining > 0 && epoch >= CLOCK_VALID_AFTER &&
			monotonic_current != null,
			remaining_seconds: remaining > 0 ? remaining : 0 };
	}
	return null;
}

export function list(database, epoch, monotonic_now) {
	let leases = [];
	for (let lease in ((database && database.leases) ?? []))
		push(leases, inspect(database, lease.id, epoch, monotonic_now));
	return leases;
}

export function next_expiry(database) {
	let result = null;
	for (let lease in ((database && database.leases) ?? []))
		if (result == null || lease.expires_at < result)
			result = lease.expires_at;
	return result;
}

export function overlay_access(compiled, database) {
	let by_identity = {};
	for (let lease in ((database && database.leases) ?? []))
		if (lease.scope == 'access')
			by_identity[lease.identity_id] = lease;
	let identities = [];
	for (let identity in (compiled.identities ?? [])) {
		const lease = by_identity[identity.id];
		push(identities, {
			...identity,
			base_verdict: identity.verdict,
			verdict: lease ? 'allow' : identity.verdict,
			verdict_source: lease ? 'temporary_approval' : 'base_policy',
			lease_id: lease ? lease.id : null,
			lease_expires_at: lease ? lease.expires_at : null,
		});
	}
	return { ...compiled, identities,
		next_transition: min_transition(compiled.next_transition, next_expiry(database)) };
}

function min_transition(first, second) {
	if (first == null)
		return second;
	if (second == null)
		return first;
	return first < second ? first : second;
}

export function overlay_application(compiled, database) {
	let application_leases = [];
	for (let lease in ((database && database.leases) ?? []))
		if (lease.scope == 'application')
			push(application_leases, lease);
	let policies = [];
	for (let policy in (compiled.policies ?? [])) {
		let matching = null;
		if (policy.class_id > CLASS_UNCLASSIFIED)
			for (let lease in application_leases)
				if (lease.identity_id == policy.identity_id &&
				    lease_matches_class(lease, policy.class_id, compiled.classes)) {
					matching = lease;
					break;
				}
		push(policies, {
			...policy,
			base_verdict: policy.verdict,
			verdict: matching ? 'allow' : policy.verdict,
			verdict_source: matching ? 'temporary_approval' : 'base_policy',
			lease_id: matching ? matching.id : null,
			lease_expires_at: matching ? matching.expires_at : null,
		});
	}
	return { ...compiled, policies,
		next_transition: min_transition(compiled.next_transition, next_expiry(database)) };
}

function snapshot_entry(scope, identity_id, subject_id, class_id, verdict) {
	const key = scope == 'access' ? `access/${identity_id}`
		: `application/${identity_id}/${class_id}`;
	return { key, scope, identity_id, subject_id,
		...(scope == 'application' ? { class_id } : {}), verdict };
}

export function effective_snapshot(access_compiled, app_compiled) {
	let entries = {};
	for (let identity in (access_compiled.identities ?? [])) {
		let subject_id = null;
		for (let candidate in (app_compiled.identities ?? []))
			if (candidate.id == identity.id)
				subject_id = candidate.subject_id;
		const entry = snapshot_entry('access', identity.id, subject_id, null,
			identity.verdict);
		entries[entry.key] = entry;
	}
	for (let policy in (app_compiled.policies ?? [])) {
		const entry = snapshot_entry('application', policy.identity_id,
			policy.subject_id, policy.class_id, policy.verdict);
		entries[entry.key] = entry;
	}
	return entries;
}

export function plan_transitions(previous, current, reason) {
	let result = [], names = keys(current ?? {});
	sort(names);
	for (let key in names) {
		const old_entry = previous ? previous[key] : null, new_entry = current[key];
		if (!old_entry || old_entry.verdict == new_entry.verdict)
			continue;
		const restrictive = old_entry.verdict == 'allow' && new_entry.verdict == 'deny';
		push(result, {
			scope: new_entry.scope,
			subject_id: new_entry.subject_id,
			identity_id: new_entry.identity_id,
			...(new_entry.class_id != null ? { class_id: new_entry.class_id } : {}),
			old_verdict: old_entry.verdict,
			new_verdict: new_entry.verdict,
			reason,
			restrictive,
			ordering: restrictive ? [
				'restrict_admission',
				'publish_restrictive_policy',
				'revoke_bypass_state',
			] : [ 'publish_permissive_policy' ],
			revocation_backend: 'normal_datapath',
			revocation_state: restrictive ? 'pending_publication' : 'not_required',
		});
	}
	return result;
}

export const constants = {
	SCHEMA_VERSION,
	MAX_ACTIVE_LEASES,
	CLOCK_VALID_AFTER,
	CLASS_DEFAULT,
	CLASS_UNCLASSIFIED,
};
