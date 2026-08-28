// SPDX-License-Identifier: Apache-2.0

export function normalize_mac(value) {
	if (value == null)
		return null;
	const mac = lc(trim('' + value));
	return match(mac, /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/) ? mac : null;
}

function identity_index(identities) {
	let index = {}, counts = {};
	for (let identity in identities) {
		counts[identity.id] = (counts[identity.id] ?? 0) + 1;
		index[identity.id] = identity;
	}
	return { index, counts };
}

export function project(compiled, bindings) {
	const identities = identity_index(compiled.identities ?? []);
	let by_mac = {}, details = [], errors = [], warnings = [];

	for (let binding in (bindings ?? [])) {
		const type_name = binding.type ?? 'mac';
		const identity_id = trim('' + (binding.identity ?? ''));
		const label = binding.section ?? binding.value ?? 'binding';
		if (type_name != 'mac') {
			push(errors, `${label}: unsupported binding type '${type_name}'`);
			push(details, { section: binding.section, identity_id, type: type_name, value: binding.value, valid: false });
			continue;
		}

		const mac = normalize_mac(binding.value);
		if (!mac) {
			push(errors, `${label}: invalid MAC '${binding.value ?? ''}'`);
			push(details, { section: binding.section, identity_id, type: type_name, value: binding.value, valid: false });
			continue;
		}

		const detail = {
			section: binding.section,
			identity_id,
			type: 'mac',
			value: mac,
			valid: true,
		};
		push(details, detail);
		by_mac[mac] ??= [];
		push(by_mac[mac], detail);
	}

	let exceptions = [], exception_seen = {};
	function force_verdict(mac, verdict) {
		if (verdict != compiled.default_verdict && !exception_seen[mac]) {
			exception_seen[mac] = true;
			push(exceptions, mac);
		}
	}

	for (let mac, owners in by_mac) {
		if (length(owners) > 1) {
			let owner_ids = [];
			for (let owner in owners)
				push(owner_ids, owner.identity_id);
			push(errors, `${mac}: binding belongs to multiple identities (${join(', ', owner_ids)})`);
			for (let owner in owners) {
				owner.valid = false;
				owner.error = 'duplicate_mac';
			}
			force_verdict(mac, 'deny');
			continue;
		}

		const detail = owners[0];
		if (!length(detail.identity_id) || !identities.index[detail.identity_id]) {
			detail.valid = false;
			detail.error = 'dangling_identity';
			push(errors, `${mac}: binding references unknown identity '${detail.identity_id}'`);
			force_verdict(mac, 'deny');
			continue;
		}
		if (identities.counts[detail.identity_id] != 1) {
			detail.valid = false;
			detail.error = 'ambiguous_identity';
			push(errors, `${mac}: binding references duplicate identity ID '${detail.identity_id}'`);
			force_verdict(mac, 'deny');
			continue;
		}

		const identity = identities.index[detail.identity_id];
		detail.identity_name = identity.name;
		detail.verdict = identity.verdict;
		detail.exception_member = identity.verdict != compiled.default_verdict;
		force_verdict(mac, identity.verdict);
	}

	sort(exceptions);
	return {
		exceptions: compiled.enabled ? exceptions : [],
		preview_exceptions: exceptions,
		bindings: details,
		binding_count: length(details),
		errors,
		warnings,
	};
}

export function project_subjects(app_compiled, bindings) {
	let subjects = {}, subject_counts = {};
	for (let identity in (app_compiled.identities ?? [])) {
		subject_counts[identity.id] = (subject_counts[identity.id] ?? 0) + 1;
		subjects[identity.id] = identity;
	}

	let by_mac = {}, details = [], selectors = [], errors = [];
	for (let binding in (bindings ?? [])) {
		const type_name = binding.type ?? 'mac';
		const identity_id = trim('' + (binding.identity ?? ''));
		const label = binding.section ?? binding.value ?? 'binding';
		if (type_name != 'mac') {
			push(errors, `${label}: unsupported application selector type '${type_name}'`);
			continue;
		}
		const mac = normalize_mac(binding.value);
		if (!mac) {
			push(errors, `${label}: invalid application selector MAC '${binding.value ?? ''}'`);
			continue;
		}
		by_mac[mac] ??= [];
		push(by_mac[mac], { section: binding.section, identity_id, mac });
	}

	for (let mac, owners in by_mac) {
		if (length(owners) != 1) {
			push(errors, `${mac}: application selector belongs to ${length(owners)} identities`);
			continue;
		}
		const owner = owners[0];
		const identity = subjects[owner.identity_id];
		if (!identity || subject_counts[owner.identity_id] != 1 || !identity.valid) {
			push(errors, `${mac}: application selector references invalid Identity '${owner.identity_id}'`);
			continue;
		}
		const detail = {
			section: owner.section,
			identity_id: owner.identity_id,
			subject_id: identity.subject_id,
			mac,
		};
		push(details, detail);
		push(selectors, { mac, subject_id: identity.subject_id });
	}

	sort(selectors, (a, b) => a.mac < b.mac ? -1 : (a.mac > b.mac ? 1 : 0));
	return {
		selectors: app_compiled.enabled ? selectors : [],
		preview_selectors: selectors,
		details,
		errors,
	};
}
