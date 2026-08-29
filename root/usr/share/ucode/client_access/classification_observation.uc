// SPDX-License-Identifier: Apache-2.0

/* Provider observation normalization, deterministic fusion, and expiry. */

import * as projection from 'client_access.classification_projection';

const CLASS_UNCLASSIFIED = 1;
const CLASS_KIND_EXACT = 1;
const CLASS_KIND_CATEGORY = 2;
const CLASS_KIND_UNCLASSIFIED = 3;

function parse_uint(value, maximum) {
	const text = trim('' + (value ?? ''));
	if (!match(text, /^(0|[1-9][0-9]*)$/))
		return null;
	const number = +text;
	return number >= 0 && number <= maximum ? number : null;
}

function valid_ipv4_address(value) {
	const octets = split(value, /\./);
	if (length(octets) != 4)
		return false;
	for (let octet in octets)
		if (parse_uint(octet, 255) == null)
			return false;
	return true;
}

function sorted_map_values(values) {
	let result = [], names = keys(values);
	sort(names);
	for (let name in names)
		push(result, values[name]);
	return result;
}

function unique_sorted(values) {
	let seen = {};
	for (let value in values)
		seen['' + value] = true;
	let result = keys(seen);
	sort(result);
	return result;
}

function category_is_ancestor(classes, category_id, class_id) {
	let current = classes['' + class_id], seen = {};
	while (current && !seen[current.id]) {
		seen[current.id] = true;
		if (current.id == category_id && current.kind == 'category')
			return true;
		current = current.parent_id != null ? classes['' + current.parent_id] : null;
	}
	return false;
}

function merge_claims(classes, claims) {
	let selected = null, conflict = false;
	let profiles = [], providers = [], observation_types = [];
	for (let claim in claims) {
		if (claim.profile_id != null) push(profiles, claim.profile_id);
		if (claim.provider_id != null) push(providers, claim.provider_id);
		if (claim.observation_type != null) push(observation_types, claim.observation_type);
		const hint = claim.hint;
		if (!hint || hint.kind == CLASS_KIND_UNCLASSIFIED) {
			conflict = true;
			continue;
		}
		if (!selected) {
			selected = hint;
			continue;
		}
		if (selected.kind == hint.kind && selected.class_id == hint.class_id)
			continue;
		if (selected.kind == CLASS_KIND_EXACT && hint.kind == CLASS_KIND_CATEGORY &&
		    category_is_ancestor(classes, hint.class_id, selected.class_id))
			continue;
		if (selected.kind == CLASS_KIND_CATEGORY && hint.kind == CLASS_KIND_EXACT &&
		    category_is_ancestor(classes, selected.class_id, hint.class_id)) {
			selected = hint;
			continue;
		}
		if (selected.kind == CLASS_KIND_CATEGORY && hint.kind == CLASS_KIND_CATEGORY) {
			if (category_is_ancestor(classes, selected.class_id, hint.class_id)) {
				selected = hint;
				continue;
			}
			if (category_is_ancestor(classes, hint.class_id, selected.class_id))
				continue;
		}
		conflict = true;
	}
	return {
		hint: conflict || !selected ? {
			class_id: CLASS_UNCLASSIFIED, category_id: 0,
			kind: CLASS_KIND_UNCLASSIFIED,
		} : selected,
		conflict: conflict || !selected,
		profiles: unique_sorted(profiles),
		providers: unique_sorted(providers),
		observation_types: unique_sorted(observation_types),
	};
}

function domain_claims(model, domain) {
	let selected = [], score = -1;
	for (let entry in model.ir) {
		let current = -1;
		if (entry.primitive == 'domain_exact' && domain == entry.value)
			current = 100000 + length(entry.value);
		else if (entry.primitive == 'domain_suffix' &&
		         length(domain) > length(entry.value) &&
		         substr(domain, length(domain) - length(entry.value) - 1) == `.${entry.value}`)
			current = length(entry.value);
		if (current > score) {
			selected = [ entry ];
			score = current;
		}
		else if (current >= 0 && current == score)
			push(selected, entry);
	}
	return selected;
}

function add_group_claim(groups, key, runtime_key, claim) {
	groups[key] ??= { runtime_key, claims: [] };
	push(groups[key].claims, claim);
}

function semantic_kind(hint) {
	if (hint.kind == CLASS_KIND_EXACT) return 'exact';
	if (hint.kind == CLASS_KIND_CATEGORY) return 'category';
	return 'unclassified';
}

export function normalize_dns(data, generation, epoch) {
	epoch ??= clock()[0];
	let errors = [];
	const record_type = data.type;
	let domain = lc(trim('' + (data.name ?? '')));
	domain = replace(domain, /\.+$/, '');
	const address = lc(trim('' + (data.address ?? '')));
	const ttl_text = trim('' + (data.ttl ?? ''));
	const ttl_value = parse_uint(ttl_text, 4294967295);
	if (record_type != 'A' && record_type != 'AAAA')
		push(errors, `Unsupported dnsmasq observation type '${record_type ?? 'missing'}'`);
	if (!match(domain, /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/))
		push(errors, `Invalid observed domain '${domain}'`);
	if ((record_type == 'A' && !valid_ipv4_address(address)) ||
	    (record_type == 'AAAA' &&
	     (!match(address, /^[0-9a-f:]+$/) || !match(address, /:/))))
		push(errors, `Invalid observed address '${address}'`);
	if (ttl_value == null)
		push(errors, `Invalid observed TTL '${ttl_text}'`);
	if (!generation || generation < 1)
		push(errors, 'Observation generation must be positive');
	let ttl = ttl_value ?? 1;
	if (ttl < 1) ttl = 1;
	if (ttl > 86400) ttl = 86400;
	const address_type = record_type == 'AAAA' ? 'ipv6' : 'ipv4';
	const observation = {
		provider_id: 'dnsmasq', observation_type: 'dns_address',
		observation_key: domain, observed_value: { address_type, address },
		expires_at: epoch + ttl, generation, authority: 'dns-answer',
		specificity: length(domain),
	};
	observation.id = `dnsmasq/dns_address/${domain}/${address_type}/${address}`;
	return { valid: !length(errors), observation, errors };
}

export function resolve(model, observations, epoch, generation, resource_limits) {
	epoch ??= clock()[0];
	let groups = {}, errors = [], warnings = [];
	let providers = {}, active = 0, expired = 0, stale = 0, next_expiry = null;
	for (let entry in model.ir) {
		if (entry.primitive == 'domain_exact' || entry.primitive == 'domain_suffix')
			continue;
		add_group_claim(groups, `${entry.primitive}/${entry.value}`,
			{ type: entry.primitive, value: entry.value }, {
				...entry, provider_id: 'native', observation_type: 'profile_expression',
			});
		providers.native = true;
	}
	for (let observation in (observations ?? [])) {
		if (observation.generation != generation) { stale++; continue; }
		if (observation.expires_at <= epoch) { expired++; continue; }
		if (next_expiry == null || observation.expires_at < next_expiry)
			next_expiry = observation.expires_at;
		if (observation.observation_type != 'dns_address')
			continue;
		providers[observation.provider_id] = true;
		active++;
		const claims = domain_claims(model, observation.observation_key);
		if (!length(claims)) continue;
		let normalized = [];
		for (let claim in claims)
			push(normalized, { ...claim, provider_id: observation.provider_id,
				observation_type: observation.observation_type });
		const result = merge_claims(model.classes, normalized);
		const address_type = observation.observed_value.address_type;
		const address = observation.observed_value.address;
		const prefix = `${address}/${address_type == 'ipv4' ? 32 : 128}`;
		const primitive = address_type == 'ipv4' ? 'ipv4_prefix' : 'ipv6_prefix';
		for (let profile_id in result.profiles)
			add_group_claim(groups, `${primitive}/${prefix}`,
				{ type: primitive, value: prefix }, {
					hint: result.hint, profile_id,
					provider_id: observation.provider_id,
					observation_type: observation.observation_type,
				});
	}
	let semantic_by_key = {}, conflicts = 0;
	for (let key, group in groups) {
		const result = merge_claims(model.classes, group.claims);
		if (result.conflict) conflicts++;
		semantic_by_key[key] = {
			key: group.runtime_key,
			result: { class_id: result.hint.class_id,
				category_id: result.hint.category_id,
				kind: semantic_kind(result.hint), kind_id: result.hint.kind },
			explanation: { profile_ids: result.profiles,
				provider_ids: result.providers,
				observation_types: result.observation_types },
		};
	}
	const semantic_state = {
		version: 1, entries: sorted_map_values(semantic_by_key),
		provider_ids: keys(providers), active_observation_count: active,
		expired_observation_count: expired, stale_observation_count: stale,
		conflict_count: conflicts, next_expiry,
	};
	sort(semantic_state.provider_ids);
	const lowered = projection.lower(model, semantic_state, resource_limits);
	for (let error in lowered.errors) push(errors, error);
	return { semantic_state, runtime_projection: lowered.projection,
		errors, warnings, next_expiry };
}
