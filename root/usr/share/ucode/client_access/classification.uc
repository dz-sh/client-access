// SPDX-License-Identifier: Apache-2.0

/*
 * Client Access V4.2 classification architecture.
 *
 * This module is deliberately backend-neutral until lower_projection().
 * Profiles and observations never reach BPF. The datapath receives only the
 * compact result of deterministic userspace reduction.
 */

const CLASS_UNCLASSIFIED = 1;
const MAX_CLASS_ID = 65535;
const CLASS_KIND_EXACT = 1;
const CLASS_KIND_CATEGORY = 2;
const CLASS_KIND_UNCLASSIFIED = 3;

const SIGNATURE_MEMORY = {
	port: 128,
	ipv4_prefix: 160,
	ipv6_prefix: 192,
	domain_base: 128,
};

const SIGNATURE_CAPACITY = {
	ports: 1024,
	ipv4_prefixes: 4096,
	ipv6_prefixes: 4096,
	domains: 4096,
};

function as_list(value) {
	if (value == null)
		return [];
	return type(value) == 'array' ? value : [ value ];
}

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
	for (let octet in octets) {
		const parsed = parse_uint(octet, 255);
		if (parsed == null)
			return false;
	}
	return true;
}

function valid_ipv4_prefix(value) {
	const parts = split(value, /\//);
	return length(parts) == 2 && valid_ipv4_address(parts[0]) &&
		parse_uint(parts[1], 32) != null;
}

function valid_ipv6_prefix(value) {
	const parts = split(value, /\//);
	return length(parts) == 2 && match(parts[0], /^[0-9a-f:]+$/) &&
		match(parts[0], /:/) && parse_uint(parts[1], 128) != null;
}

function normalized_strings(values) {
	let result = [], seen = {};
	for (let value in as_list(values)) {
		value = lc(trim('' + value));
		if (length(value) && !seen[value]) {
			seen[value] = true;
			push(result, value);
		}
	}
	sort(result);
	return result;
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

function runtime_category_id(classes, class_id) {
	let current = classes['' + class_id], seen = {};
	while (current && !seen[current.id]) {
		seen[current.id] = true;
		if (current.kind == 'category')
			return current.id;
		current = current.parent_id != null ? classes['' + current.parent_id] : null;
	}
	return null;
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

function validate_class_graph(classes, configured_ids, errors) {
	for (let class_id in configured_ids) {
		let current = class_id, seen = {};
		while (current != null) {
			if (seen[current]) {
				push(errors, `Profile class ${class_id}: parent cycle includes ${current}`);
				break;
			}
			seen[current] = true;
			const info = classes['' + current];
			if (!info)
				break;
			if (info.parent_id != null && !classes['' + info.parent_id]) {
				push(errors, `Profile class ${current}: unknown parent ${info.parent_id}`);
				break;
			}
			current = info.parent_id;
		}
	}
}

function hint_for_class(classes, class_info, allow_port_downgrade) {
	const category_id = runtime_category_id(classes, class_info.id);
	if (class_info.kind == 'category')
		return { class_id: class_info.id, category_id: class_info.id,
			kind: CLASS_KIND_CATEGORY };
	if (allow_port_downgrade)
		return category_id == null ? null : {
			class_id: category_id,
			category_id,
			kind: CLASS_KIND_CATEGORY,
		};
	return {
		class_id: class_info.id,
		category_id: category_id ?? 0,
		kind: CLASS_KIND_EXACT,
	};
}

function merge_claims(classes, claims) {
	let selected = null, conflict = false;
	let profiles = [], providers = [], observation_types = [];

	for (let claim in claims) {
		if (claim.profile_id != null)
			push(profiles, claim.profile_id);
		if (claim.provider_id != null)
			push(providers, claim.provider_id);
		if (claim.observation_type != null)
			push(observation_types, claim.observation_type);
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
			class_id: CLASS_UNCLASSIFIED,
			category_id: 0,
			kind: CLASS_KIND_UNCLASSIFIED,
		} : selected,
		conflict: conflict || !selected,
		profiles: unique_sorted(profiles),
		providers: unique_sorted(providers),
		observation_types: unique_sorted(observation_types),
	};
}

function expression_key(entry) {
	return `${entry.primitive}/${entry.value}`;
}

function add_ir(ir_by_key, entry) {
	const key = `${expression_key(entry)}/${entry.profile_id}`;
	ir_by_key[key] = entry;
}

export function compile_profiles(app_classes) {
	let errors = [], warnings = [];
	let classes = {}, profiles_by_id = {}, profile_owner = {}, configured_ids = [];

	for (let app_class in (app_classes ?? [])) {
		const id = parse_uint(app_class.id ?? app_class.class_id, MAX_CLASS_ID);
		const label = trim('' + (app_class.name ?? app_class.section ?? app_class.id ?? 'Profile'));
		if (id == null || id <= CLASS_UNCLASSIFIED) {
			push(errors, `${label}: class_id must be an integer from 2 to ${MAX_CLASS_ID}`);
			continue;
		}
		if (classes['' + id]) {
			push(errors, `${label}: duplicate class_id ${id}`);
			continue;
		}

		const profile_id = trim('' + (app_class.profile_id ?? app_class.section ?? `native:${id}`));
		if (!length(profile_id)) {
			push(errors, `${label}: Profile has no stable ID`);
			continue;
		}
		if (profile_owner[profile_id]) {
			push(errors, `${label}: duplicate Profile ID '${profile_id}'`);
			continue;
		}
		const schema_version = trim('' + (app_class.profile_schema_version ?? '1'));
		if (schema_version != '1')
			push(errors, `${label}: unsupported Profile schema '${schema_version}'`);
		const parent_id = app_class.parent_id == null || trim('' + app_class.parent_id) == ''
			? null : parse_uint(app_class.parent_id, MAX_CLASS_ID);
		if (app_class.parent_id != null && trim('' + app_class.parent_id) != '' &&
		    parent_id == null)
			push(errors, `${label}: invalid parent class '${app_class.parent_id}'`);

		const kind = trim('' + (app_class.kind ?? 'application'));
		if (kind != 'application' && kind != 'category')
			push(errors, `${label}: Profile kind must be application or category`);
		classes['' + id] = {
			id,
			name: label,
			kind: kind == 'category' ? 'category' : 'application',
			parent_id,
			profile_id,
		};
		profile_owner[profile_id] = id;
		push(configured_ids, id);
	}

	validate_class_graph(classes, configured_ids, errors);
	for (let class_id in configured_ids) {
		const class_info = classes['' + class_id];
		if (class_info.parent_id != null && classes['' + class_info.parent_id] &&
		    classes['' + class_info.parent_id].kind != 'category')
			push(errors, `Profile class ${class_id}: parent ${class_info.parent_id} is not a category`);
	}
	for (let class_id in configured_ids)
		classes['' + class_id].category_id = runtime_category_id(classes, class_id);

	for (let app_class in (app_classes ?? [])) {
		const id = parse_uint(app_class.id ?? app_class.class_id, MAX_CLASS_ID);
		const class_info = id != null ? classes['' + id] : null;
		if (!class_info || profiles_by_id[class_info.profile_id])
			continue;

		let expressions = [];
		for (let domain in normalized_strings(app_class.domains)) {
			if (!match(domain, /^(\*\.)?[a-z0-9_-]+(\.[a-z0-9_-]+)+$/)) {
				push(errors, `${class_info.name}: invalid domain pattern '${domain}'`);
				continue;
			}
			push(expressions, substr(domain, 0, 2) == '*.'
				? { primitive: 'domain_suffix', value: substr(domain, 2), subdomains_only: true }
				: { primitive: 'domain_exact', value: domain });
		}
		for (let port in normalized_strings(app_class.tcp_ports))
			push(expressions, { primitive: 'tcp_port', value: port });
		for (let port in normalized_strings(app_class.udp_ports))
			push(expressions, { primitive: 'udp_port', value: port });
		for (let prefix in normalized_strings(app_class.ipv4_prefixes))
			push(expressions, { primitive: 'ipv4_prefix', value: prefix });
		for (let prefix in normalized_strings(app_class.ipv6_prefixes))
			push(expressions, { primitive: 'ipv6_prefix', value: prefix });

		let expression_map = {};
		for (let expression in expressions)
			expression_map[`${expression.primitive}/${expression.value}`] = expression;

		profiles_by_id[class_info.profile_id] = {
			id: class_info.profile_id,
			class_id: class_info.id,
			display_name: class_info.name,
			kind: class_info.kind,
			parent_category_id: class_info.parent_id,
			schema_version: trim('' + (app_class.profile_schema_version ?? '1')),
			source: trim('' + (app_class.profile_source ?? 'native')),
			license: trim('' + (app_class.profile_license ?? 'user-configured')),
			provenance: trim('' + (app_class.profile_provenance ?? `uci:${class_info.profile_id}`)),
			expressions: sorted_map_values(expression_map),
		};
	}

	let ir_by_key = {};
	for (let profile_id, profile in profiles_by_id) {
		const class_info = classes['' + profile.class_id];
		const direct_hint = hint_for_class(classes, class_info, false);
		const port_hint = hint_for_class(classes, class_info, true);
		for (let expression in profile.expressions) {
			let hint = direct_hint, valid = true;
			if (expression.primitive == 'tcp_port' || expression.primitive == 'udp_port') {
				const port = parse_uint(expression.value, 65535);
				if (port == null || port == 0) {
					push(errors, `${profile.display_name}: invalid destination port '${expression.value}'`);
					valid = false;
				}
				else if (!port_hint) {
					push(warnings, `${profile.display_name}: port-only evidence was ignored because the application has no category parent`);
					valid = false;
				}
				hint = port_hint;
			}
			else if (expression.primitive == 'ipv4_prefix' &&
			         !valid_ipv4_prefix(expression.value)) {
				push(errors, `${profile.display_name}: invalid IPv4 prefix '${expression.value}'`);
				valid = false;
			}
			else if (expression.primitive == 'ipv6_prefix' &&
			         !valid_ipv6_prefix(expression.value)) {
				push(errors, `${profile.display_name}: invalid IPv6 prefix '${expression.value}'`);
				valid = false;
			}
			if (!valid)
				continue;
			add_ir(ir_by_key, {
				primitive: expression.primitive,
				value: expression.value,
				subdomains_only: expression.subdomains_only ?? false,
				profile_id,
				hint,
			});
		}
	}

	const ir = sorted_map_values(ir_by_key);
	let static_groups = {}, primitive_counts = {
		ports: 0, ipv4_prefixes: 0, ipv6_prefixes: 0, domains: 0,
	};
	let domain_memory_bytes = 0;
	for (let entry in ir) {
		if (entry.primitive == 'domain_exact' || entry.primitive == 'domain_suffix') {
			primitive_counts.domains++;
			domain_memory_bytes += SIGNATURE_MEMORY.domain_base + length(entry.value);
		}
		else {
			if (entry.primitive == 'tcp_port' || entry.primitive == 'udp_port')
				primitive_counts.ports++;
			else if (entry.primitive == 'ipv4_prefix')
				primitive_counts.ipv4_prefixes++;
			else if (entry.primitive == 'ipv6_prefix')
				primitive_counts.ipv6_prefixes++;
			const key = expression_key(entry);
			static_groups[key] ??= [];
			push(static_groups[key], entry);
		}
	}
	for (let key, claims in static_groups) {
		const result = merge_claims(classes, claims);
		if (result.conflict)
			push(errors, `Conflicting static Profile knowledge for '${key}'`);
	}
	for (let kind, maximum in SIGNATURE_CAPACITY)
		if (primitive_counts[kind] > maximum)
			push(errors, `Classification IR ${kind} exceeds capacity ${maximum}`);

	const profiles = sorted_map_values(profiles_by_id);
	return {
		profile_schema_version: 1,
		ir_version: 1,
		profiles,
		classes,
		configured_class_ids: configured_ids,
		ir,
		profile_count: length(profiles),
		ir_entry_count: length(ir),
		domain_memory_bytes,
		signature: sprintf('%J', { profiles, ir }),
		errors,
		warnings,
	};
}

export function normalize_dns_observation(data, generation, epoch) {
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
	if (ttl < 1)
		ttl = 1;
	if (ttl > 86400)
		ttl = 86400;
	const address_type = record_type == 'AAAA' ? 'ipv6' : 'ipv4';
	const observation = {
		provider_id: 'dnsmasq',
		observation_type: 'dns_address',
		observation_key: domain,
		observed_value: { address_type, address },
		expires_at: epoch + ttl,
		generation,
		authority: 'dns-answer',
		specificity: length(domain),
	};
	observation.id = `dnsmasq/dns_address/${domain}/${address_type}/${address}`;
	return { valid: !length(errors), observation, errors };
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
	if (hint.kind == CLASS_KIND_EXACT)
		return 'exact';
	if (hint.kind == CLASS_KIND_CATEGORY)
		return 'category';
	return 'unclassified';
}

function lower_projection(model, semantic_state, resource_limits) {
	let projection = {
		ports: [],
		ipv4_prefixes: [],
		ipv6_prefixes: [],
		signature_count: 0,
		signature_memory_bytes: model.domain_memory_bytes,
		semantic_entry_count: length(semantic_state.entries),
	};
	for (let entry in semantic_state.entries) {
		const hint = {
			class_id: entry.result.class_id,
			category_id: entry.result.category_id,
			kind: entry.result.kind_id,
		};
		if (entry.key.type == 'tcp_port' || entry.key.type == 'udp_port') {
			push(projection.ports, {
				protocol: entry.key.type == 'tcp_port' ? 6 : 17,
				port: +entry.key.value,
				hint,
			});
			projection.signature_memory_bytes += SIGNATURE_MEMORY.port;
		}
		else if (entry.key.type == 'ipv4_prefix') {
			push(projection.ipv4_prefixes, { prefix: entry.key.value, hint });
			projection.signature_memory_bytes += SIGNATURE_MEMORY.ipv4_prefix;
		}
		else if (entry.key.type == 'ipv6_prefix') {
			push(projection.ipv6_prefixes, { prefix: entry.key.value, hint });
			projection.signature_memory_bytes += SIGNATURE_MEMORY.ipv6_prefix;
		}
	}
	projection.signature_count = length(projection.ports) +
		length(projection.ipv4_prefixes) + length(projection.ipv6_prefixes);

	let errors = [];
	if (length(projection.ports) > SIGNATURE_CAPACITY.ports)
		push(errors, `Runtime projection ports exceeds capacity ${SIGNATURE_CAPACITY.ports}`);
	if (length(projection.ipv4_prefixes) > SIGNATURE_CAPACITY.ipv4_prefixes)
		push(errors, `Runtime projection IPv4 prefixes exceeds capacity ${SIGNATURE_CAPACITY.ipv4_prefixes}`);
	if (length(projection.ipv6_prefixes) > SIGNATURE_CAPACITY.ipv6_prefixes)
		push(errors, `Runtime projection IPv6 prefixes exceeds capacity ${SIGNATURE_CAPACITY.ipv6_prefixes}`);
	if (projection.signature_memory_bytes > resource_limits.signature_table_memory_limit)
		push(errors,
			`Runtime projection requires an estimated ${projection.signature_memory_bytes} bytes, exceeding limit ${resource_limits.signature_table_memory_limit}`);
	projection.signature = sprintf('%J', {
		ports: projection.ports,
		ipv4_prefixes: projection.ipv4_prefixes,
		ipv6_prefixes: projection.ipv6_prefixes,
	});
	return { projection, errors };
}

export function resolve(model, observations, epoch, generation, resource_limits) {
	epoch ??= clock()[0];
	let groups = {}, errors = [], warnings = [];
	let providers = {}, active_observations = 0, expired_observations = 0;
	let stale_observations = 0, next_expiry = null;

	for (let entry in model.ir) {
		if (entry.primitive == 'domain_exact' || entry.primitive == 'domain_suffix')
			continue;
		add_group_claim(groups, expression_key(entry), {
			type: entry.primitive,
			value: entry.value,
		}, {
			...entry,
			provider_id: 'native',
			observation_type: 'profile_expression',
		});
		providers.native = true;
	}

	for (let observation in (observations ?? [])) {
		if (observation.generation != generation) {
			stale_observations++;
			continue;
		}
		if (observation.expires_at <= epoch) {
			expired_observations++;
			continue;
		}
		if (next_expiry == null || observation.expires_at < next_expiry)
			next_expiry = observation.expires_at;
		if (observation.observation_type != 'dns_address')
			continue;
		providers[observation.provider_id] = true;
		active_observations++;
		const claims = domain_claims(model, observation.observation_key);
		if (!length(claims))
			continue;
		let normalized_claims = [];
		for (let claim in claims)
			push(normalized_claims, {
				...claim,
				provider_id: observation.provider_id,
				observation_type: observation.observation_type,
			});
		const domain_result = merge_claims(model.classes, normalized_claims);
		const address_type = observation.observed_value.address_type;
		const address = observation.observed_value.address;
		const prefix = `${address}/${address_type == 'ipv4' ? 32 : 128}`;
		const primitive = address_type == 'ipv4' ? 'ipv4_prefix' : 'ipv6_prefix';
		for (let profile_id in domain_result.profiles)
			add_group_claim(groups, `${primitive}/${prefix}`, {
				type: primitive,
				value: prefix,
			}, {
				hint: domain_result.hint,
				profile_id,
				provider_id: observation.provider_id,
				observation_type: observation.observation_type,
			});
	}

	let semantic_by_key = {}, conflicts = 0;
	for (let key, group in groups) {
		const result = merge_claims(model.classes, group.claims);
		if (result.conflict)
			conflicts++;
		semantic_by_key[key] = {
			key: group.runtime_key,
			result: {
				class_id: result.hint.class_id,
				category_id: result.hint.category_id,
				kind: semantic_kind(result.hint),
				kind_id: result.hint.kind,
			},
			explanation: {
				profile_ids: result.profiles,
				provider_ids: result.providers,
				observation_types: result.observation_types,
			},
		};
	}
	const semantic_state = {
		version: 1,
		entries: sorted_map_values(semantic_by_key),
		provider_ids: keys(providers),
		active_observation_count: active_observations,
		expired_observation_count: expired_observations,
		stale_observation_count: stale_observations,
		conflict_count: conflicts,
		next_expiry,
	};
	sort(semantic_state.provider_ids);

	const lowered = lower_projection(model, semantic_state, resource_limits);
	for (let error in lowered.errors)
		push(errors, error);
	return {
		semantic_state,
		runtime_projection: lowered.projection,
		errors,
		warnings,
		next_expiry,
	};
}

export const constants = {
	CLASS_UNCLASSIFIED,
	MAX_CLASS_ID,
	CLASS_KIND_EXACT,
	CLASS_KIND_CATEGORY,
	CLASS_KIND_UNCLASSIFIED,
	SIGNATURE_MEMORY,
	SIGNATURE_CAPACITY,
};
