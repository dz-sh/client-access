// SPDX-License-Identifier: Apache-2.0

import { evaluate_schedule } from 'client_access.policy';

const CLASS_DEFAULT = 0;
const CLASS_UNCLASSIFIED = 1;
const MAX_CLASS_ID = 65535;
const MAX_SUBJECT_ID = 4294967295;
const CLASS_KIND_EXACT = 1;
const CLASS_KIND_CATEGORY = 2;

const RESOURCE_DEFAULTS = {
	max_packets_inspected: 1,
	max_bytes_examined: 256,
	max_classification_age_ms: 200,
	max_pending_entries: 256,
	max_new_classifications_per_second: 512,
	per_subject_new_classification_rate: 64,
};

function as_list(value) {
	if (value == null)
		return [];
	return type(value) == 'array' ? value : [ value ];
}

function flag(value, fallback) {
	if (value == null)
		return fallback;
	return value === true || value == 1 || value == '1' || lc('' + value) == 'true';
}

function parse_uint(value, maximum) {
	const text = trim('' + (value ?? ''));
	if (!match(text, /^(0|[1-9][0-9]*)$/))
		return null;
	const number = +text;
	return number >= 0 && number <= maximum ? number : null;
}

function bounded_uint(value, fallback, minimum, maximum, label, errors) {
	if (value == null || trim('' + value) == '')
		return fallback;
	const parsed = parse_uint(value, maximum);
	if (parsed == null || parsed < minimum) {
		push(errors, `${label} must be an integer from ${minimum} to ${maximum}`);
		return fallback;
	}
	return parsed;
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

function normalize_verdict(value, fallback) {
	value = lc(trim('' + (value ?? '')));
	return value == 'allow' || value == 'deny' ? value : fallback;
}

function class_selector(value) {
	value = lc(trim('' + (value ?? '')));
	if (value == 'default')
		return CLASS_DEFAULT;
	if (value == 'unclassified')
		return CLASS_UNCLASSIFIED;
	return parse_uint(value, MAX_CLASS_ID);
}

function compile_rule(rule, epoch) {
	const activation = rule.activation ?? 'inactive';
	let errors = [], active = false, next_transition = null;

	if (activation == 'inactive') {
		active = false;
	}
	else if (activation == 'always_active') {
		active = true;
	}
	else if (activation == 'active_during') {
		const schedule = evaluate_schedule(rule.schedule, epoch);
		for (let error in schedule.errors)
			push(errors, error);
		if (length(errors))
			active = true;
		else {
			active = schedule.active;
			next_transition = schedule.next_epoch;
		}
	}
	else {
		push(errors, `Unknown activation '${activation}'`);
		active = true;
	}

	let verdict = normalize_verdict(rule.verdict, null);
	if (!verdict) {
		push(errors, `Unknown application verdict '${rule.verdict ?? 'missing'}'`);
		verdict = 'deny';
	}
	if (length(errors))
		verdict = 'deny';

	return { activation, active, verdict, next_transition, errors };
}

function rules_at(rules_by_class, id) {
	return rules_by_class['' + id] ?? [];
}

function active_verdict(rules) {
	let found = false, verdict = 'allow';
	for (let rule in rules) {
		if (!rule.effective_active)
			continue;
		found = true;
		if (rule.verdict == 'deny')
			verdict = 'deny';
	}
	return { found, verdict };
}

function resolve_verdict(rules_by_class, class_id, classes) {
	let current = class_id, seen = {};
	while (current != null && !seen[current]) {
		seen[current] = true;
		const result = active_verdict(rules_at(rules_by_class, current));
		if (result.found)
			return { verdict: result.verdict, matched_class_id: current };
		const class_info = classes['' + current];
		current = class_info ? class_info.parent_id : null;
	}

	const fallback = active_verdict(rules_at(rules_by_class, CLASS_DEFAULT));
	return fallback.found
		? { verdict: fallback.verdict, matched_class_id: CLASS_DEFAULT }
		: { verdict: 'allow', matched_class_id: null };
}

function validate_class_graph(classes, configured_ids, errors) {
	for (let class_id in configured_ids) {
		let current = class_id, seen = {};
		while (current != null && current != CLASS_DEFAULT && current != CLASS_UNCLASSIFIED) {
			if (seen[current]) {
				push(errors, `Application class ${class_id}: parent cycle includes ${current}`);
				break;
			}
			seen[current] = true;
			const info = classes['' + current];
			if (!info)
				break;
			if (info.parent_id != null && !classes['' + info.parent_id]) {
				push(errors, `Application class ${current}: unknown parent ${info.parent_id}`);
				break;
			}
			current = info.parent_id;
		}
	}
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

function classifier_hint(classes, class_info, allow_downgrade) {
	const category_id = runtime_category_id(classes, class_info.id);
	if (class_info.kind == 'category')
		return { class_id: class_info.id, category_id: class_info.id, kind: CLASS_KIND_CATEGORY };
	if (allow_downgrade)
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

function add_classifier_entry(entries, seen, key, entry, errors, label) {
	const prior = seen[key];
	if (prior) {
		if (sprintf('%J', prior.hint) != sprintf('%J', entry.hint))
			push(errors, `${label}: conflicting classifier evidence for '${key}'`);
		return;
	}
	seen[key] = entry;
	push(entries, entry);
}

export function compile(config, epoch) {
	epoch ??= clock()[0];
	const schema_supported = '' + (config.schema_version ?? '') == '4';
	const requested_enabled = flag(config.app_filter_enabled, false);
	let errors = [], warnings = [], next_transition = null;
	const resource_limits = {
		max_packets_inspected: bounded_uint(config.max_packets_inspected,
			RESOURCE_DEFAULTS.max_packets_inspected, 1, 1,
			'max_packets_inspected', errors),
		max_bytes_examined: bounded_uint(config.max_bytes_examined,
			RESOURCE_DEFAULTS.max_bytes_examined, 64, 8192,
			'max_bytes_examined', errors),
		max_classification_age_ms: bounded_uint(config.max_classification_age_ms,
			RESOURCE_DEFAULTS.max_classification_age_ms, 1, 10000,
			'max_classification_age_ms', errors),
		max_pending_entries: bounded_uint(config.max_pending_entries,
			RESOURCE_DEFAULTS.max_pending_entries, 1, 16384,
			'max_pending_entries', errors),
		max_new_classifications_per_second: bounded_uint(
			config.max_new_classifications_per_second,
			RESOURCE_DEFAULTS.max_new_classifications_per_second, 1, 100000,
			'max_new_classifications_per_second', errors),
		per_subject_new_classification_rate: bounded_uint(
			config.per_subject_new_classification_rate,
			RESOURCE_DEFAULTS.per_subject_new_classification_rate, 1, 100000,
			'per_subject_new_classification_rate', errors),
	};
	if (resource_limits.per_subject_new_classification_rate >
	    resource_limits.max_new_classifications_per_second) {
		push(errors, 'per_subject_new_classification_rate cannot exceed the global classification rate');
		resource_limits.per_subject_new_classification_rate =
			resource_limits.max_new_classifications_per_second;
	}

	if (!schema_supported)
		push(errors, `Unsupported configuration schema '${config.schema_version ?? 'missing'}'`);

	let unknown_subject_app_verdict = normalize_verdict(config.unknown_subject_app_verdict, null);
	if (!unknown_subject_app_verdict) {
		if (config.unknown_subject_app_verdict != null)
			push(errors, `Unknown unknown-subject application verdict '${config.unknown_subject_app_verdict}'`);
		unknown_subject_app_verdict = 'allow';
	}

	let provisional_app_verdict = normalize_verdict(config.provisional_app_verdict, null);
	if (!provisional_app_verdict)
		provisional_app_verdict = 'allow';
	if (provisional_app_verdict != 'allow') {
		push(errors, 'V4.1 only supports provisional application verdict allow');
		provisional_app_verdict = 'allow';
	}

	let identities = [], identity_by_id = {}, subject_owner = {};
	for (let identity in (config.identities ?? [])) {
		const id = trim('' + (identity.id ?? identity.section ?? ''));
		const subject_id = parse_uint(identity.subject_id, MAX_SUBJECT_ID);
		let valid = true;
		if (!length(id)) {
			push(errors, 'Application-policy Identity has no stable ID');
			valid = false;
		}
		else if (identity_by_id[id]) {
			push(errors, `Duplicate application-policy Identity ID '${id}'`);
			valid = false;
		}
		if (subject_id == null || subject_id == 0) {
			push(errors, `${identity.name ?? id ?? 'Identity'}: subject_id must be an integer from 1 to ${MAX_SUBJECT_ID}`);
			valid = false;
		}
		else if (subject_owner['' + subject_id]) {
			push(errors, `subject_id ${subject_id} belongs to both '${subject_owner['' + subject_id]}' and '${id}'`);
			valid = false;
		}

		const compiled_identity = {
			id,
			name: identity.name ?? id,
			subject_id,
			valid,
		};
		push(identities, compiled_identity);
		if (length(id) && !identity_by_id[id])
			identity_by_id[id] = compiled_identity;
		if (subject_id != null && subject_id != 0 && !subject_owner['' + subject_id])
			subject_owner['' + subject_id] = id;
	}

	let classes = {
		'0': { id: CLASS_DEFAULT, name: 'Application policy default', kind: 'default', parent_id: null },
		'1': { id: CLASS_UNCLASSIFIED, name: 'Unclassified', kind: 'unclassified', parent_id: null },
	};
	let configured_class_ids = [];
	for (let app_class in (config.app_classes ?? [])) {
		const id = parse_uint(app_class.id ?? app_class.class_id, MAX_CLASS_ID);
		const label = app_class.name ?? app_class.section ?? app_class.id ?? 'class';
		if (id == null || id <= CLASS_UNCLASSIFIED) {
			push(errors, `${label}: class_id must be an integer from 2 to ${MAX_CLASS_ID}`);
			continue;
		}
		if (classes['' + id]) {
			push(errors, `${label}: duplicate class_id ${id}`);
			continue;
		}
		const parent_id = app_class.parent_id == null || trim('' + app_class.parent_id) == ''
			? null : parse_uint(app_class.parent_id, MAX_CLASS_ID);
		if (app_class.parent_id != null && parent_id == null)
			push(errors, `${label}: invalid parent class '${app_class.parent_id}'`);
		classes['' + id] = {
			id,
			name: label,
			kind: app_class.kind == 'category' ? 'category' : 'application',
			parent_id,
			domains: normalized_strings(app_class.domains),
			tcp_ports: normalized_strings(app_class.tcp_ports),
			udp_ports: normalized_strings(app_class.udp_ports),
			ipv4_prefixes: normalized_strings(app_class.ipv4_prefixes),
			ipv6_prefixes: normalized_strings(app_class.ipv6_prefixes),
			signature_source: app_class.signature_source ?? 'user-configured',
			signature_license: app_class.signature_license ?? 'user-configured',
		};
		push(configured_class_ids, id);
	}
	validate_class_graph(classes, configured_class_ids, errors);
	for (let class_id in configured_class_ids)
		classes['' + class_id].category_id = runtime_category_id(classes, class_id);

	let classifier = {
		ports: [],
		ipv4_prefixes: [],
		ipv6_prefixes: [],
		domains: [],
	};
	let port_seen = {}, ipv4_seen = {}, ipv6_seen = {}, domain_seen = {};
	for (let class_id in configured_class_ids) {
		const class_info = classes['' + class_id];
		const direct_hint = classifier_hint(classes, class_info, false);
		const port_hint = classifier_hint(classes, class_info, true);

		for (let protocol, values in { '6': class_info.tcp_ports, '17': class_info.udp_ports }) {
			for (let value in values) {
				const port = parse_uint(value, 65535);
				if (port == null || port == 0) {
					push(errors, `${class_info.name}: invalid destination port '${value}'`);
					continue;
				}
				if (!port_hint) {
					push(warnings, `${class_info.name}: port-only evidence was ignored because the application has no category parent`);
					continue;
				}
				const entry = { protocol: +protocol, port, hint: port_hint };
				add_classifier_entry(classifier.ports, port_seen,
					`${protocol}/${port}`, entry, errors, class_info.name);
			}
		}
		for (let prefix in class_info.ipv4_prefixes) {
			if (!match(prefix, /^[0-9.]+\/[0-9]{1,2}$/)) {
				push(errors, `${class_info.name}: invalid IPv4 prefix '${prefix}'`);
				continue;
			}
			const entry = { prefix, hint: direct_hint };
			add_classifier_entry(classifier.ipv4_prefixes, ipv4_seen,
				prefix, entry, errors, class_info.name);
		}
		for (let prefix in class_info.ipv6_prefixes) {
			if (!match(prefix, /^[0-9a-f:]+\/[0-9]{1,3}$/)) {
				push(errors, `${class_info.name}: invalid IPv6 prefix '${prefix}'`);
				continue;
			}
			const entry = { prefix, hint: direct_hint };
			add_classifier_entry(classifier.ipv6_prefixes, ipv6_seen,
				prefix, entry, errors, class_info.name);
		}
		for (let domain in class_info.domains) {
			if (!match(domain, /^(\*\.)?[a-z0-9_*-]+(\.[a-z0-9_*-]+)+$/)) {
				push(errors, `${class_info.name}: invalid domain pattern '${domain}'`);
				continue;
			}
			const entry = { pattern: domain, hint: direct_hint };
			add_classifier_entry(classifier.domains, domain_seen,
				domain, entry, errors, class_info.name);
		}
	}
	classifier.signature_count = length(classifier.ports) +
		length(classifier.ipv4_prefixes) + length(classifier.ipv6_prefixes) +
		length(classifier.domains);

	let rules = [], rules_by_identity = {}, fail_closed_identity = {};
	for (let rule in (config.app_rules ?? [])) {
		const label = rule.section ?? 'application rule';
		const identity_id = trim('' + (rule.identity ?? ''));
		const class_id = class_selector(rule.class_id ?? rule.class);
		const result = compile_rule(rule, epoch);
		let valid = true;
		if (!identity_by_id[identity_id]) {
			push(errors, `${label}: unknown Identity '${identity_id}'`);
			valid = false;
		}
		if (class_id == null || !classes['' + class_id]) {
			push(errors, `${label}: unknown application class '${rule.class_id ?? rule.class ?? 'missing'}'`);
			valid = false;
		}
		for (let error in result.errors)
			push(errors, `${label}: ${error}`);
		if (result.next_transition != null &&
		    (next_transition == null || result.next_transition < next_transition))
			next_transition = result.next_transition;

		const compiled_rule = {
			section: rule.section,
			identity_id,
			class_id,
			verdict: result.verdict,
			activation: result.activation,
			effective_active: result.active,
			next_transition: result.next_transition,
			valid: valid && !length(result.errors),
			errors: result.errors,
		};
		push(rules, compiled_rule);

		if (!valid) {
			if (result.verdict == 'deny' && identity_by_id[identity_id])
				fail_closed_identity[identity_id] = true;
			continue;
		}
		rules_by_identity[identity_id] ??= {};
		rules_by_identity[identity_id]['' + class_id] ??= [];
		push(rules_by_identity[identity_id]['' + class_id], compiled_rule);
	}

	let policies = [];
	for (let identity in identities) {
		if (!identity.valid)
			continue;
		const by_class = rules_by_identity[identity.id] ?? {};
		if (fail_closed_identity[identity.id]) {
			by_class['' + CLASS_DEFAULT] ??= [];
			push(by_class['' + CLASS_DEFAULT], {
				effective_active: true,
				verdict: 'deny',
				section: null,
			});
		}

		let class_ids = [ CLASS_DEFAULT, CLASS_UNCLASSIFIED, ...configured_class_ids ];
		for (let class_id in class_ids) {
			const resolved = class_id == CLASS_DEFAULT
				? resolve_verdict(by_class, CLASS_DEFAULT, classes)
				: resolve_verdict(by_class, class_id, classes);
			push(policies, {
				identity_id: identity.id,
				subject_id: identity.subject_id,
				class_id,
				verdict: resolved.verdict,
				matched_class_id: resolved.matched_class_id,
			});
		}
	}

	return {
		schema_supported,
		requested_enabled,
		enabled: requested_enabled && schema_supported && !length(errors),
		unknown_subject_app_verdict,
		provisional_app_verdict,
		identities,
		classes,
		classifier,
		resource_limits,
		rules,
		policies,
		next_transition,
		errors,
		warnings,
	};
}

export function consistency(nft_compiled, app_compiled) {
	let warnings = [];
	if (!app_compiled.enabled)
		return { warnings };

	let nft_by_id = {};
	for (let identity in (nft_compiled.identities ?? []))
		nft_by_id[identity.id] = identity;

	for (let policy in app_compiled.policies) {
		const nft_identity = nft_by_id[policy.identity_id];
		if (!nft_identity || nft_identity.verdict != 'deny')
			continue;
		push(warnings,
			`${policy.identity_id}: application ${policy.verdict} for class ${policy.class_id} cannot affect forwarding while nftables independently denies this identity`);
	}

	return { warnings };
}

export const constants = {
	CLASS_DEFAULT,
	CLASS_UNCLASSIFIED,
	MAX_CLASS_ID,
	MAX_SUBJECT_ID,
	CLASS_KIND_EXACT,
	CLASS_KIND_CATEGORY,
	RESOURCE_DEFAULTS,
};
