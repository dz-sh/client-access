// SPDX-License-Identifier: Apache-2.0

import { evaluate_schedule } from 'client_access.policy';
import * as classification from 'client_access.classification';

const CLASS_DEFAULT = 0;
const CLASS_UNCLASSIFIED = classification.constants.CLASS_UNCLASSIFIED;
const MAX_CLASS_ID = classification.constants.MAX_CLASS_ID;
const MAX_SUBJECT_ID = 4294967295;

const RESOURCE_DEFAULTS = {
	max_packets_inspected: 1,
	max_bytes_examined: 256,
	max_classification_age_ms: 200,
	max_pending_entries: 256,
	max_new_classifications_per_second: 512,
	per_subject_new_classification_rate: 64,
	signature_table_memory_limit: 262144,
};

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
		signature_table_memory_limit: bounded_uint(
			config.signature_table_memory_limit,
			RESOURCE_DEFAULTS.signature_table_memory_limit, 4096, 8388608,
			'signature_table_memory_limit', errors),
	};
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
		push(errors, 'Only provisional application verdict allow is supported');
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

	const classification_model = classification.compile_profiles(config.app_classes);
	for (let error in classification_model.errors)
		push(errors, error);
	for (let warning in classification_model.warnings)
		push(warnings, warning);
	let classes = {
		'0': { id: CLASS_DEFAULT, name: 'Application policy default', kind: 'default', parent_id: null },
		'1': { id: CLASS_UNCLASSIFIED, name: 'Unclassified', kind: 'unclassified', parent_id: null },
	};
	for (let class_id, class_info in classification_model.classes)
		classes[class_id] = class_info;
	let configured_class_ids = [ ...classification_model.configured_class_ids ];
	sort(configured_class_ids);
	const static_classification = classification.resolve(classification_model,
		[], epoch, 1, resource_limits);
	for (let error in static_classification.errors)
		push(errors, error);
	for (let warning in static_classification.warnings)
		push(warnings, warning);

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
		classification_model,
		static_classification,
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
	RESOURCE_DEFAULTS,
};
