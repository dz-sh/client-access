// SPDX-License-Identifier: Apache-2.0

/* UCI-facing configuration adapter. It owns reads and normalization only. */

import { cursor } from 'uci';

function as_list(value) {
	if (value == null)
		return [];
	return type(value) == 'array' ? value : [ value ];
}

export function load() {
	const uci = cursor();
	let config = {
		schema_version: uci.get('client_access', 'main', 'schema_version'),
		enabled: uci.get('client_access', 'main', 'enabled'),
		mode: uci.get('client_access', 'main', 'mode'),
		app_filter_enabled: uci.get('client_access', 'main', 'app_filter_enabled'),
		unknown_subject_app_verdict: uci.get('client_access', 'main', 'unknown_subject_app_verdict'),
		provisional_app_verdict: uci.get('client_access', 'main', 'provisional_app_verdict'),
		max_packets_inspected: uci.get('client_access', 'main', 'max_packets_inspected'),
		max_bytes_examined: uci.get('client_access', 'main', 'max_bytes_examined'),
		max_classification_age_ms: uci.get('client_access', 'main', 'max_classification_age_ms'),
		max_pending_entries: uci.get('client_access', 'main', 'max_pending_entries'),
		max_new_classifications_per_second: uci.get('client_access', 'main', 'max_new_classifications_per_second'),
		per_subject_new_classification_rate: uci.get('client_access', 'main', 'per_subject_new_classification_rate'),
		signature_table_memory_limit: uci.get('client_access', 'main', 'signature_table_memory_limit'),
		deny_action: uci.get('client_access', 'main', 'deny_action'),
		source_zone: as_list(uci.get('client_access', 'main', 'source_zone')),
		destination_zone: as_list(uci.get('client_access', 'main', 'destination_zone')),
		safety_interval: uci.get('client_access', 'main', 'safety_interval') ?? 60,
		identities: [],
		bindings: [],
		app_classes: [],
		app_rules: [],
		flow_offloading: false,
		flow_offloading_hw: false,
	};

	uci.foreach('client_access', 'identity', function(s) {
		push(config.identities, {
			id: s['.name'], section: s['.name'], name: s.name ?? s['.name'],
			subject_id: s.subject_id, activation: s.activation, schedule: s.schedule,
		});
	});
	uci.foreach('client_access', 'app_class', function(s) {
		push(config.app_classes, {
			section: s['.name'], profile_id: s['.name'],
			profile_schema_version: s.profile_schema_version,
			profile_source: s.profile_source, profile_license: s.profile_license,
			profile_provenance: s.profile_provenance, id: s.class_id,
			name: s.name ?? s['.name'], kind: s.kind, parent_id: s.parent_id,
			domains: as_list(s.domain), tcp_ports: as_list(s.tcp_port),
			udp_ports: as_list(s.udp_port), ipv4_prefixes: as_list(s.ipv4_prefix),
			ipv6_prefixes: as_list(s.ipv6_prefix),
		});
	});
	uci.foreach('client_access', 'app_rule', function(s) {
		push(config.app_rules, {
			section: s['.name'], identity: s.identity, class_id: s.class_id,
			verdict: s.verdict, activation: s.activation, schedule: s.schedule,
		});
	});
	uci.foreach('client_access', 'binding', function(s) {
		push(config.bindings, {
			section: s['.name'], identity: s.identity, type: s.type, value: s.value,
		});
	});
	uci.foreach('firewall', 'defaults', function(s) {
		config.flow_offloading = s.flow_offloading == '1';
		config.flow_offloading_hw = s.flow_offloading_hw == '1';
		return false;
	});
	uci.unload();
	return config;
}
