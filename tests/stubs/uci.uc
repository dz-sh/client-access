let phase = 0;

export function advance() {
	phase++;
}

function main_option(option) {
	const scenario = getenv('CA_DAEMON_TEST_SCENARIO');
	let values = {
		schema_version: '4',
		enabled: '1',
		mode: 'blacklist',
		app_filter_enabled: '1',
		unknown_subject_app_verdict: phase == 1 && scenario == 'generation_nonreuse'
			? 'deny' : 'allow',
		provisional_app_verdict: 'allow',
		max_packets_inspected: scenario == 'fw4_restore' && phase > 0 ? '2' : '1',
		max_bytes_examined: '256',
		max_classification_age_ms: '200',
		max_pending_entries: '256',
		max_new_classifications_per_second: '512',
		per_subject_new_classification_rate: '64',
		signature_table_memory_limit: '262144',
		deny_action: 'reject',
		source_zone: [ 'lan' ],
		destination_zone: [ 'wan' ],
		safety_interval: '60',
	};
	return values[option];
}

export function cursor() {
	return {
		get: function(package_name, section, option) {
			if (package_name == 'client_access' && section == 'main')
				return main_option(option);
			return null;
		},
		foreach: function(package_name, section_type, callback) {
			const scenario = getenv('CA_DAEMON_TEST_SCENARIO');
			if (package_name == 'client_access' && section_type == 'identity')
				callback({ '.name': 'alice', name: 'Alice', subject_id: '42',
					activation: 'inactive' });
			else if (package_name == 'client_access' && section_type == 'binding')
				callback({ '.name': 'alice_mac', identity: 'alice', type: 'mac',
					value: '02:00:00:00:00:42' });
			else if (package_name == 'firewall' && section_type == 'defaults')
				callback({
					flow_offloading: scenario == 'offload_software' ? '1' : '0',
					flow_offloading_hw: scenario == 'offload_hardware' ? '1' : '0',
				});
		},
		unload: function() {},
	};
}
