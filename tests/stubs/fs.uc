let phase = 0;
let bpf_enabled = false;
let app_enforcement_enabled = false;
let policy_generation = 0;
let classifier_generation = 0;
let policy_generations = [];
let attachments = {};
let scope_active = false;
let health_checks = 0;
let files = {};
let sfo_commands = [];
let sfo_revocation_started = false;

function scenario() {
	return getenv('CA_DAEMON_TEST_SCENARIO');
}

function initialize() {
	if (scenario() == 'restart_prune' && !length(keys(attachments))) {
		attachments.lan0 = true;
		attachments.stale0 = true;
	}
	if (scenario() == 'runtime_generation_floor' &&
	    policy_generation == 0 && classifier_generation == 0) {
		policy_generation = 10;
		classifier_generation = 8;
	}
}

export function advance() {
	phase++;
}

export function simulate_fw4_reload() {
	scope_active = false;
}

export function simulate_attachment_loss() {
	delete attachments.lan0;
}

export function snapshot() {
	let names = keys(attachments);
	sort(names);
	return {
		bpf_enabled,
		app_enforcement_enabled,
		policy_generation,
		classifier_generation,
		policy_generations,
		attachments: names,
		scope_active,
		journal_present: files['/tmp/client-access-approvals.json'] != null,
		sfo_commands,
	};
}

export function stat(path) {
	initialize();
	if (path == '/usr/sbin/client-access-bpfctl')
		return {};
	if (path == '/usr/sbin/client-access-sfoctl' &&
	    (scenario() == 'offload_software' ||
	     scenario() == 'sfo_tracking_only' ||
	     scenario() == 'sfo_capacity' ||
	     scenario() == 'sfo_health_failure' ||
	     scenario() == 'sfo_access_revoke' ||
	     scenario() == 'sfo_application_revoke' ||
	     scenario() == 'sfo_deadline_failure'))
		return {};
	return null;
}

export function open(path, mode, permissions) {
	if (mode == 'r') {
		let content = files[path];
		if (content == null && path == '/tmp/client-access-approvals.json' &&
		    scenario() == 'journal_corruption')
			content = '{invalid';
		if (content == null && path == '/tmp/client-access-approvals.json' &&
		    scenario() == 'approval_journal_restart') {
			const epoch = clock()[0];
			const monotonic = clock(true)[0];
			content = sprintf('%J', {
				schema_version: 1,
				next_id: 2,
				leases: [ {
					id: `lease-${epoch}-1`,
					scope: 'access',
					identity_id: 'alice',
					subject_id: 42,
					target_key: 'access/alice',
					created_at: epoch,
					expires_at: epoch + 3600,
					monotonic_deadline: monotonic + 3600,
					duration: 'one_hour',
				} ],
			});
		}
		if (content == null)
			return null;
		return {
			read: function() { return content; },
			close: function() { return true; },
		};
	}
	if (mode == 'w') {
		if (scenario() == 'journal_write_failure')
			return null;
		let content = '';
		return {
			write: function(value) { content += value; return length(value); },
			flush: function() { return true; },
			close: function() { files[path] = content; return true; },
		};
	}
	return null;
}

export function rename(source, destination) {
	if (files[source] == null)
		return null;
	files[destination] = files[source];
	delete files[source];
	return true;
}

export function unlink(path) {
	delete files[path];
	return true;
}

function read_result(argv) {
	initialize();
	if (argv[0] == '/sbin/fw4' && argv[1] == 'zone') {
		let output = 'wan0\n';
		if (argv[2] == 'lan') {
			if (scenario() == 'interface_add' && phase > 0)
				output = 'lan0\nlan1\n';
			else if (scenario() == 'interface_remove')
				output = phase > 0 ? 'lan1\n' : 'lan0\nlan1\n';
			else
				output = 'lan0\n';
		}
		return { code: 0, output };
	}
	if (argv[0] == '/usr/sbin/nft' && argv[1] == 'list')
		return {
			code: 0,
			output: scenario() == 'offload_custom'
				? 'table inet fw4 {\nflowtable fastpath {\n}\nchain forward {\nip protocol tcp flow add @fastpath\n}\n}'
				: ((scenario() == 'offload_software' ||
				    scenario() == 'sfo_tracking_only' ||
				    scenario() == 'sfo_capacity' ||
				    scenario() == 'sfo_health_failure' ||
				    scenario() == 'offload_missing' ||
				    scenario() == 'offload_hardware' ||
				    scenario() == 'sfo_access_revoke' ||
				    scenario() == 'sfo_application_revoke' ||
				    scenario() == 'sfo_deadline_failure')
					? 'table inet fw4 {\nflowtable ft {\nhook ingress priority filter\n}\nchain forward {\nmeta l4proto { tcp, udp } flow add @ft\n}\n}'
					: 'table inet fw4 { chain forward { counter accept } }'),
		};
	if (argv[0] == '/usr/sbin/client-access-sfoctl') {
		push(sfo_commands, [ ...argv ]);
		if (argv[1] == 'revoke')
			sfo_revocation_started = true;
		const failed = scenario() == 'sfo_deadline_failure' &&
			sfo_revocation_started &&
			(argv[1] == 'revoke' || argv[1] == 'baseline');
		return {
			code: failed ? 1 : 0,
			output: sprintf('%J\n', {
				result: failed ? 'FAILED' : 'COMPLETE',
				correlation_health: failed ? 'DEGRADED' : 'HEALTHY',
				tracked_flow_count: 7,
				candidate_count: 1,
				software_offloaded_flow_count: 1,
				hardware_offloaded_flow_count: 0,
				gc_reclaimed: argv[1] == 'gc' ? 1 : 0,
				revocation_latency_ms: failed ? 2001 : 4,
			}),
		};
	}
	if (argv[0] != '/usr/sbin/client-access-bpfctl')
		return { code: 1, output: '' };

	const command = argv[1];
	if (command == 'disable') {
		bpf_enabled = false;
		return { code: 0, output: '' };
	}
	if (command == 'ensure')
		return { code: scenario() == 'ensure_failure' ? 1 : 0, output: '' };
	if (command == 'generations')
		return { code: 0, output: `${policy_generation} ${classifier_generation}\n` };
	if (command == 'attach') {
		if (scenario() == 'attach_failure')
			return { code: 1, output: '' };
		attachments[argv[2]] = true;
		return { code: 0, output: '' };
	}
	if (command == 'detach') {
		delete attachments[argv[2]];
		return { code: 0, output: '' };
	}
	if (command == 'prune') {
		if (scenario() == 'prune_failure')
			return { code: 1, output: '' };
		let retained = {};
		for (let index = 2; index < length(argv); index++)
			if (attachments[argv[index]])
				retained[argv[index]] = true;
		attachments = retained;
		return { code: 0, output: '' };
	}
	if (command == 'gc')
		return { code: 0, output: '{"removed":0}\n' };
	if (command == 'health') {
		const fail_health = scenario() == 'health_failure' ||
			scenario() == 'sfo_health_failure' ||
			(scenario() == 'status_health_failure' && health_checks > 0);
		health_checks++;
		if (fail_health)
			return { code: 1, output: '' };
		let expected = [];
		for (let index = 4; index < length(argv); index++)
			push(expected, argv[index]);
		sort(expected);
		let actual = keys(attachments);
		sort(actual);
		const healthy = bpf_enabled && +argv[2] == policy_generation &&
			+argv[3] == classifier_generation &&
			sprintf('%J', expected) == sprintf('%J', actual);
		return healthy
			? { code: 0, output: sprintf('%J\n', {
				backend_mode: 'V4_BPF_BASIC', enabled: true,
				app_enforcement_enabled,
				app_policy_generation: policy_generation,
				classifier_generation,
				flow_map_entries: 1,
				flow_capacity: 16384,
				flow_map_full: scenario() == 'sfo_capacity' ? 1 : 0,
			}) }
			: { code: 1, output: '' };
	}
	return { code: 1, output: '' };
}

function write_result(argv, content) {
	if (argv[0] == '/usr/sbin/client-access-bpfctl' && argv[1] == 'sync') {
		if (scenario() == 'sync_failure')
			return 1;
		const header = split(content, '\n')[0];
		const fields = split(header, /\s+/);
		policy_generation = +fields[3];
		classifier_generation = +fields[4];
		app_enforcement_enabled = +fields[2] == 1;
		push(policy_generations, policy_generation);
		bpf_enabled = true;
		return 0;
	}
	if (argv[0] == '/usr/sbin/nft' && argv[1] == '-f') {
		const enabling = !!match(content, /client_access_app_sources\s+\{\s+"lan0"/);
		if (enabling && (scenario() == 'nft_scope_failure' ||
		    (scenario() == 'generation_nonreuse' && phase == 1)))
			return 1;
		scope_active = enabling;
		return 0;
	}
	return 1;
}

export function popen(argv, mode) {
	if (mode == 'r') {
		const result = read_result(argv);
		return {
			read: function() { return result.output; },
			close: function() { return result.code; },
		};
	}
	if (mode == 'w') {
		let content = '';
		return {
			write: function(value) { content += value; return length(value); },
			close: function() { return write_result(argv, content); },
		};
	}
	return null;
}
