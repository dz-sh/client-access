let phase = 0;
let bpf_enabled = false;
let policy_generation = 0;
let classifier_generation = 0;
let policy_generations = [];
let attachments = {};
let scope_active = false;
let health_checks = 0;

function scenario() {
	return getenv('CA_DAEMON_TEST_SCENARIO');
}

function initialize() {
	if (scenario() == 'restart_prune' && !length(keys(attachments))) {
		attachments.lan0 = true;
		attachments.stale0 = true;
	}
}

export function advance() {
	phase++;
}

export function simulate_fw4_reload() {
	scope_active = false;
}

export function snapshot() {
	let names = keys(attachments);
	sort(names);
	return {
		bpf_enabled,
		policy_generation,
		classifier_generation,
		policy_generations,
		attachments: names,
		scope_active,
	};
}

export function stat(path) {
	initialize();
	return path == '/usr/sbin/client-access-bpfctl' ? {} : null;
}

function read_result(argv) {
	initialize();
	if (argv[0] == '/sbin/fw4' && argv[1] == 'zone')
		return { code: 0, output: argv[2] == 'lan' ? 'lan0\n' : 'wan0\n' };
	if (argv[0] == '/usr/sbin/nft' && argv[1] == 'list')
		return {
			code: 0,
			output: scenario() == 'offload_custom'
				? 'table inet fw4 { chain forward { ip protocol tcp flow add @ft } }'
				: 'table inet fw4 { chain forward { counter accept } }',
		};
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
		let keep = {};
		for (let index = 2; index < length(argv); index++)
			keep[argv[index]] = true;
		for (let name in attachments)
			if (!keep[name])
				delete attachments[name];
		return { code: 0, output: '' };
	}
	if (command == 'gc')
		return { code: 0, output: '{"removed":0}\n' };
	if (command == 'health') {
		const fail_health = scenario() == 'health_failure' ||
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
				app_policy_generation: policy_generation,
				classifier_generation,
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
		policy_generation = +fields[2];
		classifier_generation = +fields[3];
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
