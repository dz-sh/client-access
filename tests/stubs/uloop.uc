import * as fs_stub from 'fs';
import * as uci_stub from 'uci';

let startup_callback = null;
let service = null;

function fail(message) {
	warn(`FAIL: ${message}\n`);
	exit(1);
}

export function init() {}

export function timer(delay, callback) {
	if (delay == 1 && !startup_callback)
		startup_callback = callback;
	return { set: function() {} };
}

export function set_service(value) {
	service = value;
}

function reconcile(reason) {
	return service.reconcile.call(null, { reason });
}

export function run() {
	const scenario = getenv('CA_DAEMON_TEST_SCENARIO');
	if (!scenario)
		return;
	if (!startup_callback || !service)
		fail('daemon did not publish a service and startup timer');

	startup_callback();
	if (scenario == 'fw4_restore') {
		fs_stub.simulate_fw4_reload();
		uci_stub.advance();
		fs_stub.advance();
		reconcile('fw4-restore-test');
	}
	else if (scenario == 'generation_nonreuse') {
		uci_stub.advance();
		fs_stub.advance();
		reconcile('scope-failure-test');
		uci_stub.advance();
		fs_stub.advance();
		reconcile('generation-retry-test');
	}

	const status = service.status.call();
	const app = status.app_filter ?? {};
	const runtime = fs_stub.snapshot();

	if (scenario == 'restart_prune') {
		if (app.backend_mode != 'V4_BPF_BASIC' || !app.enabled ||
		    sprintf('%J', runtime.attachments) != '["lan0"]')
			fail('restart did not reconcile the exact attachment set');
	}
	else if (scenario == 'fw4_restore') {
		if (app.backend_mode != 'V4_BPF_BASIC' || !app.enabled ||
		    !app.retained_previous_snapshot || !runtime.scope_active)
			fail('fw4 scope loss was not restored before retaining V4');
	}
	else if (scenario == 'generation_nonreuse') {
		if (app.backend_mode != 'V4_BPF_BASIC' || app.app_policy_generation != 3 ||
		    sprintf('%J', runtime.policy_generations) != '[1,2,3]')
			fail('a consumed application-policy generation was reused');
	}
	else if (scenario == 'health_failure' ||
	         scenario == 'status_health_failure' ||
	         scenario == 'ensure_failure' ||
	         scenario == 'attach_failure' ||
	         scenario == 'sync_failure' ||
	         scenario == 'nft_scope_failure' ||
	         scenario == 'offload_software' ||
	         scenario == 'offload_hardware' ||
	         scenario == 'offload_custom') {
		if (!status.applied || app.backend_mode != 'V3_NFT_ONLY' || app.enabled ||
		    !app.degraded || runtime.bpf_enabled || runtime.scope_active ||
		    length(runtime.attachments))
			fail(`${scenario} did not neutralize V4 and retain V3-only mode`);
	}
	else if (scenario == 'prune_failure') {
		if (!status.applied || app.backend_mode != 'V3_NFT_ONLY' || app.enabled ||
		    !app.degraded || runtime.bpf_enabled || runtime.scope_active ||
		    sprintf('%J', runtime.attachments) != '["lan0"]')
			fail('stale attachment failure was not made neutral and visible');
	}
	else {
		fail(`unknown daemon test scenario '${scenario}'`);
	}

	print(sprintf('%J\n', { scenario, app_filter: app, runtime }));
}
