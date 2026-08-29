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

function target(inventory, scope, class_id) {
	const values = scope == 'access'
		? inventory.access_targets : inventory.application_targets;
	for (let value in values)
		if (value.identity_id == 'alice' &&
		    (scope == 'access' || value.class_id == class_id))
			return value;
	return null;
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
	else if (scenario == 'projection_failure') {
		uci_stub.advance();
		fs_stub.advance();
		reconcile('projection-failure-test');
	}
	else if (scenario == 'access_approval' || scenario == 'access_revoke' ||
	         scenario == 'journal_write_failure') {
		const approved = service.approve.call(null, {
			scope: 'access', identity_id: 'alice', duration: 'one_hour',
		});
		if (scenario == 'journal_write_failure') {
			if (approved.ok || !approved.degraded)
				fail(`journal failure did not fail and roll back approval: ${sprintf('%J', approved)}`);
		}
		else if (!approved.ok)
			fail(`access approval failed: ${sprintf('%J', approved)}`);
		if (scenario == 'access_revoke') {
			const revoked = service.revoke_approval.call(null, {
				lease_id: approved.approval.id,
			});
			if (!revoked.ok)
				fail(`access revocation failed: ${sprintf('%J', revoked)}`);
		}
	}
	else if (scenario == 'application_approval' || scenario == 'application_revoke') {
		const approved = service.approve.call(null, {
			scope: 'application', identity_id: 'alice', class_id: 10,
			duration: 'one_hour',
		});
		if (!approved.ok)
			fail(`application approval failed: ${sprintf('%J', approved)}`);
		if (scenario == 'application_revoke') {
			const revoked = service.revoke_approval.call(null, {
				lease_id: approved.approval.id,
			});
			if (!revoked.ok)
				fail(`application revocation failed: ${sprintf('%J', revoked)}`);
		}
	}
	else if (scenario == 'approval_noop') {
		const before = service.status.call().generation;
		const approved = service.approve.call(null, {
			scope: 'access', identity_id: 'alice', duration: 'one_hour',
		});
		if (!approved.ok || service.status.call().generation != before)
			fail(`base ALLOW approval caused an unnecessary nft projection: ${sprintf('%J', approved)}`);
	}

	const status = service.status.call();
	const app = status.app_filter ?? {};
	const runtime = fs_stub.snapshot();
	const approvals = service.approvals.call();

	if (scenario == 'restart_prune') {
		if (app.backend_mode != 'V4_BPF_BASIC' || !app.enabled ||
		    length(runtime.attachments) != 1 || runtime.attachments[0] != 'lan0')
			fail(`restart did not reconcile the exact attachment set: app=${sprintf('%J', app)} runtime=${sprintf('%J', runtime)}`);
	}
	else if (scenario == 'fw4_restore') {
		if (app.backend_mode != 'V4_BPF_BASIC' || !app.enabled ||
		    !app.retained_previous_snapshot || !runtime.scope_active)
			fail('fw4 scope loss was not restored before retaining V4');
	}
	else if (scenario == 'projection_failure') {
		if (app.backend_mode != 'V4_BPF_BASIC' || !app.enabled ||
		    !app.degraded || !app.retained_previous_snapshot ||
		    length(runtime.policy_generations) != 1 || !runtime.scope_active)
			fail(`failed projection did not retain the previous complete snapshot: app=${sprintf('%J', app)} runtime=${sprintf('%J', runtime)}`);
	}
	else if (scenario == 'generation_nonreuse') {
		if (app.backend_mode != 'V4_BPF_BASIC' || app.app_policy_generation != 3 ||
		    length(runtime.policy_generations) != 3 ||
		    runtime.policy_generations[0] != 1 ||
		    runtime.policy_generations[1] != 2 ||
		    runtime.policy_generations[2] != 3)
			fail(`a consumed application-policy generation was reused: app=${sprintf('%J', app)} runtime=${sprintf('%J', runtime)}`);
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
		    length(runtime.attachments) != 1 || runtime.attachments[0] != 'lan0')
			fail('stale attachment failure was not made neutral and visible');
	}
	else if (scenario == 'access_approval') {
		const access = target(approvals, 'access');
		const application = target(approvals, 'application', 10);
		if (approvals.active_count != 1 || !access ||
		    access.base_verdict != 'deny' || access.effective_verdict != 'allow' ||
		    !application || application.effective_verdict != 'deny' ||
		    !runtime.journal_present)
			fail(`policy-plane independent Access Lease is wrong: ${sprintf('%J', approvals)}`);
	}
	else if (scenario == 'access_revoke') {
		const access = target(approvals, 'access');
		const transitions = approvals.latest_transitions ?? [];
		if (approvals.active_count != 0 || !access ||
		    access.effective_verdict != 'deny' || !length(transitions) ||
		    transitions[0].reason != 'lease_revoked' ||
		    transitions[0].revocation_state != 'complete')
			fail(`manual Access Lease revocation is wrong: ${sprintf('%J', approvals)}`);
	}
	else if (scenario == 'application_approval') {
		const application = target(approvals, 'application', 10);
		if (approvals.active_count != 1 || !application ||
		    application.base_verdict != 'deny' ||
		    application.effective_verdict != 'allow' ||
		    runtime.policy_generation != 2 || runtime.classifier_generation != 1)
			fail(`Application Lease did not preserve classification generation: ${sprintf('%J', approvals)}`);
	}
	else if (scenario == 'application_revoke') {
		const application = target(approvals, 'application', 10);
		if (approvals.active_count != 0 || !application ||
		    application.effective_verdict != 'deny' ||
		    runtime.policy_generation != 3 || runtime.classifier_generation != 1)
			fail(`Application Lease revocation did not reuse cached class: ${sprintf('%J', approvals)}`);
	}
	else if (scenario == 'approval_journal_restart') {
		const access = target(approvals, 'access');
		if (approvals.active_count != 1 || !access ||
		    access.effective_verdict != 'allow')
			fail(`valid restart journal did not retain approval: ${sprintf('%J', approvals)}`);
	}
	else if (scenario == 'router_reboot') {
		const access = target(approvals, 'access');
		if (approvals.active_count != 0 || !access ||
		    access.effective_verdict != 'deny' || runtime.journal_present)
			fail(`empty volatile reboot state did not restore base DENY: ${sprintf('%J', approvals)}`);
	}
	else if (scenario == 'journal_corruption') {
		const access = target(approvals, 'access');
		if (approvals.active_count != 0 || !access ||
		    access.effective_verdict != 'deny' || !length(approvals.errors))
			fail(`corrupt journal broadened authorization: ${sprintf('%J', approvals)}`);
	}
	else if (scenario == 'journal_write_failure') {
		const access = target(approvals, 'access');
		if (approvals.active_count != 0 || !access || access.effective_verdict != 'deny')
			fail(`failed journal left approval active: ${sprintf('%J', approvals)}`);
	}
	else if (scenario == 'approval_noop') {
		const access = target(approvals, 'access');
		if (approvals.active_count != 1 || !access ||
		    access.base_verdict != 'allow' || access.effective_verdict != 'allow' ||
		    length(approvals.latest_transitions ?? []))
			fail(`base ALLOW approval created an effective transition: ${sprintf('%J', approvals)}`);
	}
	else {
		fail(`unknown daemon test scenario '${scenario}'`);
	}

	print(sprintf('%J\n', { scenario, app_filter: app, approvals, runtime }));
}
