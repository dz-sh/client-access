// SPDX-License-Identifier: Apache-2.0

/* Optional BPF backend adapter. Absence is a normal runtime result. */

import { popen, stat } from 'fs';

const BPFCTL = '/usr/sbin/client-access-bpfctl';

function capture(args) {
	const proc = popen([ BPFCTL, ...args ], 'r');
	if (!proc)
		return { code: null, output: '' };
	const output = proc.read('all') ?? '';
	return { code: proc.close(), output };
}

export function present() {
	return !!stat(BPFCTL);
}

export function generations() {
	return capture([ 'generations' ]);
}

export function ensure() {
	return capture([ 'ensure' ]);
}

export function disable() {
	return present() ? capture([ 'disable' ]) : { code: null, output: '' };
}

export function prune(interfaces) {
	return present() ? capture([ 'prune', ...(interfaces ?? []) ])
		: { code: null, output: '' };
}

export function attach(ifname) {
	return capture([ 'attach', ifname ]);
}

export function detach(ifname) {
	return capture([ 'detach', ifname ]);
}

export function publish(snapshot) {
	const proc = popen([ BPFCTL, 'sync' ], 'w');
	if (!proc)
		return { ok: false, error: `Unable to start ${BPFCTL}` };
	if (proc.write(snapshot) != length(snapshot)) {
		proc.close();
		return { ok: false, error: `Unable to write complete input to ${BPFCTL}` };
	}
	const code = proc.close();
	return code == 0 ? { ok: true, error: null }
		: { ok: false, error: `${BPFCTL} exited with code ${code}` };
}

export function gc(idle_seconds) {
	return capture([ 'gc', '' + idle_seconds ]);
}

export function health(policy_generation, classifier_generation, interfaces) {
	return capture([ 'health', '' + policy_generation,
		'' + classifier_generation, ...(interfaces ?? []) ]);
}

export function status() {
	return capture([ 'status' ]);
}

function verdict_number(verdict) {
	return verdict == 'deny' ? 1 : 0;
}

export function serialize_snapshot(app_compiled, runtime_projection,
		subject_projection, policy_generation, classifier_generation,
		tracking_enabled, app_enforcement_enabled) {
	const limits = app_compiled.resource_limits;
	let lines = [ sprintf('CONFIG %d %d %d %d %d %d %d %d %d %d %d %d',
		tracking_enabled ? 1 : 0, app_enforcement_enabled ? 1 : 0,
		policy_generation, classifier_generation,
		verdict_number(app_compiled.unknown_subject_app_verdict),
		verdict_number(app_compiled.provisional_app_verdict),
		limits.max_packets_inspected, limits.max_bytes_examined,
		limits.max_classification_age_ms, limits.max_pending_entries,
		limits.max_new_classifications_per_second,
		limits.per_subject_new_classification_rate) ];
	for (let selector in subject_projection.selectors)
		push(lines, sprintf('SUBJECT %s %d', selector.mac, selector.subject_id));
	for (let entry in app_compiled.policies)
		push(lines, sprintf('POLICY %d %d %d', entry.subject_id,
			entry.class_id, verdict_number(entry.verdict)));
	for (let entry in runtime_projection.ports)
		push(lines, sprintf('PORT %d %d %d %d %d', entry.protocol, entry.port,
			entry.hint.class_id, entry.hint.category_id, entry.hint.kind));
	for (let entry in runtime_projection.ipv4_prefixes)
		push(lines, sprintf('PREFIX4 %s %d %d %d', entry.prefix,
			entry.hint.class_id, entry.hint.category_id, entry.hint.kind));
	for (let entry in runtime_projection.ipv6_prefixes)
		push(lines, sprintf('PREFIX6 %s %d %d %d', entry.prefix,
			entry.hint.class_id, entry.hint.category_id, entry.hint.kind));
	return join('\n', lines) + '\n';
}

export const path = BPFCTL;
