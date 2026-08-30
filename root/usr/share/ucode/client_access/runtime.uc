// SPDX-License-Identifier: Apache-2.0

/* Pure V4.6 acceleration-topology classification. The caller supplies the
 * firewall configuration, a captured nftables ruleset, and optional backend
 * presence. This module never mutates firewall ownership state.
 */

function topology(ruleset) {
	let flowtables = [], actions = [], hardware_flag = false;
	for (let raw in split(ruleset ?? '', /\n/)) {
		const line = trim(raw);
		let found = match(line, /\bflowtable[ \t]+([A-Za-z0-9_.:-]+)[ \t]*\{/);
		if (found)
			push(flowtables, found[1]);
		found = match(line, /\bflow[ \t]+(add|offload)[ \t]+@([A-Za-z0-9_.:-]+)/);
		if (found)
			push(actions, found[2]);
		if (match(line, /^flags[ \t]+offload[ \t]*;?$/))
			hardware_flag = true;
	}
	return { flowtables, actions, hardware_flag };
}

export function offload_capability(config, ruleset_checked, ruleset,
		backend_present) {
	if (!ruleset_checked)
		return {
			mode: 'OFFLOAD_UNVERIFIABLE', offload_present: true,
			tracking_required: false, runtime_ruleset_verified: false,
			hardware_offload_detected: !!config.flow_offloading_hw,
			reason: 'nftables_ruleset_unavailable',
		};

	const state = topology(ruleset);
	if (config.flow_offloading_hw || state.hardware_flag)
		return {
			mode: 'HFO_UNSUPPORTED', offload_present: true,
			tracking_required: false, runtime_ruleset_verified: true,
			hardware_offload_detected: true,
			reason: 'hardware_offload_detected',
		};

	const canonical = length(state.flowtables) == 1 && state.flowtables[0] == 'ft' &&
		length(state.actions) == 1 && state.actions[0] == 'ft' &&
		match(ruleset ?? '', /table[ \t]+inet[ \t]+fw4[ \t]*\{/);
	const custom = length(state.flowtables) > 1 || length(state.actions) > 1 ||
		(length(state.flowtables) == 1 && state.flowtables[0] != 'ft') ||
		(length(state.actions) == 1 && state.actions[0] != 'ft');
	if (custom || (!config.flow_offloading &&
	    (length(state.flowtables) || length(state.actions))))
		return {
			mode: 'CUSTOM_OFFLOAD_UNSUPPORTED', offload_present: true,
			tracking_required: false, runtime_ruleset_verified: true,
			hardware_offload_detected: false,
			reason: 'noncanonical_flowtable_topology',
		};

	if (!config.flow_offloading)
		return {
			mode: backend_present ? 'SFO_AVAILABLE' : 'NO_OFFLOAD',
			offload_present: false, tracking_required: false,
			runtime_ruleset_verified: true,
			hardware_offload_detected: false, reason: null,
		};

	if (!canonical)
		return {
			mode: 'OFFLOAD_UNVERIFIABLE', offload_present: true,
			tracking_required: false, runtime_ruleset_verified: false,
			hardware_offload_detected: false,
			reason: 'canonical_fw4_sfo_not_found',
		};

	return {
		mode: backend_present ? 'SFO_ACTIVE' : 'SFO_BACKEND_MISSING',
		offload_present: true,
		tracking_required: !!backend_present,
		runtime_ruleset_verified: true,
		hardware_offload_detected: false,
		reason: backend_present ? null : 'sfo_backend_not_installed',
	};
}

export const constants = {
	MODES: [
		'NO_OFFLOAD', 'SFO_AVAILABLE', 'SFO_ACTIVE', 'SFO_DEGRADED',
		'SFO_BACKEND_MISSING', 'HFO_UNSUPPORTED',
		'CUSTOM_OFFLOAD_UNSUPPORTED', 'OFFLOAD_UNVERIFIABLE',
	],
};
