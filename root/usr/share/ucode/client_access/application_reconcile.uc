// SPDX-License-Identifier: Apache-2.0

/* Application-layer desired-state reconciliation. This module coordinates the
 * semantic result with the optional BPF and nftables runtime adapters; it does
 * not own policy or classification semantics. */

import * as runtime_policy from 'client_access.runtime';
import * as firewall from 'client_access.firewall';
import * as bpf_runtime from 'client_access.bpf_runtime';
import * as observation_store from 'client_access.observation_store';
import * as reconciliation from 'client_access.reconcile';

export function create() {
	return {
		policy_generation: 0,
		classifier_generation: 0,
		applied_signature: null,
		classifier_signature: null,
		applied_sources: [],
		applied_destinations: [],
		generation_floors_loaded: false,
		attached_interfaces: [],
	};
}

export function interfaces(state) {
	return [ ...(state.attached_interfaces ?? []) ];
}

function load_generation_floors(state) {
	if (state.generation_floors_loaded)
		return;
	const result = bpf_runtime.generations();
	const values = split(trim(result.output), /\s+/);
	if (result.code != 0 || length(values) != 2 ||
	    !match(values[0], /^(0|[1-9][0-9]*)$/) ||
	    !match(values[1], /^(0|[1-9][0-9]*)$/))
		return;
	const policy_floor = +values[0];
	const classifier_floor = +values[1];
	if (policy_floor > state.policy_generation)
		state.policy_generation = policy_floor;
	if (classifier_floor > state.classifier_generation)
		state.classifier_generation = classifier_floor;
	state.generation_floors_loaded = true;
}

function prune_interfaces(state, keep) {
	if (!bpf_runtime.present()) {
		state.attached_interfaces = [];
		return { code: null, output: '' };
	}
	const result = bpf_runtime.prune(keep);
	if (result.code == 0)
		state.attached_interfaces = [ ...keep ];
	return result;
}

export function neutralize(state, errors) {
	const disabled = bpf_runtime.disable();
	if (disabled.code != null && disabled.code != 0)
		push(errors, 'Unable to disable application BPF state');
	const pruned = prune_interfaces(state, []);
	if (pruned.code != null && pruned.code != 0)
		push(errors, 'Unable to detach all owned application BPF filters');
	const scope = firewall.apply_application_scope(false, [], []);
	if (!scope.ok)
		push(errors, scope.error);
	state.applied_signature = null;
	state.classifier_signature = null;
	state.applied_sources = [];
	state.applied_destinations = [];
	return {
		ok: (disabled.code == null || disabled.code == 0) &&
			(pruned.code == null || pruned.code == 0) && scope.ok,
		backend_present: disabled.code != null,
	};
}

function restore_scope(state, errors) {
	const scope = firewall.apply_application_scope(true, state.applied_sources,
		state.applied_destinations);
	if (scope.ok)
		return true;
	push(errors, scope.error);
	neutralize(state, errors);
	return false;
}

export function apply(state, config, app_compiled, classification_state,
		subject_projection, sources, destinations, zone_errors, force, observations) {
	let errors = [ ...app_compiled.errors, ...classification_state.errors,
		...subject_projection.errors, ...zone_errors ];
	let warnings = [ ...app_compiled.warnings, ...classification_state.warnings ];
	const runtime_projection = classification_state.runtime_projection;
	const previously_enabled = state.applied_signature != null && length(state.attached_interfaces) > 0;
	const previous_interfaces = {};
	for (let ifname in state.attached_interfaces)
		previous_interfaces[ifname] = true;

	if (!app_compiled.requested_enabled) {
		observation_store.reset(observations);
		const neutral = neutralize(state, errors);
		return {
			ok: neutral.ok,
			available: false,
			enabled: false,
			degraded: !neutral.ok,
			retained_previous_snapshot: false,
			backend_mode: 'V3_NFT_ONLY',
			generation: state.policy_generation,
			classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}
	if (!bpf_runtime.present()) {
		push(errors, 'The optional TC eBPF application backend is not installed');
		neutralize(state, errors);
		return {
			ok: false,
			available: false,
			enabled: false,
			degraded: true,
			retained_previous_snapshot: false,
			backend_mode: 'V3_NFT_ONLY',
			generation: state.policy_generation,
			classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}
	const runtime_offload = firewall.runtime_offload();
	const offload_refusal = runtime_policy.offload_refusal(config,
		runtime_offload.checked, runtime_offload.ruleset);
	if (offload_refusal) {
		push(errors, offload_refusal == 'unverifiable_ruleset'
			? 'Unable to verify that the active nftables ruleset has no flow offload path'
			: 'Disable firewall and custom nftables flow offloading before enabling application filtering');
		const neutral = neutralize(state, errors);
		return {
			ok: false,
			available: neutral.backend_present,
			enabled: false,
			degraded: true,
			retained_previous_snapshot: false,
			backend_mode: 'V3_NFT_ONLY',
			generation: state.policy_generation,
			classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}
	if (!length(sources))
		push(errors, 'No LAN source interfaces resolved for the application filter');
	if (!length(destinations))
		push(errors, 'No Internet destination interfaces resolved for the application filter');
	if (!app_compiled.enabled || length(errors)) {
		if (!previously_enabled) {
			neutralize(state, errors);
			return {
				ok: false,
				available: false,
				enabled: false,
				degraded: true,
				retained_previous_snapshot: false,
				backend_mode: 'V3_NFT_ONLY',
				generation: state.policy_generation,
				classifier_generation: state.classifier_generation,
				errors,
				warnings,
			};
		}
		const retained = restore_scope(state, errors);
		return {
			ok: false,
			available: retained,
			enabled: retained,
			degraded: true,
			retained_previous_snapshot: retained,
			backend_mode: retained ? 'V4_BPF_BASIC' : 'V3_NFT_ONLY',
			generation: state.policy_generation,
			classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}

	const ensured = bpf_runtime.ensure();
	if (ensured.code != 0) {
		push(errors, 'Unable to load or verify the TC eBPF application backend');
		neutralize(state, errors);
		return {
			ok: false,
			available: false,
			enabled: false,
			degraded: true,
			retained_previous_snapshot: false,
			backend_mode: 'V3_NFT_ONLY',
			generation: state.policy_generation,
			classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}
	load_generation_floors(state);

	let attached = [];
	for (let ifname in sources) {
		const result = bpf_runtime.attach(ifname);
		if (result.code != 0)
			push(errors, `Unable to attach application filter to '${ifname}'`);
		else
			push(attached, ifname);
	}
	if (length(errors)) {
		for (let ifname in attached)
			if (!previous_interfaces[ifname])
				bpf_runtime.detach(ifname);
		const retained = previously_enabled && restore_scope(state, errors);
		return {
			ok: false,
			available: true,
			enabled: retained,
			degraded: true,
			retained_previous_snapshot: retained,
			backend_mode: retained ? 'V4_BPF_BASIC' : 'V3_NFT_ONLY',
			generation: state.policy_generation,
			classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}

	const signature = reconciliation.application_signature(app_compiled,
		subject_projection, sources, destinations);
	const changed = signature != state.applied_signature;
	const candidate_generation = changed ? state.policy_generation + 1 : state.policy_generation;
	const current_classifier_signature = reconciliation.classifier_signature(runtime_projection);
	const classifier_changed = current_classifier_signature != state.classifier_signature;
	const candidate_classifier_generation = classifier_changed
		? state.classifier_generation + 1 : state.classifier_generation;
	if (force || changed || classifier_changed) {
		const result = bpf_runtime.publish(bpf_runtime.serialize_snapshot(app_compiled,
			runtime_projection, subject_projection, candidate_generation,
			candidate_classifier_generation));
		if (!result.ok) {
			push(errors, result.error);
			for (let ifname in attached)
				if (!previous_interfaces[ifname])
					bpf_runtime.detach(ifname);
			const retained = previously_enabled && restore_scope(state, errors);
			return {
				ok: false,
				available: true,
				enabled: retained,
				degraded: true,
				retained_previous_snapshot: retained,
				backend_mode: retained ? 'V4_BPF_BASIC' : 'V3_NFT_ONLY',
				generation: state.policy_generation,
				classifier_generation: state.classifier_generation,
				errors,
				warnings,
			};
		}
		if (changed)
			state.policy_generation = candidate_generation;
		if (classifier_changed)
			state.classifier_generation = candidate_classifier_generation;
	}
	const scope = firewall.apply_application_scope(true, sources, destinations);
	if (!scope.ok) {
		push(errors, scope.error);
		neutralize(state, errors);
		return {
			ok: false,
			available: true,
			enabled: false,
			degraded: true,
			retained_previous_snapshot: false,
		backend_mode: 'V3_NFT_ONLY',
		generation: state.policy_generation,
		classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}
	const pruned = prune_interfaces(state, sources);
	if (pruned.code != 0) {
		push(errors, 'Unable to establish the exact application-filter TC interface set');
		neutralize(state, errors);
		return {
			ok: false,
			available: true,
			enabled: false,
			degraded: true,
			retained_previous_snapshot: false,
		backend_mode: 'V3_NFT_ONLY',
		generation: state.policy_generation,
		classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}
	state.attached_interfaces = [ ...sources ];
	state.applied_sources = [ ...sources ];
	state.applied_destinations = [ ...destinations ];
	if (classifier_changed) {
		state.classifier_signature = current_classifier_signature;
	}
	state.applied_signature = signature;
	return {
		ok: true,
		available: true,
		enabled: true,
		degraded: false,
		retained_previous_snapshot: false,
		backend_mode: 'V4_BPF_BASIC',
		generation: state.policy_generation,
		classifier_generation: state.classifier_generation,
		errors,
		warnings,
	};
}

export function runtime_snapshot(state, enabled, policy_generation,
		classifier_generation) {
	if (!enabled || !bpf_runtime.present())
		return { available: false, status_json: null, error: null };

	const gc = bpf_runtime.gc(300);
	const health = bpf_runtime.health(policy_generation,
		classifier_generation, state.attached_interfaces);
	return {
		available: health.code == 0,
		status_json: health.code == 0 ? trim(health.output) : null,
		error: health.code != 0
			? 'Application-filter generations or TC attachments do not match the published snapshot'
			: (gc.code == 0 ? null : 'Unable to reclaim idle application flows'),
	};
}

