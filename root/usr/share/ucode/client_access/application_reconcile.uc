// SPDX-License-Identifier: Apache-2.0

/* Application-layer desired-state reconciliation. This module coordinates the
 * semantic result with the optional BPF and nftables runtime adapters; it does
 * not own policy or classification semantics. */

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
		applied_enforcement: false,
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
	state.applied_enforcement = false;
	return {
		ok: (disabled.code == null || disabled.code == 0) &&
			(pruned.code == null || pruned.code == 0) && scope.ok,
		backend_present: disabled.code != null,
	};
}

function restore_scope(state, errors) {
	const scope = firewall.apply_application_scope(state.applied_enforcement,
		state.applied_sources,
		state.applied_destinations);
	if (scope.ok)
		return true;
	push(errors, scope.error);
	neutralize(state, errors);
	return false;
}

export function apply(state, config, app_compiled, classification_state,
		subject_projection, sources, destinations, zone_errors, force, observations,
		acceleration) {
	const tracking_required = acceleration?.tracking_required ?? false;
	const enforcement_requested = app_compiled.requested_enabled;
	const runtime_requested = enforcement_requested || tracking_required;
	let errors = [ ...subject_projection.errors, ...zone_errors ];
	let warnings = [];
	if (enforcement_requested) {
		push(errors, ...app_compiled.errors, ...classification_state.errors);
		push(warnings, ...app_compiled.warnings, ...classification_state.warnings);
	}
	const runtime_projection = classification_state.runtime_projection;
	const previously_enabled = state.applied_signature != null && length(state.attached_interfaces) > 0;
	const previous_interfaces = {};
	for (let ifname in state.attached_interfaces)
		previous_interfaces[ifname] = true;

	if (!runtime_requested) {
		observation_store.reset(observations);
		const neutral = neutralize(state, errors);
		return {
			ok: neutral.ok,
			available: false,
			enabled: false,
			degraded: !neutral.ok,
			retained_previous_snapshot: false,
			backend_mode: 'V3_NFT_ONLY',
			tracking_enabled: false,
			generation: state.policy_generation,
			classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}
	if (!bpf_runtime.present()) {
		push(errors, tracking_required
			? 'The SFO backend requires the optional TC eBPF correlation backend'
			: 'The optional TC eBPF application backend is not installed');
		neutralize(state, errors);
		return {
			ok: false,
			available: false,
			enabled: false,
			degraded: true,
			retained_previous_snapshot: false,
			backend_mode: 'V3_NFT_ONLY',
			tracking_enabled: false,
			generation: state.policy_generation,
			classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}
	if (enforcement_requested && acceleration?.offload_present &&
	    acceleration.mode != 'SFO_ACTIVE') {
		push(errors, 'Application filtering cannot coexist with an unverified or unsupported acceleration backend');
		const neutral = neutralize(state, errors);
		return {
			ok: false,
			available: neutral.backend_present,
			enabled: false,
			degraded: true,
			retained_previous_snapshot: false,
			backend_mode: 'V3_NFT_ONLY',
			tracking_enabled: false,
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
	if ((enforcement_requested && !app_compiled.enabled) || length(errors)) {
		if (!previously_enabled) {
			neutralize(state, errors);
			return {
				ok: false,
				available: false,
				enabled: false,
				degraded: true,
				retained_previous_snapshot: false,
				backend_mode: 'V3_NFT_ONLY',
				tracking_enabled: false,
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
			tracking_enabled: retained,
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
			tracking_enabled: false,
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
			tracking_enabled: retained,
			generation: state.policy_generation,
			classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}

	const signature = sprintf('%s|tracking=%d|enforcement=%d',
		reconciliation.application_signature(app_compiled,
			subject_projection, sources, destinations),
		tracking_required ? 1 : 0, enforcement_requested ? 1 : 0);
	const changed = signature != state.applied_signature;
	const candidate_generation = changed ? state.policy_generation + 1 : state.policy_generation;
	const current_classifier_signature = reconciliation.classifier_signature(runtime_projection);
	const classifier_changed = current_classifier_signature != state.classifier_signature;
	const candidate_classifier_generation = classifier_changed
		? state.classifier_generation + 1 : state.classifier_generation;
	if (force || changed || classifier_changed) {
		const result = bpf_runtime.publish(bpf_runtime.serialize_snapshot(app_compiled,
			runtime_projection, subject_projection, candidate_generation,
			candidate_classifier_generation, true, enforcement_requested));
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
				tracking_enabled: retained,
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
	const scope = firewall.apply_application_scope(enforcement_requested,
		sources, destinations);
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
			tracking_enabled: false,
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
			tracking_enabled: false,
			generation: state.policy_generation,
			classifier_generation: state.classifier_generation,
			errors,
			warnings,
		};
	}
	state.attached_interfaces = [ ...sources ];
	state.applied_sources = [ ...sources ];
	state.applied_destinations = [ ...destinations ];
	state.applied_enforcement = enforcement_requested;
	if (classifier_changed) {
		state.classifier_signature = current_classifier_signature;
	}
	state.applied_signature = signature;
	return {
		ok: true,
		available: true,
		enabled: enforcement_requested,
		tracking_enabled: true,
		degraded: false,
		retained_previous_snapshot: false,
		backend_mode: enforcement_requested ? 'V4_BPF_BASIC' : 'V46_SFO_TRACKING',
		generation: state.policy_generation,
		classifier_generation: state.classifier_generation,
		errors,
		warnings,
	};
}

export function runtime_snapshot(state, tracking_enabled, policy_generation,
		classifier_generation) {
	if (!tracking_enabled || !bpf_runtime.present())
		return { available: false, status_json: null, error: null };

	const health = bpf_runtime.health(policy_generation,
		classifier_generation, state.attached_interfaces);
	let status = null;
	if (health.code == 0)
		try { status = json(health.output); }
		catch (error) { status = null; }
	const correlation_healthy = status != null &&
		(status.flow_map_full ?? 0) == 0 &&
		(status.flow_map_entries ?? 0) < (status.flow_capacity ?? 0);
	return {
		available: health.code == 0,
		status_json: health.code == 0 ? trim(health.output) : null,
		correlation_healthy,
		correlation_error: health.code == 0 && !correlation_healthy
			? 'BPF semantic flow capacity is exhausted or cannot be verified'
			: null,
		error: health.code != 0
			? 'BPF correlation generations or TC attachments do not match the published snapshot'
			: null,
	};
}
