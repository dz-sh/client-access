// SPDX-License-Identifier: Apache-2.0

/* Bounded runtime ownership for normalized Provider observations. */

import * as classification from 'client_access.classification';

const MAX_OBSERVATIONS = 256;
const MAX_DNS_EVENTS_PER_SECOND = 128;

export function create() {
	return {
		entries: {},
		generation: 1,
		profile_signature: null,
		window_epoch: 0,
		window_events: 0,
		accepted: 0,
		dropped: 0,
		expired: 0,
		stale: 0,
	};
}

export function size(state) {
	let count = 0;
	for (let key in state.entries)
		count++;
	return count;
}

export function values(state) {
	let names = keys(state.entries), result = [];
	sort(names);
	for (let name in names)
		push(result, state.entries[name]);
	return result;
}

export function prepare(state, profile_signature) {
	const changed = state.profile_signature == null ||
		state.profile_signature != profile_signature;
	return {
		generation: state.profile_signature != null && changed
			? state.generation + 1 : state.generation,
		observations: changed ? [] : values(state),
		profile_signature,
		profile_changed: changed,
	};
}

export function commit(state, context, epoch) {
	if (context.profile_changed) {
		state.stale += size(state);
		state.entries = {};
		state.generation = context.generation;
		state.profile_signature = context.profile_signature;
	}
	for (let id, observation in state.entries) {
		if (observation.generation != state.generation) {
			delete state.entries[id];
			state.stale++;
		}
		else if (observation.expires_at <= epoch) {
			delete state.entries[id];
			state.expired++;
		}
	}
}

export function reset(state) {
	state.entries = {};
}

export function accept_dns(state, data, epoch) {
	if (epoch != state.window_epoch) {
		state.window_epoch = epoch;
		state.window_events = 0;
	}
	if (state.window_events >= MAX_DNS_EVENTS_PER_SECOND) {
		state.dropped++;
		return false;
	}
	state.window_events++;
	const normalized = classification.normalize_dns_observation(data,
		state.generation, epoch);
	if (!normalized.valid) {
		state.dropped++;
		return false;
	}
	const observation = normalized.observation;
	if (!state.entries[observation.id] && size(state) >= MAX_OBSERVATIONS) {
		state.dropped++;
		return false;
	}
	state.entries[observation.id] = observation;
	state.accepted++;
	return true;
}

export const constants = { MAX_OBSERVATIONS, MAX_DNS_EVENTS_PER_SECOND };
