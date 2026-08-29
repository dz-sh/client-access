// SPDX-License-Identifier: Apache-2.0

/* Read-only projection of internal runtime state onto the stable status API. */

export function snapshot(state, diagnostics) {
	let result = { ...state, app_filter: { ...(state.app_filter ?? {}) } };
	result.app_filter.dns_subscribed = diagnostics.dns_subscribed;
	result.app_filter.observation_entries = diagnostics.observation_entries;
	result.app_filter.dns_events_accepted = diagnostics.dns_events_accepted;
	result.app_filter.dns_events_dropped = diagnostics.dns_events_dropped;
	result.app_filter.classification_conflicts = diagnostics.classification_conflicts;
	result.app_filter.projection_publish_errors = diagnostics.projection_publish_errors;
	return result;
}

export function application_degraded(result, errors) {
	return {
		...result,
		app_filter: {
			...(result.app_filter ?? {}),
			backend_mode: 'V3_NFT_ONLY',
			enabled: false,
			available: false,
			applied: false,
			degraded: true,
			retained_previous_snapshot: false,
			runtime_available: false,
			runtime_status_json: null,
			errors,
		},
	};
}
