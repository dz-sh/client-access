// SPDX-License-Identifier: Apache-2.0

/* Bounded read-only runtime observation. Semantic compilation never imports
 * these adapters; the composition root supplies this snapshot to the builder
 * and planner.
 */

import * as firewall from 'client_access.firewall';
import * as bpf_runtime from 'client_access.bpf_runtime';
import * as sfo_runtime from 'client_access.sfo_runtime';
import * as runtime_policy from 'client_access.runtime';

function parse_generations(result) {
	const values = split(trim(result?.output ?? ''), /\s+/);
	if (result?.code != 0 || length(values) != 2 ||
	    !match(values[0], /^(0|[1-9][0-9]*)$/) ||
	    !match(values[1], /^(0|[1-9][0-9]*)$/))
		return { known: false, policy: 0, classifier: 0 };
	return { known: true, policy: +values[0], classifier: +values[1] };
}

export function collect(config) {
	const offload = firewall.runtime_offload();
	const sfo_present = sfo_runtime.present();
	const capability = runtime_policy.offload_capability(config,
		offload.checked, offload.ruleset, sfo_present);
	const source = firewall.resolve_zones(config.source_zone);
	const destination = firewall.resolve_zones(config.destination_zone);
	const bpf_present = bpf_runtime.present();
	const generations = bpf_present
		? parse_generations(bpf_runtime.generations())
		: { known: true, policy: 0, classifier: 0 };

	return {
		application: {
			backend_present: bpf_present,
			policy_generation: generations.policy,
			classifier_generation: generations.classifier,
			generations_known: generations.known,
		},
		acceleration: {
			capability,
			ruleset_checked: offload.checked,
			backend_present: sfo_present,
		},
		topology: { source, destination },
	};
}
