// SPDX-License-Identifier: Apache-2.0

/* Stable public facade. Profile/IR compilation, observation fusion, and
 * runtime lowering are owned by focused internal modules.
 */

import * as ir from 'client_access.classification_ir';
import * as observation from 'client_access.classification_observation';

export function compile_profiles(app_classes) {
	return ir.compile_profiles(app_classes);
}

export function normalize_dns_observation(data, generation, epoch) {
	return observation.normalize_dns(data, generation, epoch);
}

export function resolve(model, observations, epoch, generation, resource_limits) {
	return observation.resolve(model, observations, epoch, generation,
		resource_limits);
}

export const constants = ir.constants;
