// SPDX-License-Identifier: Apache-2.0

/* V41-OFF-001..003: V4.1 supports refusal, not offload coordination. Keep the
 * decision pure so the daemon and remote policy tests exercise identical
 * semantics.
 */
export function offload_refusal(config, ruleset_checked, ruleset) {
	if (!ruleset_checked)
		return 'unverifiable_ruleset';
	if (config.flow_offloading || config.flow_offloading_hw)
		return 'firewall_configuration';
	if (match(ruleset ?? '', /\bflow\s+(add|offload)\s+@/))
		return 'custom_flowtable';
	return null;
}
