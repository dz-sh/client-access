// SPDX-License-Identifier: Apache-2.0

/* Lowers semantic classification state into bounded datapath tables. */

const SIGNATURE_MEMORY = {
	port: 128,
	ipv4_prefix: 160,
	ipv6_prefix: 192,
};

const SIGNATURE_CAPACITY = {
	ports: 1024,
	ipv4_prefixes: 4096,
	ipv6_prefixes: 4096,
};

export function lower(model, semantic_state, resource_limits) {
	let projection = {
		ports: [], ipv4_prefixes: [], ipv6_prefixes: [],
		signature_count: 0,
		signature_memory_bytes: model.domain_memory_bytes,
		semantic_entry_count: length(semantic_state.entries),
	};
	for (let entry in semantic_state.entries) {
		const hint = {
			class_id: entry.result.class_id,
			category_id: entry.result.category_id,
			kind: entry.result.kind_id,
		};
		if (entry.key.type == 'tcp_port' || entry.key.type == 'udp_port') {
			push(projection.ports, {
				protocol: entry.key.type == 'tcp_port' ? 6 : 17,
				port: +entry.key.value, hint,
			});
			projection.signature_memory_bytes += SIGNATURE_MEMORY.port;
		}
		else if (entry.key.type == 'ipv4_prefix') {
			push(projection.ipv4_prefixes, { prefix: entry.key.value, hint });
			projection.signature_memory_bytes += SIGNATURE_MEMORY.ipv4_prefix;
		}
		else if (entry.key.type == 'ipv6_prefix') {
			push(projection.ipv6_prefixes, { prefix: entry.key.value, hint });
			projection.signature_memory_bytes += SIGNATURE_MEMORY.ipv6_prefix;
		}
	}
	projection.signature_count = length(projection.ports) +
		length(projection.ipv4_prefixes) + length(projection.ipv6_prefixes);

	let errors = [];
	if (length(projection.ports) > SIGNATURE_CAPACITY.ports)
		push(errors, `Runtime projection ports exceeds capacity ${SIGNATURE_CAPACITY.ports}`);
	if (length(projection.ipv4_prefixes) > SIGNATURE_CAPACITY.ipv4_prefixes)
		push(errors, `Runtime projection IPv4 prefixes exceeds capacity ${SIGNATURE_CAPACITY.ipv4_prefixes}`);
	if (length(projection.ipv6_prefixes) > SIGNATURE_CAPACITY.ipv6_prefixes)
		push(errors, `Runtime projection IPv6 prefixes exceeds capacity ${SIGNATURE_CAPACITY.ipv6_prefixes}`);
	if (projection.signature_memory_bytes > resource_limits.signature_table_memory_limit)
		push(errors,
			`Runtime projection requires an estimated ${projection.signature_memory_bytes} bytes, exceeding limit ${resource_limits.signature_table_memory_limit}`);
	projection.signature = sprintf('%J', {
		ports: projection.ports,
		ipv4_prefixes: projection.ipv4_prefixes,
		ipv6_prefixes: projection.ipv6_prefixes,
	});
	return { projection, errors };
}

export const constants = { SIGNATURE_MEMORY, SIGNATURE_CAPACITY };
