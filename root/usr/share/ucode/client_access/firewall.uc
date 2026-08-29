// SPDX-License-Identifier: Apache-2.0

/* fw4/nftables runtime adapter. It consumes desired projections only. */

import { popen } from 'fs';

const NFT = '/usr/sbin/nft';
const FW4 = '/sbin/fw4';

function capture(argv) {
	const proc = popen(argv, 'r');
	if (!proc)
		return { code: null, output: '' };
	const output = proc.read('all') ?? '';
	return { code: proc.close(), output };
}

function unique_strings(values) {
	let result = [], seen = {};
	for (let value in values) {
		value = trim('' + value);
		if (length(value) && !seen[value]) {
			seen[value] = true;
			push(result, value);
		}
	}
	sort(result);
	return result;
}

function nft_quote(value) {
	return '"' + replace(replace(value, /\\/g, '\\\\'), /"/g, '\\"') + '"';
}

function nft_elements(name, values, formatter) {
	let script = `flush set inet fw4 ${name}\n`;
	if (length(values))
		script += `add element inet fw4 ${name} { ${join(', ', map(values, formatter))} }\n`;
	return script;
}

function apply_script(script, description) {
	const proc = popen([ NFT, '-f', '-' ], 'w');
	if (!proc)
		return { ok: false, error: `Unable to start nft${description}` };
	if (proc.write(script) != length(script)) {
		proc.close();
		return { ok: false, error: `Unable to write complete nft${description} transaction` };
	}
	const code = proc.close();
	return code == 0
		? { ok: true, error: null }
		: { ok: false, error: `${description || 'nft'} transaction failed with exit code ${code}` };
}

export function resolve_zones(zones) {
	let interfaces = [], errors = [];
	for (let zone in zones) {
		zone = trim('' + zone);
		if (!length(zone))
			continue;
		const result = capture([ FW4, 'zone', zone ]);
		if (result.code != 0) {
			push(errors, `Unable to resolve firewall zone '${zone}'`);
			continue;
		}
		for (let ifname in split(trim(result.output), /\s+/))
			if (length(ifname))
				push(interfaces, ifname);
	}
	return { interfaces: unique_strings(interfaces), errors };
}

export function apply_access(compiled, projection, sources, destinations) {
	let exceptions = projection.exceptions;
	if (!compiled.enabled) {
		exceptions = [];
		sources = [];
		destinations = [];
	}
	let script = '';
	script += nft_elements('client_access_exceptions', exceptions, value => value);
	script += nft_elements('client_access_sources', sources, nft_quote);
	script += nft_elements('client_access_destinations', destinations, nft_quote);
	script += nft_elements('client_access_whitelist_mode',
		compiled.enabled && compiled.mode == 'whitelist' ? [ 'ipv4', 'ipv6' ] : [],
		value => value);
	script += nft_elements('client_access_drop_mode',
		compiled.enabled && compiled.deny_action == 'drop' ? [ 'ipv4', 'ipv6' ] : [],
		value => value);
	return apply_script(script, '');
}

export function apply_application_scope(enabled, sources, destinations) {
	if (!enabled) {
		sources = [];
		destinations = [];
	}
	let script = '';
	script += nft_elements('client_access_app_sources', sources, nft_quote);
	script += nft_elements('client_access_app_destinations', destinations, nft_quote);
	const proc = popen([ NFT, '-f', '-' ], 'w');
	if (!proc)
		return { ok: false, error: 'Unable to start nft for application-filter scope' };
	if (proc.write(script) != length(script)) {
		proc.close();
		return { ok: false, error: 'Unable to write complete application-filter scope transaction' };
	}
	const code = proc.close();
	return code == 0
		? { ok: true, error: null }
		: { ok: false, error: `Application-filter nft scope failed with exit code ${code}` };
}

export function runtime_offload() {
	const result = capture([ NFT, 'list', 'ruleset' ]);
	return { checked: result.code == 0, ruleset: result.output };
}
