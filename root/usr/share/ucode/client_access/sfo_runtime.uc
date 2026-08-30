// SPDX-License-Identifier: Apache-2.0

/* Optional V4.6 SFO process adapter. The helper speaks structured ctnetlink;
 * this module only transports bounded commands and JSON results.
 */

import { popen, stat } from 'fs';

const SFOCTL = '/usr/sbin/client-access-sfoctl';

function capture(arguments) {
	const proc = popen([ SFOCTL, ...arguments ], 'r');
	if (!proc)
		return { code: null, output: '', value: null };
	const output = proc.read('all') ?? '';
	const code = proc.close();
	let value = null;
	try {
		value = json(output);
	}
	catch (error) {
		value = null;
	}
	return { code, output, value };
}

export function present() {
	return !!stat(SFOCTL);
}

export function status() {
	return capture([ 'status' ]);
}

export function baseline(deadline_ms) {
	return capture([ 'baseline', '' + deadline_ms ]);
}

export function revoke(subject_id, class_id, deadline_ms) {
	return capture([ 'revoke', '' + subject_id,
		class_id == null ? '-' : '' + class_id, '' + deadline_ms ]);
}

export function gc(idle_seconds) {
	return capture([ 'gc', '' + idle_seconds ]);
}

export const path = SFOCTL;
