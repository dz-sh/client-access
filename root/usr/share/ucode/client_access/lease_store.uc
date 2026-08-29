// SPDX-License-Identifier: Apache-2.0

/* Volatile lease journal adapter. Lease meaning remains in lease.uc. */

import { open, rename, unlink } from 'fs';
import * as lease from 'client_access.lease';

const MAX_JOURNAL_BYTES = 262144;
const MAX_ERRORS = 16;

function add_error(errors, value) {
	if (length(errors) >= MAX_ERRORS)
		return;
	for (let existing in errors)
		if (existing == value)
			return;
	push(errors, value);
}

export function read(path, context, epoch, monotonic_now) {
	let errors = [], value = lease.empty_database();
	const fp = open(path, 'r');
	if (fp) {
		const content = fp.read('all');
		fp.close();
		if (content != null && length(content) <= MAX_JOURNAL_BYTES) {
			try {
				value = json(content);
			}
			catch (error) {
				value = null;
				add_error(errors,
					'Temporary Approval journal contains invalid JSON and was ignored');
			}
		}
		else if (content != null)
			add_error(errors,
				`Temporary Approval journal exceeded ${MAX_JOURNAL_BYTES} bytes and was ignored`);
	}
	const parsed = lease.parse_database(value, context, epoch, monotonic_now);
	for (let error in parsed.errors)
		add_error(errors, error);
	return { ...parsed, errors };
}

export function write(path, database) {
	const temporary = `${path}.new`;
	const content = sprintf('%J\n', database);
	let fp = open(temporary, 'w', 384);
	if (!fp)
		return { ok: false, error: 'Unable to create Temporary Approval journal' };
	const written = fp.write(content) == length(content);
	const flushed = written && fp.flush();
	const closed = fp.close();
	if (!written || !flushed || !closed) {
		unlink(temporary);
		return { ok: false, error: 'Unable to write Temporary Approval journal' };
	}
	if (!rename(temporary, path)) {
		unlink(temporary);
		return { ok: false, error: 'Unable to atomically replace Temporary Approval journal' };
	}
	return { ok: true, error: null };
}

export const constants = { MAX_JOURNAL_BYTES, MAX_ERRORS };
