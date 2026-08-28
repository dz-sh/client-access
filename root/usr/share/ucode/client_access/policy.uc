// SPDX-License-Identifier: Apache-2.0

const WEEK_MINUTES = 7 * 24 * 60;
const CLOCK_VALID_AFTER = 1577836800;
const DAY_INDEX = { mon: 0, tue: 1, wed: 2, thu: 3, fri: 4, sat: 5, sun: 6 };

function as_list(value) {
	if (value == null)
		return [];
	return type(value) == 'array' ? value : [ value ];
}

function flag(value, fallback) {
	if (value == null)
		return fallback;
	return value === true || value == 1 || value == '1' || lc('' + value) == 'true';
}

function add_interval(intervals, start, end) {
	if (end <= WEEK_MINUTES)
		push(intervals, [ start, end ]);
	else {
		push(intervals, [ start, WEEK_MINUTES ]);
		push(intervals, [ 0, end - WEEK_MINUTES ]);
	}
}

function parse_time(hour, minute) {
	hour = +hour;
	minute = +minute;
	return hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59
		? hour * 60 + minute : null;
}

export function parse_window(value) {
	const spec = lc(trim('' + (value ?? '')));
	const m = match(spec, /^([a-z*,]+)@([0-9]{2}):([0-9]{2})-([0-9]{2}):([0-9]{2})$/);
	if (!m)
		return { error: `Invalid schedule '${spec}'`, intervals: [] };

	const start = parse_time(m[2], m[3]);
	const end = parse_time(m[4], m[5]);
	if (start == null || end == null)
		return { error: `Invalid time in schedule '${spec}'`, intervals: [] };

	let days = [];
	if (m[1] == '*')
		days = [ 0, 1, 2, 3, 4, 5, 6 ];
	else {
		const seen = {};
		for (let token in split(m[1], ',')) {
			const day = DAY_INDEX[token];
			if (day == null)
				return { error: `Invalid weekday '${token}' in schedule '${spec}'`, intervals: [] };
			if (!seen[day]) {
				seen[day] = true;
				push(days, day);
			}
		}
	}

	let intervals = [];
	for (let day in days) {
		const base = day * 1440;
		if (start == end)
			add_interval(intervals, base, base + 1440);
		else if (start < end)
			add_interval(intervals, base + start, base + end);
		else
			add_interval(intervals, base + start, base + 1440 + end);
	}

	return { error: null, intervals };
}

function compile_windows(values) {
	let intervals = [], errors = [];
	for (let value in as_list(values)) {
		const parsed = parse_window(value);
		if (parsed.error)
			push(errors, parsed.error);
		for (let interval in parsed.intervals)
			push(intervals, interval);
	}
	return { intervals, errors };
}

function weekly_minute(tm) {
	const day = tm.wday == 7 ? 6 : tm.wday - 1;
	return day * 1440 + tm.hour * 60 + tm.min;
}

function schedule_state(intervals, minute) {
	for (let interval in intervals)
		if (minute >= interval[0] && minute < interval[1])
			return true;
	return false;
}

function next_boundary(intervals, minute) {
	let best = null;
	for (let interval in intervals) {
		for (let boundary in interval) {
			let delta = (boundary - minute + WEEK_MINUTES) % WEEK_MINUTES;
			if (delta == 0)
				delta = WEEK_MINUTES;
			if (best == null || delta < best)
				best = delta;
		}
	}
	return best;
}

export function evaluate_schedule(values, epoch) {
	epoch ??= clock()[0];
	const clock_valid = epoch >= CLOCK_VALID_AFTER;
	const windows = compile_windows(values);
	let errors = [ ...windows.errors ];
	if (!length(windows.intervals))
		push(errors, 'Schedule has no valid windows');
	if (!clock_valid)
		push(errors, 'Clock is not valid');
	if (length(errors)) {
		return {
			active: false,
			next_epoch: null,
			clock_valid,
			errors,
		};
	}

	const tm = localtime(epoch);
	const minute = weekly_minute(tm);
	const active = schedule_state(windows.intervals, minute);
	const delta = next_boundary(windows.intervals, minute);
	return {
		active,
		next_epoch: delta == null ? null : epoch - tm.sec + delta * 60,
		clock_valid,
		errors,
	};
}

function fail_closed(default_verdict, schedule_active, next_epoch, reason, errors) {
	return {
		verdict: 'deny',
		effective_active: default_verdict != 'deny',
		schedule_active,
		next_epoch,
		reason,
		errors,
	};
}

function compile_identity(identity, default_verdict, exception_verdict, epoch, clock_valid) {
	const activation = identity.activation ?? 'inactive';
	let schedule_active = null, next_epoch = null, errors = [];

	if (activation == 'inactive') {
		return {
			verdict: default_verdict,
			effective_active: false,
			schedule_active,
			next_epoch,
			reason: 'inactive',
			errors,
		};
	}

	if (activation == 'always_active') {
		return {
			verdict: exception_verdict,
			effective_active: true,
			schedule_active,
			next_epoch,
			reason: 'always_active',
			errors,
		};
	}

	if (activation != 'active_during') {
		push(errors, `Unknown activation '${activation}'`);
		return fail_closed(default_verdict, schedule_active, next_epoch, 'invalid_activation', errors);
	}

	const windows = compile_windows(identity.schedule);
	for (let error in windows.errors)
		push(errors, error);
	if (!length(windows.intervals))
		push(errors, 'Active-during identity has no valid schedule windows');

	if (!clock_valid) {
		push(errors, 'Clock is not valid; scheduled activation is fail-closed');
		return fail_closed(default_verdict, schedule_active, next_epoch, 'invalid_clock', errors);
	}
	if (length(errors))
		return fail_closed(default_verdict, schedule_active, next_epoch, 'invalid_schedule', errors);

	const tm = localtime(epoch);
	const minute = weekly_minute(tm);
	schedule_active = schedule_state(windows.intervals, minute);
	const delta = next_boundary(windows.intervals, minute);
	if (delta != null)
		next_epoch = epoch - tm.sec + delta * 60;

	return {
		verdict: schedule_active ? exception_verdict : default_verdict,
		effective_active: schedule_active,
		schedule_active,
		next_epoch,
		reason: schedule_active ? 'schedule_match' : 'schedule_miss',
		errors,
	};
}

export function compile(config, epoch) {
	epoch ??= clock()[0];
	const schema_supported = '' + (config.schema_version ?? '') == '4';
	const requested_enabled = flag(config.enabled, false);
	const mode_valid = config.mode == 'blacklist' || config.mode == 'whitelist';
	const mode = config.mode == 'whitelist' ? 'whitelist' : 'blacklist';
	const default_verdict = mode == 'whitelist' ? 'deny' : 'allow';
	const exception_verdict = mode == 'whitelist' ? 'allow' : 'deny';
	const clock_valid = epoch >= CLOCK_VALID_AFTER;
	let errors = [], warnings = [], identities = [], next_transition = null;
	let seen_ids = {};

	if (!schema_supported)
		push(errors, `Unsupported configuration schema '${config.schema_version ?? 'missing'}'`);
	if (!mode_valid)
		push(errors, `Unknown global mode '${config.mode ?? 'missing'}'`);

	for (let identity in (config.identities ?? [])) {
		const id = trim('' + (identity.id ?? identity.section ?? ''));
		if (!length(id))
			push(errors, 'Identity has no stable ID');
		else if (seen_ids[id])
			push(errors, `Duplicate identity ID '${id}'`);
		else
			seen_ids[id] = true;

		const result = compile_identity(identity, default_verdict, exception_verdict, epoch, clock_valid);
		for (let error in result.errors)
			push(errors, `${identity.name ?? id ?? 'identity'}: ${error}`);
		if (result.next_epoch != null &&
		    (next_transition == null || result.next_epoch < next_transition))
			next_transition = result.next_epoch;

		push(identities, {
			id,
			section: identity.section,
			name: identity.name ?? id,
			activation: identity.activation ?? 'inactive',
			verdict: result.verdict,
			effective_active: result.effective_active,
			reason: result.reason,
			schedule_active: result.schedule_active,
			next_transition: result.next_epoch,
		});
	}

	return {
		schema_supported,
		mode_valid,
		requested_enabled,
		enabled: requested_enabled && schema_supported && mode_valid,
		mode,
		deny_action: config.deny_action == 'drop' ? 'drop' : 'reject',
		default_verdict,
		exception_verdict,
		clock_valid,
		identities,
		next_transition,
		errors,
		warnings,
	};
}

export function safety_delay_ms(compiled, epoch, safety_interval) {
	epoch ??= clock()[0];
	safety_interval = +safety_interval;
	if (safety_interval < 5 || safety_interval > 300)
		safety_interval = 60;

	let delay = safety_interval * 1000;
	if (compiled.enabled && compiled.next_transition != null) {
		const boundary_delay = (compiled.next_transition - epoch) * 1000;
		if (boundary_delay > 0 && boundary_delay < delay)
			delay = boundary_delay;
	}
	return delay < 250 ? 250 : delay;
}
