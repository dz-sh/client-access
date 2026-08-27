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

export function normalize_mac(value) {
	if (value == null)
		return null;
	const mac = lc(trim('' + value));
	return match(mac, /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/) ? mac : null;
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

function device_verdict(device, default_verdict, epoch, clock_valid) {
	const policy = device.policy ?? 'inherit';
	const scheduled = policy == 'allow_during' || policy == 'block_during';
	let errors = [], active = null, next_epoch = null;

	if (!flag(device.enabled, true) || policy == 'inherit')
		return { verdict: default_verdict, active, next_epoch, errors, applies: false };
	if (policy == 'always_allow')
		return { verdict: 'allow', active, next_epoch, errors, applies: true };
	if (policy == 'always_block')
		return { verdict: 'deny', active, next_epoch, errors, applies: true };
	if (!scheduled) {
		push(errors, `Unknown policy '${policy}'`);
		return { verdict: 'deny', active, next_epoch, errors, applies: true };
	}

	const windows = compile_windows(device.schedule);
	for (let error in windows.errors)
		push(errors, error);
	if (!clock_valid) {
		push(errors, 'Clock is not valid; scheduled policy is fail-closed');
		return { verdict: 'deny', active, next_epoch, errors, applies: true };
	}
	if (!length(windows.intervals) || length(windows.errors)) {
		if (!length(windows.intervals))
			push(errors, 'Scheduled policy has no valid windows');
		return { verdict: 'deny', active, next_epoch, errors, applies: true };
	}

	const tm = localtime(epoch);
	const minute = weekly_minute(tm);
	active = schedule_state(windows.intervals, minute);
	const delta = next_boundary(windows.intervals, minute);
	if (delta != null)
		next_epoch = epoch - tm.sec + delta * 60;

	return {
		verdict: policy == 'allow_during'
			? (active ? 'allow' : 'deny')
			: (active ? 'deny' : 'allow'),
		active,
		next_epoch,
		errors,
		applies: true,
	};
}

export function compile(config, epoch) {
	epoch ??= clock()[0];
	const mode = config.mode == 'whitelist' ? 'whitelist' : 'blacklist';
	const default_verdict = mode == 'whitelist' ? 'deny' : 'allow';
	const clock_valid = epoch >= CLOCK_VALID_AFTER;
	let errors = [], warnings = [], clients = [], verdicts = {}, next_transition = null;

	for (let device in (config.devices ?? [])) {
		const result = device_verdict(device, default_verdict, epoch, clock_valid);
		let valid_macs = [];
		for (let raw_mac in as_list(device.mac)) {
			const mac = normalize_mac(raw_mac);
			if (!mac) {
				push(errors, `${device.name ?? device.section ?? 'device'}: invalid MAC '${raw_mac}'`);
				continue;
			}
			push(valid_macs, mac);
			if (!result.applies)
				continue;

			if (verdicts[mac] && verdicts[mac] != result.verdict) {
				push(warnings, `${mac} has conflicting policies; deny wins`);
				verdicts[mac] = 'deny';
			}
			else
				verdicts[mac] = result.verdict;
		}

		for (let error in result.errors)
			push(errors, `${device.name ?? device.section ?? 'device'}: ${error}`);
		if (result.applies && !length(valid_macs))
			push(errors, `${device.name ?? device.section ?? 'device'}: active policy has no valid MAC address`);
		if (result.next_epoch != null &&
		    (next_transition == null || result.next_epoch < next_transition))
			next_transition = result.next_epoch;

		push(clients, {
			section: device.section,
			name: device.name,
			macs: valid_macs,
			policy: device.policy ?? 'inherit',
			verdict: result.verdict,
			schedule_active: result.active,
			next_transition: result.next_epoch,
		});
	}

	let exceptions = [];
	for (let mac, verdict in verdicts)
		if (verdict != default_verdict)
			push(exceptions, mac);
	sort(exceptions);

	return {
		enabled: flag(config.enabled, false),
		mode,
		deny_action: config.deny_action == 'drop' ? 'drop' : 'reject',
		default_verdict,
		clock_valid,
		exceptions,
		clients,
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
