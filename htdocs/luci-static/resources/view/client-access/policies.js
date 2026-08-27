'use strict';
'require view';
'require form';
'require rpc';
'require ui';

const callStatus = rpc.declare({
	object: 'client_access',
	method: 'status',
	expect: { '': {} }
});

const callReconcile = rpc.declare({
	object: 'client_access',
	method: 'reconcile',
	params: [ 'reason' ],
	expect: { '': {} }
});

function formatTime(epoch) {
	return epoch ? new Date(epoch * 1000).toLocaleString() : _('None');
}

function statusBox(status) {
	const disabled = status.running && status.enabled === false;
	const ok = status.running && status.applied;
	const errors = Array.isArray(status.errors) ? status.errors : [];
	const warnings = Array.isArray(status.warnings) ? status.warnings : [];

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, [ _('Runtime status') ]),
		E('div', { 'class': ok ? 'alert-message success' : 'alert-message warning' }, [
			disabled
				? _('Internet access control is globally disabled. No client policy is enforced.')
				: (ok ? _('Policy is synchronized with nftables.') : _('Policy is not synchronized with nftables.')),
		]),
		E('div', { 'class': 'table' }, [
			E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td left' }, [ _('Mode') ]),
				E('div', { 'class': 'td left' }, [ status.mode || '-' ]),
				E('div', { 'class': 'td left' }, [ _('Exception MACs') ]),
				E('div', { 'class': 'td left' }, [ String(status.exception_count || 0) ]),
			]),
			E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td left' }, [ _('Next policy transition') ]),
				E('div', { 'class': 'td left' }, [ formatTime(status.next_transition) ]),
				E('div', { 'class': 'td left' }, [ _('Generation') ]),
				E('div', { 'class': 'td left' }, [ String(status.generation || 0) ]),
			]),
		]),
		errors.length ? E('p', { 'class': 'alert-message error' }, [ errors.join('; ') ]) : '',
		warnings.length ? E('p', { 'class': 'alert-message warning' }, [ warnings.join('; ') ]) : '',
		E('button', {
			'class': 'btn cbi-button-action',
			'click': ui.createHandlerFn(null, function() {
				return callReconcile('luci-manual').then(function() { window.location.reload(); });
			})
		}, [ _('Reconcile now') ])
	]);
}

function validateSchedule(sectionId, value) {
	if (!value)
		return true;

	const m = value.toLowerCase().match(/^([a-z*,]+)@(\d{2}):(\d{2})-(\d{2}):(\d{2})$/);
	if (!m)
		return _('Use DAYS@HH:MM-HH:MM, for example mon,tue@08:00-21:30.');

	const validDays = { mon: 1, tue: 1, wed: 1, thu: 1, fri: 1, sat: 1, sun: 1 };
	if (m[1] !== '*' && m[1].split(',').some(function(day) { return !validDays[day]; }))
		return _('Weekdays must be mon, tue, wed, thu, fri, sat, sun, or *.');
	if (+m[2] > 23 || +m[3] > 59 || +m[4] > 23 || +m[5] > 59)
		return _('Hour must be 00-23 and minute must be 00-59.');

	return true;
}

return view.extend({
	load: function() {
		return L.resolveDefault(callStatus(), { running: false, errors: [ _('Daemon is unavailable') ] });
	},

	render: function(status) {
		let m, s, o;
		m = new form.Map('client_access', _('Client Internet Access'),
			_('Controls LAN-to-uplink access through one nftables MAC exception set. Policy changes affect new and related flows only; established or offloaded flows continue.'));

		s = m.section(form.NamedSection, 'main', 'client_access', _('Default LAN policy'));
		s.anonymous = true;
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('Enable enforcement'));
		o.default = '0';
		o.rmempty = false;
		o.description = _('Global master switch. It is disabled by default; when disabled, neither blacklist nor whitelist policy is enforced.');

		o = s.option(form.ListValue, 'mode', _('Default mode'));
		o.value('blacklist', _('Blacklist — allow by default'));
		o.value('whitelist', _('Whitelist — deny by default'));
		o.default = 'blacklist';
		o.rmempty = false;

		o = s.option(form.ListValue, 'deny_action', _('Deny action'));
		o.value('reject', _('Reject'));
		o.value('drop', _('Drop'));
		o.default = 'reject';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'source_zone', _('LAN firewall zones'));
		o.default = [ 'lan' ];
		o.rmempty = false;
		o.datatype = 'uciname';

		o = s.option(form.DynamicList, 'destination_zone', _('Uplink firewall zones'));
		o.default = [ 'wan' ];
		o.rmempty = false;
		o.datatype = 'uciname';

		o = s.option(form.Value, 'safety_interval', _('Clock safety recheck'));
		o.datatype = 'range(5,300)';
		o.default = '60';
		o.rmempty = false;
		o.description = _('Seconds between safety checks for manual clock changes. Exact schedule boundaries wake the same global timer earlier.');

		s = m.section(form.GridSection, 'device', _('Per-device policies'));
		s.addremove = true;
		s.sortable = true;
		s.nodescriptions = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;

		o = s.option(form.Value, 'name', _('Device name'));
		o.rmempty = false;

		o = s.option(form.DynamicList, 'mac', _('MAC address'));
		o.datatype = 'macaddr';
		o.rmempty = false;

		o = s.option(form.ListValue, 'policy', _('Policy'));
		o.value('inherit', _('Inherit default'));
		o.value('always_allow', _('Always allow'));
		o.value('always_block', _('Always block'));
		o.value('allow_during', _('Allow during schedule'));
		o.value('block_during', _('Block during schedule'));
		o.default = 'inherit';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'schedule', _('Schedule windows'));
		o.depends('policy', 'allow_during');
		o.depends('policy', 'block_during');
		o.placeholder = 'mon,tue,wed,thu,fri@08:00-21:30';
		o.validate = validateSchedule;
		o.description = _('Windows are combined. A window crossing midnight is supported; equal start and end means the whole selected day.');

		return m.render().then(function(formNode) {
			return E([], [ statusBox(status), formNode ]);
		});
	}
});
