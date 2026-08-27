'use strict';
'require view';
'require form';
'require rpc';
'require uci';
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
	const disabled = status.running && status.enabled === false && status.schema_supported !== false;
	const ok = status.running && status.applied;
	const errors = Array.isArray(status.errors) ? status.errors : [];
	const warnings = Array.isArray(status.warnings) ? status.warnings : [];

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, [ _('Runtime status') ]),
		E('div', { 'class': ok || disabled ? 'alert-message success' : 'alert-message warning' }, [
			disabled
				? _('Internet access control is globally disabled. Identities and bindings remain configured but no forwarding policy is enforced.')
				: (ok ? _('Identity activation is synchronized with nftables.') : _('Policy is not synchronized with nftables.')),
		]),
		E('div', { 'class': 'table' }, [
			E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td left' }, [ _('Mode') ]),
				E('div', { 'class': 'td left' }, [ status.mode || '-' ]),
				E('div', { 'class': 'td left' }, [ _('Identities') ]),
				E('div', { 'class': 'td left' }, [ String(status.identity_count || 0) ]),
			]),
			E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td left' }, [ _('Currently active') ]),
				E('div', { 'class': 'td left' }, [ String(status.active_identity_count || 0) ]),
				E('div', { 'class': 'td left' }, [ _('MAC bindings') ]),
				E('div', { 'class': 'td left' }, [ String(status.binding_count || 0) ]),
			]),
			E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td left' }, [ _('Next activation transition') ]),
				E('div', { 'class': 'td left' }, [ formatTime(status.next_transition) ]),
				E('div', { 'class': 'td left' }, [ _('Exception MACs') ]),
				E('div', { 'class': 'td left' }, [ String(status.exception_count || 0) ]),
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

function validateUniqueMac(sectionId, value) {
	if (!value)
		return true;
	const candidate = value.toLowerCase();
	const duplicate = uci.sections('client_access', 'binding').some(function(binding) {
		return binding['.name'] !== sectionId &&
			binding.type === 'mac' &&
			String(binding.value || '').toLowerCase() === candidate;
	});
	return duplicate ? _('This MAC address is already bound to another identity.') : true;
}

function activationLabels(mode) {
	if (mode === 'whitelist') {
		return {
			inactive: _('Inactive — follow default deny'),
			always_active: _('Always active — always allow'),
			active_during: _('Active during schedule — allow while active')
		};
	}
	return {
		inactive: _('Inactive — follow default allow'),
		always_active: _('Always active — always block'),
		active_during: _('Active during schedule — block while active')
	};
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(callStatus(), { running: false, errors: [ _('Daemon is unavailable') ] }),
			uci.load('client_access')
		]);
	},

	render: function(data) {
		const status = data[0];
		const labels = activationLabels(status.mode);
		const configuredIdentities = uci.sections('client_access', 'identity');
		let m, s, o;

		m = new form.Map('client_access', _('Client Internet Access'),
			_('Policies are attached to stable identities. MAC addresses are bindings used only to project currently active identities into one nftables exception set.'));

		s = m.section(form.NamedSection, 'main', 'client_access', _('Global policy'));
		s.anonymous = true;
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('Enable enforcement'));
		o.default = '0';
		o.rmempty = false;
		o.description = _('Global master switch. It is disabled by default and bypasses both blacklist and whitelist behavior.');

		o = s.option(form.ListValue, 'mode', _('Global mode'));
		o.value('blacklist', _('Blacklist — default allow; active identities are denied'));
		o.value('whitelist', _('Whitelist — default deny; active identities are allowed'));
		o.default = 'blacklist';
		o.rmempty = false;
		o.description = _('Changing mode reverses the access meaning of every active identity.');

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
		o.description = _('Seconds between safety checks. Exact weekly schedule boundaries wake the same global timer earlier.');

		s = m.section(form.GridSection, 'identity', _('Managed identities'));
		s.anonymous = false;
		s.addremove = true;
		s.sortable = true;
		s.nodescriptions = true;
		s.description = _('The UCI section name is the stable identity ID. It must not be derived from a MAC address.');
		const removeIdentity = s.handleRemove;
		s.handleRemove = function(sectionId, ev) {
			uci.sections('client_access', 'binding').forEach(function(binding) {
				if (binding.identity === sectionId)
					uci.remove('client_access', binding['.name']);
			});
			return removeIdentity.call(this, sectionId, ev);
		};

		o = s.option(form.Value, 'name', _('Display name'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'activation', _('Activation'));
		o.value('inactive', labels.inactive);
		o.value('always_active', labels.always_active);
		o.value('active_during', labels.active_during);
		o.default = 'inactive';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'schedule', _('Active schedule'));
		o.depends('activation', 'active_during');
		o.placeholder = 'mon,tue,wed,thu,fri@08:00-21:30';
		o.validate = validateSchedule;
		o.description = _('Use *@HH:MM-HH:MM for every day, group weekdays with commas, or add separate rows for different days and multiple daily periods. Windows are combined as a union and may cross midnight.');

		s = m.section(form.GridSection, 'binding', _('Identity bindings'));
		s.anonymous = true;
		s.addremove = true;
		s.sortable = false;
		s.nodescriptions = true;
		s.description = _('Bindings associate nftables selectors with identities. They do not contain policy or schedule state.');

		o = s.option(form.ListValue, 'identity', _('Identity'));
		configuredIdentities.forEach(function(identity) {
			o.value(identity['.name'], identity.name || identity['.name']);
		});
		o.rmempty = false;

		o = s.option(form.ListValue, 'type', _('Binding type'));
		o.value('mac', _('MAC address'));
		o.default = 'mac';
		o.rmempty = false;

		o = s.option(form.Value, 'value', _('Value'));
		o.datatype = 'macaddr';
		o.rmempty = false;
		o.validate = validateUniqueMac;

		return m.render().then(function(formNode) {
			return E([], [ statusBox(status), formNode ]);
		});
	}
});
