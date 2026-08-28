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

const callIdentities = rpc.declare({
	object: 'client_access',
	method: 'identities',
	expect: { '': { identities: [] } }
});

const callObservations = rpc.declare({
	object: 'client_access',
	method: 'observations',
	expect: { '': { observations: [] } }
});

const callReconcile = rpc.declare({
	object: 'client_access',
	method: 'reconcile',
	params: [ 'reason' ],
	expect: { '': {} }
});

const DAYS = [
	{ id: 'mon', label: _('Monday') },
	{ id: 'tue', label: _('Tuesday') },
	{ id: 'wed', label: _('Wednesday') },
	{ id: 'thu', label: _('Thursday') },
	{ id: 'fri', label: _('Friday') },
	{ id: 'sat', label: _('Saturday') },
	{ id: 'sun', label: _('Sunday') }
];

function asList(value) {
	if (value == null)
		return [];
	return Array.isArray(value) ? value : [ value ];
}

function randomIdentityId() {
	const bytes = new Uint8Array(12);
	window.crypto.getRandomValues(bytes);
	return 'identity_' + Array.from(bytes, function(value) {
		return value.toString(16).padStart(2, '0');
	}).join('');
}

function randomSubjectId() {
	const configured = {};
	uci.sections('client_access', 'identity').forEach(function(identity) {
		configured[String(identity.subject_id || '')] = true;
	});
	let value;
	do {
		const bytes = new Uint32Array(1);
		window.crypto.getRandomValues(bytes);
		value = bytes[0] || 1;
	} while (configured[String(value)]);
	return String(value);
}

function saveChanges() {
	return uci.save()
		.then(L.bind(ui.changes.init, ui.changes))
		.then(L.bind(ui.changes.displayChanges, ui.changes));
}

function accessPolicyFromUci() {
	if (uci.get('client_access', 'main', 'enabled') !== '1')
		return 'off';
	return uci.get('client_access', 'main', 'mode') === 'whitelist'
		? 'allow_selected' : 'block_selected';
}

function formatTime(epoch) {
	return epoch ? new Date(epoch * 1000).toLocaleString() : _('No scheduled change');
}

function accessResult(verdict, enabled) {
	if (!enabled)
		return _('Control is off');
	return verdict === 'deny' ? _('Blocked now') : _('Allowed now');
}

function applyPolicyLabel(activation) {
	if (activation === 'always_active')
		return _('Always');
	if (activation === 'active_during')
		return _('On schedule');
	return _('Never');
}

function resultReason(identity, status) {
	if (!status.enabled)
		return _('Internet access control is off.');
	if (!identity)
		return _('Apply the pending configuration to calculate the current result.');
	if (identity.reason === 'always_active')
		return _('The policy always applies to this identity.');
	if (identity.reason === 'schedule_match')
		return _('The policy applies because a weekly period matches now.');
	if (identity.reason === 'schedule_miss')
		return _('The policy does not apply because no weekly period matches now.');
	if (identity.reason === 'inactive')
		return _('The policy never applies to this identity.');
	return _('The current result is fail-closed because this identity has a configuration error.');
}

function statusPanel(status) {
	const disabled = status.running && status.enabled === false && status.schema_supported !== false;
	const ok = status.running && status.applied;
	const errors = Array.isArray(status.errors) ? status.errors : [];
	const warnings = Array.isArray(status.warnings) ? status.warnings : [];

	return E('div', { 'class': 'cbi-section' }, [
		E('div', { 'class': ok || disabled ? 'alert-message success' : 'alert-message warning' }, [
			disabled
				? _('Internet access control is off. All clients can access the Internet.')
				: (ok ? _('The configured Internet access policy is active.') : _('The policy could not be fully applied.'))
		]),
		E('details', {}, [
			E('summary', {}, [ _('Diagnostics') ]),
			E('div', { 'class': 'table' }, [
				E('div', { 'class': 'tr' }, [
					E('div', { 'class': 'td left' }, [ _('Managed identities') ]),
					E('div', { 'class': 'td left' }, [ String(status.identity_count || 0) ]),
					E('div', { 'class': 'td left' }, [ _('Recognized MAC addresses') ]),
					E('div', { 'class': 'td left' }, [ String(status.binding_count || 0) ])
				]),
				E('div', { 'class': 'tr' }, [
					E('div', { 'class': 'td left' }, [ _('Selected now') ]),
					E('div', { 'class': 'td left' }, [ String(status.active_identity_count || 0) ]),
					E('div', { 'class': 'td left' }, [ _('Next policy change') ]),
					E('div', { 'class': 'td left' }, [ formatTime(status.next_transition) ])
				])
			]),
			errors.length ? E('p', { 'class': 'alert-message error' }, [ errors.join('; ') ]) : '',
			warnings.length ? E('p', { 'class': 'alert-message warning' }, [ warnings.join('; ') ]) : '',
			E('button', {
				'class': 'btn cbi-button-action',
				'click': ui.createHandlerFn(null, function() {
					return callReconcile('luci-manual').then(function() { window.location.reload(); });
				})
			}, [ _('Reapply policy') ])
		])
	]);
}

function parseScheduleMap(sectionId) {
	const result = {};
	DAYS.forEach(function(day) { result[day.id] = []; });
	asList(uci.get('client_access', sectionId, 'schedule')).forEach(function(value) {
		const match = String(value || '').toLowerCase().match(/^([a-z*,]+)@(\d{2}:\d{2}-\d{2}:\d{2})$/);
		if (!match)
			return;
		const selected = match[1] === '*' ? DAYS.map(function(day) { return day.id; }) : match[1].split(',');
		selected.forEach(function(day) {
			if (result[day] && result[day].indexOf(match[2]) === -1)
				result[day].push(match[2] === '00:00-00:00' ? 'all-day' : match[2]);
		});
	});
	return result;
}

function writeScheduleDay(sectionId, day, values) {
	const schedule = parseScheduleMap(sectionId);
	schedule[day] = asList(values).map(function(value) {
		return String(value || '').trim().toLowerCase();
	}).filter(function(value) { return value.length > 0; });
	const serialized = [];
	DAYS.forEach(function(item) {
		schedule[item.id].forEach(function(value) {
			serialized.push(item.id + '@' + (value === 'all-day' ? '00:00-00:00' : value));
		});
	});
	if (serialized.length)
		uci.set('client_access', sectionId, 'schedule', serialized);
	else
		uci.unset('client_access', sectionId, 'schedule');
}

function validatePeriod(sectionId, value) {
	if (!value)
		return true;
	if (String(value).toLowerCase() === 'all-day')
		return true;
	const match = String(value).match(/^(\d{2}):(\d{2})-(\d{2}):(\d{2})$/);
	if (!match)
		return _('Enter a time period such as 08:00-12:00, or all-day.');
	if (+match[1] > 23 || +match[2] > 59 || +match[3] > 23 || +match[4] > 59)
		return _('Hours must be 00-23 and minutes must be 00-59.');
	return true;
}

function bindingsForIdentity(sectionId) {
	return uci.sections('client_access', 'binding').filter(function(binding) {
		return binding.identity === sectionId && (binding.type || 'mac') === 'mac';
	});
}

function recognizedMacs(sectionId) {
	return bindingsForIdentity(sectionId).map(function(binding) {
		return String(binding.value || '').toLowerCase();
	}).filter(function(value) { return value.length > 0; }).sort();
}

function validateUniqueMac(sectionId, value) {
	if (!value)
		return true;
	const candidate = String(value).toLowerCase();
	const duplicate = uci.sections('client_access', 'binding').some(function(binding) {
		return binding.identity !== sectionId &&
			(binding.type || 'mac') === 'mac' &&
			String(binding.value || '').toLowerCase() === candidate;
	});
	return duplicate ? _('This MAC address is already recognized as another identity.') : true;
}

function writeRecognizedMacs(sectionId, values) {
	bindingsForIdentity(sectionId).forEach(function(binding) {
		uci.remove('client_access', binding['.name']);
	});
	asList(values).map(function(value) {
		return String(value || '').trim().toLowerCase();
	}).filter(function(value) { return value.length > 0; }).forEach(function(value) {
		const binding = uci.add('client_access', 'binding');
		uci.set('client_access', binding, 'identity', sectionId);
		uci.set('client_access', binding, 'type', 'mac');
		uci.set('client_access', binding, 'value', value);
	});
}

function detectedDevicesHtml(identity) {
	if (!identity || !identity.bindings || !identity.bindings.length)
		return '<em>%h</em>'.format(_('No recognized MAC addresses.'));
	return identity.bindings.map(function(binding) {
		const addresses = asList(binding.ipaddrs).concat(asList(binding.ip6addrs));
		const detected = binding.observed
			? [ binding.observed_name || _('Detected client'), addresses.join(', ') ].filter(Boolean).join(' · ')
			: _('Not currently detected');
		return '<div><code>%h</code><br><small>%h</small></div>'.format(binding.value || '', detected);
	}).join('');
}

function identityById(inventory) {
	const result = {};
	(inventory.identities || []).forEach(function(identity) { result[identity.id] = identity; });
	return result;
}

function identityOutcomeSentence(identity, status) {
	if (!identity)
		return _('The current result will be calculated after applying the configuration.');
	return '%s %s'.format(accessResult(identity.verdict, status.enabled), resultReason(identity, status));
}

function createIdentity(observation) {
	const nameInput = E('input', {
		'class': 'cbi-input-text',
		'value': observation.name || observation.value
	});

	ui.showModal(_('Manage as new identity'), [
		E('p', {}, [ _('Create a persistent identity for this detected MAC address. The detected name is only a suggestion.') ]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, [ _('Name') ]),
			E('div', { 'class': 'cbi-value-field' }, [ nameInput ])
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, [ _('Recognized MAC address') ]),
			E('div', { 'class': 'cbi-value-field' }, [ E('code', {}, [ observation.value ]) ])
		]),
		E('p', { 'class': 'alert-message notice' }, [ _('Apply policy: Never. Creating this identity will not change its Internet access until you edit it.') ]),
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
			' ',
			E('button', {
				'class': 'btn cbi-button-positive important',
				'click': function(ev) {
					const name = nameInput.value.trim();
					if (!name) {
						nameInput.focus();
						return;
					}
					ev.currentTarget.disabled = true;
					ev.currentTarget.classList.add('spinning');
					const identityId = randomIdentityId();
					uci.add('client_access', 'identity', identityId);
					uci.set('client_access', identityId, 'name', name);
					uci.set('client_access', identityId, 'subject_id', randomSubjectId());
					uci.set('client_access', identityId, 'activation', 'inactive');
					const binding = uci.add('client_access', 'binding');
					uci.set('client_access', binding, 'identity', identityId);
					uci.set('client_access', binding, 'type', 'mac');
					uci.set('client_access', binding, 'value', observation.value);
					ui.hideModal();
					return saveChanges();
				}
			}, [ _('Create identity') ])
		])
	]);
}

function addToIdentity(observation, identities, inventoryById, status) {
	const identitySelect = E('select', { 'class': 'cbi-input-select' }, identities.map(function(identity) {
		return E('option', { 'value': identity['.name'] }, [ identity.name || identity['.name'] ]);
	}));
	const outcome = E('p', { 'class': 'alert-message notice' });
	const updateOutcome = function() {
		const identity = inventoryById[identitySelect.value];
		outcome.textContent = identityOutcomeSentence(identity, status);
	};
	identitySelect.addEventListener('change', updateOutcome);
	updateOutcome();

	ui.showModal(_('Add to existing identity'), [
		E('p', {}, [ _('This detected MAC address will be recognized as the selected identity.') ]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, [ _('Detected MAC address') ]),
			E('div', { 'class': 'cbi-value-field' }, [ E('code', {}, [ observation.value ]) ])
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, [ _('Identity') ]),
			E('div', { 'class': 'cbi-value-field' }, [ identitySelect ])
		]),
		outcome,
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
			' ',
			E('button', {
				'class': 'btn cbi-button-positive important',
				'click': function(ev) {
					ev.currentTarget.disabled = true;
					ev.currentTarget.classList.add('spinning');
					const binding = uci.add('client_access', 'binding');
					uci.set('client_access', binding, 'identity', identitySelect.value);
					uci.set('client_access', binding, 'type', 'mac');
					uci.set('client_access', binding, 'value', observation.value);
					ui.hideModal();
					return saveChanges();
				}
			}, [ _('Add MAC address') ])
		])
	]);
}

function unknownClientsSection(observationInventory, configuredIdentities, inventoryById, status) {
	const observations = (observationInventory.observations || []).filter(function(observation) {
		return !observation.bound;
	});
	const rows = observations.map(function(observation) {
		const actions = [
			E('button', {
				'class': 'btn cbi-button-add',
				'click': function() { createIdentity(observation); }
			}, [ _('Manage as new identity') ])
		];
		if (configuredIdentities.length) {
			actions.push(' ');
			actions.push(E('button', {
				'class': 'btn cbi-button-action',
				'click': function() {
					addToIdentity(observation, configuredIdentities, inventoryById, status);
				}
			}, [ _('Add to existing identity') ]));
		}
		return E('tr', { 'class': 'tr cbi-section-table-row' }, [
			E('td', { 'class': 'td' }, [ observation.name || _('Unknown client') ]),
			E('td', { 'class': 'td' }, [ asList(observation.ipaddrs).concat(asList(observation.ip6addrs)).join(', ') || '-' ]),
			E('td', { 'class': 'td' }, [ E('code', {}, [ observation.value ]) ]),
			E('td', { 'class': 'td' }, [ E('div', {}, actions) ])
		]);
	});

	return E('div', { 'class': 'cbi-section' }, [
		E('div', { 'class': 'cbi-section-descr' }, [
			_('These LAN clients were detected but are not recognized as an identity. They follow the global default and do not participate in scheduling.')
		]),
		observationInventory.error ? E('p', { 'class': 'alert-message error' }, [ observationInventory.error ]) : '',
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'btn', 'click': function() { window.location.reload(); } }, [ _('Refresh') ])
		]),
		E('table', { 'class': 'table cbi-section-table' }, [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, [ _('Detected name') ]),
				E('th', { 'class': 'th' }, [ _('IP addresses') ]),
				E('th', { 'class': 'th' }, [ _('MAC address') ]),
				E('th', { 'class': 'th' }, [ _('Action') ])
			]),
			rows.length ? rows : E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td', 'colspan': 4 }, [ _('No unknown clients detected') ])
			])
		])
	]);
}

function clientViews(managedSection, unknownSection) {
	const managedPane = E('div', {}, [ managedSection ]);
	const unknownPane = E('div', { 'style': 'display:none' }, [ unknownSection ]);
	const managedButton = E('button', { 'class': 'btn cbi-button-action important' }, [ _('Managed') ]);
	const unknownButton = E('button', { 'class': 'btn' }, [ _('Unknown') ]);

	function selectPane(showUnknown) {
		managedPane.style.display = showUnknown ? 'none' : '';
		unknownPane.style.display = showUnknown ? '' : 'none';
		managedButton.className = showUnknown ? 'btn' : 'btn cbi-button-action important';
		unknownButton.className = showUnknown ? 'btn cbi-button-action important' : 'btn';
	}
	managedButton.addEventListener('click', function() { selectPane(false); });
	unknownButton.addEventListener('click', function() { selectPane(true); });

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, [ _('Clients') ]),
		E('div', { 'style': 'margin-bottom:1em' }, [ managedButton, ' ', unknownButton ]),
		managedPane,
		unknownPane
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(callStatus(), { running: false, errors: [ _('Service is unavailable') ] }),
			L.resolveDefault(callIdentities(), { identities: [] }),
			L.resolveDefault(callObservations(), { observations: [] }),
			uci.load('client_access')
		]);
	},

	render: function(data) {
		const status = data[0];
		const identityInventory = data[1];
		const observationInventory = data[2];
		const inventoryById = identityById(identityInventory);
		const configuredIdentities = uci.sections('client_access', 'identity');
		const initialAccessPolicy = accessPolicyFromUci();
		let m, s, o;

		m = new form.Map('client_access', _('Client Access'),
			_('Choose one Internet access policy, then choose when it applies to each identity.'));

		s = m.section(form.NamedSection, 'main', 'client_access', _('Internet access policy'));
		s.anonymous = true;
		s.addremove = false;
		s.tab('policy', _('Policy'));
		s.tab('advanced', _('Advanced settings'));

		o = s.taboption('policy', form.ListValue, '_access_policy', _('Internet access policy'));
		o.value('off', _('Off'));
		o.value('block_selected', _('Block selected clients'));
		o.value('allow_selected', _('Allow selected clients'));
		o.default = 'off';
		o.rmempty = false;
		o.description = _('Off allows every client. Block selected clients allows everyone else. Allow selected clients blocks everyone else, including unknown clients.');
		o.cfgvalue = accessPolicyFromUci;
		o.write = function(sectionId, value) {
			uci.set('client_access', sectionId, 'enabled', value === 'off' ? '0' : '1');
			if (value !== 'off')
				uci.set('client_access', sectionId, 'mode', value === 'allow_selected' ? 'whitelist' : 'blacklist');
		};
		o.remove = function() {};
		o.onchange = function(ev, sectionId, value) {
			if ((initialAccessPolicy === 'block_selected' && value === 'allow_selected') ||
			    (initialAccessPolicy === 'allow_selected' && value === 'block_selected')) {
				ui.addNotification(null, E('p', {}, [
					_('This reverses the result for both selected and unselected clients. Unknown clients follow the unselected result.')
				]), 'warning');
			}
		};

		o = s.taboption('advanced', form.ListValue, 'deny_action', _('When access is blocked'));
		o.value('reject', _('Reject the connection'));
		o.value('drop', _('Silently drop traffic'));
		o.default = 'reject';
		o.rmempty = false;

		o = s.taboption('advanced', form.DynamicList, 'source_zone', _('LAN firewall zones'));
		o.default = [ 'lan' ];
		o.rmempty = false;
		o.datatype = 'uciname';

		o = s.taboption('advanced', form.DynamicList, 'destination_zone', _('Internet firewall zones'));
		o.default = [ 'wan' ];
		o.rmempty = false;
		o.datatype = 'uciname';

		s = m.section(form.GridSection, 'identity', _('Managed identities'));
		s.anonymous = true;
		s.addremove = true;
		s.sortable = true;
		s.nodescriptions = true;
		s.addbtntitle = _('Add identity');
		s.sectiontitle = function(sectionId) {
			return uci.get('client_access', sectionId, 'name') || _('Unnamed identity');
		};
		const addIdentity = s.handleAdd;
		s.handleAdd = function(ev) {
			const identityId = randomIdentityId();
			const result = addIdentity.call(this, ev, identityId);
			uci.set('client_access', identityId, 'subject_id', randomSubjectId());
			return result;
		};
		const removeIdentity = s.handleRemove;
		s.handleRemove = function(sectionId, ev) {
			bindingsForIdentity(sectionId).forEach(function(binding) {
				uci.remove('client_access', binding['.name']);
			});
			return removeIdentity.call(this, sectionId, ev);
		};
		s.tab('identity', _('Identity'));
		s.tab('schedule', _('Weekly schedule'));

		o = s.option(form.DummyValue, '_current_result', _('Current result'));
		o.modalonly = false;
		o.cfgvalue = function(sectionId) {
			const identity = inventoryById[sectionId];
			return identity ? accessResult(identity.verdict, status.enabled) : _('Pending');
		};

		o = s.option(form.DummyValue, '_apply_policy_summary', _('Apply policy'));
		o.modalonly = false;
		o.cfgvalue = function(sectionId) {
			return applyPolicyLabel(uci.get('client_access', sectionId, 'activation'));
		};

		o = s.option(form.DummyValue, '_next_change', _('Next change'));
		o.modalonly = false;
		o.cfgvalue = function(sectionId) {
			const identity = inventoryById[sectionId];
			return identity ? formatTime(identity.next_transition) : _('Pending');
		};

		o = s.option(form.DummyValue, '_mac_count', _('MAC addresses'));
		o.modalonly = false;
		o.cfgvalue = function(sectionId) { return String(recognizedMacs(sectionId).length); };

		o = s.taboption('identity', form.Value, 'name', _('Name'));
		o.rmempty = false;

		o = s.taboption('identity', form.ListValue, 'activation', _('Apply policy'));
		o.value('inactive', _('Never'));
		o.value('always_active', _('Always'));
		o.value('active_during', _('On schedule'));
		o.default = 'inactive';
		o.rmempty = false;
		o.description = _('Choose when the selected global policy applies to this identity.');
		o.validate = function(sectionId, value) {
			if (value !== 'active_during')
				return true;
			const section = this.section;
			const hasPeriod = DAYS.some(function(day) {
				return asList(section.formvalue(sectionId, '_schedule_' + day.id)).some(function(period) {
					return String(period || '').trim().length > 0;
				});
			});
			return hasPeriod ? true : _('Add at least one weekly period when Apply policy is On schedule.');
		};

		o = s.taboption('identity', form.DummyValue, '_derived_result', _('Current result'));
		o.cfgvalue = function(sectionId) {
			const identity = inventoryById[sectionId];
			return identity
				? '%s — %s'.format(accessResult(identity.verdict, status.enabled), resultReason(identity, status))
				: _('Apply the pending configuration to calculate the current result.');
		};

		o = s.taboption('identity', form.DynamicList, '_recognized_macs', _('Recognized MAC addresses'));
		o.datatype = 'macaddr';
		o.placeholder = '02:00:00:00:00:01';
		o.rmempty = true;
		o.cfgvalue = recognizedMacs;
		o.validate = validateUniqueMac;
		o.write = writeRecognizedMacs;
		o.remove = function(sectionId) { writeRecognizedMacs(sectionId, []); };

		o = s.taboption('identity', form.DummyValue, '_detected_devices', _('Detected LAN devices'));
		o.rawhtml = true;
		o.cfgvalue = function(sectionId) { return detectedDevicesHtml(inventoryById[sectionId]); };
		o.description = _('Names and IP addresses are best-effort discovery information. A recognized MAC can remain configured when it is not currently detected.');

		DAYS.forEach(function(day) {
			o = s.taboption('schedule', form.DynamicList, '_schedule_' + day.id, day.label);
			o.depends('activation', 'active_during');
			o.retain = true;
			o.placeholder = '08:00-12:00';
			o.rmempty = true;
			o.cfgvalue = function(sectionId) { return parseScheduleMap(sectionId)[day.id]; };
			o.validate = validatePeriod;
			o.write = function(sectionId, value) { writeScheduleDay(sectionId, day.id, value); };
			o.remove = function(sectionId) { writeScheduleDay(sectionId, day.id, []); };
			o.description = day.id === 'mon'
				? _('Add one or more periods. Use all-day for the whole day. A period such as 22:00-07:00 ends the next day.')
				: null;
		});

		return m.render().then(function(formNode) {
			const managedSection = formNode.querySelector('#cbi-client_access-identity');
			if (managedSection) {
				managedSection.parentNode.removeChild(managedSection);
				formNode.appendChild(clientViews(managedSection,
					unknownClientsSection(observationInventory, configuredIdentities, inventoryById, status)));
			}
			return E([], [ statusPanel(status), formNode ]);
		});
	}
});
