'use strict';
'require view';
'require rpc';
'require uci';
'require ui';

const callObservations = rpc.declare({
	object: 'client_access',
	method: 'observations',
	expect: { '': { observations: [] } }
});

const callIdentities = rpc.declare({
	object: 'client_access',
	method: 'identities',
	expect: { '': { identities: [] } }
});

function saveChanges() {
	return uci.save()
		.then(L.bind(ui.changes.init, ui.changes))
		.then(L.bind(ui.changes.displayChanges, ui.changes));
}

function randomIdentityId() {
	const bytes = new Uint8Array(12);
	window.crypto.getRandomValues(bytes);
	return 'identity_' + Array.from(bytes, function(value) {
		return value.toString(16).padStart(2, '0');
	}).join('');
}

function modeLabels(mode) {
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

function parseSchedules(value) {
	return String(value || '').split(/\n/).map(function(line) {
		return line.trim();
	}).filter(function(line) { return line.length > 0; });
}

function createIdentity(observation, mode) {
	const labels = modeLabels(mode);
	const nameInput = E('input', {
		'class': 'cbi-input-text',
		'value': observation.name || observation.value
	});
	const activationSelect = E('select', { 'class': 'cbi-input-select' }, [
		E('option', { 'value': 'inactive' }, [ labels.inactive ]),
		E('option', { 'value': 'always_active' }, [ labels.always_active ]),
		E('option', { 'value': 'active_during' }, [ labels.active_during ])
	]);
	const scheduleInput = E('textarea', {
		'class': 'cbi-input-textarea',
		'placeholder': 'mon,tue,wed,thu,fri@08:00-21:30\nsat,sun@09:00-23:00',
		'rows': 4
	});

	ui.showModal(_('Create identity'), [
		E('p', {}, [ _('Create a persistent identity and bind the observed MAC to it. The observed name is only a suggestion.') ]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, [ _('Display name') ]),
			E('div', { 'class': 'cbi-value-field' }, [ nameInput ])
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, [ _('MAC binding') ]),
			E('div', { 'class': 'cbi-value-field' }, [ E('code', {}, [ observation.value ]) ])
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, [ _('Activation') ]),
			E('div', { 'class': 'cbi-value-field' }, [ activationSelect ])
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, [ _('Active schedule') ]),
			E('div', { 'class': 'cbi-value-field' }, [
				scheduleInput,
				E('div', { 'class': 'cbi-value-description' }, [ _('Required for active-during. Enter one DAYS@HH:MM-HH:MM window per line; windows are combined as a union.') ])
			])
		]),
		E('div', { 'class': 'right' }, [
			E('button', {
				'class': 'btn',
				'click': ui.hideModal
			}, [ _('Cancel') ]),
			' ',
			E('button', {
				'class': 'btn cbi-button-positive important',
				'click': function(ev) {
					const name = nameInput.value.trim();
					const activation = activationSelect.value;
					const schedules = parseSchedules(scheduleInput.value);
					if (!name) {
						nameInput.focus();
						return;
					}
					if (activation === 'active_during' && schedules.length === 0) {
						scheduleInput.focus();
						return;
					}

					ev.currentTarget.disabled = true;
					ev.currentTarget.classList.add('spinning');
					const identityId = randomIdentityId();
					uci.add('client_access', 'identity', identityId);
					uci.set('client_access', identityId, 'name', name);
					uci.set('client_access', identityId, 'activation', activation);
					if (activation === 'active_during')
						uci.set('client_access', identityId, 'schedule', schedules);
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

function bindExisting(observation, identities) {
	const identitySelect = E('select', { 'class': 'cbi-input-select' }, identities.map(function(identity) {
		return E('option', { 'value': identity.id }, [ identity.name || identity.id ]);
	}));

	ui.showModal(_('Bind to existing identity'), [
		E('p', {}, [ _('The MAC binding will immediately follow the selected identity activation after the pending configuration is applied.') ]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, [ _('Observed MAC') ]),
			E('div', { 'class': 'cbi-value-field' }, [ E('code', {}, [ observation.value ]) ])
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, [ _('Identity') ]),
			E('div', { 'class': 'cbi-value-field' }, [ identitySelect ])
		]),
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
			}, [ _('Bind') ])
		])
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(callObservations(), { observations: [] }),
			L.resolveDefault(callIdentities(), { identities: [] }),
			uci.load('client_access')
		]);
	},

	render: function(data) {
		const inventory = data[0];
		const identityInventory = data[1];
		const identities = identityInventory.identities || [];
		const observations = (inventory.observations || []).filter(function(observation) {
			return !observation.bound;
		});
		const rows = observations.map(function(observation) {
			const actions = [
				E('button', {
					'class': 'btn cbi-button-add',
					'click': function() { createIdentity(observation, identityInventory.mode); }
				}, [ _('Create identity') ])
			];
			if (identities.length) {
				actions.push(' ');
				actions.push(E('button', {
					'class': 'btn cbi-button-action',
					'click': function() { bindExisting(observation, identities); }
				}, [ _('Bind existing') ]));
			}
			return [
				observation.name || _('Unknown'),
				(observation.ipaddrs || []).concat(observation.ip6addrs || []).join(', ') || '-',
				E('code', {}, [ observation.value ]),
				E('div', {}, actions)
			];
		});

		return E([], [
			E('h2', {}, [ _('Unknown clients') ]),
			inventory.error ? E('p', { 'class': 'alert-message error' }, [ inventory.error ]) : '',
			identityInventory.error ? E('p', { 'class': 'alert-message error' }, [ identityInventory.error ]) : '',
			E('div', { 'class': 'cbi-map-descr' }, [
				_('Unknown clients are temporary observations without a configured binding. They follow the global default rule and do not participate in scheduling. Private MAC addresses are never merged automatically.')
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': function() { window.location.reload(); } }, [ _('Refresh') ])
			]),
			E('div', { 'class': 'table cbi-section-table' }, [
				E('div', { 'class': 'tr table-titles' }, [
					E('div', { 'class': 'th' }, [ _('Observed name') ]),
					E('div', { 'class': 'th' }, [ _('IP addresses') ]),
					E('div', { 'class': 'th' }, [ _('MAC') ]),
					E('div', { 'class': 'th' }, [ _('Action') ])
				]),
				rows.length ? rows.map(function(row) {
					return E('div', { 'class': 'tr cbi-section-table-row' }, row.map(function(cell) {
						return E('div', { 'class': 'td' }, [ cell ]);
					}));
				}) : E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td' }, [ _('No unknown clients found') ]) ])
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
