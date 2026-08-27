'use strict';
'require view';
'require rpc';
'require uci';
'require ui';

const callDevices = rpc.declare({
	object: 'client_access',
	method: 'devices',
	expect: { '': { devices: [] } }
});

function addPolicy(device, ev) {
	ev.currentTarget.disabled = true;
	ev.currentTarget.classList.add('spinning');

	const section = uci.add('client_access', 'device');
	uci.set('client_access', section, 'name', device.name || device.mac);
	uci.set('client_access', section, 'enabled', '1');
	uci.set('client_access', section, 'mac', [ device.mac ]);
	uci.set('client_access', section, 'policy', 'inherit');

	return uci.save()
		.then(L.bind(ui.changes.init, ui.changes))
		.then(L.bind(ui.changes.displayChanges, ui.changes));
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(callDevices(), { devices: [] }),
			uci.load('client_access')
		]);
	},

	render: function(data) {
		const inventory = data[0];
		const devices = inventory.devices || [];
		const rows = devices.map(function(device) {
			return [
				device.name || _('Unknown'),
				(device.ipaddrs || []).concat(device.ip6addrs || []).join(', ') || '-',
				E('code', {}, [ device.mac ]),
				device.configured ? device.policy : _('Not configured'),
				device.verdict === 'deny' ? _('Deny') : _('Allow'),
				device.configured ? '-' : E('button', {
					'class': 'btn cbi-button-add',
					'click': function(ev) { return addPolicy(device, ev); }
				}, [ _('Add policy') ])
			];
		});

		return E([], [
			E('h2', {}, [ _('Detected LAN devices') ]),
			inventory.error ? E('p', { 'class': 'alert-message error' }, [ inventory.error ]) : '',
			E('div', { 'class': 'cbi-map-descr' }, [
				_('Names and addresses are aggregated from DHCP, neighbour and host-hint data and may include recently seen or statically configured hosts.')
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': function() { window.location.reload(); } }, [ _('Refresh') ])
			]),
			E('div', { 'class': 'table cbi-section-table' }, [
				E('div', { 'class': 'tr table-titles' }, [
					E('div', { 'class': 'th' }, [ _('Name') ]),
					E('div', { 'class': 'th' }, [ _('IP addresses') ]),
					E('div', { 'class': 'th' }, [ _('MAC') ]),
					E('div', { 'class': 'th' }, [ _('Policy') ]),
					E('div', { 'class': 'th' }, [ _('Current result') ]),
					E('div', { 'class': 'th' }, [ _('Action') ])
				]),
				rows.length ? rows.map(function(row) {
					return E('div', { 'class': 'tr cbi-section-table-row' }, row.map(function(cell) {
						return E('div', { 'class': 'td' }, [ cell ]);
					}));
				}) : E('div', { 'class': 'tr' }, [ E('div', { 'class': 'td' }, [ _('No devices found') ]) ])
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
