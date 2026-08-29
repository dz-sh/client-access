'use strict';
'require ui';
'require client-access.rpc as caRpc';
'require client-access.common as common';

function approvalError(result) {
	const errors = result && Array.isArray(result.errors) ? result.errors : [];
	return errors.length ? errors.join('; ') : _('The temporary approval operation failed.');
}

function runApproval(scope, identityId, classId, duration) {
	return caRpc.approve(scope, identityId, classId == null ? 0 : classId,
		duration).then(function(result) {
		if (!result || result.ok !== true) {
			ui.addNotification(null, E('p', {}, [ approvalError(result) ]), 'error');
			return;
		}
		window.location.reload();
	});
}

function runRevocation(leaseId) {
	return caRpc.revokeApproval(leaseId).then(function(result) {
		if (!result || result.ok !== true) {
			ui.addNotification(null, E('p', {}, [ approvalError(result) ]), 'error');
			return;
		}
		window.location.reload();
	});
}

function actionButton(label, handler, className) {
	return E('button', {
		'type': 'button', 'class': className || 'btn cbi-button-action',
		'click': ui.createHandlerFn(null, handler)
	}, [ label ]);
}

function actions(scope, identityId, classId, target, inventory) {
	if (!target)
		return E('span', {}, [ _('Apply pending configuration before creating an approval.') ]);
	const available = scope === 'access'
		? inventory.access_available : inventory.application_available;
	if (!available)
		return E('span', {}, [ scope === 'access'
			? _('Enable and apply Internet access control before creating an access approval.')
			: _('Enable and apply application filtering before creating an application approval.') ]);
	if (target.lease_id) {
		const lease = (inventory.approvals || []).find(function(item) {
			return item.id === target.lease_id;
		});
		return E('div', { 'class': 'alert-message notice' }, [
			E('strong', {}, [ _('Temporary approval active') ]), E('br'),
			_('Base: %s · Effective: %s').format(
				target.base_verdict === 'deny' ? _('Blocked') : _('Allowed'),
				target.effective_verdict === 'deny' ? _('Blocked') : _('Allowed')),
			E('br'),
			_('Expires: %s (%s remaining)').format(common.formatTime(target.lease_expires_at),
				common.formatRemaining(lease ? lease.remaining_seconds : 0)),
			E('div', { 'style': 'margin-top:.6em' }, [
				actionButton(_('Set 1 hour from now'), function() {
					return runApproval(scope, identityId, classId, 'one_hour');
				}), ' ',
				actionButton(_('Set until today ends'), function() {
					return runApproval(scope, identityId, classId, 'today');
				}), ' ',
				actionButton(_('Revoke now'), function() {
					return runRevocation(target.lease_id);
				}, 'btn cbi-button-negative')
			])
		]);
	}
	if (target.base_verdict !== 'deny')
		return E('span', {}, [
			_('The base policy already allows this target, so a temporary approval would not change access.')
		]);
	if (!inventory.clock_valid)
		return E('span', {}, [ _('The router clock is not valid, so temporary approval is unavailable.') ]);
	return E('div', {}, [
		E('p', {}, [
			_('Base: Blocked · Temporary approval changes only the runtime result and does not edit the saved rule.')
		]),
		actionButton(_('Approve for 1 hour'), function() {
			return runApproval(scope, identityId, classId, 'one_hour');
		}), ' ',
		actionButton(_('Approve today'), function() {
			return runApproval(scope, identityId, classId, 'today');
		})
	]);
}

function panel(inventory) {
	const approvals = inventory.approvals || [];
	const errors = inventory.errors || [];
	const accessTargets = inventory.access_targets || [];
	const applicationTargets = inventory.application_targets || [];
	const transitions = inventory.latest_transitions || [];
	const rows = approvals.map(function(lease) {
		const target = lease.scope === 'access'
			? accessTargets.find(function(item) { return item.identity_id === lease.identity_id; })
			: applicationTargets.find(function(item) {
				return item.identity_id === lease.identity_id &&
					Number(item.class_id) === Number(lease.class_id);
			});
		const identityName = target && target.identity_name
			? target.identity_name : lease.identity_id;
		const scopeLabel = lease.scope === 'access' ? _('Internet access')
			: _('Application: %s').format(target && target.class_name
				? target.class_name : String(lease.class_id));
		return E('div', { 'class': 'tr' }, [
			E('div', { 'class': 'td left' }, [ identityName ]),
			E('div', { 'class': 'td left' }, [ scopeLabel ]),
			E('div', { 'class': 'td left' }, [ common.formatTime(lease.expires_at) ]),
			E('div', { 'class': 'td left' }, [ common.formatRemaining(lease.remaining_seconds) ]),
			E('div', { 'class': 'td left' }, [ actionButton(_('Revoke'),
				function() { return runRevocation(lease.id); }, 'btn cbi-button-negative') ])
		]);
	});
	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, [ _('Temporary approvals') ]),
		E('p', {}, [
			_('These runtime-only ALLOW overrides are separate from saved policies. They disappear at expiry and after a router reboot.')
		]),
		approvals.length ? E('div', { 'class': 'table' }, [
			E('div', { 'class': 'tr table-titles' }, [
				E('div', { 'class': 'th left' }, [ _('Identity') ]),
				E('div', { 'class': 'th left' }, [ _('Scope') ]),
				E('div', { 'class': 'th left' }, [ _('Expires') ]),
				E('div', { 'class': 'th left' }, [ _('Remaining') ]),
				E('div', { 'class': 'th left' }, [ _('Action') ])
			]), ...rows
		]) : E('p', { 'class': 'alert-message notice' }, [ _('No temporary approvals are active.') ]),
		inventory.journal_available === false
			? E('p', { 'class': 'alert-message warning' }, [
				_('Volatile approval state is not synchronized; new approvals must not be trusted until the service reports recovery.')
			]) : '',
		errors.length ? E('p', { 'class': 'alert-message error' }, [ errors.join('; ') ]) : '',
		transitions.length ? E('details', {}, [
			E('summary', {}, [ _('Latest authorization transition') ]),
			E('p', {}, [ transitions.map(function(item) {
				return '%s: %s → %s (%s)'.format(item.identity_id,
					String(item.old_verdict).toUpperCase(),
					String(item.new_verdict).toUpperCase(), item.reason);
			}).join('; ') ])
		]) : ''
	]);
}

return { actions: actions, panel: panel };
