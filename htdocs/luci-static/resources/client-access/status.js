'use strict';
'require ui';
'require client-access.rpc as caRpc';
'require client-access.common as common';

function accessPanel(status) {
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
					E('div', { 'class': 'td left' }, [ common.formatTime(status.next_transition) ])
				])
			]),
			errors.length ? E('p', { 'class': 'alert-message error' }, [ errors.join('; ') ]) : '',
			warnings.length ? E('p', { 'class': 'alert-message warning' }, [ warnings.join('; ') ]) : '',
			E('button', {
				'class': 'btn cbi-button-action',
				'click': ui.createHandlerFn(null, function() {
					return caRpc.reconcile('luci-manual').then(function() { window.location.reload(); });
				})
			}, [ _('Reapply policy') ])
		])
	]);
}

function runtimeStatus(appStatus) {
	try {
		return JSON.parse(appStatus.runtime_status_json || '{}');
	}
	catch (error) {
		return {};
	}
}

function applicationPanel(status) {
	const appStatus = status.app_filter || {};
	const runtime = runtimeStatus(appStatus);
	const resourceLimits = appStatus.resource_limits || {};
	const disabled = !appStatus.requested_enabled;
	const healthy = appStatus.enabled && !appStatus.degraded;
	const exact = runtime.flows_classified_exact || 0;
	const category = runtime.flows_classified_category || 0;
	const unclassified = runtime.flows_unclassified || 0;
	const terminal = exact + category + unclassified;
	const coverage = terminal ? Math.round(100 * (exact + category) / terminal) : 0;

	return E('div', { 'class': 'cbi-section' }, [
		E('div', { 'class': disabled || healthy ? 'alert-message success' : 'alert-message warning' }, [
			disabled
				? _('Application filtering is off. The nftables Internet access policy remains independent.')
				: (healthy
					? _('Application filtering is active for managed identities.')
					: _('Application filtering is degraded; see diagnostics before relying on its rules.'))
		]),
		E('details', {}, [
			E('summary', {}, [ _('Application diagnostics') ]),
			E('p', {}, [
				_('Packets still pass the application layer while a new flow is pending. One early packet is inspected, so a denied application has a small initial leakage window.')
			]),
			E('div', { 'class': 'table' }, [
				E('div', { 'class': 'tr' }, [
					E('div', { 'class': 'td left' }, [ _('Backend') ]),
					E('div', { 'class': 'td left' }, [ appStatus.backend_mode || 'V3_NFT_ONLY' ]),
					E('div', { 'class': 'td left' }, [ _('Classifier coverage') ]),
					E('div', { 'class': 'td left' }, [ terminal ? coverage + '%' : _('No terminal flows yet') ])
				]),
				E('div', { 'class': 'tr' }, [
					E('div', { 'class': 'td left' }, [ _('Exact / category') ]),
					E('div', { 'class': 'td left' }, [ '%s / %s'.format(exact, category) ]),
					E('div', { 'class': 'td left' }, [ _('Unclassified / load shed') ]),
					E('div', { 'class': 'td left' }, [ '%s / %s'.format(unclassified, runtime.flows_unclassified_load_shed || 0) ])
				]),
				E('div', { 'class': 'tr' }, [
					E('div', { 'class': 'td left' }, [ _('Policy / classifier generation') ]),
					E('div', { 'class': 'td left' }, [ '%s / %s'.format(appStatus.app_policy_generation || 0, appStatus.classifier_generation || 0) ]),
					E('div', { 'class': 'td left' }, [ _('Flow map') ]),
					E('div', { 'class': 'td left' }, [ '%s / %s'.format(runtime.flow_map_entries || 0, runtime.flow_capacity || 0) ])
				]),
				E('div', { 'class': 'tr' }, [
					E('div', { 'class': 'td left' }, [ _('DNS correlation') ]),
					E('div', { 'class': 'td left' }, [ appStatus.dns_subscribed ? _('Subscribed') : _('Unavailable') ]),
					E('div', { 'class': 'td left' }, [ _('DNS events accepted / dropped') ]),
					E('div', { 'class': 'td left' }, [ '%s / %s'.format(appStatus.dns_events_accepted || 0, appStatus.dns_events_dropped || 0) ])
				]),
				E('div', { 'class': 'tr' }, [
					E('div', { 'class': 'td left' }, [ _('Profiles / normalized evidence') ]),
					E('div', { 'class': 'td left' }, [ '%s / %s'.format(appStatus.profile_count || 0, appStatus.classification_ir_entry_count || 0) ]),
					E('div', { 'class': 'td left' }, [ _('Semantic / runtime entries') ]),
					E('div', { 'class': 'td left' }, [ '%s / %s'.format(appStatus.semantic_entry_count || 0, appStatus.runtime_projection_entry_count || 0) ])
				]),
				E('div', { 'class': 'tr' }, [
					E('div', { 'class': 'td left' }, [ _('Signature table estimate') ]),
					E('div', { 'class': 'td left' }, [ '%s / %s B'.format(appStatus.classifier_signature_memory_bytes || 0, resourceLimits.signature_table_memory_limit || 0) ]),
					E('div', { 'class': 'td left' }, [ _('Backend schema') ]),
					E('div', { 'class': 'td left' }, [ String(runtime.bpf_schema_version || _('Unavailable')) ])
				])
			]),
			(appStatus.errors || []).length
				? E('p', { 'class': 'alert-message error' }, [ appStatus.errors.join('; ') ]) : '',
			(appStatus.warnings || []).length
				? E('p', { 'class': 'alert-message warning' }, [ appStatus.warnings.join('; ') ]) : ''
		])
	]);
}

return { accessPanel: accessPanel, applicationPanel: applicationPanel };
