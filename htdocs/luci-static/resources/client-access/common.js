'use strict';

function asList(value) {
	if (value == null)
		return [];
	return Array.isArray(value) ? value : [ value ];
}

function formatTime(epoch) {
	return epoch ? new Date(epoch * 1000).toLocaleString() : _('No scheduled change');
}

function formatRemaining(seconds) {
	seconds = Math.max(0, Number(seconds) || 0);
	if (seconds < 60)
		return _('%d seconds').format(Math.ceil(seconds));
	if (seconds < 3600)
		return _('%d minutes').format(Math.ceil(seconds / 60));
	const hours = Math.floor(seconds / 3600);
	const minutes = Math.ceil((seconds % 3600) / 60);
	return minutes ? _('%d hours %d minutes').format(hours, minutes)
		: _('%d hours').format(hours);
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

return {
	asList: asList,
	formatTime: formatTime,
	formatRemaining: formatRemaining,
	accessResult: accessResult,
	applyPolicyLabel: applyPolicyLabel
};
