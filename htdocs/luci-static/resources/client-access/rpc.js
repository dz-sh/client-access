'use strict';
'require rpc';

return {
	status: rpc.declare({ object: 'client_access', method: 'status', expect: { '': {} } }),
	identities: rpc.declare({
		object: 'client_access', method: 'identities', expect: { '': { identities: [] } }
	}),
	observations: rpc.declare({
		object: 'client_access', method: 'observations', expect: { '': { observations: [] } }
	}),
	approvals: rpc.declare({
		object: 'client_access', method: 'approvals',
		expect: { '': { approvals: [], access_targets: [], application_targets: [] } }
	}),
	approve: rpc.declare({
		object: 'client_access', method: 'approve',
		params: [ 'scope', 'identity_id', 'class_id', 'duration' ], expect: { '': {} }
	}),
	revokeApproval: rpc.declare({
		object: 'client_access', method: 'revoke_approval',
		params: [ 'lease_id' ], expect: { '': {} }
	}),
	reconcile: rpc.declare({
		object: 'client_access', method: 'reconcile', params: [ 'reason' ], expect: { '': {} }
	})
};
