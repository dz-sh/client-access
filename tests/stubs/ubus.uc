import * as uloop_stub from 'uloop';

export function connect() {
	return {
		subscriber: function() {
			return { subscribe: function() { return true; } };
		},
		publish: function(name, service) {
			uloop_stub.set_service(service);
			return true;
		},
		call: function() { return {}; },
		disconnect: function() {},
	};
}
