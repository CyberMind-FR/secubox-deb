'use strict';
async function callStatus(params) {
    return sbxFetch('/api/v1/vhost/status', params, 'GET');
}

async function callListVHosts(params) {
    return sbxFetch('/api/v1/vhost/list_vhosts', params, 'GET');
}

async function callGetVHost(params) {
    return sbxFetch('/api/v1/vhost/get_vhost', params, 'GET');
}

async function callAddVHost(params) {
    return sbxFetch('/api/v1/vhost/add_vhost', params, 'POST');
}

async function callUpdateVHost(params) {
    return sbxFetch('/api/v1/vhost/update_vhost', params, 'GET');
}

async function callDeleteVHost(params) {
    return sbxFetch('/api/v1/vhost/delete_vhost', params, 'POST');
}

async function callTestBackend(params) {
    return sbxFetch('/api/v1/vhost/test_backend', params, 'GET');
}

async function callRequestCert(params) {
    return sbxFetch('/api/v1/vhost/request_cert', params, 'GET');
}

async function callListCerts(params) {
    return sbxFetch('/api/v1/vhost/list_certs', params, 'GET');
}

async function callReloadNginx(params) {
    return sbxFetch('/api/v1/vhost/reload_nginx', params, 'GET');
}

async function callGetAccessLogs(params) {
    return sbxFetch('/api/v1/vhost/get_access_logs', params, 'GET');
}

return baseclass.extend({
	getStatus: callStatus,
	listVHosts: callListVHosts,
	getVHost: callGetVHost,
	addVHost: callAddVHost,
	updateVHost: callUpdateVHost,
	deleteVHost: callDeleteVHost,
	testBackend: callTestBackend,
	requestCert: callRequestCert,
	listCerts: callListCerts,
	reloadNginx: callReloadNginx,
	getAccessLogs: callGetAccessLogs,

	// Wrapper for template-based VHost creation
	createVHost: function(config) {
		var domain = config.domain;
		var backend = config.backend || config.upstream;
		var tlsMode = config.tls_mode || (config.requires_ssl ? 'acme' : 'off');
		var auth = config.auth || false;
		var authUser = config.auth_user || null;
		var authPass = config.auth_pass || null;
		var websocket = config.websocket_enabled || config.websocket_support || false;
		var enabled = config.enabled !== false;
		var certPath = config.cert_path || null;
		var keyPath = config.key_path || null;
		var sectionId = config.section_id || config.id || null;

		return callAddVHost(
			domain,
			backend,
			tlsMode,
			auth,
			authUser,
			authPass,
			websocket,
			enabled,
			certPath,
			keyPath,
			sectionId
		);
	}
});
