'use strict';
// Status and overview
async function callStatus(params) {
    return sbxFetch('/api/v1/auth/status', params, 'GET');
}

// OAuth providers
async function callListProviders(params) {
    return sbxFetch('/api/v1/auth/list_providers', params, 'GET');
}

async function callSetProvider(params) {
    return sbxFetch('/api/v1/auth/set_provider', params, 'POST');
}

async function callDeleteProvider(params) {
    return sbxFetch('/api/v1/auth/delete_provider', params, 'POST');
}

// Vouchers
async function callListVouchers(params) {
    return sbxFetch('/api/v1/auth/list_vouchers', params, 'GET');
}

async function callCreateVoucher(params) {
    return sbxFetch('/api/v1/auth/create_voucher', params, 'POST');
}

async function callDeleteVoucher(params) {
    return sbxFetch('/api/v1/auth/delete_voucher', params, 'POST');
}

async function callValidateVoucher(params) {
    return sbxFetch('/api/v1/auth/validate_voucher', params, 'GET');
}

// Sessions
async function callListSessions(params) {
    return sbxFetch('/api/v1/auth/list_sessions', params, 'GET');
}

async function callRevokeSession(params) {
    return sbxFetch('/api/v1/auth/revoke_session', params, 'GET');
}

// Logs
async function callGetLogs(params) {
    return sbxFetch('/api/v1/auth/get_logs', params, 'GET');
}

return baseclass.extend({
	getStatus: callStatus,
	listProviders: callListProviders,
	setProvider: callSetProvider,
	deleteProvider: callDeleteProvider,
	listVouchers: callListVouchers,
	createVoucher: callCreateVoucher,
	deleteVoucher: callDeleteVoucher,
	validateVoucher: callValidateVoucher,
	listSessions: callListSessions,
	getSessions: callListSessions,  // Alias for compatibility
	revokeSession: callRevokeSession,
	getLogs: callGetLogs
});
