'use strict';
/**
 * Client Guardian API
 * Package: luci-app-client-guardian
 * RPCD object: luci.client-guardian
 */

// Version: 0.4.0

async function callStatus(params) {
    return sbxFetch('/api/v1/nac/status', params, 'GET');
}

async function callClients(params) {
    return sbxFetch('/api/v1/nac/clients', params, 'GET');
}

async function callGetClient(params) {
    return sbxFetch('/api/v1/nac/get_client', params, 'GET');
}

async function callZones(params) {
    return sbxFetch('/api/v1/nac/zones', params, 'GET');
}

async function callParental(params) {
    return sbxFetch('/api/v1/nac/parental', params, 'GET');
}


async function callAlerts(params) {
    return sbxFetch('/api/v1/nac/alerts', params, 'GET');
}

async function callLogs(params) {
    return sbxFetch('/api/v1/nac/logs', params, 'GET');
}

async function callApproveClient(params) {
    return sbxFetch('/api/v1/nac/approve_client', params, 'GET');
}

async function callBanClient(params) {
    return sbxFetch('/api/v1/nac/ban_client', params, 'POST');
}

async function callQuarantineClient(params) {
    return sbxFetch('/api/v1/nac/quarantine_client', params, 'GET');
}

async function callUpdateClient(params) {
    return sbxFetch('/api/v1/nac/update_client', params, 'GET');
}

async function callUpdateZone(params) {
    return sbxFetch('/api/v1/nac/update_zone', params, 'GET');
}

async function callSendTestAlert(params) {
    return sbxFetch('/api/v1/nac/send_test_alert', params, 'GET');
}

async function callGetPolicy(params) {
    return sbxFetch('/api/v1/nac/get_policy', params, 'GET');
}

async function callSetPolicy(params) {
    return sbxFetch('/api/v1/nac/set_policy', params, 'POST');
}

async function callSyncZones(params) {
    return sbxFetch('/api/v1/nac/sync_zones', params, 'GET');
}

function formatMac(mac) {
	if (!mac) return '';
	return mac.toUpperCase().replace(/(.{2})(?=.)/g, '$1:');
}

function formatDuration(seconds) {
	if (!seconds) return 'Unlimited';
	var h = Math.floor(seconds / 3600);
	var m = Math.floor((seconds % 3600) / 60);
	if (h > 24) return Math.floor(h / 24) + 'd';
	if (h > 0) return h + 'h ' + m + 'm';
	return m + 'm';
}

function formatBytes(bytes) {
	if (!bytes || bytes === 0) return '0 B';
	var units = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(bytes) / Math.log(1024));
	i = Math.min(i, units.length - 1);
	return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
}

function getDeviceIcon(hostname, mac) {
	hostname = (hostname || '').toLowerCase();
	mac = (mac || '').toLowerCase();

	// Mobile devices
	if (hostname.match(/android|iphone|ipad|mobile|phone|samsung|xiaomi|huawei/))
		return '📱';

	// Computers
	if (hostname.match(/pc|laptop|desktop|macbook|imac|windows|linux|ubuntu/))
		return '💻';

	// IoT devices
	if (hostname.match(/camera|bulb|switch|sensor|thermostat|doorbell|lock/))
		return '📷';

	// Smart TV / Media
	if (hostname.match(/tv|roku|chromecast|firestick|appletv|media/))
		return '📺';

	// Gaming
	if (hostname.match(/playstation|xbox|nintendo|switch|steam/))
		return '🎮';

	// Network equipment
	if (hostname.match(/router|switch|ap|access[-_]?point|bridge/))
		return '🌐';

	// Printers
	if (hostname.match(/printer|print|hp-|canon-|epson-/))
		return '🖨️';

	// Default
	return '🔌';
}

return baseclass.extend({
	// Core methods
	getStatus: callStatus,
	getClients: callClients,
	getClient: callGetClient,
	getZones: callZones,
	getParental: callParental,
	getAlerts: callAlerts,
	getLogs: callLogs,

	// Client management
	approveClient: callApproveClient,
	banClient: callBanClient,
	quarantineClient: callQuarantineClient,
	updateClient: callUpdateClient,

	// Configuration
	updateZone: callUpdateZone,
	sendTestAlert: callSendTestAlert,
	syncZones: callSyncZones,
	getPolicy: callGetPolicy,
	setPolicy: callSetPolicy,

	// Utility functions
	formatMac: formatMac,
	formatDuration: formatDuration,
	formatBytes: formatBytes,
	getDeviceIcon: getDeviceIcon
});
