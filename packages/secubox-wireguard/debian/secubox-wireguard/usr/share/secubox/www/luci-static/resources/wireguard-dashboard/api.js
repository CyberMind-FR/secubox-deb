'use strict';
/**
 * WireGuard Dashboard API
 * Package: luci-app-wireguard-dashboard
 * RPCD object: luci.wireguard-dashboard
 */

// Version: 0.4.0

async function callStatus(params) {
    return sbxFetch('/api/v1/wireguard/status', params, 'GET');
}

async function callGetPeers(params) {
    return sbxFetch('/api/v1/wireguard/peers', params, 'GET');
}

async function callGetInterfaces(params) {
    return sbxFetch('/api/v1/wireguard/interfaces', params, 'GET');
}

async function callGenerateKeys(params) {
    return sbxFetch('/api/v1/wireguard/generate_keys', params, 'POST');
}

async function callCreateInterface(params) {
    return sbxFetch('/api/v1/wireguard/create_interface', params, 'POST');
}

async function callAddPeer(params) {
    return sbxFetch('/api/v1/wireguard/add_peer', params, 'POST');
}

async function callRemovePeer(params) {
    return sbxFetch('/api/v1/wireguard/remove_peer', params, 'POST');
}

async function callGetConfig(params) {
    return sbxFetch('/api/v1/wireguard/config', params, 'GET');
}

async function callGenerateConfig(params) {
    return sbxFetch('/api/v1/wireguard/generate_config', params, 'POST');
}

async function callGenerateQR(params) {
    return sbxFetch('/api/v1/wireguard/generate_qr', params, 'POST');
}

async function callGetTraffic(params) {
    return sbxFetch('/api/v1/wireguard/traffic', params, 'GET');
}

async function callInterfaceControl(params) {
    return sbxFetch('/api/v1/wireguard/interface_control', params, 'GET');
}

async function callPeerDescriptions(params) {
    return sbxFetch('/api/v1/wireguard/peer_descriptions', params, 'GET');
}

async function callBandwidthRates(params) {
    return sbxFetch('/api/v1/wireguard/bandwidth_rates', params, 'POST');
}

async function callPingPeer(params) {
    return sbxFetch('/api/v1/wireguard/ping_peer', params, 'GET');
}

async function callGetEndpoints(params) {
    return sbxFetch('/api/v1/wireguard/get_endpoints', params, 'GET');
}

async function callSetEndpoint(params) {
    return sbxFetch('/api/v1/wireguard/set_endpoint', params, 'POST');
}

async function callSetDefaultEndpoint(params) {
    return sbxFetch('/api/v1/wireguard/set_default_endpoint', params, 'POST');
}

async function callDeleteEndpoint(params) {
    return sbxFetch('/api/v1/wireguard/delete_endpoint', params, 'POST');
}

// Uplink API calls (Reverse MWAN WireGuard)
async function callUplinkStatus(params) {
    return sbxFetch('/api/v1/wireguard/uplink_status', params, 'GET');
}

async function callGetUplinks(params) {
    return sbxFetch('/api/v1/wireguard/uplinks', params, 'GET');
}

async function callAddUplink(params) {
    return sbxFetch('/api/v1/wireguard/add_uplink', params, 'POST');
}

async function callRemoveUplink(params) {
    return sbxFetch('/api/v1/wireguard/remove_uplink', params, 'POST');
}

async function callTestUplink(params) {
    return sbxFetch('/api/v1/wireguard/test_uplink', params, 'GET');
}

async function callOfferUplink(params) {
    return sbxFetch('/api/v1/wireguard/offer_uplink', params, 'GET');
}

async function callWithdrawUplink(params) {
    return sbxFetch('/api/v1/wireguard/withdraw_uplink', params, 'GET');
}

async function callSetUplinkPriority(params) {
    return sbxFetch('/api/v1/wireguard/set_uplink_priority', params, 'POST');
}

async function callSetUplinkFailover(params) {
    return sbxFetch('/api/v1/wireguard/set_uplink_failover', params, 'POST');
}

function buildEndpointSelector(endpointData, inputId) {
	var endpoints = (endpointData || {}).endpoints || [];
	var defaultId = (endpointData || {})['default'] || '';

	if (endpoints.length === 0) {
		// No saved endpoints - return a plain text input
		return E('input', {
			'type': 'text',
			'id': inputId,
			'class': 'cbi-input-text',
			'placeholder': 'vpn.example.com or 203.0.113.1',
			'data-mode': 'text'
		});
	}

	var container = E('div', { 'style': 'display: flex; flex-direction: column; gap: 8px;' });

	var options = endpoints.map(function(ep) {
		return E('option', {
			'value': ep.address,
			'selected': (ep.id === defaultId) ? '' : null,
			'data-id': ep.id
		}, (ep.name || ep.id) + ' (' + ep.address + ')');
	});

	options.push(E('option', { 'value': '__custom__' }, _('Custom...')));

	var select = E('select', {
		'id': inputId,
		'class': 'cbi-input-select',
		'data-mode': 'select',
		'change': function() {
			var customInput = container.querySelector('.wg-custom-endpoint');
			if (this.value === '__custom__') {
				customInput.style.display = '';
				customInput.focus();
			} else {
				customInput.style.display = 'none';
			}
		}
	}, options);

	var customInput = E('input', {
		'type': 'text',
		'class': 'cbi-input-text wg-custom-endpoint',
		'placeholder': 'vpn.example.com or 203.0.113.1',
		'style': 'display: none; margin-top: 4px;'
	});

	container.appendChild(select);
	container.appendChild(customInput);

	return container;
}

function getEndpointValue(inputId) {
	var el = document.getElementById(inputId);
	if (!el) return '';

	if (el.dataset.mode === 'text') {
		return el.value.trim();
	}

	// select mode
	if (el.value === '__custom__') {
		var container = el.closest('div');
		var customInput = container ? container.querySelector('.wg-custom-endpoint') : null;
		return customInput ? customInput.value.trim() : '';
	}

	return el.value;
}

function formatBytes(bytes) {
	if (bytes === 0) return '0 B';
	var k = 1024;
	var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatLastHandshake(timestamp) {
	if (!timestamp) return 'Never';
	var now = Math.floor(Date.now() / 1000);
	var diff = now - timestamp;
	if (diff < 60) return diff + 's ago';
	if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
	if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
	return Math.floor(diff / 86400) + 'd ago';
}

function getPeerStatusClass(status) {
	if (status === 'active') return 'active';
	if (status === 'idle') return 'idle';
	return 'inactive';
}

function shortenKey(key, length) {
	if (!key) return 'N/A';
	length = length || 8;
	return key.substring(0, length) + '...';
}

function formatHandshake(seconds) {
	if (!seconds || seconds === 0) return 'Never';
	if (seconds < 60) return seconds + 's ago';
	if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
	if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
	return Math.floor(seconds / 86400) + 'd ago';
}

function formatRate(bytesPerSec) {
	if (!bytesPerSec || bytesPerSec === 0) return '0 B/s';
	var k = 1024;
	var sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
	var i = Math.floor(Math.log(bytesPerSec) / Math.log(k));
	if (i >= sizes.length) i = sizes.length - 1;
	return parseFloat((bytesPerSec / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

return baseclass.extend({
	getStatus: callStatus,
	getPeers: callGetPeers,
	getInterfaces: callGetInterfaces,
	getConfig: callGetConfig,
	getTraffic: callGetTraffic,
	generateKeys: callGenerateKeys,
	createInterface: callCreateInterface,
	addPeer: callAddPeer,
	removePeer: callRemovePeer,
	generateConfig: callGenerateConfig,
	generateQR: callGenerateQR,
	interfaceControl: callInterfaceControl,
	getPeerDescriptions: callPeerDescriptions,
	getBandwidthRates: callBandwidthRates,
	pingPeer: callPingPeer,
	getEndpoints: callGetEndpoints,
	setEndpoint: callSetEndpoint,
	setDefaultEndpoint: callSetDefaultEndpoint,
	deleteEndpoint: callDeleteEndpoint,
	// Uplink API (Reverse MWAN)
	getUplinkStatus: callUplinkStatus,
	getUplinks: callGetUplinks,
	addUplink: callAddUplink,
	removeUplink: callRemoveUplink,
	testUplink: callTestUplink,
	offerUplink: callOfferUplink,
	withdrawUplink: callWithdrawUplink,
	setUplinkPriority: callSetUplinkPriority,
	setUplinkFailover: callSetUplinkFailover,
	buildEndpointSelector: buildEndpointSelector,
	getEndpointValue: getEndpointValue,
	formatBytes: formatBytes,
	formatLastHandshake: formatLastHandshake,
	getPeerStatusClass: getPeerStatusClass,
	shortenKey: shortenKey,
	formatHandshake: formatHandshake,
	formatRate: formatRate,

	// Aggregate function for overview page
	getAllData: function() {
		return Promise.all([
			callStatus(),
			callGetPeers(),
			callGetInterfaces(),
			callGetTraffic(),
			callPeerDescriptions()
		]).then(function(results) {
			// Handle RPC expect unwrapping - results may be array or object
			var peersData = results[1] || [];
			var interfacesData = results[2] || [];

			return {
				status: results[0] || {},
				peers: Array.isArray(peersData) ? peersData : (peersData.peers || []),
				interfaces: Array.isArray(interfacesData) ? interfacesData : (interfacesData.interfaces || []),
				traffic: results[3] || {},
				descriptions: (results[4] || {}).descriptions || {}
			};
		});
	},

	// Get data with bandwidth rates for real-time monitoring
	getMonitoringData: function() {
		return Promise.all([
			callStatus(),
			callGetPeers(),
			callBandwidthRates(),
			callPeerDescriptions()
		]).then(function(results) {
			// Handle RPC expect unwrapping - results may be array or object
			var peersData = results[1] || [];
			var ratesData = results[2] || [];

			return {
				status: results[0] || {},
				peers: Array.isArray(peersData) ? peersData : (peersData.peers || []),
				rates: Array.isArray(ratesData) ? ratesData : (ratesData.rates || []),
				descriptions: (results[3] || {}).descriptions || {}
			};
		});
	}
});
