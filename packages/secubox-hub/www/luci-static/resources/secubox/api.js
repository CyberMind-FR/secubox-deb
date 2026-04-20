'use strict';
/**
 * SecuBox Master API
 * Package: luci-app-secubox
 * RPCD object: luci.secubox
 */

// Version: 0.7.1 - Fixed RPCD method names

async function callStatus(params) {
    return sbxFetch('/api/v1/hub/status', params, 'GET');
}

async function callModules(params) {
    return sbxFetch('/api/v1/hub/modules', params, 'GET');
}

async function callModulesByCategory(params) {
    return sbxFetch('/api/v1/hub/menu', params, 'GET');
}

async function callModuleInfo(params) {
    return sbxFetch('/api/v1/hub/module_status', params, 'GET');
}

async function callStartModule(params) {
    return sbxFetch('/api/v1/hub/start_module', params, 'POST');
}

async function callStopModule(params) {
    return sbxFetch('/api/v1/hub/stop_module', params, 'POST');
}

async function callRestartModule(params) {
    return sbxFetch('/api/v1/hub/restart_module', params, 'POST');
}

// NEW v0.3.1: Enable/Disable module methods
async function callEnableModule(params) {
    return sbxFetch('/api/v1/hub/enable_module', params, 'POST');
}

async function callDisableModule(params) {
    return sbxFetch('/api/v1/hub/disable_module', params, 'POST');
}

async function callCheckModuleEnabled(params) {
    return sbxFetch('/api/v1/hub/check_module_enabled', params, 'GET');
}

async function callHealth(params) {
    return sbxFetch('/api/v1/hub/health', params, 'GET');
}

async function callDiagnostics(params) {
    return sbxFetch('/api/v1/hub/diagnostics', params, 'GET');
}

async function callSystemHealth(params) {
    return sbxFetch('/api/v1/hub/system_health', params, 'GET');
}

async function callPublicIPs(params) {
    return sbxFetch('/api/v1/hub/network_summary', params, 'GET');
}

async function callAlerts(params) {
    return sbxFetch('/api/v1/hub/alerts', params, 'GET');
}

async function callQuickAction(params) {
    return sbxFetch('/api/v1/hub/quick_actions', params, 'GET');
}

async function callDashboardData(params) {
    return sbxFetch('/api/v1/hub/dashboard', params, 'GET');
}

async function callGetTheme(params) {
    return sbxFetch('/api/v1/hub/theme', params, 'GET');
}

async function callSetTheme(params) {
    return sbxFetch('/api/v1/hub/set_theme', params, 'POST');
}

async function callDismissAlert(params) {
    return sbxFetch('/api/v1/hub/dismiss_notification', params, 'POST');
}

async function callClearAlerts(params) {
    return sbxFetch('/api/v1/hub/dismiss_all_notifications', params, 'POST');
}

async function callFixPermissions(params) {
    return sbxFetch('/api/v1/hub/fix_permissions', params, 'GET');
}

async function callFirstRunStatus(params) {
    return sbxFetch('/api/v1/hub/first_run_status', params, 'GET');
}

async function callApplyFirstRun(params) {
    return sbxFetch('/api/v1/hub/apply_first_run', params, 'POST');
}

async function callListApps(params) {
    return sbxFetch('/api/v1/hub/list_apps', params, 'GET');
}

async function callGetAppManifest(params) {
    return sbxFetch('/api/v1/hub/get_app_manifest', params, 'GET');
}

async function callApplyAppWizard(params) {
    return sbxFetch('/api/v1/hub/apply_app_wizard', params, 'POST');
}

async function callListProfiles(params) {
    return sbxFetch('/api/v1/hub/listProfiles', params, 'GET');
}

async function callApplyProfile(params) {
    return sbxFetch('/api/v1/hub/applyProfile', params, 'POST');
}

async function callRollbackProfile(params) {
    return sbxFetch('/api/v1/hub/rollbackProfile', params, 'POST');
}

// App Store methods
async function callGetAppstoreApps(params) {
    return sbxFetch('/api/v1/hub/get_appstore_apps', params, 'GET');
}

async function callGetAppstoreApp(params) {
    return sbxFetch('/api/v1/hub/get_appstore_app', params, 'GET');
}

async function callInstallAppstoreApp(params) {
    return sbxFetch('/api/v1/hub/install_appstore_app', params, 'GET');
}

async function callRemoveAppstoreApp(params) {
    return sbxFetch('/api/v1/hub/remove_appstore_app', params, 'POST');
}

// P2P Hub methods - Collaborative peer-to-peer app catalog sharing
async function callGetP2PPeers(params) {
    return sbxFetch('/api/v1/hub/p2p_get_peers', params, 'GET');
}

async function callP2PDiscover(params) {
    return sbxFetch('/api/v1/hub/p2p_discover', params, 'GET');
}

async function callP2PAddPeer(params) {
    return sbxFetch('/api/v1/hub/p2p_add_peer', params, 'GET');
}

async function callP2PRemovePeer(params) {
    return sbxFetch('/api/v1/hub/p2p_remove_peer', params, 'GET');
}

async function callP2PGetPeerCatalog(params) {
    return sbxFetch('/api/v1/hub/p2p_get_peer_catalog', params, 'GET');
}

async function callP2PShareCatalog(params) {
    return sbxFetch('/api/v1/hub/p2p_share_catalog', params, 'GET');
}

async function callP2PGetSettings(params) {
    return sbxFetch('/api/v1/hub/p2p_get_settings', params, 'GET');
}

async function callP2PSetSettings(params) {
    return sbxFetch('/api/v1/hub/p2p_set_settings', params, 'GET');
}

function formatUptime(seconds) {
	if (!seconds) return '0s';
	var d = Math.floor(seconds / 86400);
	var h = Math.floor((seconds % 86400) / 3600);
	var m = Math.floor((seconds % 3600) / 60);
	if (d > 0) return d + 'd ' + h + 'h';
	if (h > 0) return h + 'h ' + m + 'm';
	return m + 'm';
}

function formatBytes(bytes) {
	if (!bytes) return '0 B';
	var k = 1024;
	var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(bytes) / Math.log(k));
	return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
}

function formatBits(bytes, decimals) {
	if (!bytes) return '0 bps';
	var bits = bytes * 8;
	var k = 1000;  // SI units (1000, not 1024)
	var sizes = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
	var i = Math.floor(Math.log(bits) / Math.log(k));
	var d = (decimals !== undefined) ? decimals : 1;
	return (bits / Math.pow(k, i)).toFixed(d) + ' ' + sizes[i];
}

return baseclass.extend({
	getStatus: callStatus,
	getModules: callModules,
	getModulesByCategory: callModulesByCategory,
	getModuleInfo: callModuleInfo,
	// DEPRECATED: Use enable/disable instead
	startModule: callStartModule,
	stopModule: callStopModule,
	restartModule: callRestartModule,
	// NEW v0.3.1: Enable/Disable methods
	enableModule: callEnableModule,
	disableModule: callDisableModule,
	checkModuleEnabled: callCheckModuleEnabled,
	// Health & diagnostics
	getHealth: callHealth,
	getDiagnostics: callDiagnostics,
	getSystemHealth: callSystemHealth,
	getPublicIPs: callPublicIPs,
	getAlerts: callAlerts,
	quickAction: callQuickAction,
	getDashboardData: callDashboardData,
	getTheme: callGetTheme,
	setTheme: callSetTheme,
	dismissAlert: callDismissAlert,
	clearAlerts: callClearAlerts,
	fixPermissions: callFixPermissions,
	getFirstRunStatus: callFirstRunStatus,
	applyFirstRun: callApplyFirstRun,
	listApps: callListApps,
	getAppManifest: callGetAppManifest,
	applyAppWizard: callApplyAppWizard,
	listProfiles: callListProfiles,
	applyProfile: callApplyProfile,
	rollbackProfile: callRollbackProfile,
	// App Store
	getAppstoreApps: callGetAppstoreApps,
	getAppstoreApp: callGetAppstoreApp,
	installAppstoreApp: callInstallAppstoreApp,
	removeAppstoreApp: callRemoveAppstoreApp,
	// P2P Hub - Collaborative catalog sharing
	getP2PPeers: callGetP2PPeers,
	p2pDiscover: callP2PDiscover,
	p2pAddPeer: callP2PAddPeer,
	p2pRemovePeer: callP2PRemovePeer,
	p2pGetPeerCatalog: callP2PGetPeerCatalog,
	p2pShareCatalog: callP2PShareCatalog,
	p2pGetSettings: callP2PGetSettings,
	p2pSetSettings: callP2PSetSettings,
	// Utilities
	formatUptime: formatUptime,
	formatBytes: formatBytes,
	formatBits: formatBits
});
