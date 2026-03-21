'use strict';
/**
 * CrowdSec Dashboard API
 * Package: luci-app-crowdsec-dashboard
 * RPCD object: luci.crowdsec-dashboard
 * CrowdSec Core: 1.7.4+
 */

// Version: 0.7.0

async function callStatus(params) {
    return sbxFetch('/api/v1/crowdsec/status', params, 'GET');
}

async function callDecisions(params) {
    return sbxFetch('/api/v1/crowdsec/decisions', params, 'GET');
}

async function callAlerts(params) {
    return sbxFetch('/api/v1/crowdsec/alerts', params, 'GET');
}

async function callBouncers(params) {
    return sbxFetch('/api/v1/crowdsec/bouncers', params, 'GET');
}

async function callMetrics(params) {
    return sbxFetch('/api/v1/crowdsec/metrics', params, 'GET');
}

async function callMachines(params) {
    return sbxFetch('/api/v1/crowdsec/machines', params, 'GET');
}

async function callHub(params) {
    return sbxFetch('/api/v1/crowdsec/hub', params, 'GET');
}

async function callStats(params) {
    return sbxFetch('/api/v1/crowdsec/stats', params, 'GET');
}

async function callGetOverview(params) {
    return sbxFetch('/api/v1/crowdsec/get_overview', params, 'GET');
}

async function callSecuboxLogs(params) {
    return sbxFetch('/api/v1/crowdsec/secubox_logs', params, 'GET');
}

async function callCollectDebug(params) {
    return sbxFetch('/api/v1/crowdsec/collect_debug', params, 'GET');
}

async function callBan(params) {
    return sbxFetch('/api/v1/crowdsec/ban', params, 'POST');
}

async function callUnban(params) {
    return sbxFetch('/api/v1/crowdsec/unban', params, 'POST');
}

// CrowdSec v1.7.4+ features
async function callWAFStatus(params) {
    return sbxFetch('/api/v1/crowdsec/waf_status', params, 'GET');
}

async function callMetricsConfig(params) {
    return sbxFetch('/api/v1/crowdsec/metrics_config', params, 'GET');
}

async function callConfigureMetrics(params) {
    return sbxFetch('/api/v1/crowdsec/configure_metrics', params, 'GET');
}

async function callCollections(params) {
    return sbxFetch('/api/v1/crowdsec/collections', params, 'GET');
}

async function callInstallCollection(params) {
    return sbxFetch('/api/v1/crowdsec/install_collection', params, 'GET');
}

async function callRemoveCollection(params) {
    return sbxFetch('/api/v1/crowdsec/remove_collection', params, 'POST');
}

async function callUpdateHub(params) {
    return sbxFetch('/api/v1/crowdsec/update_hub', params, 'GET');
}

async function callRegisterBouncer(params) {
    return sbxFetch('/api/v1/crowdsec/register_bouncer', params, 'GET');
}

async function callDeleteBouncer(params) {
    return sbxFetch('/api/v1/crowdsec/delete_bouncer', params, 'POST');
}

// Firewall Bouncer Management
async function callFirewallBouncerStatus(params) {
    return sbxFetch('/api/v1/crowdsec/firewall_bouncer_status', params, 'GET');
}

async function callControlFirewallBouncer(params) {
    return sbxFetch('/api/v1/crowdsec/control_firewall_bouncer', params, 'GET');
}

async function callFirewallBouncerConfig(params) {
    return sbxFetch('/api/v1/crowdsec/firewall_bouncer_config', params, 'GET');
}

async function callUpdateFirewallBouncerConfig(params) {
    return sbxFetch('/api/v1/crowdsec/update_firewall_bouncer_config', params, 'GET');
}

async function callNftablesStats(params) {
    return sbxFetch('/api/v1/crowdsec/nftables_stats', params, 'GET');
}

// Wizard Methods
async function callCheckWizardNeeded(params) {
    return sbxFetch('/api/v1/crowdsec/check_wizard_needed', params, 'GET');
}

async function callWizardState(params) {
    return sbxFetch('/api/v1/crowdsec/wizard_state', params, 'GET');
}

async function callRepairLapi(params) {
    return sbxFetch('/api/v1/crowdsec/repair_lapi', params, 'GET');
}

async function callRepairCapi(params) {
    return sbxFetch('/api/v1/crowdsec/repair_capi', params, 'GET');
}

async function callResetWizard(params) {
    return sbxFetch('/api/v1/crowdsec/reset_wizard', params, 'GET');
}

// Console Methods
async function callConsoleStatus(params) {
    return sbxFetch('/api/v1/crowdsec/console_status', params, 'GET');
}

async function callConsoleEnroll(params) {
    return sbxFetch('/api/v1/crowdsec/console_enroll', params, 'GET');
}

async function callConsoleDisable(params) {
    return sbxFetch('/api/v1/crowdsec/console_disable', params, 'GET');
}

async function callServiceControl(params) {
    return sbxFetch('/api/v1/crowdsec/service_control', params, 'GET');
}

// Acquisition Methods
async function callConfigureAcquisition(params) {
    return sbxFetch('/api/v1/crowdsec/configure_acquisition', params, 'GET');
}

async function callAcquisitionConfig(params) {
    return sbxFetch('/api/v1/crowdsec/acquisition_config', params, 'GET');
}

async function callAcquisitionMetrics(params) {
    return sbxFetch('/api/v1/crowdsec/acquisition_metrics', params, 'GET');
}

// Health Check & CAPI Methods
async function callHealthCheck(params) {
    return sbxFetch('/api/v1/crowdsec/health_check', params, 'GET');
}

async function callCapiMetrics(params) {
    return sbxFetch('/api/v1/crowdsec/capi_metrics', params, 'GET');
}

async function callHubAvailable(params) {
    return sbxFetch('/api/v1/crowdsec/hub_available', params, 'GET');
}

async function callInstallHubItem(params) {
    return sbxFetch('/api/v1/crowdsec/install_hub_item', params, 'GET');
}

async function callRemoveHubItem(params) {
    return sbxFetch('/api/v1/crowdsec/remove_hub_item', params, 'POST');
}

async function callGetSettings(params) {
    return sbxFetch('/api/v1/crowdsec/get_settings', params, 'GET');
}

async function callSaveSettings(params) {
    return sbxFetch('/api/v1/crowdsec/save_settings', params, 'GET');
}

function formatDuration(seconds) {
	if (!seconds) return 'N/A';
	if (seconds < 60) return seconds + 's';
	if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
	if (seconds < 86400) return Math.floor(seconds / 3600) + 'h';
	return Math.floor(seconds / 86400) + 'd';
}

function formatDate(dateStr) {
	if (!dateStr) return 'N/A';
	try {
		var date = new Date(dateStr);
		return date.toLocaleString();
	} catch(e) {
		return dateStr;
	}
}

function isValidIP(ip) {
	if (!ip) return false;

	// IPv4 regex
	var ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

	// IPv6 regex (simplified)
	var ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

	return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

function parseScenario(scenario) {
	if (!scenario) return 'N/A';

	// Extract human-readable part from scenario name
	// e.g., "crowdsecurity/ssh-bruteforce" -> "SSH Bruteforce"
	var parts = scenario.split('/');
	var name = parts[parts.length - 1];

	// Convert dash-separated to title case
	return name.split('-').map(function(word) {
		return word.charAt(0).toUpperCase() + word.slice(1);
	}).join(' ');
}

function getCountryFlag(countryCode) {
	if (!countryCode || countryCode === 'N/A') return '';

	// Convert country code to flag emoji
	// e.g., "US" -> "🇺🇸"
	var code = countryCode.toUpperCase();
	if (code.length !== 2) return '';

	var codePoints = [];
	for (var i = 0; i < code.length; i++) {
		codePoints.push(0x1F1E6 - 65 + code.charCodeAt(i));
	}
	return String.fromCodePoint.apply(null, codePoints);
}

function formatRelativeTime(dateStr) {
	if (!dateStr) return 'N/A';

	try {
		var date = new Date(dateStr);
		var now = new Date();
		var seconds = Math.floor((now - date) / 1000);

		if (seconds < 60) return seconds + 's ago';
		if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
		if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
		if (seconds < 2592000) return Math.floor(seconds / 86400) + 'd ago';
		return Math.floor(seconds / 2592000) + 'mo ago';
	} catch(e) {
		return dateStr;
	}
}

return baseclass.extend({
	getStatus: callStatus,
	getDecisions: callDecisions,
	getAlerts: callAlerts,
	getBouncers: callBouncers,
	getMetrics: callMetrics,
	getMachines: callMachines,
	getHub: callHub,
	getStats: callStats,
	getOverview: callGetOverview,
	getSecuboxLogs: callSecuboxLogs,
	collectDebugSnapshot: callCollectDebug,
	addBan: callBan,
	removeBan: callUnban,

	// CrowdSec v1.7.4+ features
	getWAFStatus: callWAFStatus,
	getMetricsConfig: callMetricsConfig,
	configureMetrics: callConfigureMetrics,
	getCollections: callCollections,
	installCollection: callInstallCollection,
	removeCollection: callRemoveCollection,
	updateHub: callUpdateHub,
	registerBouncer: callRegisterBouncer,
	deleteBouncer: callDeleteBouncer,

	// Firewall Bouncer Management
	getFirewallBouncerStatus: callFirewallBouncerStatus,
	controlFirewallBouncer: callControlFirewallBouncer,
	getFirewallBouncerConfig: callFirewallBouncerConfig,
	updateFirewallBouncerConfig: callUpdateFirewallBouncerConfig,
	getNftablesStats: callNftablesStats,

	// Wizard Methods
	checkWizardNeeded: callCheckWizardNeeded,
	getWizardState: callWizardState,
	repairLapi: callRepairLapi,
	repairCapi: callRepairCapi,
	resetWizard: callResetWizard,

	// Console Methods
	getConsoleStatus: callConsoleStatus,
	consoleEnroll: callConsoleEnroll,
	consoleDisable: callConsoleDisable,

	// Service Control
	serviceControl: callServiceControl,

	// Acquisition Methods
	configureAcquisition: callConfigureAcquisition,
	getAcquisitionConfig: callAcquisitionConfig,
	getAcquisitionMetrics: callAcquisitionMetrics,

	// Health Check & CAPI Methods
	getHealthCheck: callHealthCheck,
	getCapiMetrics: callCapiMetrics,
	getHubAvailable: callHubAvailable,
	installHubItem: callInstallHubItem,
	removeHubItem: callRemoveHubItem,

	// Settings Management
	getSettings: callGetSettings,
	saveSettings: callSaveSettings,

	formatDuration: formatDuration,
	formatDate: formatDate,
	formatRelativeTime: formatRelativeTime,
	isValidIP: isValidIP,
	parseScenario: parseScenario,
	getCountryFlag: getCountryFlag,

	// Aliases for compatibility
	banIP: callBan,
	unbanIP: callUnban,

	getDashboardData: function() {
		return Promise.all([
			callStatus(),
			callStats(),
			callDecisions(),
			callAlerts()
		]).then(function(results) {
			// Check if any result has an error (service not running)
			var status = results[0] || {};
			var stats = results[1] || {};
			var decisionsRaw = results[2] || [];
			var alerts = results[3] || [];

			// Flatten alerts->decisions structure
			var decisions = [];
			if (Array.isArray(decisionsRaw)) {
				decisionsRaw.forEach(function(alert) {
					if (alert.decisions && Array.isArray(alert.decisions)) {
						decisions = decisions.concat(alert.decisions);
					}
				});
			}

			return {
				status: status,
				stats: (stats.error) ? {} : stats,
				decisions: decisions,
				alerts: alerts,
				error: stats.error || null
			};
		});
	}
});
