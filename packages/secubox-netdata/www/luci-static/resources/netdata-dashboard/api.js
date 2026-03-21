'use strict';
/**
 * Netdata Dashboard API
 * Package: luci-app-netdata-dashboard
 * RPCD object: luci.netdata-dashboard
 */

// Version: 0.5.0

// System stats methods (from RPCD backend)
async function callStats(params) {
    return sbxFetch('/api/v1/netdata/stats', params, 'GET');
}

async function callCPU(params) {
    return sbxFetch('/api/v1/netdata/cpu', params, 'GET');
}

async function callMemory(params) {
    return sbxFetch('/api/v1/netdata/memory', params, 'GET');
}

async function callDisk(params) {
    return sbxFetch('/api/v1/netdata/disk', params, 'GET');
}

async function callNetwork(params) {
    return sbxFetch('/api/v1/netdata/network', params, 'GET');
}

async function callProcesses(params) {
    return sbxFetch('/api/v1/netdata/processes', params, 'GET');
}

async function callSensors(params) {
    return sbxFetch('/api/v1/netdata/sensors', params, 'GET');
}

async function callSystem(params) {
    return sbxFetch('/api/v1/netdata/system', params, 'GET');
}

// Netdata integration methods
async function callNetdataStatus(params) {
    return sbxFetch('/api/v1/netdata/netdata_status', params, 'GET');
}

async function callNetdataAlarms(params) {
    return sbxFetch('/api/v1/netdata/netdata_alarms', params, 'GET');
}

async function callNetdataInfo(params) {
    return sbxFetch('/api/v1/netdata/netdata_info', params, 'GET');
}

async function callRestartNetdata(params) {
    return sbxFetch('/api/v1/netdata/restart_netdata', params, 'POST');
}

async function callStartNetdata(params) {
    return sbxFetch('/api/v1/netdata/start_netdata', params, 'POST');
}

async function callStopNetdata(params) {
    return sbxFetch('/api/v1/netdata/stop_netdata', params, 'POST');
}

async function callSecuboxLogs(params) {
    return sbxFetch('/api/v1/netdata/seccubox_logs', params, 'GET');
}

async function callCollectDebug(params) {
    return sbxFetch('/api/v1/netdata/collect_debug', params, 'GET');
}

function formatBytes(bytes) {
	if (!bytes || bytes === 0) return '0 B';
	var units = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(1024));
	i = Math.min(i, units.length - 1);
	return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
}

function formatUptime(seconds) {
	if (!seconds) return '0s';
	var d = Math.floor(seconds / 86400);
	var h = Math.floor((seconds % 86400) / 3600);
	var m = Math.floor((seconds % 3600) / 60);
	var parts = [];
	if (d > 0) parts.push(d + 'd');
	if (h > 0) parts.push(h + 'h');
	if (m > 0) parts.push(m + 'm');
	return parts.join(' ') || '0m';
}

function formatKB(kb) {
	if (!kb || kb === 0) return '0 KB';
	var units = ['KB', 'MB', 'GB', 'TB'];
	var i = 0;
	var size = kb;
	while (size >= 1024 && i < units.length - 1) {
		size = size / 1024;
		i++;
	}
	return size.toFixed(2) + ' ' + units[i];
}

function getStatusClass(percent) {
	if (percent >= 90) return 'critical';
	if (percent >= 75) return 'warning';
	if (percent >= 50) return 'info';
	return 'good';
}

function getTempClass(temp) {
	if (!temp) return 'good';
	if (temp >= 80) return 'critical';
	if (temp >= 70) return 'warning';
	if (temp >= 60) return 'info';
	return 'good';
}

return baseclass.extend({
	// System stats
	getStats: callStats,
	getCPU: callCPU,
	getCpu: callCPU,  // Alias for consistency
	getMemory: callMemory,
	getDisk: callDisk,
	getNetwork: callNetwork,
	getProcesses: callProcesses,
	getSensors: callSensors,
	getSystem: callSystem,

	// Netdata integration
	getNetdataStatus: callNetdataStatus,
	getNetdataAlarms: callNetdataAlarms,
	getNetdataInfo: callNetdataInfo,
	restartNetdata: callRestartNetdata,
	startNetdata: callStartNetdata,
	stopNetdata: callStopNetdata,
	getSecuboxLogs: callSecuboxLogs,
	collectDebugSnapshot: callCollectDebug,

	// Combined data fetch for dashboard
	getAllData: function() {
		return Promise.all([
			callStats(),
			callCPU(),
			callMemory(),
			callDisk(),
			callNetwork(),
			callProcesses(),
			callSystem()
		]).then(function(results) {
			return {
				stats: results[0] || {},
				cpu: results[1] || {},
				memory: results[2] || {},
				disk: results[3] || {},
				network: results[4] || {},
				processes: results[5] || {},
				system: results[6] || {}
			};
		});
	},

	// Utility functions
	formatBytes: formatBytes,
	formatKB: formatKB,
	formatUptime: formatUptime,
	getStatusClass: getStatusClass,
	getTempClass: getTempClass
});
