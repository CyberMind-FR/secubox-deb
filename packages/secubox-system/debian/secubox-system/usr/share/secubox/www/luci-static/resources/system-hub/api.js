'use strict';
/**
 * System Hub API
 * Package: luci-app-system-hub
 * RPCD object: luci.system-hub
 * Version: 0.4.0
 */

// Debug log to verify correct version is loaded
console.log('🔧 System Hub API v0.4.0 loaded at', new Date().toISOString());

async function callStatus(params) {
    return sbxFetch('/api/v1/system/status', params, 'GET');
}

async function callGetSystemInfo(params) {
    return sbxFetch('/api/v1/system/get_system_info', params, 'GET');
}

async function callGetHealth(params) {
    return sbxFetch('/api/v1/system/get_health', params, 'GET');
}

async function callGetServiceHealth(params) {
    return sbxFetch('/api/v1/system/get_service_health', params, 'GET');
}

async function callListServices(params) {
    return sbxFetch('/api/v1/system/list_services', params, 'GET');
}

async function callServiceAction(params) {
    return sbxFetch('/api/v1/system/service_action', params, 'GET');
}

async function callGetLogs(params) {
    return sbxFetch('/api/v1/system/get_logs', params, 'GET');
}

async function callGetDenoisedLogs(params) {
    return sbxFetch('/api/v1/system/get_denoised_logs', params, 'GET');
}

async function callGetDenoiseStats(params) {
    return sbxFetch('/api/v1/system/get_denoise_stats', params, 'GET');
}

async function callBackupConfig(params) {
    return sbxFetch('/api/v1/system/backup_config', params, 'GET');
}

async function callRestoreConfig(params) {
    return sbxFetch('/api/v1/system/restore_config', params, 'GET');
}

async function callGetBackupSchedule(params) {
    return sbxFetch('/api/v1/system/get_backup_schedule', params, 'GET');
}

async function callSetBackupSchedule(params) {
    return sbxFetch('/api/v1/system/set_backup_schedule', params, 'POST');
}

async function callReboot(params) {
    return sbxFetch('/api/v1/system/reboot', params, 'GET');
}

async function callGetStorage(params) {
    return sbxFetch('/api/v1/system/get_storage', params, 'GET');
}

async function callGetSettings(params) {
    return sbxFetch('/api/v1/system/get_settings', params, 'GET');
}

async function callSaveSettings(params) {
    return sbxFetch('/api/v1/system/save_settings', params, 'GET');
}

async function callGetComponents(params) {
    return sbxFetch('/api/v1/system/get_components', params, 'GET');
}

async function callGetComponentsByCategory(params) {
    return sbxFetch('/api/v1/system/get_components_by_category', params, 'GET');
}

async function callCollectDiagnostics(params) {
    return sbxFetch('/api/v1/system/collect_diagnostics', params, 'GET');
}

async function callListDiagnostics(params) {
    return sbxFetch('/api/v1/system/list_diagnostics', params, 'GET');
}

async function callDownloadDiagnostic(params) {
    return sbxFetch('/api/v1/system/download_diagnostic', params, 'GET');
}

async function callDeleteDiagnostic(params) {
    return sbxFetch('/api/v1/system/delete_diagnostic', params, 'POST');
}

async function callRunDiagnosticTest(params) {
    return sbxFetch('/api/v1/system/run_diagnostic_test', params, 'GET');
}

async function callUploadDiagnostics(params) {
    return sbxFetch('/api/v1/system/upload_diagnostics', params, 'GET');
}

async function callListDiagnosticProfiles(params) {
    return sbxFetch('/api/v1/system/list_diagnostic_profiles', params, 'GET');
}

async function callGetDiagnosticProfile(params) {
    return sbxFetch('/api/v1/system/get_diagnostic_profile', params, 'GET');
}

async function callRemoteStatus(params) {
    return sbxFetch('/api/v1/system/remote_status', params, 'GET');
}

async function callRemoteInstall(params) {
    return sbxFetch('/api/v1/system/remote_install', params, 'GET');
}

async function callRemoteConfigure(params) {
    return sbxFetch('/api/v1/system/remote_configure', params, 'GET');
}

async function callRemoteGetCredentials(params) {
    return sbxFetch('/api/v1/system/remote_get_credentials', params, 'GET');
}

async function callRemoteServiceAction(params) {
    return sbxFetch('/api/v1/system/remote_service_action', params, 'GET');
}

async function callRemoteSaveSettings(params) {
    return sbxFetch('/api/v1/system/remote_save_settings', params, 'GET');
}

// TTYD Web Console
async function callTtydStatus(params) {
    return sbxFetch('/api/v1/system/ttyd_status', params, 'GET');
}

async function callTtydInstall(params) {
    return sbxFetch('/api/v1/system/ttyd_install', params, 'GET');
}

async function callTtydStart(params) {
    return sbxFetch('/api/v1/system/ttyd_start', params, 'GET');
}

async function callTtydStop(params) {
    return sbxFetch('/api/v1/system/ttyd_stop', params, 'GET');
}

async function callTtydConfigure(params) {
    return sbxFetch('/api/v1/system/ttyd_configure', params, 'GET');
}

return baseclass.extend({
	// RPC methods - exposed via ubus
	getStatus: callStatus,
	getSystemInfo: callGetSystemInfo,
	getHealth: callGetHealth,
	getServiceHealth: function(refresh) {
		return callGetServiceHealth({ refresh: refresh ? 1 : 0 });
	},
	getComponents: callGetComponents,
	getComponentsByCategory: callGetComponentsByCategory,
	listServices: callListServices,
	serviceAction: callServiceAction,
	getLogs: callGetLogs,
	getDenoisedLogs: function(lines, filter, mode) {
		return callGetDenoisedLogs({ lines: lines, filter: filter, mode: mode });
	},
	getDenoiseStats: callGetDenoiseStats,
	backupConfig: callBackupConfig,
	restoreConfig: function(fileName, data) {
		if (typeof fileName === 'object')
			return callRestoreConfig(fileName);

		return callRestoreConfig({
			file_name: fileName,
			data: data
		});
	},
	getBackupSchedule: callGetBackupSchedule,
	setBackupSchedule: function(data) {
		return callSetBackupSchedule(data);
	},
	reboot: callReboot,
	getStorage: callGetStorage,
	getSettings: callGetSettings,
	saveSettings: callSaveSettings,

	collectDiagnostics: function(includeLogs, includeConfig, includeNetwork, anonymize, profile) {
		return callCollectDiagnostics({
			include_logs: includeLogs ? 1 : 0,
			include_config: includeConfig ? 1 : 0,
			include_network: includeNetwork ? 1 : 0,
			anonymize: anonymize ? 1 : 0,
			profile: profile || 'manual'
		});
	},

	listDiagnostics: callListDiagnostics,

	listDiagnosticProfiles: callListDiagnosticProfiles,

	getDiagnosticProfile: function(name) {
		return callGetDiagnosticProfile(name);
	},

	downloadDiagnostic: function(name) {
		return callDownloadDiagnostic({ name: name });
	},
	deleteDiagnostic: function(name) {
		return callDeleteDiagnostic({ name: name });
	},
	runDiagnosticTest: function(test) {
		return callRunDiagnosticTest(test);
	},

	uploadDiagnostics: function(name) {
		return callUploadDiagnostics({ name: name });
	},

	formatBytes: function(bytes) {
		if (!bytes || bytes <= 0)
			return '0 B';
		var units = ['B', 'KB', 'MB', 'GB'];
		var i = Math.floor(Math.log(bytes) / Math.log(1024));
		return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
	},

	remoteStatus: callRemoteStatus,
	remoteInstall: callRemoteInstall,
	remoteConfigure: function(data) {
		return callRemoteConfigure(data);
	},
	remoteCredentials: callRemoteGetCredentials,
	remoteServiceAction: function(action) {
		return callRemoteServiceAction({ action: action });
	},
	remoteSaveSettings: function(data) {
		return callRemoteSaveSettings(data);
	},

	// TTYD Web Console
	ttydStatus: callTtydStatus,
	ttydInstall: callTtydInstall,
	ttydStart: callTtydStart,
	ttydStop: callTtydStop,
	ttydConfigure: function(data) {
		return callTtydConfigure(data);
	}
});
