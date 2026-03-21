'use strict';
// ============================================
// Core Status & Monitoring
// ============================================

async function callStatus(params) {
    return sbxFetch('/api/v1/qos/status', params, 'GET');
}

async function callListRules(params) {
    return sbxFetch('/api/v1/qos/list_rules', params, 'GET');
}

async function callAddRule(params) {
    return sbxFetch('/api/v1/qos/add_rule', params, 'POST');
}

async function callDeleteRule(params) {
    return sbxFetch('/api/v1/qos/delete_rule', params, 'POST');
}

async function callListQuotas(params) {
    return sbxFetch('/api/v1/qos/list_quotas', params, 'GET');
}

async function callGetQuota(params) {
    return sbxFetch('/api/v1/qos/get_quota', params, 'GET');
}

async function callSetQuota(params) {
    return sbxFetch('/api/v1/qos/set_quota', params, 'POST');
}

async function callResetQuota(params) {
    return sbxFetch('/api/v1/qos/reset_quota', params, 'GET');
}

async function callGetUsageRealtime(params) {
    return sbxFetch('/api/v1/qos/get_usage_realtime', params, 'GET');
}

async function callGetUsageHistory(params) {
    return sbxFetch('/api/v1/qos/get_usage_history', params, 'GET');
}

async function callGetMedia(params) {
    return sbxFetch('/api/v1/qos/get_media', params, 'GET');
}

async function callGetClasses(params) {
    return sbxFetch('/api/v1/qos/get_classes', params, 'GET');
}

// ============================================
// Smart QoS & DPI
// ============================================

async function callGetDpiApplications(params) {
    return sbxFetch('/api/v1/qos/get_dpi_applications', params, 'GET');
}

async function callGetSmartSuggestions(params) {
    return sbxFetch('/api/v1/qos/get_smart_suggestions', params, 'GET');
}

async function callApplyDpiRule(params) {
    return sbxFetch('/api/v1/qos/apply_dpi_rule', params, 'POST');
}

// ============================================
// Device Groups
// ============================================

async function callListGroups(params) {
    return sbxFetch('/api/v1/qos/list_groups', params, 'GET');
}

async function callGetGroup(params) {
    return sbxFetch('/api/v1/qos/get_group', params, 'GET');
}

async function callCreateGroup(params) {
    return sbxFetch('/api/v1/qos/create_group', params, 'POST');
}

async function callUpdateGroup(params) {
    return sbxFetch('/api/v1/qos/update_group', params, 'GET');
}

async function callDeleteGroup(params) {
    return sbxFetch('/api/v1/qos/delete_group', params, 'POST');
}

async function callAddToGroup(params) {
    return sbxFetch('/api/v1/qos/add_to_group', params, 'POST');
}

async function callRemoveFromGroup(params) {
    return sbxFetch('/api/v1/qos/remove_from_group', params, 'POST');
}

// ============================================
// Analytics
// ============================================

async function callGetAnalyticsSummary(params) {
    return sbxFetch('/api/v1/qos/get_analytics_summary', params, 'GET');
}

async function callGetHourlyData(params) {
    return sbxFetch('/api/v1/qos/get_hourly_data', params, 'GET');
}

async function callRecordStats(params) {
    return sbxFetch('/api/v1/qos/record_stats', params, 'GET');
}

// ============================================
// Device Profiles
// ============================================

async function callGetBuiltinProfiles(params) {
    return sbxFetch('/api/v1/qos/get_builtin_profiles', params, 'GET');
}

async function callListProfiles(params) {
    return sbxFetch('/api/v1/qos/list_profiles', params, 'GET');
}

async function callGetProfile(params) {
    return sbxFetch('/api/v1/qos/get_profile', params, 'GET');
}

async function callCreateProfile(params) {
    return sbxFetch('/api/v1/qos/create_profile', params, 'POST');
}

async function callUpdateProfile(params) {
    return sbxFetch('/api/v1/qos/update_profile', params, 'GET');
}

async function callDeleteProfile(params) {
    return sbxFetch('/api/v1/qos/delete_profile', params, 'POST');
}

async function callCloneProfile(params) {
    return sbxFetch('/api/v1/qos/clone_profile', params, 'GET');
}

async function callAssignProfileToDevice(params) {
    return sbxFetch('/api/v1/qos/assign_profile_to_device', params, 'GET');
}

async function callAssignProfileToGroup(params) {
    return sbxFetch('/api/v1/qos/assign_profile_to_group', params, 'GET');
}

async function callRemoveProfileAssignment(params) {
    return sbxFetch('/api/v1/qos/remove_profile_assignment', params, 'POST');
}

async function callListProfileAssignments(params) {
    return sbxFetch('/api/v1/qos/list_profile_assignments', params, 'GET');
}

// ============================================
// Parental Controls
// ============================================

async function callListParentalSchedules(params) {
    return sbxFetch('/api/v1/qos/list_parental_schedules', params, 'GET');
}

async function callCreateParentalSchedule(params) {
    return sbxFetch('/api/v1/qos/create_parental_schedule', params, 'POST');
}

async function callUpdateParentalSchedule(params) {
    return sbxFetch('/api/v1/qos/update_parental_schedule', params, 'GET');
}

async function callDeleteParentalSchedule(params) {
    return sbxFetch('/api/v1/qos/delete_parental_schedule', params, 'POST');
}

async function callToggleParentalSchedule(params) {
    return sbxFetch('/api/v1/qos/toggle_parental_schedule', params, 'GET');
}

async function callListPresetModes(params) {
    return sbxFetch('/api/v1/qos/list_preset_modes', params, 'GET');
}

async function callActivatePresetMode(params) {
    return sbxFetch('/api/v1/qos/activate_preset_mode', params, 'GET');
}

async function callGetFilterCategories(params) {
    return sbxFetch('/api/v1/qos/get_filter_categories', params, 'GET');
}

// ============================================
// Bandwidth Alerts
// ============================================

async function callGetAlertSettings(params) {
    return sbxFetch('/api/v1/qos/get_alert_settings', params, 'GET');
}

async function callUpdateAlertSettings(params) {
    return sbxFetch('/api/v1/qos/update_alert_settings', params, 'GET');
}

async function callConfigureEmail(params) {
    return sbxFetch('/api/v1/qos/configure_email', params, 'GET');
}

async function callConfigureSms(params) {
    return sbxFetch('/api/v1/qos/configure_sms', params, 'GET');
}

async function callTestNotification(params) {
    return sbxFetch('/api/v1/qos/test_notification', params, 'GET');
}

async function callGetAlertHistory(params) {
    return sbxFetch('/api/v1/qos/get_alert_history', params, 'GET');
}

async function callAcknowledgeAlert(params) {
    return sbxFetch('/api/v1/qos/acknowledge_alert', params, 'GET');
}

async function callGetPendingAlerts(params) {
    return sbxFetch('/api/v1/qos/get_pending_alerts', params, 'GET');
}

async function callCheckAlertThresholds(params) {
    return sbxFetch('/api/v1/qos/check_alert_thresholds', params, 'GET');
}

// ============================================
// Traffic Graphs
// ============================================

async function callGetRealtimeBandwidth(params) {
    return sbxFetch('/api/v1/qos/get_realtime_bandwidth', params, 'GET');
}

async function callGetHistoricalTraffic(params) {
    return sbxFetch('/api/v1/qos/get_historical_traffic', params, 'GET');
}

async function callGetDeviceTraffic(params) {
    return sbxFetch('/api/v1/qos/get_device_traffic', params, 'GET');
}

async function callGetTopTalkers(params) {
    return sbxFetch('/api/v1/qos/get_top_talkers', params, 'GET');
}

async function callGetProtocolBreakdown(params) {
    return sbxFetch('/api/v1/qos/get_protocol_breakdown', params, 'GET');
}

// ============================================
// Export API Module
// ============================================

return baseclass.extend({
	// Core
	getStatus: callStatus,
	listRules: callListRules,
	addRule: callAddRule,
	deleteRule: callDeleteRule,
	listQuotas: callListQuotas,
	getQuota: callGetQuota,
	setQuota: callSetQuota,
	resetQuota: callResetQuota,
	getUsageRealtime: callGetUsageRealtime,
	getUsageHistory: callGetUsageHistory,
	getMedia: callGetMedia,
	getClasses: callGetClasses,

	// Smart QoS
	getDpiApplications: callGetDpiApplications,
	getSmartSuggestions: callGetSmartSuggestions,
	applyDpiRule: callApplyDpiRule,

	// Groups
	listGroups: callListGroups,
	getGroup: callGetGroup,
	createGroup: callCreateGroup,
	updateGroup: callUpdateGroup,
	deleteGroup: callDeleteGroup,
	addToGroup: callAddToGroup,
	removeFromGroup: callRemoveFromGroup,

	// Analytics
	getAnalyticsSummary: callGetAnalyticsSummary,
	getHourlyData: callGetHourlyData,
	recordStats: callRecordStats,

	// Profiles
	getBuiltinProfiles: callGetBuiltinProfiles,
	listProfiles: callListProfiles,
	getProfile: callGetProfile,
	createProfile: callCreateProfile,
	updateProfile: callUpdateProfile,
	deleteProfile: callDeleteProfile,
	cloneProfile: callCloneProfile,
	assignProfileToDevice: callAssignProfileToDevice,
	assignProfileToGroup: callAssignProfileToGroup,
	removeProfileAssignment: callRemoveProfileAssignment,
	listProfileAssignments: callListProfileAssignments,

	// Parental Controls
	listParentalSchedules: callListParentalSchedules,
	createParentalSchedule: callCreateParentalSchedule,
	updateParentalSchedule: callUpdateParentalSchedule,
	deleteParentalSchedule: callDeleteParentalSchedule,
	toggleParentalSchedule: callToggleParentalSchedule,
	listPresetModes: callListPresetModes,
	activatePresetMode: callActivatePresetMode,
	getFilterCategories: callGetFilterCategories,

	// Alerts
	getAlertSettings: callGetAlertSettings,
	updateAlertSettings: callUpdateAlertSettings,
	configureEmail: callConfigureEmail,
	configureSms: callConfigureSms,
	testNotification: callTestNotification,
	getAlertHistory: callGetAlertHistory,
	acknowledgeAlert: callAcknowledgeAlert,
	getPendingAlerts: callGetPendingAlerts,
	checkAlertThresholds: callCheckAlertThresholds,

	// Traffic Graphs
	getRealtimeBandwidth: callGetRealtimeBandwidth,
	getHistoricalTraffic: callGetHistoricalTraffic,
	getDeviceTraffic: callGetDeviceTraffic,
	getTopTalkers: callGetTopTalkers,
	getProtocolBreakdown: callGetProtocolBreakdown
});
