'use strict';
/**
 * CDN Cache API
 * Package: luci-app-cdn-cache
 * RPCD object: luci.cdn-cache
 */

// Version: 0.5.0

async function callStatus(params) {
    return sbxFetch('/api/v1/cdn/status', params, 'GET');
}

async function callStats(params) {
    return sbxFetch('/api/v1/cdn/stats', params, 'GET');
}

async function callCacheList(params) {
    return sbxFetch('/api/v1/cdn/cache_list', params, 'GET');
}

async function callTopDomains(params) {
    return sbxFetch('/api/v1/cdn/top_domains', params, 'GET');
}

async function callBandwidthSavings(params) {
    return sbxFetch('/api/v1/cdn/bandwidth_savings', params, 'POST');
}

async function callPurgeCache(params) {
    return sbxFetch('/api/v1/cdn/purge_cache', params, 'POST');
}

async function callPurgeDomain(params) {
    return sbxFetch('/api/v1/cdn/purge_domain', params, 'POST');
}

async function callPreloadUrl(params) {
    return sbxFetch('/api/v1/cdn/preload_url', params, 'GET');
}

async function callGetPolicies(params) {
    return sbxFetch('/api/v1/cdn/policies', params, 'GET');
}

async function callAddPolicy(params) {
    return sbxFetch('/api/v1/cdn/add_policy', params, 'POST');
}

async function callRemovePolicy(params) {
    return sbxFetch('/api/v1/cdn/remove_policy', params, 'POST');
}

// Specification-compliant methods (rules = policies)
async function callListRules(params) {
    return sbxFetch('/api/v1/cdn/list_rules', params, 'GET');
}

async function callAddRule(params) {
    return sbxFetch('/api/v1/cdn/add_rule', params, 'POST');
}

async function callDeleteRule(params) {
    return sbxFetch('/api/v1/cdn/delete_rule', params, 'POST');
}

async function callSetLimits(params) {
    return sbxFetch('/api/v1/cdn/set_limits', params, 'POST');
}

function formatBytes(bytes) {
	if (!bytes || bytes === 0) return '0 B';
	var k = 1024;
	var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
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

function formatHitRatio(hits, misses) {
	var total = hits + misses;
	if (total === 0) return '0%';
	return ((hits / total) * 100).toFixed(1) + '%';
}

return baseclass.extend({
	getStatus: callStatus,
	getStats: callStats,
	getCacheList: callCacheList,
	getTopDomains: callTopDomains,
	getBandwidthSavings: callBandwidthSavings,
	purgeCache: callPurgeCache,
	purgeDomain: callPurgeDomain,
	preloadUrl: callPreloadUrl,
	// Policy methods
	getPolicies: callGetPolicies,
	addPolicy: callAddPolicy,
	removePolicy: callRemovePolicy,
	// Specification-compliant methods (rules = policies)
	listRules: callListRules,
	addRule: callAddRule,
	deleteRule: callDeleteRule,
	setLimits: callSetLimits,
	// Utility functions
	formatBytes: formatBytes,
	formatUptime: formatUptime,
	formatHitRatio: formatHitRatio
});
