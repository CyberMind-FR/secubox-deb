/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SECUBOX API UTILITIES — Safe JSON Fetch with Error Recovery
 *  v1.0.0 — Robust API handling for all SecuBox modules
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  SecuBox-Deb :: Shared API Utilities
 *  CyberMind — https://cybermind.fr
 *  Author: Gerald Kerma <gandalf@gk2.net>
 *  License: Proprietary / ANSSI CSPN candidate
 *
 *  Features:
 *  - Safe JSON parsing (never throws on HTML responses)
 *  - Automatic 401 redirect to login
 *  - Timeout handling
 *  - Graceful degradation on network errors
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 */

(function(global) {
    'use strict';

    const DEFAULT_TIMEOUT = 10000;  // 10s default timeout
    const VERSION = '1.0.0';

    /**
     * Safe JSON parse - never throws, returns fallback on error
     * @param {string} text - Text to parse
     * @param {*} fallback - Fallback value on error (default: null)
     * @returns {*} Parsed JSON or fallback
     */
    function safeJsonParse(text, fallback) {
        if (!text || typeof text !== 'string') return fallback !== undefined ? fallback : null;

        // Quick check: if starts with < it's definitely HTML
        var trimmed = text.trim();
        if (trimmed.charAt(0) === '<') {
            console.warn('[API] Response is HTML, not JSON');
            return fallback !== undefined ? fallback : null;
        }

        try {
            return JSON.parse(text);
        } catch (e) {
            console.warn('[API] JSON parse error:', e.message, '- First 100 chars:', text.substring(0, 100));
            return fallback !== undefined ? fallback : null;
        }
    }

    /**
     * Get auth token from localStorage
     * @returns {string|null} JWT token or null
     */
    function getToken() {
        try {
            return localStorage.getItem('sbx_token');
        } catch (e) {
            return null;
        }
    }

    /**
     * Build headers with optional auth
     * @param {Object} extra - Extra headers to include
     * @returns {Object} Headers object
     */
    function buildHeaders(extra) {
        var headers = { 'Content-Type': 'application/json' };
        var token = getToken();
        if (token) {
            headers['Authorization'] = 'Bearer ' + token;
        }
        if (extra) {
            Object.keys(extra).forEach(function(key) {
                headers[key] = extra[key];
            });
        }
        return headers;
    }

    /**
     * Safe fetch with JSON response handling
     * Handles all error cases gracefully without throwing
     *
     * @param {string} url - URL to fetch
     * @param {Object} options - Fetch options (method, body, headers, etc.)
     * @param {number} timeout - Timeout in ms (default: 10000)
     * @returns {Promise<Object>} Response object: { ok, status, data, error }
     */
    async function safeFetch(url, options, timeout) {
        timeout = timeout || DEFAULT_TIMEOUT;
        var ctrl = new AbortController();
        var tm = setTimeout(function() { ctrl.abort(); }, timeout);

        try {
            var fetchOpts = Object.assign({}, options || {});
            fetchOpts.signal = ctrl.signal;

            // Add default headers if not provided
            if (!fetchOpts.headers) {
                fetchOpts.headers = buildHeaders();
            }

            var res = await fetch(url, fetchOpts);
            clearTimeout(tm);

            // Handle 401 - redirect to login
            if (res.status === 401) {
                console.log('[API] 401 Unauthorized, redirecting to login');
                if (!/\/login\.html$/.test(location.pathname)) window.location = '/login.html?redirect=' + encodeURIComponent(window.location.pathname);
                return { ok: false, status: 401, error: 'Unauthorized', data: null };
            }

            // Get response text
            var text = '';
            try {
                text = await res.text();
            } catch (e) {
                console.warn('[API] Error reading response body:', e.message);
            }

            // Check content type
            var ct = res.headers.get('content-type') || '';
            var isJson = ct.includes('application/json') ||
                        (text.trim().startsWith('{') || text.trim().startsWith('['));

            if (!res.ok) {
                // Try to parse error message from JSON response
                var errorData = isJson ? safeJsonParse(text, {}) : {};
                var errorMsg = errorData.detail || errorData.message || errorData.error || ('HTTP ' + res.status);
                return { ok: false, status: res.status, error: errorMsg, data: errorData };
            }

            if (!isJson) {
                console.warn('[API] Response is not JSON:', ct, '- First 100 chars:', text.substring(0, 100));
                return { ok: false, status: res.status, error: 'Response is not JSON', data: null };
            }

            var data = safeJsonParse(text, null);
            if (data === null) {
                return { ok: false, status: res.status, error: 'Invalid JSON response', data: null };
            }

            return { ok: true, status: res.status, data: data, error: null };

        } catch (e) {
            clearTimeout(tm);

            if (e.name === 'AbortError') {
                console.warn('[API] Request timeout:', url);
                return { ok: false, status: 0, error: 'Request timeout', data: null };
            }

            console.warn('[API] Network error:', e.message);
            return { ok: false, status: 0, error: e.message || 'Network error', data: null };
        }
    }

    /**
     * Simple API wrapper - returns data directly or empty object on error
     * Use this for simple cases where you just want the data
     *
     * @param {string} baseUrl - Base API URL (e.g., '/api/v1/cyberfeed')
     * @param {string} path - API path (e.g., '/feeds')
     * @param {Object} options - Fetch options
     * @returns {Promise<Object>} Response data or empty object
     */
    async function api(baseUrl, path, options) {
        var url = baseUrl + (path || '');
        var result = await safeFetch(url, options);
        return result.ok ? result.data : {};
    }

    /**
     * Create a module-specific API function
     *
     * @param {string} baseUrl - Base API URL for the module
     * @returns {Function} API function bound to baseUrl
     */
    function createModuleApi(baseUrl) {
        return function(path, options) {
            return api(baseUrl, path, options);
        };
    }

    /**
     * POST JSON data
     *
     * @param {string} url - Full URL
     * @param {Object} data - Data to POST
     * @returns {Promise<Object>} Response data or empty object
     */
    async function postJson(url, data) {
        var result = await safeFetch(url, {
            method: 'POST',
            headers: buildHeaders(),
            body: JSON.stringify(data || {})
        });
        return result.ok ? result.data : {};
    }

    /**
     * DELETE request
     *
     * @param {string} url - Full URL
     * @returns {Promise<Object>} Response data or empty object
     */
    async function deleteRequest(url) {
        var result = await safeFetch(url, {
            method: 'DELETE',
            headers: buildHeaders()
        });
        return result.ok ? result.data : {};
    }

    // Export to global scope
    global.SecuBoxAPI = {
        version: VERSION,
        safeJsonParse: safeJsonParse,
        safeFetch: safeFetch,
        api: api,
        createModuleApi: createModuleApi,
        postJson: postJson,
        deleteRequest: deleteRequest,
        getToken: getToken,
        buildHeaders: buildHeaders
    };

    // Also export individual functions for convenience
    global.safeJsonParse = safeJsonParse;
    global.safeFetch = safeFetch;

    console.log('[SecuBoxAPI] v' + VERSION + ' loaded');

})(typeof window !== 'undefined' ? window : this);
