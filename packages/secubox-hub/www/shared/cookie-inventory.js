// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SECUBOX COOKIE INVENTORY — browser-side document.cookie snapshotter
 *  v1.0.0 — Companion of the mitmproxy cookie_audit addon
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  SecuBox-Deb :: Cookie Inventory
 *  CyberMind — https://cybermind.fr
 *  License: Proprietary / ANSSI CSPN candidate
 *
 *  Snapshots document.cookie at DOMContentLoaded, +2s post-load and on
 *  visibilitychange. Cookie values are sha256-hashed via SubtleCrypto — the
 *  raw value never leaves the page. POSTed to /api/v1/cookie-audit/ingest
 *  with credentials:'omit'. Operator-owned RGPD/ePrivacy audit only.
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 */
(function () {
    'use strict';
    if (window.__SBX_COOKIE_INVENTORY__) return;
    window.__SBX_COOKIE_INVENTORY__ = true;

    var VERSION = '1.0.0';
    var INGEST_URL = window.SECUBOX_COOKIE_AUDIT_INGEST
        || '/api/v1/cookie-audit/ingest';
    var POST_LOAD_DELAY_MS = 2000;
    var MAX_SNAPSHOTS = 8;
    var snapshotsSent = 0;

    function hasSubtle() {
        return !!(window.crypto && window.crypto.subtle && window.TextEncoder);
    }

    async function sha256Hex(s) {
        if (!hasSubtle()) return null;
        try {
            var enc = new TextEncoder().encode(s || '');
            var buf = await crypto.subtle.digest('SHA-256', enc);
            var bytes = new Uint8Array(buf);
            var hex = '';
            for (var i = 0; i < bytes.length; i++) {
                hex += bytes[i].toString(16).padStart(2, '0');
            }
            return hex;
        } catch (e) {
            return null;
        }
    }

    function parseCookies(raw) {
        if (!raw) return [];
        return raw.split(';').map(function (kv) {
            var eq = kv.indexOf('=');
            if (eq < 0) return { name: kv.trim(), value: '' };
            return { name: kv.slice(0, eq).trim(), value: kv.slice(eq + 1) };
        }).filter(function (c) { return c.name; });
    }

    async function buildPayload(reason) {
        var entries = parseCookies(document.cookie);
        var cookies = [];
        for (var i = 0; i < entries.length; i++) {
            var hash = await sha256Hex(entries[i].value);
            cookies.push({ name: entries[i].name, value_hash: hash });
        }
        return {
            host: location.hostname,
            path: location.pathname,
            ts: new Date().toISOString(),
            ua: navigator.userAgent,
            reason: reason,
            cookies: cookies,
            version: VERSION
        };
    }

    async function snapshot(reason) {
        if (snapshotsSent >= MAX_SNAPSHOTS) return;
        try {
            var payload = await buildPayload(reason);
            await fetch(INGEST_URL, {
                method: 'POST',
                credentials: 'omit',
                mode: 'cors',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            snapshotsSent++;
        } catch (e) {
            // Audit is best-effort. Never break the host page.
        }
    }

    function schedule() {
        snapshot('initial');
        setTimeout(function () { snapshot('post-load'); }, POST_LOAD_DELAY_MS);
        document.addEventListener('visibilitychange', function () {
            if (document.visibilityState === 'visible') snapshot('visible');
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', schedule);
    } else {
        schedule();
    }

    window.SecuBoxCookieInventory = {
        version: VERSION,
        snapshotNow: function () { return snapshot('manual'); }
    };
})();
