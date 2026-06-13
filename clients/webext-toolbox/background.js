// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: webext-toolbox :: background
// Keeps the toolbar badge in sync with the live tracker count and
// re-pairs over the R3 tunnel when the token expires. Works as a
// Chromium MV3 service worker (importScripts) AND a Firefox event page
// (api.js preloaded via background.scripts).

if (typeof importScripts === "function") {
  // Chromium service worker: api.js isn't auto-loaded, pull it in.
  try { importScripts("api.js"); } catch (_) {}
}

// NB: do NOT declare `const ext` here — api.js already declares it in the
// shared script scope (event page) / worker global (importScripts), and a
// second `const ext` is a "redeclaration of const ext" SyntaxError that
// kills the whole background script. Use api.ext instead.
const api = globalThis.SbxApi;

const ALARM = "sbx-refresh";
const PERIOD_MIN = 1; // poll the cabine once a minute

function setBadge(text, color) {
  try {
    api.ext.action.setBadgeText({ text: text || "" });
    if (color) ext.action.setBadgeBackgroundColor({ color });
  } catch (_) {}
}

// Pull the graph, update the badge with the live tracker count. Auto
// re-pairs once if the stored token has expired.
async function refresh() {
  const cfg = await api.getConfig();
  if (!cfg.host) { setBadge("", "#6b6b7a"); return; }

  let token = cfg.token;
  const run = async (tok) => api.graph(cfg.host, tok, cfg.since);

  try {
    if (!token) token = await api.pair(cfg.host);
    let data;
    try {
      data = await run(token);
    } catch (e) {
      if (String(e.message) === "token-expired") {
        token = await api.pair(cfg.host);   // one silent re-pair
        data = await run(token);
      } else throw e;
    }
    await api.setConfig({ token });
    const n = (data.stats && data.stats.total_trackers) || 0;
    // colour escalates with operator-grade / anti-bot presence
    const opg = (data.stats && data.stats.opgrade_sites) || 0;
    const ab = (data.stats && data.stats.antibot_sites) || 0;
    const color = opg > 0 ? "#6e40c9" : ab > 0 ? "#e63946" : "#c9a84c";
    setBadge(n > 999 ? "999+" : String(n), color);
    await ext.storage.local.set({ lastStats: data.stats || {}, lastError: "" });
  } catch (e) {
    setBadge("!", "#6b6b7a");
    await ext.storage.local.set({ lastError: String(e.message || e) });
  }
}

api.ext.runtime.onInstalled.addListener(() => {
  api.ext.alarms.create(ALARM, { periodInMinutes: PERIOD_MIN });
  refresh();
});
api.ext.runtime.onStartup && api.ext.runtime.onStartup.addListener(() => {
  api.ext.alarms.create(ALARM, { periodInMinutes: PERIOD_MIN });
  refresh();
});
api.ext.alarms.onAlarm.addListener((a) => { if (a.name === ALARM) refresh(); });

// popup asks for an immediate refresh after pairing / config change
api.ext.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "refresh") {
    refresh().then(() => sendResponse({ ok: true }));
    return true; // async response
  }
});
