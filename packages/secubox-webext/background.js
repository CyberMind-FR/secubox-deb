// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox Companion — background event page (P1)
// Periodically probes the first configured module and reflects overall health
// on the toolbar badge. Kept minimal; richer metrics arrive with the sidebar
// widget (#401 P2).
const api = globalThis.browser ?? globalThis.chrome;

const DEFAULTS = {
  hubBase: "",
  modules: ["hub", "waf", "wireguard", "peertube", "photoprism", "nextcloud"],
};

async function refreshBadge() {
  const cfg = { ...DEFAULTS, ...(await api.storage.local.get(DEFAULTS)) };
  if (!cfg.hubBase) {
    api.action.setBadgeText({ text: "" });
    return;
  }
  let up = 0;
  await Promise.all(cfg.modules.map(async (mod) => {
    try {
      const r = await fetch(`${cfg.hubBase}/api/v1/${mod}/health`, {
        credentials: "include", cache: "no-store", signal: AbortSignal.timeout(4000),
      });
      if (r.ok) up++;
    } catch { /* down */ }
  }));
  const total = cfg.modules.length;
  api.action.setBadgeText({ text: up === total ? "" : `${total - up}` });
  api.action.setBadgeBackgroundColor({ color: up === total ? "#00ff41" : "#e63946" });
}

// Probe every 5 min (alarms survive event-page suspension).
api.alarms?.create("secubox-probe", { periodInMinutes: 5 });
api.alarms?.onAlarm.addListener((a) => { if (a.name === "secubox-probe") refreshBadge(); });
api.runtime.onStartup?.addListener(refreshBadge);
api.runtime.onInstalled?.addListener(refreshBadge);
refreshBadge();
