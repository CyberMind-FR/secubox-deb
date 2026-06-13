// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
const api = globalThis.SbxApi;
const $ = (id) => document.getElementById(id);

async function load() {
  const cfg = await api.getConfig();
  $("host").value = cfg.host;
  $("token").value = cfg.token || "";
  $("since").value = String(cfg.since);
}

$("save").addEventListener("click", async () => {
  await api.setConfig({
    host: $("host").value.trim() || api.DEFAULTS.host,
    token: $("token").value.trim(),
    since: parseInt($("since").value, 10) || api.DEFAULTS.since,
  });
  api.ext.runtime.sendMessage({ type: "refresh" });
  $("msg").textContent = "Enregistré ✓";
  setTimeout(() => ($("msg").textContent = ""), 1500);
});

load();
