// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox Companion — options
const api = globalThis.browser ?? globalThis.chrome;

const DEFAULTS = {
  hubBase: "",
  modules: ["hub", "crowdsec", "waf", "wireguard", "peertube", "photoprism", "nextcloud"],
  cookieEndpoint: "/api/v1/avatar/cred/poke/youtube",
};

async function load() {
  const cfg = { ...DEFAULTS, ...(await api.storage.local.get(DEFAULTS)) };
  document.getElementById("hubBase").value = cfg.hubBase;
  document.getElementById("modules").value = cfg.modules.join(", ");
  document.getElementById("cookieEndpoint").value = cfg.cookieEndpoint;
}

async function save() {
  const hubBase = document.getElementById("hubBase").value.trim().replace(/\/+$/, "");
  const modules = document.getElementById("modules").value
    .split(",").map((s) => s.trim()).filter(Boolean);
  const cookieEndpoint = document.getElementById("cookieEndpoint").value.trim() || DEFAULTS.cookieEndpoint;
  await api.storage.local.set({ hubBase, modules, cookieEndpoint });
  const saved = document.getElementById("saved");
  saved.textContent = "✓ saved";
  setTimeout(() => (saved.textContent = ""), 1500);
}

document.addEventListener("DOMContentLoaded", () => {
  load();
  document.getElementById("save").addEventListener("click", save);
});
