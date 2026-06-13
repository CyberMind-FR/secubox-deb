// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: webext-toolbox :: popup controller

// NB: api.js (loaded first in this page) already declares `const ext` in the
// shared script scope — re-declaring it here is a "redeclaration of const ext"
// SyntaxError that aborts popup.js. Use api.ext instead.
const api = globalThis.SbxApi;
const $ = (id) => document.getElementById(id);

function show(which) {
  $("pair").hidden = which !== "pair";
  $("live").hidden = which !== "live";
}

function fillTopList(nodes) {
  const list = $("topList");
  list.innerHTML = "";
  (nodes || [])
    .slice()
    .sort((a, b) => (b.hits || 0) - (a.hits || 0))
    .slice(0, 12)
    .forEach((n) => {
      const row = document.createElement("div");
      row.className = "row";
      const dom = document.createElement("span");
      dom.className = "dom";
      dom.textContent = n.domain || n.id;
      row.appendChild(dom);
      if (n.opgrade_vendor) addTier(row, "opg", n.opgrade_vendor);
      else if (n.antibot_vendor) addTier(row, "ab", n.antibot_vendor);
      else if (n.cdn_vendor) addTier(row, "cdn", n.cdn_vendor);
      const hits = document.createElement("span");
      hits.className = "hits";
      hits.textContent = (n.hits || 0) + "×";
      row.appendChild(hits);
      list.appendChild(row);
    });
}
function addTier(row, cls, label) {
  const t = document.createElement("span");
  t.className = "tier " + cls;
  t.textContent = label;
  row.appendChild(t);
}

function paint(data) {
  const s = data.stats || {};
  $("sTrackers").textContent = s.total_trackers ?? 0;
  $("sSites").textContent = s.total_sites ?? 0;
  $("sAntibot").textContent = s.antibot_sites ?? 0;
  $("sOpgrade").textContent = s.opgrade_sites ?? 0;
  globalThis.renderGraph($("graph"), data);
  fillTopList(data.nodes);
}

async function load() {
  const cfg = await api.getConfig();
  $("ver").textContent = "v" + (api.ext.runtime.getManifest().version || "");

  // tunnel indicator
  api.r3Check(cfg.host).then((r) => {
    const dot = $("r3dot");
    dot.className = "r3 " + (r.tunnel ? "on" : "off");
    dot.title = r.tunnel ? `Tunnel R3 actif (${r.peer_ip || "?"})` : "Hors tunnel R3";
  });

  if (!cfg.token) {
    $("host").value = cfg.host;
    show("pair");
    return;
  }
  show("live");
  $("liveMsg").textContent = "Chargement…";
  try {
    const data = await api.graph(cfg.host, cfg.token, cfg.since);
    paint(data);
    $("liveMsg").textContent = "";
  } catch (e) {
    if (String(e.message) === "token-expired") {
      // token died — drop it and go back to pairing
      await api.setConfig({ token: "" });
      show("pair");
      $("host").value = cfg.host;
      $("pairMsg").textContent = "Session expirée — ré-appaire.";
    } else {
      $("liveMsg").textContent = "Erreur : " + e.message;
    }
  }
}

// ── events ──
$("pairBtn").addEventListener("click", async () => {
  const host = $("host").value.trim() || api.DEFAULTS.host;
  $("pairMsg").textContent = "Appairage…";
  try {
    await api.setConfig({ host });
    const token = await api.pair(host);
    await api.setConfig({ token });
    api.ext.runtime.sendMessage({ type: "refresh" });
    await load();
  } catch (e) {
    $("pairMsg").textContent = e.message + " (es-tu sur le tunnel ?)";
  }
});

$("openFull").addEventListener("click", async () => {
  const cfg = await api.getConfig();
  api.ext.tabs.create({ url: api.socialUrl(cfg.host, cfg.token) });
});
$("pdf").addEventListener("click", async () => {
  const cfg = await api.getConfig();
  api.ext.tabs.create({ url: api.reportUrl(cfg.host, cfg.token) });
});
$("wipe").addEventListener("click", async () => {
  if (!confirm("Effacer toutes tes données de cartographie sur la cabine ?")) return;
  const cfg = await api.getConfig();
  try {
    const r = await api.wipe(cfg.host, cfg.token);
    $("liveMsg").textContent = `Effacé : ${r.rows_deleted ?? 0} entrées.`;
    await api.setConfig({ token: "" });
    setTimeout(load, 800);
  } catch (e) {
    $("liveMsg").textContent = "Erreur effacement : " + e.message;
  }
});
$("settings").addEventListener("click", (e) => {
  e.preventDefault();
  api.ext.runtime.openOptionsPage();
});

load();
