// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: webext-toolbox :: api
// Thin client over the R3 toolbox social endpoints. Shared by the
// background service worker and the popup. Cross-origin fetches are
// allowed because the extension holds host_permissions for the cabine
// vhosts — no server-side CORS needed.

// browser (Firefox promise API) || chrome (Chromium / FF MV3 SW)
const ext = globalThis.browser || globalThis.chrome;

const DEFAULTS = {
  host: "kbin.gk2.secubox.in",
  token: "",
  since: 86400,
};

// base URL from a stored host (accept bare host or full origin)
function baseUrl(host) {
  const h = (host || DEFAULTS.host).trim().replace(/\/+$/, "");
  if (/^https?:\/\//i.test(h)) return h;
  return `https://${h}`;
}

async function getConfig() {
  const stored = await ext.storage.local.get(["host", "token", "since"]);
  return { ...DEFAULTS, ...stored };
}

async function setConfig(patch) {
  await ext.storage.local.set(patch);
  return getConfig();
}

// Extract the HMAC token from a /social/{token} URL path.
function tokenFromUrl(url) {
  try {
    const u = new URL(url);
    const m = u.pathname.match(/\/social\/([^/?#]+)/);
    if (m && m[1] !== "me" && m[1].split(".").length === 4) return m[1];
  } catch (_) {}
  return null;
}

// Pair: hit /social/me over the tunnel; it 303-redirects to
// /social/{token}. fetch follows the redirect, so response.url carries
// the minted token. Returns the token or throws.
async function pair(host) {
  const url = `${baseUrl(host)}/social/me`;
  const resp = await fetch(url, { redirect: "follow", credentials: "omit" });
  const tok = tokenFromUrl(resp.url);
  if (!tok) throw new Error("pairing failed — not on the R3 tunnel?");
  return tok;
}

// r3-check: is this client on the R3 tunnel right now?
async function r3Check(host) {
  try {
    const resp = await fetch(`${baseUrl(host)}/wg/r3-check`, { credentials: "omit" });
    if (!resp.ok) return { tunnel: false, peer_ip: null };
    return await resp.json();
  } catch (_) {
    return { tunnel: false, peer_ip: null };
  }
}

// graph: the per-session cartographie JSON. Throws on HTTP error so the
// caller can show "token expired — re-pair".
async function graph(host, token, since) {
  const qs = new URLSearchParams({ since: String(since || DEFAULTS.since) });
  const resp = await fetch(`${baseUrl(host)}/social/graph/${token}?${qs}`, {
    credentials: "omit",
  });
  if (resp.status === 403 || resp.status === 404) {
    throw new Error("token-expired");
  }
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return await resp.json();
}

// RGPD art.17 wipe.
async function wipe(host, token) {
  const resp = await fetch(`${baseUrl(host)}/social/wipe/${token}`, {
    method: "POST",
    credentials: "omit",
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return await resp.json();
}

function socialUrl(host, token) {
  return `${baseUrl(host)}/social/${token}`;
}
function reportUrl(host, token) {
  return `${baseUrl(host)}/social/report/${token}.pdf`;
}

const SbxApi = {
  DEFAULTS,
  ext,
  baseUrl,
  getConfig,
  setConfig,
  pair,
  r3Check,
  graph,
  wipe,
  socialUrl,
  reportUrl,
  tokenFromUrl,
};

// Usable both as a classic background script (globalThis) and an ES-less
// service worker. No module syntax to stay loadable as plain script.
globalThis.SbxApi = SbxApi;
