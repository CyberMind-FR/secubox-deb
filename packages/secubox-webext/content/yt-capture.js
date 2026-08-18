// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox Companion — YouTube PO-token capture (content script, isolated world)
// Injects a page-world hook that watches YouTube's own streaming requests for
// the `pot` (PO token) param + visitor_data, and stashes them in extension
// storage so the popup can relay them to the avatar broker (#402 / #401 P4).
// EXPERIMENTAL: YouTube obfuscates + rotates these; best-effort only.
const api = globalThis.browser ?? globalThis.chrome;

try {
  const s = document.createElement("script");
  s.src = api.runtime.getURL("content/yt-hook.js");
  s.async = false;
  (document.head || document.documentElement).appendChild(s);
  s.remove();
} catch (e) { /* page CSP may block; nothing we can do */ }

window.addEventListener("message", (e) => {
  if (e.source !== window || !e.data || e.data.__secubox !== "yt-pot") return;
  const upd = {};
  if (e.data.po_token) { upd.yt_po_token = e.data.po_token; upd.yt_po_token_at = Date.now(); }
  if (e.data.visitor_data) upd.yt_visitor_data = e.data.visitor_data;
  if (Object.keys(upd).length) api.storage.local.set(upd);
});
