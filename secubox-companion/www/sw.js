// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: service worker — offline app shell
//
// Caches ONLY the app itself (shell + core + modules), so the Companion opens
// offline. It never caches the box API: those responses are per-token and are
// cached separately (IndexedDB) by core/api.js, which also queues writes.
// Same-origin app assets → stale-while-revalidate. Box API (cross-origin) →
// passthrough (the page handles offline reads/queue).

const VERSION = 'sbx-companion-v23';
const SHELL = [
  './', './index.html', './manifest.webmanifest',
  './styles/charte.css', './styles/fonts.css',
  './styles/fonts/space-grotesk-400.woff2', './styles/fonts/space-grotesk-500.woff2',
  './styles/fonts/space-grotesk-700.woff2', './styles/fonts/jetbrains-mono-400.woff2',
  './styles/fonts/jetbrains-mono-700.woff2',
  './core/app.js', './core/api.js', './core/store.js',
  './core/registry.js', './core/auth.js', './core/ui.js', './core/metrics.js',
  './modules/index.json',
];

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const c = await caches.open(VERSION);
    await c.addAll(SHELL.map(u => new Request(u, { cache: 'reload' }))).catch(() => {});
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== VERSION) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;                    // writes never touched by SW
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;     // box API: let the page handle it

  // NETWORK-FIRST for app assets: always serve fresh code when online (a deploy
  // takes effect on the next load, not two loads later), fall back to cache only
  // when offline. Avoids the stale-serving that made every fix need reloads.
  e.respondWith((async () => {
    const cache = await caches.open(VERSION);
    try {
      // `cache: 'reload'` bypasses the BROWSER HTTP cache so a deploy is live on
      // the next load — a plain fetch(req) can hand back a heuristically-cached
      // old view.js (JS carries no Cache-Control here), which is what made every
      // fix appear to need repeated hard refreshes.
      const res = await fetch(new Request(req, { cache: 'reload' }));
      if (res && res.ok) cache.put(req, res.clone());
      return res;
    } catch {
      return (await cache.match(req)) || Response.error();
    }
  })());
});
