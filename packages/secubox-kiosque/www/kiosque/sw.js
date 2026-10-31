// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
// Service worker du kiosque (#3330) : met en cache les SEULS fichiers statiques de /kiosque/ (hors ligne, installation).
// Jamais une réponse d'API : /api/ passe toujours par le réseau, n'est ni lue ni écrite dans le cache.
'use strict';
const CACHE = 'kiosque-0.1.0';
const STATIQUES = ['/kiosque/', '/kiosque/index.html', '/kiosque/kiosque.css', '/kiosque/kiosque.js',
  '/kiosque/manifest.webmanifest', '/kiosque/icone.svg'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(STATIQUES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== self.location.origin || !STATIQUES.includes(u.pathname)) {
    return;   // API, autre origine, autre page : le navigateur fait la requête normalement, rien n'est mis en cache
  }
  // réseau d'abord (version à jour), cache en repli hors ligne
  e.respondWith(fetch(e.request).then((r) => {
    if (r.ok) { const copie = r.clone(); caches.open(CACHE).then((c) => c.put(e.request, copie)); }
    return r;
  }).catch(() => caches.match(e.request)));
});
