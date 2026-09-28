// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SBX OS :: SERVICE WORKER — « même loin de la box, votre monde vous suit ».
 *
 * TROIS STRATÉGIES, ET LE CHOIX SE FAIT PAR NATURE DE LA RESSOURCE. Une seule
 * stratégie pour tout donne toujours un mauvais compromis : soit l'application
 * met du temps à s'ouvrir, soit elle affiche des données périmées.
 *
 *   COQUILLE (HTML, CSS, JS)      cache d'abord, réseau en arrière-plan
 *     L'application s'ouvre INSTANTANÉMENT, même hors ligne. La nouvelle
 *     version est récupérée en silence et servie au lancement suivant.
 *
 *   MANIFESTE (le bureau)         réseau d'abord, cache en secours
 *     Le bureau doit refléter ce que la Mine a décidé. Servir un manifeste
 *     périmé ferait disparaître une carlette qu'on vient d'accorder — ou
 *     l'inverse. Hors ligne, le dernier connu vaut mieux que rien.
 *
 *   MÉDIAS (vidéo, images)        cache d'abord, jamais rafraîchi
 *     Un épisode déjà vu ne change pas. On le garde tel quel.
 *
 * CE QU'ON NE MET JAMAIS EN CACHE. Les réponses d'API autres que le manifeste,
 * et tout ce qui n'est pas un GET. Un POST mis en cache rejouerait une action ;
 * une réponse d'API gardée montrerait l'état d'hier en croyant montrer celui
 * d'aujourd'hui.
 *
 * PÉRIMÈTRE (v6, #1605). L'origine est PARTAGÉE avec le Hall : ce worker ne
 * traite que /sbxos/, ne purge que ses propres caches `sbxos-*`, laisse au
 * réseau l'aperçu Aurora (/sbxos/aurora/, /sbxos/assets/, /sbxos/art/), ne met
 * jamais en cache une réponse privée, et sait se retirer : /sbxos/offline/
 * kill.json = {"kill":true} le désinscrit et vide ses caches.
 *
 * LE NOM DU CACHE PORTE LA VERSION. Changer `VERSION` suffit à repartir propre :
 * l'ancien cache est effacé à l'activation. C'est ce qui évite qu'une coquille
 * d'hier serve un JavaScript d'aujourd'hui.
 */

const VERSION = 'sbxos-v6';
const CACHE_COQUILLE = `${VERSION}-coquille`;
const CACHE_MANIFESTE = `${VERSION}-manifeste`;
const CACHE_MEDIAS = `${VERSION}-medias`;
const BASE = '/sbxos/';

/** La coquille, en chemins ABSOLUS : la portée ne dépend plus de l'URL du worker. */
const COQUILLE = [
  '/sbxos/', '/sbxos/index.html', '/sbxos/manifest.webmanifest',
  '/sbxos/ui/styles.css', '/sbxos/ui/sbx-carlette.js', '/sbxos/ui/sbx-damier.js',
  '/sbxos/hall/hall.js', '/sbxos/mine/mine.js', '/sbxos/mine/clone.js', '/sbxos/mine/apercu.js',
];

/** Laissés au réseau même sous /sbxos/ : l'aperçu Aurora et ses fichiers. */
const HORS_PERIMETRE = ['/sbxos/aurora/', '/sbxos/assets/', '/sbxos/art/', '/sbxos/offline/'];

const MEDIAS_MAX = 40;
const KILL_URL = '/sbxos/offline/kill.json';
let dernierKill = 0;

/** Interrupteur d'arrêt : seul un 200 JSON {"kill":true} retire le worker. */
async function verifieKill(force) {
  const maint = Date.now();
  if (!force && maint - dernierKill < 3600e3) return false;
  dernierKill = maint;
  try {
    const r = await fetch(KILL_URL, { cache: 'no-store', credentials: 'omit' });
    if (r.status !== 200) return false;
    const j = await r.json();
    if (!j || j.kill !== true) return false;
  } catch (e) { return false; }
  const noms = await caches.keys();
  await Promise.all(noms.filter(n => n.startsWith('sbxos-')).map(n => caches.delete(n)));
  await self.registration.unregister();
  return true;
}

self.addEventListener('install', (ev) => {
  ev.waitUntil((async () => {
    const c = await caches.open(CACHE_COQUILLE);
    await Promise.all(COQUILLE.map(async (u) => {
      try { await c.add(new Request(u, { cache: 'reload' })); }
      catch (e) { console.warn('[sw] coquille, absent :', u); }
    }));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (ev) => {
  ev.waitUntil((async () => {
    // SEULEMENT nos propres caches d'une autre version : le Hall partage l'origine.
    const noms = await caches.keys();
    await Promise.all(noms
      .filter(n => n.startsWith('sbxos-') && !n.startsWith(VERSION + '-'))
      .map(n => caches.delete(n)));
    if (await verifieKill(true)) return;
    await self.clients.claim();
  })());
});

function estMedia(url) {
  return /\.(?:mp4|webm|m4v|mp3|ogg|oga|opus|webp|png|jpe?g|avif|svg)$/i.test(url.pathname);
}

function estManifeste(url) {
  return url.pathname.endsWith('/manifeste.json') || url.pathname.endsWith('/curation.json');
}

/** Une réponse qu'on a le droit de garder : publique, complète, sans cookie posé. */
function gardable(r) {
  if (!r || !r.ok || r.status !== 200 || r.type === 'opaque') return false;
  const cc = (r.headers.get('Cache-Control') || '').toLowerCase();
  if (/(^|[,\s])(private|no-store)([,\s]|$)/.test(cc)) return false;
  if (r.headers.has('Set-Cookie')) return false;
  return true;
}

async function tailleMedias() {
  const c = await caches.open(CACHE_MEDIAS);
  const clefs = await c.keys();
  for (let i = 0; i < clefs.length - MEDIAS_MAX; i++) await c.delete(clefs[i]);
}

async function cacheDAbord(req, nomCache, { rafraichir = false, clef = req } = {}) {
  const c = await caches.open(nomCache);
  const garde = await c.match(clef);
  if (garde) {
    if (rafraichir) {
      fetch(req).then(r => { if (gardable(r)) c.put(clef, r.clone()); }).catch(() => {});
    }
    return garde;
  }
  const r = await fetch(req);
  if (gardable(r)) c.put(clef, r.clone());
  return r;
}

async function reseauDAbord(req, nomCache) {
  const c = await caches.open(nomCache);
  try {
    const r = await fetch(req);
    if (gardable(r)) c.put(req, r.clone());
    return r;
  } catch (e) {
    const garde = await c.match(req);
    if (garde) return garde;
    throw e;
  }
}

/** Le client est-il une page de l'aperçu Aurora ? Alors on ne s'en mêle pas. */
async function clientAurora(ev) {
  const id = ev.clientId || ev.resultingClientId;
  if (!id) return false;
  try {
    const cl = await self.clients.get(id);
    return !!cl && new URL(cl.url).pathname.startsWith('/sbxos/aurora/');
  } catch (e) { return false; }
}

self.addEventListener('fetch', (ev) => {
  const req = ev.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  // PÉRIMÈTRE : /sbxos/ seulement. /api/, /acces/, /domaine.js, /fonts/,
  // /hls.min.js… et tout le Hall passent droit.
  if (!url.pathname.startsWith(BASE)) return;
  if (HORS_PERIMETRE.some(p => url.pathname.startsWith(p))) return;

  verifieKill(false);          // au plus une fois par heure, sans attendre

  ev.respondWith((async () => {
    if (await clientAurora(ev)) return fetch(req);
    if (estManifeste(url)) return reseauDAbord(req, CACHE_MANIFESTE);
    if (estMedia(url)) {
      const r = await cacheDAbord(req, CACHE_MEDIAS);
      tailleMedias();
      return r;
    }
    // Navigations : une seule clé, jamais la chaîne de requête (?entree=…).
    const nav = req.mode === 'navigate';
    const clef = nav ? '/sbxos/index.html' : req;
    try {
      return await cacheDAbord(req, CACHE_COQUILLE, { rafraichir: true, clef });
    } catch (e) {
      if (nav) {
        const c = await caches.open(CACHE_COQUILLE);
        return (await c.match('/sbxos/index.html')) || Response.error();
      }
      return Response.error();
    }
  })());
});

/**
 * Messages de la page. `oublie` vide les médias ; `session` (l'état de session
 * a changé) vide ce qui dépend de la personne. Plus aucun message ne fait
 * télécharger une URL arbitraire au worker.
 */
self.addEventListener('message', (ev) => {
  const d = ev.data || {};
  if (d.sbx === 'oublie') ev.waitUntil(caches.delete(CACHE_MEDIAS));
  if (d.sbx === 'session') {
    ev.waitUntil(Promise.all([caches.delete(CACHE_MEDIAS), caches.delete(CACHE_MANIFESTE)]));
  }
});
