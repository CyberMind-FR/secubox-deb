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
 * LE NOM DU CACHE PORTE LA VERSION. Changer `VERSION` suffit à repartir propre :
 * l'ancien cache est effacé à l'activation. C'est ce qui évite qu'une coquille
 * d'hier serve un JavaScript d'aujourd'hui.
 */

// v2 : le damier réglable change la coquille (hall.js, sbx-damier.js,
// sbx-carlette.js, index.html). Sans ce changement de nom, la stratégie
// « cache d'abord » servirait l'ancienne coquille jusqu'au lancement SUIVANT —
// et le réglage paraîtrait n'avoir rien fait.
const VERSION = 'sbxos-v4';
const CACHE_COQUILLE = `${VERSION}-coquille`;
const CACHE_MANIFESTE = `${VERSION}-manifeste`;
const CACHE_MEDIAS = `${VERSION}-medias`;

/** La coquille : tout ce qu'il faut pour ouvrir l'application sans réseau. */
const COQUILLE = [
  './',
  './index.html',
  './manifest.webmanifest',
  './ui/styles.css',
  './ui/sbx-carlette.js',
  './ui/sbx-damier.js',
  './hall/hall.js',
  './mine/mine.js',
  './mine/clone.js',
];

/** Combien de médias on garde. Au-delà, le plus ancien sort. */
const MEDIAS_MAX = 40;

self.addEventListener('install', (ev) => {
  ev.waitUntil((async () => {
    const c = await caches.open(CACHE_COQUILLE);
    // `addAll` échoue EN BLOC si un seul fichier manque — et l'installation
    // entière échouerait avec lui. On ajoute donc un par un : une coquille
    // incomplète vaut mieux qu'une PWA qui refuse de s'installer.
    await Promise.all(COQUILLE.map(async (u) => {
      try { await c.add(new Request(u, { cache: 'reload' })); }
      catch (e) { console.warn('[sw] coquille, absent :', u); }
    }));
    // On prend la main tout de suite : sans cela la première visite tourne
    // sans service worker, et rien n'est mis en cache avant un rechargement.
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (ev) => {
  ev.waitUntil((async () => {
    const noms = await caches.keys();
    await Promise.all(noms
      .filter(n => !n.startsWith(VERSION))
      .map(n => caches.delete(n)));
    await self.clients.claim();
  })());
});

/** Un média ? C'est l'extension qui tranche, pas le chemin. */
function estMedia(url) {
  return /\.(?:mp4|webm|m4v|mp3|ogg|oga|opus|webp|png|jpe?g|avif|svg)$/i
    .test(new URL(url).pathname);
}

function estManifeste(url) {
  // LA CURATION SUIT LA MÊME RÈGLE QUE LE MANIFESTE : réseau d'abord. C'est
  // elle qui dit ce que le Hall montre ; servie depuis le cache, un service
  // retiré resterait sur le bureau — ou l'inverse.
  const p = new URL(url).pathname;
  return p.endsWith('/manifeste.json') || p.endsWith('/curation.json');
}

/** Borne le cache des médias, du plus ancien au plus récent. */
async function tailleMedias() {
  const c = await caches.open(CACHE_MEDIAS);
  const clefs = await c.keys();
  // `keys()` rend l'ordre d'insertion : les premiers sont les plus anciens.
  for (let i = 0; i < clefs.length - MEDIAS_MAX; i++) await c.delete(clefs[i]);
}

async function cacheDAbord(req, nomCache, { rafraichir = false } = {}) {
  const c = await caches.open(nomCache);
  const garde = await c.match(req);
  if (garde) {
    if (rafraichir) {
      // Rafraîchissement SILENCIEUX : on a déjà répondu, l'échec réseau ne
      // regarde personne.
      fetch(req).then(r => { if (r.ok) c.put(req, r.clone()); }).catch(() => {});
    }
    return garde;
  }
  const r = await fetch(req);
  if (r.ok) c.put(req, r.clone());
  return r;
}

async function reseauDAbord(req, nomCache) {
  const c = await caches.open(nomCache);
  try {
    const r = await fetch(req);
    if (r.ok) c.put(req, r.clone());
    return r;
  } catch (e) {
    const garde = await c.match(req);
    if (garde) return garde;
    throw e;
  }
}

self.addEventListener('fetch', (ev) => {
  const req = ev.request;

  // On ne touche QUE les GET de notre propre origine. Le reste passe droit :
  // une requête vers un service embarqué (PeerTube, Nextcloud) porte des
  // cookies de session et n'a rien à faire dans nos caches.
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (estManifeste(url)) {
    ev.respondWith(reseauDAbord(req, CACHE_MANIFESTE));
    return;
  }
  if (estMedia(url)) {
    ev.respondWith(cacheDAbord(req, CACHE_MEDIAS).then(async (r) => {
      tailleMedias();                      // sans attendre : la réponse part
      return r;
    }));
    return;
  }
  // Les appels d'API ne sont PAS mis en cache — voir l'en-tête du fichier.
  if (url.pathname.startsWith('/api/')) return;

  ev.respondWith(
    cacheDAbord(req, CACHE_COQUILLE, { rafraichir: true })
      .catch(async () => {
        // Hors ligne et rien en cache : pour une navigation, on rend la
        // coquille plutôt qu'une page d'erreur du navigateur. L'application
        // s'ouvre, et c'est elle qui dira ce qu'elle sait.
        if (req.mode === 'navigate') {
          const c = await caches.open(CACHE_COQUILLE);
          return (await c.match('./index.html')) || Response.error();
        }
        return Response.error();
      })
  );
});

/**
 * REPRISE DE LECTURE — le Hall demande de garder un média sous la main.
 *
 * C'est l'application qui décide, pas le service worker : lui ne sait pas ce
 * qui a été regardé. Le message vient du théâtre au moment où l'on quitte une
 * vidéo.
 */
self.addEventListener('message', (ev) => {
  const d = ev.data || {};
  if (d.sbx === 'garde' && typeof d.url === 'string') {
    ev.waitUntil((async () => {
      try {
        const c = await caches.open(CACHE_MEDIAS);
        await c.add(new Request(d.url, { mode: 'cors' }));
        await tailleMedias();
      } catch (e) { /* média non joignable : on n'insiste pas */ }
    })());
  }
  if (d.sbx === 'oublie') {
    ev.waitUntil(caches.delete(CACHE_MEDIAS));
  }
});
