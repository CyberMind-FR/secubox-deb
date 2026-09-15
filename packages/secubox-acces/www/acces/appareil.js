// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SecuBox :: Accès — L'IDENTITÉ DE CET APPAREIL (#1344).
 *
 * CE QUE CE FICHIER RÉPARE. La première version tirait 32 octets au hasard et
 * les appelait « clé publique ». L'empreinte qu'on faisait comparer à
 * l'administrateur n'engageait donc personne : aucun secret ne lui
 * correspondait, et rien ne reliait l'empreinte validée à l'appareil qui se
 * présenterait ensuite. Le geste de vérification était du théâtre.
 *
 * ICI, LA CLÉ PRIVÉE N'EST PAS EXPORTABLE. `extractable: false` fait vivre la
 * clé dans le navigateur sans qu'aucun script — le nôtre compris — ne puisse la
 * lire. On ne peut que DEMANDER une signature. Conséquence directe : même une
 * injection de script dans cette page ne permet pas d'emporter l'identité de
 * l'appareil ailleurs.
 *
 * ELLE VIT DANS IndexedDB, pas dans localStorage : c'est le seul stockage du
 * navigateur capable de conserver un CryptoKey non exportable. localStorage ne
 * garde que du texte, ce qui obligerait à exporter la clé — donc à la rendre
 * exportable, donc à perdre la garantie ci-dessus.
 *
 * P-256 ET NON X25519. Notre cœur cryptographique est en X25519/Ed25519, et
 * c'est le bon choix côté serveur. Mais la clé est engendrée ici par un
 * NAVIGATEUR, et WebCrypto n'expose Ed25519 que depuis très récemment. P-256
 * (ECDSA, SHA-256) est disponible partout depuis dix ans. Mieux vaut une vraie
 * clé que tout le monde peut engendrer qu'une meilleure clé que la moitié des
 * appareils refuserait.
 */

export const API = '/api/v1/acces';

const BASE = 'sbx-acces';
const MAGASIN = 'appareil';
const CLE = 'identite';

// ── IndexedDB, réduit à ce dont on a besoin ─────────────────────────────────

function base() {
  return new Promise((ok, non) => {
    const r = indexedDB.open(BASE, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(MAGASIN);
    r.onsuccess = () => ok(r.result);
    r.onerror = () => non(r.error);
  });
}

function lit(clef) {
  return base().then(db => new Promise((ok, non) => {
    const t = db.transaction(MAGASIN, 'readonly').objectStore(MAGASIN).get(clef);
    t.onsuccess = () => ok(t.result);
    t.onerror = () => non(t.error);
  }));
}

function ecrit(clef, valeur) {
  return base().then(db => new Promise((ok, non) => {
    const t = db.transaction(MAGASIN, 'readwrite').objectStore(MAGASIN).put(valeur, clef);
    t.onsuccess = () => ok(valeur);
    t.onerror = () => non(t.error);
  }));
}

// ── Octets ↔ hexadécimal ────────────────────────────────────────────────────

const hex = (buf) => [...new Uint8Array(buf)]
  .map(o => o.toString(16).padStart(2, '0')).join('');

const octets = (h) => new Uint8Array(
  h.match(/.{2}/g).map(p => parseInt(p, 16)));

// ── L'identité ──────────────────────────────────────────────────────────────

/**
 * Rend l'identité de cet appareil, en l'engendrant au premier appel.
 *
 * Le DID dérive de la clé publique : deux appareils ne peuvent pas le
 * revendiquer, et il n'y a rien à tirer au sort. Un identifiant aléatoire
 * aurait pu être recopié par n'importe qui ; celui-ci désigne une clé.
 */
export async function identite() {
  const garde = await lit(CLE).catch(() => null);
  if (garde && garde.paire && garde.publique) return garde;

  const paire = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,                       // NON EXPORTABLE — voir l'en-tête
    ['sign', 'verify']);

  const brut = await crypto.subtle.exportKey('raw', paire.publicKey);
  const publique = hex(brut);    // 04 ‖ X ‖ Y, 65 octets
  const digest = await crypto.subtle.digest('SHA-256', brut);
  const did = 'did:sbx:' + hex(digest).slice(0, 32);

  const id = { paire, publique, did };
  await ecrit(CLE, id);
  return id;
}

/** L'empreinte, telle que la box la calcule : six groupes de quatre. */
export async function empreinte(publiqueHex) {
  const d = await crypto.subtle.digest('SHA-256', octets(publiqueHex));
  const h = hex(d).slice(0, 24);
  return h.match(/.{4}/g).join(' ');
}

/**
 * Signe un défi. WebCrypto rend `r ‖ s` — c'est ce que la box attend, et
 * c'est le point où les deux mondes se ratent d'habitude : `cryptography`
 * parle DER, et la conversion se fait côté serveur, pas ici.
 */
export async function signe(paire, defiHex) {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, paire.privateKey, octets(defiHex));
  return hex(sig);
}

// ── Le suivi local ──────────────────────────────────────────────────────────
// Le jeton de suivi N'EST PAS un secret d'authentification : il ne sert qu'à
// consulter l'état de SA demande. C'est la signature qui ouvre la session, et
// elle exige la clé. Un jeton lu par-dessus une épaule ne fait donc rien entrer.

const SUIVI = 'sbx-acces-suivi';

export function retiens(jeton) {
  try { localStorage.setItem(SUIVI, jeton); } catch (e) { /* mode privé */ }
}

export function jetonGarde() {
  try { return localStorage.getItem(SUIVI) || ''; } catch (e) { return ''; }
}

export function oublie() {
  try { localStorage.removeItem(SUIVI); } catch (e) { /* rien à faire */ }
}

// ── Le parcours ─────────────────────────────────────────────────────────────

async function json(chemin, options) {
  const r = await fetch(API + chemin, Object.assign(
    { credentials: 'same-origin' }, options));
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.detail || ('HTTP ' + r.status));
  }
  return r.json();
}

export async function demande(champs) {
  const id = await identite();
  const j = await json('/invitation/demande', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      did: id.did, cle_publique: id.publique,
      nom: champs.nom, appareil: champs.appareil, message: champs.message,
    }),
  });
  if (j.jeton) retiens(j.jeton);
  return j;
}

export async function suivi() {
  const id = await identite();
  const jeton = jetonGarde();
  if (!jeton) return null;
  try {
    return await json('/invitation/suivi?did=' + encodeURIComponent(id.did)
      + '&jeton=' + encodeURIComponent(jeton));
  } catch (e) {
    return null;    // demande inconnue ou jeton périmé : on repart du formulaire
  }
}

/**
 * OUVRE LA SESSION — le chaînon qui manquait.
 *
 * L'appareil ne présente pas son jeton comme un mot de passe : il PROUVE qu'il
 * détient la clé dont l'administrateur a comparé l'empreinte. Sans cela, le
 * geste de comparaison n'aurait servi à rien, et quiconque lirait le jeton
 * entrerait à la place du demandeur.
 */
export async function ouvreSession() {
  const id = await identite();
  const jeton = jetonGarde();
  if (!jeton) throw new Error('aucune demande sur cet appareil');

  const { defi } = await json('/session/defi?did=' + encodeURIComponent(id.did)
    + '&jeton=' + encodeURIComponent(jeton));
  const signature = await signe(id.paire, defi);

  return json('/session/ouvrir', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did: id.did, jeton, defi, signature }),
  });
}
