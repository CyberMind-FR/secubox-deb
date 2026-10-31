// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
// Kiosque distant (#3330), première version : lecture seule, API EXISTANTES du maître (même origine), session de
// l'administrateur (jeton sbx_token). Jamais de données inventées : une valeur absente reste « — ». Tout le texte passe par
// textContent (jamais de HTML injecté). Appairage par QR : version suivante.
'use strict';

const RAFRAICHIR_MS = 15000;
const VEILLE_MS = 60000;
const etat = { boxes: [], choisie: null };

const $ = (id) => document.getElementById(id);
const texte = (id, v) => { const n = $(id); if (n) n.textContent = (v === undefined || v === null || v === '') ? '—' : String(v); };
const jeton = () => { try { return localStorage.getItem('sbx_token') || ''; } catch (e) { return ''; } };

function versConnexion() {
  location.replace('/login.html?redirect=' + encodeURIComponent('/kiosque/'));
}

async function api(chemin) {
  const t = jeton();
  if (!t) { versConnexion(); return null; }
  try {
    const r = await fetch(chemin, { headers: { Authorization: 'Bearer ' + t }, credentials: 'same-origin', cache: 'no-store' });
    if (r.status === 401) { versConnexion(); return null; }
    if (!r.ok) return null;
    return await r.json();
  } catch (e) {
    return null;
  }
}

function nombre(o, cles) {
  if (!o || typeof o !== 'object') return null;
  for (const c of cles) {
    const v = o[c];
    if (typeof v === 'number' && Number.isFinite(v)) return v;
  }
  return null;
}

function duree(s) {
  if (typeof s !== 'number' || !Number.isFinite(s)) return null;
  const j = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return j > 0 ? j + ' j ' + h + ' h' : h + ' h ' + m + ' min';
}

// ---- box du maillage (liste, pastilles, onglet Box) ----
function dessinerBoxes() {
  const p = $('boxes'), l = $('liste-boxes');
  p.replaceChildren(); l.replaceChildren();
  for (const b of etat.boxes) {
    const bouton = document.createElement('button');
    bouton.type = 'button';
    bouton.className = 'pastille';
    bouton.setAttribute('role', 'tab');
    bouton.setAttribute('aria-selected', String(etat.choisie === b.nom));
    const pt = document.createElement('span');
    pt.className = 'point ' + (b.en_ligne ? 'ok' : 'ko');
    pt.setAttribute('aria-hidden', 'true');
    bouton.append(pt, document.createTextNode(b.nom));
    bouton.addEventListener('click', () => { etat.choisie = b.nom; dessinerBoxes(); });
    p.append(bouton);

    const li = document.createElement('li');
    const nom = document.createElement('span');
    nom.className = 'nom';
    nom.textContent = b.nom;
    const info = document.createElement('span');
    info.className = 'detail';
    info.textContent = (b.en_ligne ? 'en ligne' : 'hors ligne') + ' · ' + (b.interface === 'distante' ? 'interface distante' : 'interface locale');
    const a = document.createElement('a');
    a.className = 'bouton';
    a.rel = 'noopener noreferrer';
    a.target = '_blank';
    a.textContent = 'Ouvrir l’administration';
    // même chemin que la Flotte : box distante = connexion du maître (code à usage unique) ; box locale = son admin relayé
    a.href = b.interface === 'distante'
      ? '/api/v1/pilotage/boxes/' + encodeURIComponent(b.nom) + '/connexion-vhost'
      : 'https://admin.' + encodeURIComponent(b.nom) + '.secubox.in/';
    li.append(nom, info, a);
    l.append(li);
  }
}

async function chargerBoxes() {
  const d = await api('/api/v1/pilotage/boxes');
  if (!d) return;
  const liste = Array.isArray(d) ? d : (Array.isArray(d.boxes) ? d.boxes : []);
  etat.boxes = liste.filter((b) => b && typeof b.nom === 'string');
  dessinerBoxes();
}

// ---- le maître (hub, WAF, radio) : seules les box servies par CE maître ont ces API en direct ----
async function chargerMaitre() {
  const [sante, memoire, uptime, reseau, waf, radio] = await Promise.all([
    api('/api/v1/hub/system_health'), api('/api/v1/hub/memory'), api('/api/v1/hub/uptime'),
    api('/api/v1/hub/network_summary'), api('/api/v1/waf/stats'), api('/api/v1/radio/current'),
  ]);
  if (sante) {
    texte('a-etat', sante.overall);
    texte('a-etat-detail', Array.isArray(sante.issues) && sante.issues.length ? sante.issues.length + ' service(s) à l’arrêt' : 'aucun service à l’arrêt');
    $('v-etat').textContent = 'État : ' + (sante.overall ?? '—');
  }
  if (memoire) {
    const pc = nombre(memoire, ['percent']);
    texte('a-memoire', pc === null ? null : Math.round(pc) + ' %');
    const dispo = nombre(memoire, ['available_mb']);
    texte('a-memoire-detail', dispo === null ? '' : dispo + ' Mo disponibles');
  }
  if (uptime) texte('a-uptime', duree(nombre(uptime, ['seconds'])));
  if (reseau) {
    texte('r-wan', reseau.wan_status === 'connected' ? 'connectée' : (reseau.wan_status ? 'coupée' : null));
    texte('r-lan', reseau.lan_ip && reseau.lan_ip !== 'N/A' ? reseau.lan_ip : null);
    texte('r-mode', reseau.mode || reseau.network_mode || null);
  }
  const bloques = nombre(waf, ['total_blocked', 'blocked', 'bloques', 'blocks', 'total']);
  texte('s-bloques', bloques);
  texte('s-detail', waf ? 'pare-feu applicatif du maître' : 'statistiques du pare-feu indisponibles');
  if (radio && radio.piste && !radio.silence) {
    texte('m-titre', radio.piste.titre || radio.piste.title || radio.piste.nom);
    texte('m-detail', radio.piste.artiste || radio.piste.artist || '');
  } else {
    texte('m-titre', radio ? 'silence' : null);
    texte('m-detail', radio ? '' : 'radio indisponible');
  }
  texte('a-charge', null);
  texte('a-charge-detail', 'bientôt');
  $('liaison').textContent = 'via le maître · ' + new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
}

// ---- onglets, veille, rafraîchissement ----
function montrer(ecran) {
  for (const s of document.querySelectorAll('.ecran')) s.classList.toggle('actif', s.id === 'ecran-' + ecran);
  for (const o of document.querySelectorAll('.onglet')) o.classList.toggle('actif', o.dataset.ecran === ecran);
}

let minuteurVeille = null;
function reveil() {
  $('veille').hidden = true;
  clearTimeout(minuteurVeille);
  minuteurVeille = setTimeout(() => { $('veille').hidden = false; horloge(); }, VEILLE_MS);
}
function horloge() {
  const d = new Date();
  $('v-heure').textContent = d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  $('v-date').textContent = d.toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long' });
}

async function rafraichir() {
  if (document.visibilityState === 'hidden') return;
  await Promise.all([chargerBoxes(), chargerMaitre()]);
}

document.addEventListener('DOMContentLoaded', () => {
  for (const o of document.querySelectorAll('.onglet')) o.addEventListener('click', () => montrer(o.dataset.ecran));
  $('veille').addEventListener('click', reveil);
  for (const ev of ['pointerdown', 'keydown']) document.addEventListener(ev, reveil, { passive: true });
  setInterval(horloge, 10000);
  reveil();
  rafraichir();
  setInterval(rafraichir, RAFRAICHIR_MS);
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/kiosque/sw.js', { scope: '/kiosque/' }).catch(() => {});
});
