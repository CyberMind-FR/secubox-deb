// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
// Kiosque distant (#3330) : lecture seule, API EXISTANTES du maître (même origine), session de
// l'administrateur (jeton sbx_token). Jamais de données inventées : une valeur absente reste « — ». Tout le texte passe par
// textContent (jamais de HTML injecté). Appairage par QR : version suivante.
'use strict';

const RAFRAICHIR_MS = 15000;
const VEILLE_MS = 60000;
const MAITRE = '';                         // pastille du maître : ses API hub/WAF/radio en direct
const etat = { boxes: [], choisie: MAITRE };

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

// ---- données d'une box du maillage, lues dans l'inventaire du pilotage du maître (0.2.0) ----
// Fonction pure (testée sous node) : jamais de valeur inventée, null quand l'inventaire ne la porte pas.
function nombreInv(inv, chemin) {
  const v = inv ? inv[chemin] : undefined;
  const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
  return typeof n === 'number' && Number.isFinite(n) ? n : null;
}
function donneesBox(d) {
  const inv = d && typeof d.inventaire === 'object' && d.inventaire ? d.inventaire : {};
  const total = nombreInv(inv, 'Device.DeviceInfo.MemoryStatus.Total');
  const libre = nombreInv(inv, 'Device.DeviceInfo.MemoryStatus.Free');
  const cpu = nombreInv(inv, 'Device.DeviceInfo.ProcessStatus.CPUUsage');
  const echecs = nombreInv(inv, 'Device.X_SECUBOX_Services.FailedNumberOfEntries');
  const iface = inv['Device.X_SECUBOX_Pilotage.Interface'];
  const liees = inv['Device.X_SECUBOX_Pilotage.MainsLiees'];
  return {
    etat: d && d.en_ligne ? 'en ligne' : 'hors ligne',
    etatDetail: echecs === null ? null : (echecs === 0 ? 'aucun service en échec' : echecs + ' service(s) en échec'),
    memoire: total && libre !== null ? Math.round(100 * (total - libre) / total) + ' %' : null,
    memoireDetail: libre === null ? null : Math.round(libre / 1024) + ' Mo disponibles',
    charge: cpu === null ? null : Math.round(cpu) + ' %',
    uptime: duree(nombreInv(inv, 'Device.DeviceInfo.UpTime')),
    interface: iface === 'distante' || iface === 'locale' ? iface : null,
    mainsLiees: typeof liees === 'boolean' ? (liees ? 'oui' : 'non') : null,
    agent: d && typeof d.agent_version === 'string' && d.agent_version ? d.agent_version : null,
  };
}

// ---- box du maillage (liste, pastilles, onglet Box) ----
function pastille(libelle, enLigne, cle) {
  const bouton = document.createElement('button');
  bouton.type = 'button';
  bouton.className = 'pastille';
  bouton.setAttribute('role', 'tab');
  bouton.setAttribute('aria-selected', String(etat.choisie === cle));
  const pt = document.createElement('span');
  pt.className = 'point ' + (enLigne ? 'ok' : 'ko');
  pt.setAttribute('aria-hidden', 'true');
  bouton.append(pt, document.createTextNode(libelle));
  bouton.addEventListener('click', () => { etat.choisie = cle; dessinerBoxes(); rafraichir(); });
  return bouton;
}

function dessinerBoxes() {
  const p = $('boxes'), l = $('liste-boxes');
  p.replaceChildren(); l.replaceChildren();
  p.append(pastille('le maître', true, MAITRE));
  for (const b of etat.boxes) {
    p.append(pastille(b.nom, b.en_ligne, b.nom));

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
  if (etat.choisie !== MAITRE) return;       // une box a été choisie entre-temps : ses données priment
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
  texte('a-pilotage', 'maître du maillage');
  texte('a-pilotage-detail', etat.boxes.length + ' box pilotée(s)');
  $('liaison').textContent = 'via le maître · ' + new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
}

// ---- une box du maillage : son inventaire ; sécurité, réseau et médias en direct restent ceux du maître ----
async function chargerBox(nom) {
  const d = await api('/api/v1/pilotage/boxes/' + encodeURIComponent(nom));
  if (etat.choisie !== nom) return;          // autre pastille choisie entre-temps
  const v = donneesBox(d || {});
  texte('a-etat', d ? v.etat : null);
  texte('a-etat-detail', v.etatDetail);
  texte('a-memoire', v.memoire);
  texte('a-memoire-detail', v.memoireDetail);
  texte('a-charge', v.charge);
  texte('a-charge-detail', v.charge === null ? 'non relevée par cette box' : 'processeur');
  texte('a-uptime', v.uptime);
  texte('a-pilotage', v.interface === null ? null : 'interface ' + v.interface);
  texte('a-pilotage-detail', 'mains liées : ' + (v.mainsLiees ?? '—') + ' · agent ' + (v.agent ?? '—'));
  for (const id of ['s-bloques', 'r-wan', 'r-lan', 'r-mode', 'm-titre']) texte(id, null);
  texte('s-detail', 'statistiques en direct : maître seulement');
  texte('m-detail', 'médias : maître seulement');
  $('v-etat').textContent = nom + ' : ' + (d ? v.etat : '—');
  $('liaison').textContent = nom + ' via le maître · ' + new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
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
  const choisie = etat.choisie;
  await Promise.all([chargerBoxes(), choisie === MAITRE ? chargerMaitre() : chargerBox(choisie)]);
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
