// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox-Deb :: acces — l'onglet « Moi » (#1829)
//
// ACCÈS EST L'ÉCRAN UNIQUE (décision du 2026-10-01). Ce qui, dans l'Identity
// Manager, concernait la PERSONNE vit ici, sous la porte qui l'a fait entrer :
// ses appareils (renommer, révoquer, rendre de confiance), en ajouter un, ses
// services, et « Administrer la box » (élévation explicite, #1827).
//
// Les données viennent toujours de sbxid (/api/v1/sbxid) : le magasin ne change
// pas, seul l'écran se déplace. Sans cette API sur l'hôte (le vhost acces.<box>
// ne la monte pas), rendMoi() rend `false` et la page garde sa vue d'avant.

import { identite, signe } from './appareil.js';

const SBX = '/api/v1/sbxid';

async function api(chemin, options) {
  const r = await fetch(SBX + chemin, Object.assign({
    credentials: 'same-origin', headers: { 'Content-Type': 'application/json' } }, options));
  const ct = r.headers.get('content-type') || '';
  if (ct.indexOf('json') < 0) throw new Error('route indisponible sur cet hôte');
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(j.detail || ('HTTP ' + r.status)), { status: r.status });
  return j;
}
const poste = (chemin, corps) => api(chemin, { method: 'POST', body: corps ? JSON.stringify(corps) : undefined });

function el(t, c, txt) {
  const n = document.createElement(t);
  if (c) n.className = c;
  if (txt != null) n.textContent = txt;      // textContent : les noms viennent des appareils
  return n;
}
function carte(parent, cle, icone, titre, sous) {
  const s = el('section', 'carte');
  const h = el('div', 'sec-h');
  h.append(el('span', 'k', cle), el('div', 'rule'), el('span', null, icone));
  s.appendChild(h);
  if (titre) s.appendChild(el('h2', null, titre));
  if (sous) s.appendChild(el('p', 'sous', sous));
  parent.appendChild(s);
  return s;
}
function message(parent, txt, cls) {
  const p = el('p', cls || 'err', txt);
  parent.appendChild(p);
  setTimeout(() => p.remove(), 6000);
}
const quand = (t) => t ? new Date(t * 1000).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' }) : '—';

const ROLES = { guest: 'Invité', member: 'Membre', subscriber: 'Abonné', beta_tester: 'Bêta-testeur',
                moderator: 'Modérateur', sbx_operator: 'Opérateur SBX' };
const CONFIANCE = { trusted: ['acceptee', 'de confiance'], verified: ['', 'admis'], pending: ['', 'en attente'] };

/**
 * Rend l'onglet « Moi » dans `conteneur`. `false` si cette session ne désigne
 * pas une personne SBX OS (ou si l'API n'est pas montée sur cet hôte).
 */
export async function rendMoi(conteneur) {
  let m;
  try { m = await api('/moi'); } catch (e) { return false; }
  if (!m || !m.identite) return false;
  conteneur.textContent = '';
  const u = m.identite;

  // ── Qui ────────────────────────────────────────────────────────────────
  const qui = carte(conteneur, 'Moi', '🪪', u.pseudo);
  const roles = el('p', 'sous');
  roles.textContent = 'Rôles : ' + ((u.roles || []).map(r => ROLES[r] || r).join(', ') || '—')
    + ' · ' + (u.capabilities || []).length + ' capacité(s). Aucune n’ouvre SSH, sudo ou root.';
  qui.appendChild(roles);
  // TRANSITOIRE (#1829, jusqu'à l'étape A2) : l'administration des personnes
  // et des demandes vit encore sur l'ancienne page ; le menu du Hall n'y mène
  // plus, on en garde donc le chemin ici pour qui l'administre.
  if ((u.capabilities || []).includes('admin.users')) {
    const g = el('div', 'gestes');
    const a = el('a', null, 'Personnes et demandes (administration) →');
    a.href = '/identite/#admin';
    g.appendChild(a);
    qui.appendChild(g);
  }

  // ── Administrer la box (élévation, #1827) ──────────────────────────────
  await rendElevation(conteneur);

  // ── Mes appareils ──────────────────────────────────────────────────────
  const app = carte(conteneur, 'Mes appareils', '📱', null,
    'Un appareil de confiance a un certificat signé par lui-même et par la box : il peut administrer.');
  const liste = el('div', 'liste');
  app.appendChild(liste);
  for (const d of m.appareils || []) liste.appendChild(ligneAppareil(d, d.device_uuid === m.appareil_courant, conteneur));
  if (!(m.appareils || []).length) liste.appendChild(el('p', 'vide', 'Aucun appareil.'));

  // ── Ajouter un appareil ────────────────────────────────────────────────
  if (m.appareil_courant) {
    const aj = carte(conteneur, 'Ajouter un appareil', '➕', null,
      'Un QR de dix minutes, à scanner avec le nouvel appareil : il entre à votre nom, sans passer par l’administration.');
    const res = el('div');
    const g = el('div', 'gestes');
    const b = el('button', 'fort', 'Ajouter un appareil');
    b.onclick = async () => {
      b.disabled = true;
      try { montreLien(res, await poste('/appareils/inviter'), 'Scannez avec le nouvel appareil'); }
      catch (e) { message(aj, e.message); }
      b.disabled = false;
    };
    g.appendChild(b);
    aj.append(g, res);
  }

  // ── Mes services ───────────────────────────────────────────────────────
  const c = m.connexions || {};
  const sv = carte(conteneur, 'Mes services', '🔑', null,
    'Les services s’ouvrent sans mot de passe depuis le Hall : la box tient les secrets, jamais vous.');
  const chips = el('div', 'liste');
  for (const l of m.liens || []) {
    if (l.app === 'systeme') continue;                 // pas un service : le compte d'administration
    chips.appendChild(el('span', 'badge lie', l.app + ' · ' + l.app_handle));
  }
  for (const s of c.services || []) chips.appendChild(el('span', 'badge', s));
  if (!chips.childNodes.length) chips.appendChild(el('p', 'vide', 'Aucun service relié pour l’instant.'));
  sv.appendChild(chips);
  const gs = el('div', 'gestes');
  const lien = el('a', null, 'Gérer mes accès aux services');
  lien.href = '/acces.html';
  gs.appendChild(lien);
  sv.appendChild(gs);
  return true;
}

function ligneAppareil(d, courant, conteneur) {
  const row = el('div', 'ligne');
  const qui = el('div', 'qui');
  const nom = el('div', 'nom', d.name + (courant ? ' — cet appareil' : ''));
  qui.appendChild(nom);
  const conf = CONFIANCE[d.trust] || ['', d.trust];
  const etat = el('span', 'etat ' + (d.revoked_at ? 'refusee' : conf[0]),
    d.revoked_at ? 'révoqué le ' + quand(d.revoked_at) : conf[1]);
  qui.appendChild(etat);
  qui.appendChild(el('div', 'sous', (d.agent ? d.agent + ' · ' : '') + 'dernière session : ' + quand(d.last_seen_at)
    + (d.certificate ? ' · certificat jusqu’au ' + String(d.certificate.expires).slice(0, 10) : '')));
  row.appendChild(qui);
  const act = el('div', 'act');
  if (!d.revoked_at) {
    if (courant && d.trust !== 'trusted') {
      const b = el('button', 'fort', 'Rendre de confiance');
      b.title = 'Cet appareil signe son certificat ; sa clé ne le quitte pas';
      b.onclick = () => rendConfiance(d, b, conteneur);
      act.appendChild(b);
    }
    const r = el('button', null, 'Renommer');
    r.onclick = () => renomme(d, nom, act, conteneur);
    const x = el('button', 'non', 'Révoquer');
    x.onclick = () => confirme(act, courant ? 'Révoquer l’appareil que vous utilisez ?' : `Révoquer « ${d.name} » ?`,
      async () => {
        const j = await poste('/appareils/' + d.device_uuid + '/revoquer');
        message(conteneur, `Appareil révoqué · ${j.sessions_coupees || 0} session(s) coupée(s)`, 'sous');
      }, conteneur);
    act.append(r, x);
  }
  row.appendChild(act);
  return row;
}

function confirme(act, question, oui, conteneur) {
  act.textContent = '';
  act.appendChild(el('span', 'err', question));
  const y = el('button', 'non', 'Confirmer');
  const n = el('button', null, 'Annuler');
  y.onclick = async () => {
    y.disabled = true;
    try { await oui(); } catch (e) { message(conteneur, e.message); }
    rendMoi(conteneur);
  };
  n.onclick = () => rendMoi(conteneur);
  act.append(y, n);
}

function renomme(d, nom, act, conteneur) {
  const inp = el('input');
  inp.type = 'text'; inp.value = d.name; inp.maxLength = 60;
  inp.setAttribute('aria-label', 'Nouveau nom');
  nom.replaceWith(inp);
  act.textContent = '';
  const ok = el('button', 'fort', 'Enregistrer');
  const fin = async () => {
    try { await api('/appareils/' + d.device_uuid, { method: 'PATCH', body: JSON.stringify({ nom: inp.value }) }); }
    catch (e) { message(conteneur, e.message); }
    rendMoi(conteneur);
  };
  ok.onclick = fin;
  inp.onkeydown = (e) => { if (e.key === 'Enter') fin(); if (e.key === 'Escape') rendMoi(conteneur); };
  act.appendChild(ok);
  inp.focus();
}

// RENDRE DE CONFIANCE = émettre le certificat de l'appareil : la box prépare
// la charge, l'APPAREIL la signe (sa clé ne sort pas), le nœud contresigne.
async function rendConfiance(d, b, conteneur) {
  b.disabled = true;
  try {
    const id = await identite();
    const prep = await poste('/appareils/' + d.device_uuid + '/certificat/preparer');
    const sig = await signe(id.paire, prep.message_hex);
    await poste('/appareils/' + d.device_uuid + '/certificat/signer', { serial: prep.serial, sig_user: sig });
    message(conteneur, 'Appareil de confiance : certificat signé par lui-même et par la box.', 'sous');
  } catch (e) { message(conteneur, e.message); }
  rendMoi(conteneur);
}

function montreLien(box, r, titre) {
  box.textContent = '';
  box.appendChild(el('p', 'sous', titre + ' — valable jusqu’à ' + quand(r.expire_le) + ', une seule fois.'));
  if (r.qr) {
    const img = el('img');
    img.src = r.qr; img.alt = 'QR du lien'; img.width = 180; img.height = 180;
    img.style.cssText = 'background:#fff;padding:6px;border-radius:6px';
    box.appendChild(img);
  }
  const l = el('input');
  l.type = 'text'; l.readOnly = true; l.value = r.lien; l.style.width = '100%';
  l.onfocus = () => l.select();
  box.appendChild(l);
}

// ── ADMINISTRER LA BOX (#1827) ──────────────────────────────────────────────
// La session ouverte ici n'est jamais une session d'administration. Ce geste en
// ouvre une À PART : défi signé par cet appareil (de confiance), OTP du compte
// hors du réseau local, bon d'une minute remis à admin.<box>.
async function rendElevation(conteneur) {
  let e;
  try { e = await api('/elevation/etat'); } catch (x) { return; }
  if (!e.lie) return;
  const s = carte(conteneur, 'Administration', '🛡️', 'Administrer la box');
  if (!e.possible) {
    s.appendChild(el('p', 'sous', e.motif || 'Indisponible depuis cette session.'));
    return;
  }
  const heures = Math.max(1, Math.round(e.duree_s / 3600));
  s.appendChild(el('p', 'sous', `En tant que ${e.compte}, signée par cet appareil (${e.appareil}) — `
    + `session de ${heures} h au plus. ` + (e.otp_requis
      ? 'Hors du réseau local, le code OTP du compte est exigé.'
      : 'Sur le réseau local, la clé de cet appareil suffit.')));
  const f = el('form', 'gestes');
  let otp = null;
  if (e.otp_requis) {
    otp = el('input');
    Object.assign(otp, { inputMode: 'numeric', autocomplete: 'one-time-code', maxLength: 6,
                         placeholder: 'code OTP', required: true, pattern: '[0-9]{6}' });
    otp.style.width = '9em';
    f.appendChild(otp);
  }
  const b = el('button', 'fort', 'Administrer la box');
  const sortie = el('span');
  f.append(b, sortie);
  s.appendChild(f);
  f.onsubmit = async (ev) => {
    ev.preventDefault();
    b.disabled = true; sortie.textContent = 'Signature…';
    try {
      const id = await identite();
      const d = await poste('/elevation/defi', { compte: e.compte });
      const sig = await signe(id.paire, d.message_hex);          // la clé ne quitte pas l'appareil
      const r = await poste('/elevation', { defi: d.defi, signature: sig, otp: otp ? otp.value.trim() : null });
      // Un LIEN, pas une fenêtre ouverte d'office : après une attente réseau,
      // le navigateur bloquerait window.open — et le bon ne sert qu'une fois.
      sortie.textContent = '';
      const a = el('a', 'fort', 'Ouvrir l’administration ↗');
      a.href = r.url; a.target = '_blank'; a.rel = 'noopener';
      sortie.append(a, el('span', 'sous', ` lien valable ${r.expire_dans} s`));
    } catch (x) { sortie.textContent = ''; message(s, x.message); }
    b.disabled = false;
  };
}
