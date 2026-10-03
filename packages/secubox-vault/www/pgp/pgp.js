/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
 * Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
 * Source-Disclosed License — All rights reserved except as expressly granted.
 * See LICENCE-CMSD-1.0.md for terms.
 *
 * SecuBox — OpenPGP du Coffre, dans le navigateur, à origine séparée (#1852, P5).
 *
 * RÈGLES
 *  · La clé secrète n'existe que dans la mémoire de cette page : jamais de localStorage, de cookie, de postMessage.
 *  · On ne parle qu'au cadre PARENT, et seulement si son origine figure dans origines.json (liste de la box).
 *  · Pas d'oracle : chaque opération porte sur un texte que la page a RECU du webmail pour l'utilisateur connecté ;
 *    elle ne signe jamais autre chose que ce que la personne vient d'écrire.
 *  · Un destinataire sans clé n'est JAMAIS chiffré « à blanc » : on refuse en nommant les adresses manquantes.
 */
(function () {
  'use strict';
  var openpgp = window.openpgp;
  var VAULT = '/api/v1/vault/moi';
  var PGP = '/api/v1/openpgp';
  var COURRIEL = /^[^@\s<>"]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;
  var TEXTE_MAX = 1024 * 1024;
  var CONTACTS_MAX = 55;             // un secret du Coffre tient 64 Kio
  var TTL_ANNUAIRE_MS = 5 * 60 * 1000;

  var origines = [];
  var cle = null;                    // clé privée déverrouillée (objet openpgp), EN MÉMOIRE
  var contacts = null;               // {courriel: {empreinte, armure, vu}} appris par Autocrypt
  var annuaire = null, annuaireT = 0;

  function Erreur(code, message, extra) {
    var e = new Error(message || code);
    e.code = code; e.extra = extra || {};
    return e;
  }

  // ── réseau ───────────────────────────────────────────────────────────
  function appel(url, opts) {
    opts = opts || {};
    opts.credentials = 'same-origin';
    opts.headers = Object.assign({ 'Accept': 'application/json' }, opts.headers || {});
    return fetch(url, opts);
  }
  function erreurHttp(r, defaut) {
    if (r.status === 401) return Erreur('non_connecte', 'session absente ou expirée');
    if (r.status === 423) return Erreur('coffre_scelle', 'le Coffre de la box est scellé');
    if (r.status === 403) return Erreur('refuse', 'accès refusé : aucune personne derrière cette session, ou compartiment fermé');
    if (r.status === 404) return Erreur('absent', defaut || 'introuvable');
    return Erreur('erreur', 'HTTP ' + r.status);
  }
  function lireSecret(nom) {
    return appel(VAULT + '/secrets/' + nom + '/lire', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ouverture: { genre: 'session' } })
    });
  }

  // ── la clé de la personne ────────────────────────────────────────────
  async function chargeCle() {
    if (cle) return cle;
    var r = await lireSecret('openpgp-secrete');
    if (r.status === 404) throw Erreur('pas_de_cle', "aucune clé OpenPGP dans « Mon coffre » : créez-la d'abord");
    if (!r.ok) throw erreurHttp(r);
    var j = await r.json();
    var k = await openpgp.readPrivateKey({ armoredKey: j.valeur });
    // La clé du Coffre n'a pas de phrase propre : c'est le compartiment qui la protège (openpgp_perso.py).
    if (!k.isDecrypted()) throw Erreur('cle_protegee', 'la clé a une phrase de passe : non gérée ici');
    cle = k;
    return cle;
  }

  // ── contacts appris (Autocrypt) : un secret du compartiment ──────────
  async function chargeContacts() {
    if (contacts) return contacts;
    var r = await lireSecret('openpgp-contacts');
    if (r.status === 404) { contacts = {}; return contacts; }
    if (!r.ok) throw erreurHttp(r);
    try { contacts = (JSON.parse((await r.json()).valeur).cles) || {}; } catch (e) { contacts = {}; }
    return contacts;
  }
  async function poseContacts() {
    var noms = Object.keys(contacts);
    if (noms.length > CONTACTS_MAX) {                                  // les plus anciens partent d'abord
      noms.sort(function (a, b) { return contacts[a].vu - contacts[b].vu; });
      noms.slice(0, noms.length - CONTACTS_MAX).forEach(function (n) { delete contacts[n]; });
    }
    var r = await appel(VAULT + '/secrets', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ouverture: { genre: 'session' }, nom: 'openpgp-contacts',
                             valeur: JSON.stringify({ v: 1, cles: contacts }) })
    });
    if (!r.ok) throw erreurHttp(r);
  }

  // ── clés des correspondants : annuaire de la box d'abord, contacts ensuite ──
  async function lireAnnuaire() {
    if (annuaire && Date.now() - annuaireT < TTL_ANNUAIRE_MS) return annuaire;
    var r = await appel(PGP + '/annuaire');
    if (!r.ok) throw erreurHttp(r);
    annuaire = (await r.json()).cles || [];
    annuaireT = Date.now();
    return annuaire;
  }
  async function clesPour(courriel) {
    var c = String(courriel || '').trim().toLowerCase();
    if (!COURRIEL.test(c)) return [];
    var trouvees = [];
    try {
      var entrees = (await lireAnnuaire()).filter(function (e) { return (e.verifies || []).indexOf(c) >= 0; });
      for (var i = 0; i < entrees.length && /^[0-9A-F]{40}$/.test(entrees[i].empreinte); i++) {
        var r = await appel(PGP + '/annuaire/' + entrees[i].empreinte + '.asc');
        if (r.ok) trouvees.push(await openpgp.readKey({ armoredKey: await r.text() }));
      }
    } catch (e) { /* annuaire injoignable : les contacts appris suffisent peut-être */ }
    if (!trouvees.length) {
      var ct = (await chargeContacts())[c];
      if (ct) trouvees.push(await openpgp.readKey({ armoredKey: ct.armure }));
    }
    return trouvees;
  }

  // ── validations d'entrée ─────────────────────────────────────────────
  function texte(d, champ) {
    var t = d[champ];
    if (typeof t !== 'string' || !t.length || t.length > TEXTE_MAX) throw Erreur('entree', champ + ' : texte attendu, 1 Mo au plus');
    return t;
  }
  function armure(d) {
    var a = d.armure;
    if (typeof a !== 'string' || a.indexOf('-----BEGIN PGP') < 0 || a.length > 2 * TEXTE_MAX) throw Erreur('entree', 'bloc OpenPGP armuré attendu');
    return a;
  }

  // ── état d'une signature, jamais « valide » sans preuve ──────────────
  async function etatSignatures(signatures, clesConnues) {
    if (!signatures || !signatures.length) return { etat: 'aucune' };
    for (var i = 0; i < signatures.length; i++) {
      try {
        await signatures[i].verified;
        var k = clesConnues.find(function (x) { return x.getKeys(signatures[i].keyID).length; });
        return { etat: 'valide', empreinte: k ? k.getFingerprint().toUpperCase() : null,
                 uid: k ? ((k.users[0] && k.users[0].userID && k.users[0].userID.email) || null) : null };
      } catch (e) {
        var connue = clesConnues.some(function (x) { return x.getKeys(signatures[i].keyID).length; });
        if (connue) return { etat: 'invalide' };
      }
    }
    return { etat: 'cle_inconnue' };
  }

  // ── les opérations ───────────────────────────────────────────────────
  var OPS = {
    status: async function () {
      var k = await chargeCle();
      var uids = k.users.map(function (u) { return u.userID && u.userID.email; }).filter(Boolean);
      return { disponible: true, empreinte: k.getFingerprint().toUpperCase(), adresses: uids };
    },

    chiffrer: async function (d) {
      var t = texte(d, 'texte');
      var dest = d.destinataires;
      if (!Array.isArray(dest) || !dest.length || dest.length > 50) throw Erreur('entree', 'destinataires : 1 à 50 adresses');
      var k = await chargeCle();
      var cles = [], manquants = [];
      for (var i = 0; i < dest.length; i++) {
        var trouv = await clesPour(dest[i]);
        if (trouv.length) cles = cles.concat(trouv); else manquants.push(String(dest[i]).slice(0, 254));
      }
      if (manquants.length) throw Erreur('cle_manquante', 'pas de clé pour : ' + manquants.join(', '), { manquants: manquants });
      cles.push(k.toPublic());                                       // lisible dans « Envoyés »
      var message = await openpgp.createMessage({ text: t });
      var a = await openpgp.encrypt({ message: message, encryptionKeys: cles,
                                      signingKeys: d.signer === false ? undefined : k, format: 'armored' });
      return { armure: a, signe: d.signer !== false };
    },

    signer: async function (d) {
      var k = await chargeCle();
      var message = await openpgp.createCleartextMessage({ text: texte(d, 'texte') });
      return { armure: await openpgp.sign({ message: message, signingKeys: k, format: 'armored' }) };
    },

    dechiffrer: async function (d) {
      var a = armure(d);
      var k = await chargeCle();
      var message = await openpgp.readMessage({ armoredMessage: a });
      var connues = (await clesPour(d.expediteur)).concat([k.toPublic()]);
      var r = await openpgp.decrypt({ message: message, decryptionKeys: k, verificationKeys: connues });
      return { texte: String(r.data), signature: await etatSignatures(r.signatures, connues) };
    },

    verifier: async function (d) {
      var a = armure(d);
      var k = await chargeCle();
      var connues = (await clesPour(d.expediteur)).concat([k.toPublic()]);
      var message = a.indexOf('BEGIN PGP SIGNED MESSAGE') >= 0
        ? await openpgp.readCleartextMessage({ cleartextMessage: a })
        : await openpgp.readMessage({ armoredMessage: a });
      var r = await openpgp.verify({ message: message, verificationKeys: connues });
      return { texte: String(r.data), signature: await etatSignatures(r.signatures, connues) };
    },

    // Autocrypt ENTRANT : l'en-tête d'un courriel reçu. La clé n'est retenue que si elle porte l'adresse annoncée, est
    // PUBLIQUE, valide (non expirée, non révoquée) ; une clé déjà connue de l'annuaire de la box n'est jamais supplantée.
    apprendre: async function (d) {
      var c = String(d.courriel || '').trim().toLowerCase();
      if (!COURRIEL.test(c)) throw Erreur('entree', 'adresse invalide');
      var kd = String(d.keydata || '').replace(/\s+/g, '');
      if (!/^[A-Za-z0-9+/=]{40,16000}$/.test(kd)) throw Erreur('entree', 'keydata invalide');
      var bin = Uint8Array.from(atob(kd), function (x) { return x.charCodeAt(0); });
      var k = await openpgp.readKey({ binaryKey: bin });
      if (k.isPrivate()) throw Erreur('refuse', 'clé secrète refusée');
      await k.verifyPrimaryKey();                                    // lève si révoquée ou expirée
      var porte = k.users.some(function (u) { return u.userID && u.userID.email && u.userID.email.toLowerCase() === c; });
      if (!porte) throw Erreur('refuse', "la clé ne porte pas l'adresse annoncée");
      if ((await clesPour(c)).length && !(await chargeContacts())[c]) return { appris: false, motif: 'annuaire' };
      var ct = await chargeContacts();
      var emp = k.getFingerprint().toUpperCase();
      if (ct[c] && ct[c].empreinte === emp) return { appris: false, motif: 'deja' };
      ct[c] = { empreinte: emp, armure: k.armor(), vu: Math.floor(Date.now() / 1000) };
      await poseContacts();
      return { appris: true, empreinte: emp };
    },

    verrouiller: async function () { cle = null; contacts = null; annuaire = null; return {}; }
  };

  // ── dialogue avec le webmail ─────────────────────────────────────────
  function repondre(ev, id, corps) {
    ev.source.postMessage(Object.assign({ id: id }, corps), ev.origin);
  }
  window.addEventListener('message', function (ev) {
    if (ev.source !== window.parent || origines.indexOf(ev.origin) < 0) return;      // ni parent ni liste : silence
    var d = ev.data;
    if (!d || typeof d !== 'object' || typeof d.id !== 'string' || d.id.length > 64 ||
        typeof d.op !== 'string' || !Object.prototype.hasOwnProperty.call(OPS, d.op)) return;
    OPS[d.op](d).then(function (r) {
      repondre(ev, d.id, Object.assign({ ok: true }, r));
    }, function (e) {
      // Un message d'erreur n'est jamais une trace de la bibliothèque : code connu, texte court.
      repondre(ev, d.id, { ok: false, code: e.code || 'erreur', message: (e.code ? e.message : 'opération impossible').slice(0, 300),
                           extra: e.extra || {} });
    });
  });
  window.addEventListener('pagehide', function () { cle = null; contacts = null; });

  fetch('origines.json', { credentials: 'same-origin' }).then(function (r) { return r.ok ? r.json() : { origines: [] }; })
    .then(function (j) {
      origines = (j.origines || []).filter(function (o) { return typeof o === 'string' && /^https:\/\/[a-z0-9.-]+(:[0-9]{1,5})?$/.test(o); });
      // « prêt » : seulement aux origines autorisées (postMessage borné par origine cible).
      origines.forEach(function (o) { try { window.parent.postMessage({ pret: true }, o); } catch (e) { /* cadre absent */ } });
    });
})();
