/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
 * Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
 * Source-Disclosed License — All rights reserved except as expressly granted.
 * See LICENCE-CMSD-1.0.md for terms.
 *
 * SecuBox-Deb :: secubox_pgp — côté navigateur du webmail (#1852, P5).
 *
 * AUCUNE CRYPTOGRAPHIE ICI. Ce script parle, par postMessage, à la page OpenPGP du Coffre (autre origine, cadre invisible) :
 * il lui envoie du texte, il reçoit un résultat. Il ne voit jamais la clé. Tout ce qui vient de la page (texte déchiffré,
 * adresses, messages) est inséré par textContent — jamais en HTML.
 *
 * LE MESSAGE NE PART JAMAIS EN CLAIR PAR ERREUR : si le chiffrement est demandé et échoue (clé manquante, Coffre scellé,
 * page muette), l'envoi est annulé et la raison affichée ; le texte en clair reste dans la fenêtre de rédaction.
 */
(function () {
  'use strict';
  var ADRESSE = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}/g;
  var cadre = null, pret = false, attentePret = [], reponses = {}, compteur = 0;

  function origine() { return window.rcmail && rcmail.env.secubox_pgp_origine; }
  function tr(cle, vars) { return rcmail.get_label('secubox_pgp.' + cle, vars); }

  // ── le cadre de la page du Coffre ────────────────────────────────────
  function ouvre() {
    if (cadre) return;
    cadre = document.createElement('iframe');
    cadre.setAttribute('aria-hidden', 'true');
    cadre.setAttribute('tabindex', '-1');
    cadre.setAttribute('sandbox', 'allow-scripts allow-same-origin');
    cadre.referrerPolicy = 'no-referrer';
    cadre.style.cssText = 'display:none;width:0;height:0;border:0';
    cadre.src = origine() + '/pgp/';
    document.body.appendChild(cadre);
  }
  window.addEventListener('message', function (ev) {
    if (!cadre || ev.origin !== origine() || ev.source !== cadre.contentWindow) return;     // une seule origine, un seul cadre
    var d = ev.data;
    if (!d || typeof d !== 'object') return;
    if (d.pret === true) {
      pret = true;
      attentePret.splice(0).forEach(function (f) { f(); });
    } else if (typeof d.id === 'string' && reponses[d.id]) {
      var r = reponses[d.id]; delete reponses[d.id];
      clearTimeout(r.t);
      r.ok(d);
    }
  });
  function appel(op, corps, delai) {
    return new Promise(function (ok, ko) {
      ouvre();
      function envoie() {
        var id = 'sbx' + (++compteur);
        reponses[id] = { ok: ok, t: setTimeout(function () { delete reponses[id]; ko({ code: 'indisponible' }); }, delai || 20000) };
        cadre.contentWindow.postMessage(Object.assign({ id: id, op: op }, corps || {}), origine());
      }
      if (pret) envoie();
      else {
        attentePret.push(envoie);
        setTimeout(function () { if (!pret) ko({ code: 'indisponible' }); }, 15000);
      }
    }).then(function (r) { if (r.ok === false) throw r; return r; });
  }
  function raison(e) {
    var m = { cle_manquante: function () { return tr('manquants', { adresses: ((e.extra || {}).manquants || []).join(', ') }); },
              pas_de_cle: function () { return tr('pasdecle'); }, coffre_scelle: function () { return tr('coffrescelle'); },
              non_connecte: function () { return tr('nonconnecte'); }, indisponible: function () { return tr('indisponible'); } };
    return (m[e && e.code] || function () { return String((e && e.message) || tr('indisponible')).slice(0, 300); })();
  }

  // ── lecture d'un message ─────────────────────────────────────────────
  var BLOC = /-----BEGIN PGP (MESSAGE|SIGNED MESSAGE)-----[\s\S]*?-----END PGP (MESSAGE|SIGNATURE)-----/;

  function bandeau(classe, texte) {
    var b = document.createElement('div');
    b.className = 'secubox-pgp-bandeau ' + classe;
    b.textContent = texte;
    return b;
  }
  function etatSignature(sig) {
    if (!sig || sig.etat === 'aucune') return bandeau('neutre', tr('sigaucune'));
    if (sig.etat === 'valide') return bandeau('ok', tr('sigvalide') + (sig.uid ? ' — ' + sig.uid : '') + (sig.empreinte ? ' (' + sig.empreinte.slice(-16) + ')' : ''));
    if (sig.etat === 'invalide') return bandeau('ko', tr('siginvalide'));
    return bandeau('neutre', tr('sigconnue'));
  }

  function traiteMessage(conteneur) {
    var info = rcmail.env.secubox_pgp_message || {};
    var texte = conteneur.textContent || '';
    var m = BLOC.exec(texte);
    // Autocrypt entrant : la clé annoncée par l'expéditeur est apprise (la page du Coffre la valide).
    if (info.autocrypt && info.autocrypt.keydata) {
      appel('apprendre', info.autocrypt).catch(function () { /* sans clé ou Coffre scellé : on n'apprend rien, sans bruit */ });
    }
    if (!m) return;
    var armure = m[0], chiffre = m[1] === 'MESSAGE';
    appel(chiffre ? 'dechiffrer' : 'verifier', { armure: armure, expediteur: info.expediteur || '' }, 30000).then(function (r) {
      var zone = document.createElement('div');
      zone.appendChild(bandeau('neutre', chiffre ? tr('dechiffre') : tr('signe')));
      zone.appendChild(etatSignature(r.signature));
      var pre = document.createElement('pre');
      pre.className = 'secubox-pgp-texte';
      pre.textContent = r.texte;                                  // jamais innerHTML : le texte vient d'un tiers
      zone.appendChild(pre);
      conteneur.textContent = '';
      conteneur.appendChild(zone);
    }, function (e) {
      conteneur.insertBefore(bandeau('ko', raison(e)), conteneur.firstChild);
    });
  }

  // ── composition ──────────────────────────────────────────────────────
  var etat = { chiffrer: false, signer: false, emis: false };

  function majBoutons() {
    [].forEach.call(document.querySelectorAll('a.secubox-pgp.chiffrer'), function (a) { a.classList.toggle('on', etat.chiffrer); });
    [].forEach.call(document.querySelectorAll('a.secubox-pgp.signer'), function (a) { a.classList.toggle('on', etat.signer); });
  }
  function enHtml() {
    var h = document.querySelector('[name="_is_html"]');
    return !!h && parseInt(h.value || '0', 10) > 0;
  }
  function destinataires() {
    var v = [];
    [].forEach.call(document.querySelectorAll('[name="_to"],[name="_cc"],[name="_bcc"]'), function (c) {
      v = v.concat(String(c.value || '').match(ADRESSE) || []);
    });
    var vus = {};
    return v.map(function (a) { return a.toLowerCase(); }).filter(function (a) { return vus[a] ? false : (vus[a] = true); });
  }

  function basculer(quoi) {
    if (!etat[quoi] && enHtml()) { rcmail.display_message(tr('textebrut'), 'error'); return; }
    etat[quoi] = !etat[quoi];
    if (quoi === 'chiffrer' && etat.chiffrer) etat.signer = false;           // chiffrer signe déjà
    majBoutons();
  }

  function avantEnvoi() {
    if (etat.emis || !(etat.chiffrer || etat.signer)) return undefined;     // pas demandé, ou déjà transformé : on laisse passer
    if (enHtml()) { rcmail.display_message(tr('textebrut'), 'error'); return false; }
    var zone = document.getElementById('composebody');
    var clair = zone.value;
    var op, corps;
    if (etat.chiffrer) {
      var dest = destinataires();
      if (!dest.length) return undefined;                                    // Roundcube refusera lui-même l'absence de destinataire
      op = 'chiffrer'; corps = { texte: clair, destinataires: dest, signer: true };
    } else { op = 'signer'; corps = { texte: clair }; }
    rcmail.set_busy(true, 'sending');
    appel(op, corps, 30000).then(function (r) {
      zone.value = r.armure;
      etat.emis = true;                                                       // la 2e passe de « send » ne retransforme pas
      rcmail.set_busy(false);
      try { rcmail.command('send', '', null, null); }                         // le formulaire part, SÉRIALISÉ, avec l'armure
      finally { etat.emis = false; zone.value = clair; }                      // le clair revient dans la fenêtre si l'envoi échoue
    }, function (e) {
      rcmail.set_busy(false);
      rcmail.display_message(raison(e), 'error');                             // le clair est intact : rien n'est parti
    });
    return false;                                                             // on annule cet envoi-ci ; il sera refait avec l'armure
  }

  if (window.rcmail) {
    rcmail.addEventListener('init', function () {
      if (rcmail.env.action === 'compose') {
        ouvre();                                                              // le cadre se charge pendant la rédaction
        rcmail.register_command('plugin.secubox_pgp.chiffrer', function () { basculer('chiffrer'); }, true);
        rcmail.register_command('plugin.secubox_pgp.signer', function () { basculer('signer'); }, true);
        rcmail.addEventListener('beforesend', avantEnvoi);
      } else if (rcmail.env.action === 'show' || rcmail.env.action === 'preview') {
        ouvre();
        var c = document.getElementById('messagebody') || document.querySelector('.message-part');
        if (c) traiteMessage(c);
      }
    });
  }
  window.secuboxPgp = { _appel: appel, _traiteMessage: traiteMessage, _destinataires: destinataires, _BLOC: BLOC };   // tests
})();
