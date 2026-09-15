// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SBXOS :: Lexie — la fenêtre vocale du Hall (#1287).
//
// LEXIE NE COMPREND RIEN, ET C'EST VOULU. Elle capte, elle envoie, elle prononce.
// L'intention, le rôle et l'action appartiennent à ZIA, dont la couche d'action
// traduit déjà « mets la radio en pause » en `media.pause` sur le service radio.
// Lui donner un second cerveau dédoublerait le seul endroit du système qui a le
// droit de décider — et les deux finiraient par diverger.
//
// LA BOUCLE :
//   micro → /api/v1/voice/asr → texte
//        → /api/v1/zia/v1/chat → réponse + actions DÉJÀ VALIDÉES
//        → sbxExecuteAction    → la cardlet agit
//        → /api/v1/voice/tts   → la réponse prend une voix
//
// TROIS CHOIX TECHNIQUES QUI MÉRITENT LEUR EXPLICATION :
//
//  1. ON JOUE PAR WEB AUDIO, PAS PAR UNE URL blob:. La CSP du Hall est
//     `default-src 'self'` sans `media-src` ; un `blob:` serait refusé en
//     silence. `decodeAudioData` sur l'ArrayBuffer évite l'URL, donc évite
//     d'élargir la CSP — on ne desserre pas une politique pour du confort.
//
//  2. ON ENCODE LE WAV 16 kHz MONO DANS LE NAVIGATEUR. whisper.cpp veut
//     exactement cela ; le faire ici épargne à la box une dépendance ffmpeg et
//     divise le poids de l'envoi. Le navigateur a déjà le rééchantillonneur.
//
//  3. ON N'ÉCOUTE PAS EN PERMANENCE. Il n'existe aucun détecteur de mot-clé
//     local dans SBXOS : une « écoute active » permanente signifierait envoyer
//     le son de la pièce en continu. C'est un autre produit et un autre
//     consentement. Lexie écoute quand on le lui demande, et le montre.

(function () {
  'use strict';

  var API_VOICE = '/api/v1/voice';
  var API_ZIA = '/api/v1/zia';

  // ── Authentification : l'idiome du Hall (#400, SSO-lite) ───────────────────
  // Le cookie de session suffit à `require_jwt` ; on n'ajoute le Bearer que s'il
  // existe, plutôt que d'exiger un jeton que la plupart des visites n'ont pas.
  function jeton() {
    try { return localStorage.getItem('sbx_token') || ''; } catch (e) { return ''; }
  }
  function entetes(sup) {
    var h = sup || {};
    var j = jeton();
    if (j) h['Authorization'] = 'Bearer ' + j;
    return h;
  }

  // ── État ───────────────────────────────────────────────────────────────────
  var moteur = null;        // dernier état connu du moteur (null = pas encore su)
  var ecoutant = false;
  var flux = null;          // MediaStream en cours
  var enregistreur = null;  // MediaRecorder
  var morceaux = [];
  var ctxAudio = null;      // AudioContext partagé (créé au premier geste)
  var sourceEnCours = null; // AudioBufferSourceNode en lecture
  var analyseur = null, animation = 0;
  var el = {};              // références DOM

  function ctx() {
    if (!ctxAudio) {
      var C = window.AudioContext || window.webkitAudioContext;
      if (!C) return null;
      ctxAudio = new C();
    }
    if (ctxAudio.state === 'suspended') { ctxAudio.resume().catch(function () {}); }
    return ctxAudio;
  }

  // ── Encodage WAV 16 kHz mono ───────────────────────────────────────────────
  // Rééchantillonnage par OfflineAudioContext : c'est le moteur du navigateur qui
  // filtre et rééchantillonne, pas une boucle maison qui produirait du repliement.
  function versWav16k(arrayBuffer) {
    var c = ctx();
    if (!c) return Promise.reject(new Error('Web Audio indisponible dans ce navigateur.'));
    return c.decodeAudioData(arrayBuffer.slice(0)).then(function (buf) {
      var cible = 16000;
      var duree = Math.max(1, Math.ceil(buf.duration * cible));
      var OC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      var off = new OC(1, duree, cible);
      var src = off.createBufferSource();
      src.buffer = buf;
      src.connect(off.destination);
      src.start(0);
      return off.startRendering();
    }).then(function (rendu) {
      return encodeWav(rendu.getChannelData(0), 16000);
    });
  }

  function encodeWav(pcm, taux) {
    var n = pcm.length;
    var tampon = new ArrayBuffer(44 + n * 2);
    var v = new DataView(tampon);
    function txt(o, s) { for (var i = 0; i < s.length; i++) v.setUint8(o + i, s.charCodeAt(i)); }
    txt(0, 'RIFF'); v.setUint32(4, 36 + n * 2, true); txt(8, 'WAVE');
    txt(12, 'fmt '); v.setUint32(16, 16, true); v.setUint16(20, 1, true);
    v.setUint16(22, 1, true); v.setUint32(24, taux, true);
    v.setUint32(28, taux * 2, true); v.setUint16(32, 2, true); v.setUint16(34, 16, true);
    txt(36, 'data'); v.setUint32(40, n * 2, true);
    for (var i = 0; i < n; i++) {
      // Bornage AVANT conversion : un échantillon hors [-1,1] déborderait en
      // int16 et produirait un craquement au lieu d'une saturation propre.
      var s = Math.max(-1, Math.min(1, pcm[i]));
      v.setInt16(44 + i * 2, s < 0 ? s * 0x8000 : s * 0x7fff, true);
    }
    return new Blob([tampon], { type: 'audio/wav' });
  }

  // ── Le moteur : son état RÉEL, jamais supposé ──────────────────────────────
  function sondeMoteur() {
    return fetch(API_VOICE + '/moteur', {
      headers: entetes({ 'Accept': 'application/json' }), credentials: 'same-origin'
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (j) {
      moteur = j; peintEtat(); return j;
    }).catch(function (e) {
      moteur = { joignable: false, tts: false, asr: false,
                 detail: 'Service vocal injoignable (' + e.message + '). '
                       + 'Vérifiez secubox-voice.' };
      peintEtat();
      return moteur;
    });
  }

  // ── Prononcer ──────────────────────────────────────────────────────────────
  function parle(texte, profil) {
    if (!texte) return Promise.resolve(false);
    if (moteur && moteur.tts === false) {
      // On ne fait PAS semblant : le texte est déjà affiché, on dit juste
      // pourquoi il n'est pas prononcé.
      note('🔇 ' + (moteur.detail || 'Synthèse indisponible.'));
      return Promise.resolve(false);
    }
    return fetch(API_VOICE + '/tts', {
      method: 'POST', credentials: 'same-origin',
      headers: entetes({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ texte: texte, profil: profil || 'lexie', format: 'wav' })
    }).then(function (r) {
      if (r.status === 503) {
        return r.json().then(function (j) { throw new Error(j.detail || 'moteur absent'); });
      }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      var av = r.headers.get('X-Avertissement');
      if (av) note('⚠️ ' + av);
      return r.arrayBuffer();
    }).then(function (ab) {
      var c = ctx();
      if (!c) return false;
      return c.decodeAudioData(ab).then(function (buf) {
        taisToi();
        var s = c.createBufferSource();
        s.buffer = buf; s.connect(c.destination); s.start(0);
        sourceEnCours = s;
        s.onended = function () { if (sourceEnCours === s) sourceEnCours = null; };
        return true;
      });
    }).catch(function (e) {
      note('🔇 ' + e.message);
      return false;
    });
  }

  function taisToi() {
    if (sourceEnCours) {
      try { sourceEnCours.stop(); } catch (e) {}
      sourceEnCours = null;
    }
  }

  // ── Écouter ────────────────────────────────────────────────────────────────
  function ecoute(actif) {
    if (actif === false) { return arreteEcoute(); }
    if (ecoutant) return Promise.resolve(false);
    if (moteur && moteur.asr === false) {
      note('🎙️ ' + (moteur.detail || 'Reconnaissance indisponible.'));
      return Promise.resolve(false);
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      note('🎙️ Ce navigateur n’expose pas de micro (ou la page n’est pas en HTTPS).');
      return Promise.resolve(false);
    }
    return navigator.mediaDevices.getUserMedia({
      audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true }
    }).then(function (s) {
      flux = s; morceaux = [];
      enregistreur = new MediaRecorder(s);
      enregistreur.ondataavailable = function (e) { if (e.data && e.data.size) morceaux.push(e.data); };
      enregistreur.onstop = function () { transcris(new Blob(morceaux, { type: 'audio/webm' })); };
      enregistreur.start();
      ecoutant = true;
      vumetre(s);
      peintEtat();
      return true;
    }).catch(function (e) {
      // Distinguer le refus de l'absence : ce ne sont pas les mêmes gestes de
      // réparation, et une seule phrase pour les deux n'aide personne.
      note(e && e.name === 'NotAllowedError'
        ? '🎙️ Micro refusé. Autorisez-le dans la barre d’adresse, puis réessayez.'
        : '🎙️ Micro indisponible : ' + ((e && e.message) || e));
      return false;
    });
  }

  function arreteEcoute() {
    if (!ecoutant) return Promise.resolve(false);
    ecoutant = false;
    try { enregistreur && enregistreur.state !== 'inactive' && enregistreur.stop(); } catch (e) {}
    if (flux) { flux.getTracks().forEach(function (t) { t.stop(); }); flux = null; }
    if (animation) { cancelAnimationFrame(animation); animation = 0; }
    analyseur = null;
    peintEtat();
    return Promise.resolve(true);
  }

  function transcris(blob) {
    dis('…', 'attente');
    blob.arrayBuffer().then(versWav16k).then(function (wav) {
      var fd = new FormData();
      fd.append('fichier', wav, 'commande.wav');
      fd.append('langue', 'fr');
      return fetch(API_VOICE + '/asr', {
        method: 'POST', credentials: 'same-origin', headers: entetes({}), body: fd
      });
    }).then(function (r) {
      if (r.status === 503) {
        return r.json().then(function (j) { throw new Error(j.detail || 'moteur absent'); });
      }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (j) {
      if (j.vide) { dis('(rien entendu)', 'vide'); return; }
      dis(j.texte, 'vous');
      demandeAZia(j.texte);
    }).catch(function (e) {
      dis('', 'vide');
      note('🎙️ ' + e.message);
    });
  }

  // ── Demander à ZIA, puis agir ──────────────────────────────────────────────
  // Le préfixe « Lexie, » est RETIRÉ s'il est là, mais jamais exigé : sans
  // détecteur de mot-clé, il n'a aucune fonction technique — seulement l'habitude
  // de s'adresser à quelqu'un. On ne fait pas d'une habitude une contrainte.
  function sansPrefixe(t) {
    return String(t || '').replace(/^\s*(lexie|lexy|alexie)\s*[,:!.]?\s*/i, '');
  }

  function demandeAZia(texte) {
    var msg = sansPrefixe(texte);
    return fetch(API_ZIA + '/v1/chat', {
      method: 'POST', credentials: 'same-origin',
      headers: entetes({ 'Content-Type': 'application/json', 'Accept': 'application/json' }),
      body: JSON.stringify({ message: msg })
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (j) {
      var reponse = (j && j.text) || '';
      var actions = (j && j.actions) || [];
      // ON AGIT AVANT DE PARLER. Si l'action échoue, la phrase « je mets la radio
      // en pause » serait un mensonge — mieux vaut le savoir avant de la dire.
      var agies = 0;
      actions.forEach(function (a) {
        if (typeof window.sbxExecuteAction === 'function' && window.sbxExecuteAction(a)) agies++;
      });
      if (actions.length && !agies) {
        reponse = 'Je n’ai pas pu appliquer cette action — le service visé n’est '
                + 'pas ouvert dans le Hall.';
      }
      dis(reponse, 'lexie');
      if (actions.length) { note('⚡ ' + agies + '/' + actions.length + ' action(s) appliquée(s)'); }
      return parle(reponse, 'lexie');
    }).catch(function (e) {
      dis('ZIA est injoignable (' + e.message + ').', 'lexie');
    });
  }

  // ── Interface ──────────────────────────────────────────────────────────────
  var CSS = ''
    + '.lexie-bouton{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:999px;'
    + 'border:1px solid var(--bord,rgba(140,170,200,.28));background:transparent;color:inherit;'
    + 'font:inherit;font-size:.78rem;cursor:pointer;line-height:1}'
    + '.lexie-bouton:hover{border-color:var(--cyan,#00d4ff);color:var(--cyan,#00d4ff)}'
    + '.lexie-bouton.actif{border-color:var(--cyan,#00d4ff);color:var(--cyan,#00d4ff);'
    + 'box-shadow:0 0 10px rgba(0,212,255,.25)}'
    + '.lexie-pastille{width:7px;height:7px;border-radius:50%;background:var(--muted,#6b7b8b)}'
    + '.lexie-bouton.actif .lexie-pastille{background:var(--cyan,#00d4ff);animation:lexiePouls 1.1s infinite}'
    + '@keyframes lexiePouls{0%,100%{opacity:1}50%{opacity:.25}}'
    + '.lexie-vol{position:fixed;right:18px;top:64px;width:min(340px,calc(100vw - 36px));z-index:9999;'
    + 'background:var(--carte,#12161d);color:var(--encre,#e8e6d9);border:1px solid var(--bord,rgba(140,170,200,.28));'
    + 'border-radius:14px;box-shadow:0 18px 48px rgba(0,0,0,.45);overflow:hidden;font-size:.82rem}'
    + '.lexie-vol[hidden]{display:none}'
    + '.lexie-tete{display:flex;align-items:center;gap:8px;padding:10px 12px;'
    + 'border-bottom:1px solid var(--bord,rgba(140,170,200,.22))}'
    + '.lexie-nom{font-weight:700;letter-spacing:.02em}'
    /* L'ÉTAT DU MOTEUR EST UN GLYPHE, PLUS UNE ÉTIQUETTE. « LOCALE » en
       majuscules dans une pastille bordée pesait autant que le nom de la
       fenêtre pour une information qu'on ne consulte qu'une fois. Un emoji se
       lit sans se lire.
       LA PASTILLE COLORÉE RESTE, EN PETIT : l'emoji porte le SENS, le point de
       couleur porte la GRAVITÉ — c'est lui qu'on repère du coin de l'œil quand
       le moteur tombe. */
    + '.lexie-tag{font-size:.92rem;line-height:1;cursor:help;position:relative;'
    + 'display:inline-flex;align-items:center;opacity:.95}'
    + '.lexie-tag::after{content:"";position:absolute;right:-1px;bottom:-1px;'
    + 'width:6px;height:6px;border-radius:50%;background:currentColor;'
    + 'box-shadow:0 0 0 1.5px var(--carte,#12161d)}'
    + '.lexie-tag.local{color:var(--vert,#4ade80)}.lexie-tag.distant{color:var(--orange,#ff9944)}'
    + '.lexie-tag.hs{color:var(--rouge,#ff4466)}'
    + '.lexie-x{margin-left:auto;background:none;border:0;color:inherit;font-size:1.05rem;'
    + 'cursor:pointer;opacity:.6;line-height:1;padding:2px 4px}.lexie-x:hover{opacity:1}'
    + '.lexie-onde{display:block;width:100%;height:44px;background:var(--fond,#0f172a)}'
    + '.lexie-corps{padding:10px 12px;display:flex;flex-direction:column;gap:8px}'
    + '.lexie-ligne{display:flex;gap:7px;align-items:flex-start;line-height:1.35}'
    + '.lexie-ligne .qui{flex:0 0 auto;opacity:.55;font-size:.62rem;text-transform:uppercase;'
    + 'letter-spacing:.07em;padding-top:2px;min-width:38px}'
    + '.lexie-ligne.vous .txt{color:var(--cyan,#00d4ff)}'
    + '.lexie-ligne.attente .txt,.lexie-ligne.vide .txt{opacity:.5;font-style:italic}'
    + '.lexie-note{font-size:.7rem;opacity:.72;border-top:1px dashed var(--bord,rgba(140,170,200,.22));'
    + 'padding-top:7px;margin:0}'
    + '.lexie-pied{display:flex;gap:8px;padding:10px 12px;border-top:1px solid var(--bord,rgba(140,170,200,.22))}'
    + '.lexie-mic{flex:1;padding:8px;border-radius:9px;border:1px solid var(--cyan,#00d4ff);'
    + 'background:rgba(0,212,255,.1);color:var(--cyan,#00d4ff);font:inherit;font-size:.8rem;cursor:pointer}'
    + '.lexie-mic[disabled]{opacity:.4;cursor:not-allowed;border-color:var(--muted,#6b7b8b);'
    + 'background:transparent;color:var(--muted,#6b7b8b)}'
    + '.lexie-mic.on{background:rgba(255,68,102,.14);border-color:var(--rouge,#ff4466);color:var(--rouge,#ff4466)}'
    + '.lexie-stop{padding:8px 10px;border-radius:9px;border:1px solid var(--bord,rgba(140,170,200,.28));'
    + 'background:transparent;color:inherit;font:inherit;font-size:.8rem;cursor:pointer}'
    + '@media (prefers-reduced-motion:reduce){.lexie-bouton.actif .lexie-pastille{animation:none}}';

  function monte() {
    if (el.vol) return;
    var s = document.createElement('style');
    s.textContent = CSS;
    document.head.appendChild(s);

    var vol = document.createElement('div');
    vol.className = 'lexie-vol';
    vol.hidden = true;
    vol.setAttribute('role', 'dialog');
    vol.setAttribute('aria-label', 'Lexie — commande vocale');
    vol.innerHTML =
        '<div class="lexie-tete"><span class="lexie-nom">🎙️ Lexie</span>'
      + '<span class="lexie-tag" data-r="tag">…</span>'
      + '<button class="lexie-x" data-r="fermer" aria-label="Fermer">✕</button></div>'
      + '<canvas class="lexie-onde" data-r="onde" width="340" height="44"></canvas>'
      + '<div class="lexie-corps"><div data-r="fil"></div><p class="lexie-note" data-r="note"></p></div>'
      + '<div class="lexie-pied">'
      + '<button class="lexie-mic" data-r="mic">🎙️ Parler</button>'
      + '<button class="lexie-stop" data-r="stop" title="Couper la voix">🤫</button></div>';
    document.body.appendChild(vol);

    el.vol = vol;
    ['tag', 'fermer', 'onde', 'fil', 'note', 'mic', 'stop'].forEach(function (k) {
      el[k] = vol.querySelector('[data-r="' + k + '"]');
    });
    el.fermer.onclick = ferme;
    el.mic.onclick = function () { ecoutant ? arreteEcoute() : ecoute(true); };
    el.stop.onclick = taisToi;
    // Échap ferme : c'est le réflexe pour toute fenêtre flottante.
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !vol.hidden) ferme();
    });
  }

  function peintEtat() {
    if (!el.vol) return;
    var m = moteur || {};
    var genre = m.joignable ? (m.genre === 'distant' ? 'distant' : 'local') : 'hs';
    // 🏠 la voix tourne SUR la box · 🛰️ elle est relayée ailleurs · ⛔ injoignable.
    // Le 🏠 est le même signe que celui du nommage DPI pour « cette box » : un
    // vocabulaire visuel ne vaut que s'il est constant d'un écran à l'autre.
    var SIGNES = { local: '🏠', distant: '🛰️', hs: '⛔' };
    var MOTS = { local: 'Voix locale — le moteur tourne sur la box',
                 distant: 'Voix distante — le moteur est relayé ailleurs',
                 hs: 'Moteur vocal injoignable' };
    el.tag.className = 'lexie-tag ' + genre;
    el.tag.textContent = SIGNES[genre];
    // UN EMOJI QUI REMPLACE UN MOT NE DOIT PAS RETIRER LE MOT de l'arbre
    // d'accessibilité : un lecteur d'écran annoncerait « maison » au lieu de
    // « voix locale ». Le sens vit donc dans aria-label, et l'infobulle y
    // ajoute le détail du moteur quand il y en a un.
    el.tag.setAttribute('role', 'img');
    el.tag.setAttribute('aria-label', MOTS[genre]);
    el.tag.title = m.detail ? (MOTS[genre] + ' — ' + m.detail) : MOTS[genre];
    el.mic.disabled = !(m.asr !== false && m.joignable !== false);
    el.mic.classList.toggle('on', ecoutant);
    el.mic.textContent = ecoutant ? '⏹️ J’écoute — cliquez pour envoyer' : '🎙️ Parler';
    if (el.bouton) el.bouton.classList.toggle('actif', ecoutant);
    if (!m.joignable && m.detail) note(m.detail);
  }

  function dis(texte, qui) {
    if (!el.fil) return;
    if (qui === 'attente' || qui === 'vide') {
      var prov = el.fil.querySelector('.lexie-ligne.attente');
      if (prov) prov.remove();
      if (qui === 'vide') return;
    }
    var d = document.createElement('div');
    d.className = 'lexie-ligne ' + (qui || '');
    var nom = qui === 'vous' ? 'vous' : (qui === 'attente' ? '…' : 'lexie');
    d.innerHTML = '<span class="qui"></span><span class="txt"></span>';
    d.querySelector('.qui').textContent = nom;
    d.querySelector('.txt').textContent = texte;   // jamais innerHTML : c'est du dit
    el.fil.appendChild(d);
    while (el.fil.children.length > 6) el.fil.removeChild(el.fil.firstChild);
    el.fil.scrollTop = el.fil.scrollHeight;
  }

  function note(t) { if (el.note) el.note.textContent = t || ''; }

  function vumetre(stream) {
    var c = ctx();
    if (!c || !el.onde) return;
    var src = c.createMediaStreamSource(stream);
    analyseur = c.createAnalyser();
    analyseur.fftSize = 512;
    src.connect(analyseur);
    var data = new Uint8Array(analyseur.frequencyBinCount);
    var g = el.onde.getContext('2d');
    var L = el.onde.width, H = el.onde.height;
    (function boucle() {
      if (!analyseur) return;
      animation = requestAnimationFrame(boucle);
      analyseur.getByteTimeDomainData(data);
      g.clearRect(0, 0, L, H);
      g.lineWidth = 1.5;
      g.strokeStyle = getComputedStyle(el.vol).getPropertyValue('--cyan') || '#00d4ff';
      g.beginPath();
      for (var i = 0; i < L; i++) {
        var v = data[Math.floor(i * data.length / L)] / 128 - 1;
        var y = H / 2 + v * (H / 2 - 2);
        i ? g.lineTo(i, y) : g.moveTo(i, y);
      }
      g.stroke();
    })();
  }

  function ouvre() {
    monte();
    el.vol.hidden = false;
    if (el.bouton) el.bouton.setAttribute('aria-expanded', 'true');
    sondeMoteur();
  }
  function ferme() {
    arreteEcoute(); taisToi();
    if (el.vol) el.vol.hidden = true;
    if (el.bouton) el.bouton.setAttribute('aria-expanded', 'false');
  }
  function bascule() { monte(); (el.vol.hidden ? ouvre : ferme)(); }

  // ── Greffe du bouton dans la barre du Hall ─────────────────────────────────
  function greffe() {
    var barre = document.querySelector('.mast-main');
    if (!barre || document.querySelector('.lexie-bouton')) return;
    var b = document.createElement('button');
    b.className = 'lexie-bouton';
    b.type = 'button';
    b.setAttribute('aria-expanded', 'false');
    b.title = 'Lexie — commande vocale locale';
    b.innerHTML = '<span class="lexie-pastille"></span><span>Lexie</span>';
    b.onclick = bascule;
    barre.appendChild(b);
    el.bouton = b;
  }

  // ── Les capacités voice.* arrivent ICI, pas dans un iframe ─────────────────
  // `sbxPost` vise un cadre de cardlet ; Lexie n'en est pas une, elle est native
  // au Hall. Le Hall doit donc router `service === 'voice'` vers ce module —
  // sans quoi ZIA validerait une action que personne n'exécuterait.
  window.sbxVoiceCmd = function (msg) {
    if (!msg || msg.sbx !== 'cmd') return false;
    if (msg.action === 'dire') { monte(); ouvre(); parle(String(msg.texte || ''), msg.profil); return true; }
    if (msg.action === 'ecoute') { monte(); ouvre(); ecoute(msg.v !== false); return true; }
    if (msg.action === 'tais-toi') { taisToi(); return true; }
    return false;
  };

  window.Lexie = {
    ouvre: ouvre, ferme: ferme, bascule: bascule,
    parle: parle, ecoute: ecoute, taisToi: taisToi,
    moteur: function () { return moteur; }, sonde: sondeMoteur
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', greffe);
  } else { greffe(); }
})();
