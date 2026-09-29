// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox :: ZIA — saisie vocale (#1658). Commune à la page plein écran et à
// la carte /micro. Le même chemin que Lexie : /api/v1/voice/asr reconnaît
// d'abord les commandes courantes (~1 s), sinon transcrit (whisper). Le texte
// est inséré comme un message TAPÉ — ZIA reste le seul cerveau. La réponse
// peut être lue (🔊) : Web Audio sur l'ArrayBuffer, jamais une URL blob:, pour
// ne pas élargir la CSP.
(function () {
  'use strict';
  var API = '/api/v1/voice';
  var SEUIL = 0.02, SILENCE_MS = 1000, SANS_PAROLE_MS = 5000, MAX_MS = 8000;
  var lire = false, ctxLecture = null;
  try { lire = localStorage.getItem('zia.voix.lire') === '1'; } catch (e) { /* stockage refusé */ }

  function enregistre(flux, surNiveau) {
    return new Promise(function (fini) {
      var ctx = new AudioContext(), src = ctx.createMediaStreamSource(flux), an = ctx.createAnalyser();
      an.fftSize = 1024; src.connect(an);
      var buf = new Float32Array(an.fftSize), morceaux = [], rec = new MediaRecorder(flux);
      var t0 = performance.now(), parle = false, dernier = t0, tic;
      rec.ondataavailable = function (e) { morceaux.push(e.data); };
      rec.onstop = function () {
        clearInterval(tic); src.disconnect(); ctx.close();
        flux.getTracks().forEach(function (t) { t.stop(); });
        fini(new Blob(morceaux, { type: rec.mimeType }));
      };
      rec.start();
      tic = setInterval(function () {
        an.getFloatTimeDomainData(buf);
        var s = 0; for (var i = 0; i < buf.length; i++) s += buf[i] * buf[i];
        var rms = Math.sqrt(s / buf.length), t = performance.now();
        if (surNiveau) surNiveau(Math.min(1, rms * 10));
        if (rms > SEUIL) { parle = true; dernier = t; }
        if ((parle && t - dernier > SILENCE_MS) || (!parle && t - t0 > SANS_PAROLE_MS) || t - t0 > MAX_MS) {
          if (rec.state === 'recording') rec.stop();
        }
      }, 50);
      ZIAVoix._arrete = function () { if (rec.state === 'recording') rec.stop(); };
    });
  }

  function transcrit(blob) {
    var f = new FormData();
    f.append('fichier', blob, 'zia.webm'); f.append('langue', 'fr');
    return fetch(API + '/asr', { method: 'POST', body: f, credentials: 'same-origin' }).then(function (r) {
      if (r.status === 401 || r.status === 403) throw new Error('Connectez-vous pour parler à ZIA.');
      if (r.status === 429) throw new Error('La voix est occupée, réessayez.');
      if (!r.ok) throw new Error('Voix indisponible (' + r.status + ').');
      return r.json();
    }).then(function (j) { return (j && j.texte || '').trim(); });
  }

  function dit(texte) {
    if (!lire || !texte) return;
    var propre = String(texte).replace(/\*\*/g, '').replace(/[#>`_]/g, '').slice(0, 600);
    fetch(API + '/tts', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ texte: propre, profil: 'zia', format: 'wav' }) })
      .then(function (r) { return r.ok ? r.arrayBuffer() : null; })
      .then(function (ab) {
        if (!ab) return;
        ctxLecture = ctxLecture || new AudioContext();
        return ctxLecture.decodeAudioData(ab).then(function (b) {
          var s = ctxLecture.createBufferSource(); s.buffer = b; s.connect(ctxLecture.destination); s.start();
        });
      }).catch(function () { /* la lecture est un plus, jamais un échec */ });
  }

  var ZIAVoix = {
    /** form : le formulaire du chat ; envoie(texte) : la fonction d'envoi de la page ; note(msg) : message système. */
    init: function (form, envoie, note) {
      if (!navigator.mediaDevices || !window.MediaRecorder) return;
      // Micro non délégué à ce cadre (autre origine) : pas de bouton qui échouera.
      try { if (document.featurePolicy && !document.featurePolicy.allowsFeature('microphone')) return; } catch (e) { /* API absente */ }
      var micro = document.createElement('button');
      micro.type = 'button'; micro.className = 'zia-micro'; micro.title = 'Parler à ZIA';
      micro.setAttribute('aria-label', 'Parler à ZIA'); micro.textContent = '🎙️';
      var haut = document.createElement('button');
      haut.type = 'button'; haut.className = 'zia-haut'; haut.setAttribute('aria-pressed', String(lire));
      haut.title = 'Lire les réponses'; haut.setAttribute('aria-label', 'Lire les réponses à voix haute');
      haut.textContent = lire ? '🔊' : '🔈';
      haut.addEventListener('click', function () {
        lire = !lire; haut.textContent = lire ? '🔊' : '🔈'; haut.setAttribute('aria-pressed', String(lire));
        try { localStorage.setItem('zia.voix.lire', lire ? '1' : '0'); } catch (e) { /* stockage refusé */ }
      });
      var envoi = form.querySelector('button[type="submit"]');
      form.insertBefore(micro, envoi); form.insertBefore(haut, envoi);
      var ecoute = false;
      micro.addEventListener('click', function () {
        if (ecoute) { ZIAVoix._arrete(); return; }
        navigator.mediaDevices.getUserMedia({ audio: true }).then(function (flux) {
          ecoute = true; micro.classList.add('ecoute'); micro.textContent = '⏺'; note('ZIA écoute…');
          return enregistre(flux, function (n) { micro.style.boxShadow = '0 0 0 ' + (2 + n * 10) + 'px rgba(244,63,94,.35)'; });
        }).then(function (blob) {
          ecoute = false; micro.classList.remove('ecoute'); micro.textContent = '🎙️'; micro.style.boxShadow = '';
          if (!blob) return;
          note('Je transcris…');
          return transcrit(blob).then(function (t) { note(null); if (t) envoie(t); else note('Je n’ai rien entendu.'); });
        }).catch(function (e) {
          ecoute = false; micro.classList.remove('ecoute'); micro.textContent = '🎙️'; micro.style.boxShadow = '';
          var refus = e && (e.name === 'NotAllowedError' || e.name === 'SecurityError');
          note(refus ? 'Micro non autorisé ici. Ouvrez ZIA depuis le Hall, ou autorisez le micro pour ce site.'
                     : (e && e.message ? e.message : 'Micro refusé ou absent.'));
        });
      });
    },
    dit: dit,
    _arrete: function () {}
  };
  window.ZIAVoix = ZIAVoix;
})();
