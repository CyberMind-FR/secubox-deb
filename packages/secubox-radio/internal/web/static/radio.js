(function () {
  'use strict';
  // ── LA SYNCHRONISATION ────────────────────────────────────────────────────
  //
  // LE SERVEUR EST L'AUTORITE. Il dit « telle piste, a tel offset, a telle
  // heure ». Le client ne decide de rien : il se positionne et se corrige.
  //
  // LA LATENCE EST MESUREE, PAS SUPPOSEE. Entre l'instant ou le serveur repond
  // et celui ou le navigateur lit la reponse, il s'ecoule un aller-retour.
  // Sans le compenser, chaque auditeur accumule SON propre retard et la
  // synchronisation derive — d'autant plus sur une liaison lente, c'est-a-dire
  // exactement quand on en aurait le plus besoin.
  var DERIVE_MAX = 1.5;   // secondes : au-dela, on se replace
  var PERIODE    = 5000;  // ms entre deux interrogations

  var ecran = document.getElementById('ecran');
  var titre = document.getElementById('titre');
  var meta  = document.getElementById('meta');
  var derive = document.getElementById('derive');
  var file  = document.getElementById('file');
  var chat  = document.getElementById('chat');
  var dire  = document.getElementById('dire');
  var avert = document.getElementById('avert');
  var boutonAime = document.getElementById('aime');

  var pisteEnCours = 0;
  var curseurChat = 0;
  var ecartHorloge = 0;   // horloge serveur - horloge locale, en ms

  function json(url, options) {
    options = options || {};
    options.headers = options.headers || {};
    // L'EN-TETE D'INTENTION : un site tiers ne peut pas le poser sur une
    // requete inter-origines, alors que le cookie de session, lui, serait
    // joint automatiquement.
    options.headers['X-Sbx-Radio'] = '1';
    if (options.body) options.headers['Content-Type'] = 'application/json';
    return fetch(url, options).then(function (r) {
      return r.json().then(function (d) { return { code: r.status, corps: d }; });
    });
  }

  function fmt(ms) {
    var s = Math.max(0, Math.floor(ms / 1000));
    return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
  }

  function pose(e) {
    if (!e || e.silence) {
      titre.textContent = 'Silence';
      meta.textContent = 'Aucune piste prête — proposez-en une.';
      ecran.removeAttribute('src');
      pisteEnCours = 0;
      return;
    }
    var p = e.piste;
    var envoi = Date.now();
    // L'aller-retour est deja passe : on estime la moitie pour le sens retour.
    var offset = (e.offset_ms + (envoi - dernierAppel) / 2) / 1000;

    if (p.id !== pisteEnCours) {
      pisteEnCours = p.id;
      titre.textContent = p.titre || p.source;
      meta.textContent = (p.auteur ? p.auteur + ' · ' : '') + '♥ ' + p.coeurs;
      boutonAime.classList.toggle('on', !!p.aime);
      boutonAime.textContent = '♥ ' + p.coeurs;
      ecran.src = '/media/' + p.id;
      ecran.currentTime = offset;
      // AUTOPLAY REFUSE = SILENCE INEXPLIQUE. Le navigateur bloque la lecture
      // automatique avec du son ; on le DIT plutot que de laisser l'ecran noir.
      var essai = ecran.play();
      if (essai && essai.catch) {
        essai.catch(function () { avert.hidden = false; });
      }
      return;
    }
    var ecart = ecran.currentTime - offset;
    derive.textContent = 'décalage ' + (ecart >= 0 ? '+' : '') + ecart.toFixed(1) + ' s';
    if (Math.abs(ecart) > DERIVE_MAX) {
      // ON SE REPLACE SANS RIEN DEMANDER : une radio ne se met pas en pause
      // pour attendre un auditeur en retard.
      ecran.currentTime = offset;
    }
  }

  function poseFile(pistes) {
    file.innerHTML = '';
    (pistes || []).forEach(function (p) {
      var d = document.createElement('div');
      d.className = 'tuile' + (p.id === pisteEnCours ? ' joue' : '');
      var glyphe = p.ecarte ? '⚠' : (p.en_cache ? '🎬' : '⏬');
      var etat = p.ecarte ? (p.raison || 'écartée')
               : (p.en_cache ? '♥ ' + p.coeurs : 'récupération…');
      d.innerHTML = '<div class="vg">' + glyphe + '</div><div class="bas">' +
        '<div class="n"></div><div class="m"></div></div>';
      // textContent et non innerHTML : le titre vient d'un service tiers.
      d.querySelector('.n').textContent = p.titre || p.source;
      d.querySelector('.m').textContent = etat;
      file.appendChild(d);
    });
  }

  function poseChat(phrases) {
    if (!phrases || !phrases.length) return;
    var colle = chat.scrollTop + chat.clientHeight >= chat.scrollHeight - 8;
    phrases.forEach(function (p) {
      curseurChat = Math.max(curseurChat, p.ID || p.id || 0);
      var d = document.createElement('div');
      d.className = 'ph';
      var b = document.createElement('b');
      b.textContent = p.Pseudo || p.pseudo || '?';
      var s = document.createElement('span');
      // textContent : le corps vient d'un membre, il ne devient jamais du
      // balisage. C'est ici la seule barriere, et elle suffit.
      s.textContent = ' ' + (p.Corps || p.corps || '');
      d.appendChild(b); d.appendChild(s);
      chat.appendChild(d);
    });
    // ON NE RAMENE EN BAS QUE SI L'ON Y ETAIT : sinon on arrache la lecture a
    // qui remonte le fil.
    if (colle) chat.scrollTop = chat.scrollHeight;
  }

  var dernierAppel = Date.now();
  function sonde() {
    dernierAppel = Date.now();
    json('/api/v1/radio/current?depuis=' + curseurChat).then(function (r) {
      if (r.corps.horloge_ms) ecartHorloge = r.corps.horloge_ms - Date.now();
      pose(r.corps);
      poseChat(r.corps.chat);
    }).catch(function () { /* une sonde ratee n'est pas une panne */ });
    json('/api/v1/radio/playlist').then(function (r) {
      poseFile(r.corps.pistes);
    }).catch(function () {});
  }

  boutonAime.addEventListener('click', function () {
    if (!pisteEnCours) return;
    var pose = !boutonAime.classList.contains('on');
    json('/api/v1/radio/pistes/' + pisteEnCours + '/coeur',
         { method: pose ? 'POST' : 'DELETE' }).then(function (r) {
      if (r.corps.piste) {
        boutonAime.classList.toggle('on', r.corps.piste.aime);
        boutonAime.textContent = '♥ ' + r.corps.piste.coeurs;
      }
    });
  });

  document.getElementById('recaler').addEventListener('click', function () {
    pisteEnCours = 0; // force le repositionnement complet
    avert.hidden = true;
    sonde();
  });

  dire.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' || !dire.value.trim()) return;
    var corps = dire.value;
    dire.value = '';
    json('/api/v1/radio/chat', { method: 'POST', body: JSON.stringify({ corps: corps }) })
      .then(function (r) {
        if (r.code === 429) { dire.placeholder = 'Laissez souffler l’antenne…'; }
        else if (r.corps.phrase) { poseChat([r.corps.phrase]); }
      });
  });

  document.getElementById('proposer').addEventListener('submit', function (e) {
    e.preventDefault();
    var champ = document.getElementById('source');
    var s = champ.value.trim();
    if (!s) return;
    json('/api/v1/radio/propositions',
         { method: 'POST', body: JSON.stringify({ source: s }) }).then(function (r) {
      var m = document.getElementById('retour');
      if (r.code === 409) m.textContent = 'Cette piste a déjà été refusée.';
      else if (r.code >= 400) m.textContent = r.corps.error || 'Refusé.';
      else { m.textContent = r.corps.neuve ? 'Proposée — en attente de validation.'
                                           : 'Déjà dans la file.'; champ.value = ''; }
    });
  });

  sonde();
  setInterval(sonde, PERIODE);
})();
