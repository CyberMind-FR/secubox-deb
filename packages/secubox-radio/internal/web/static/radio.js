(function () {
  'use strict';

  // ── LE PSEUDONYME ─────────────────────────────────────────────────────────
  //
  // CE N'EST PAS UNE AUTHENTIFICATION, et la page ne pretend pas le contraire.
  // Sur cette board le LAN est de confiance ; ce cookie sert a ATTRIBUER des
  // gestes entre gens qui se connaissent — qui a propose, qui a aime, qui a
  // parle. L'identifiant est tire une fois puis conserve : sans lui, chaque
  // rechargement ferait de vous quelqu'un d'autre, et « retirer mon coeur »
  // n'aurait plus de sens.
  function cookie(n) {
    var m = document.cookie.match(new RegExp('(^|; )' + n + '=([^;]*)'));
    return m ? decodeURIComponent(m[2]) : '';
  }
  function poseCookie(n, v) {
    document.cookie = n + '=' + encodeURIComponent(v) + ';path=/;max-age=31536000;SameSite=Lax';
  }
  if (!cookie('sbx_radio')) {
    poseCookie('sbx_radio', String(Math.floor(Math.random() * 9e15) + 1e3));
  }
  function nom() {
    var n = cookie('sbx_radio_nom');
    if (!n) {
      n = (prompt('Votre nom sur l\'antenne ?') || '').trim();
      if (n) poseCookie('sbx_radio_nom', n);
    }
    return n;
  }

  // ── LA SYNCHRONISATION ────────────────────────────────────────────────────
  //
  // LE SERVEUR EST L'AUTORITE : il dit « telle piste, a tel offset, a telle
  // heure ». Le client se positionne et se corrige, il ne decide de rien.
  //
  // LA LATENCE EST MESUREE, PAS SUPPOSEE. Sans la compenser, chaque auditeur
  // accumule SON propre retard — d'autant plus sur une liaison lente,
  // c'est-a-dire exactement quand on en aurait le plus besoin.
  var DERIVE_MAX = 1.5, PERIODE = 5000;

  var $ = function (id) { return document.getElementById(id); };
  var ecran = $('ecran'), pochette = $('pochette'), glyphe = $('glyphe');
  var titre = $('titre'), meta = $('meta'), jauge = $('jauge');
  var ecoule = $('ecoule'), duree = $('duree'), derive = $('derive');
  var file = $('file'), chat = $('chat'), dire = $('dire');
  var avert = $('avert'), bAime = $('aime'), bJouer = $('jouer');

  var pisteEnCours = 0, curseurChat = 0, dernierAppel = Date.now();

  function json(url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    // L'EN-TETE D'INTENTION : un site tiers ne peut pas le poser sur une
    // requete inter-origines, alors que le cookie, lui, serait joint tout seul.
    opts.headers['X-Sbx-Radio'] = '1';
    if (opts.body) opts.headers['Content-Type'] = 'application/json';
    return fetch(url, opts).then(function (r) {
      return r.json().catch(function () { return {}; })
        .then(function (d) { return { code: r.status, corps: d }; });
    });
  }

  function mmss(ms) {
    var s = Math.max(0, Math.floor(ms / 1000));
    return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
  }

  // La pochette est RELAYEE par le demon : la lier ferait contacter Google par
  // chaque auditeur, et obligerait a ouvrir la politique de securite.
  function poseVignette(cible, glypheEl, p) {
    if (!p || String(p.source || '').indexOf('yt:') !== 0) return;
    var img = new Image();
    img.alt = '';
    img.onload = function () {
      if (glypheEl) glypheEl.remove();
      cible.innerHTML = '';
      cible.appendChild(img);
    };
    img.src = '/vignette/' + p.id;
  }

  function pose(e) {
    if (!e || e.silence) {
      ecran.classList.add('muet');
      titre.textContent = 'Silence';
      meta.textContent = 'Aucune piste prête — proposez-en une.';
      jauge.style.width = '0';
      ecoule.textContent = '0:00'; duree.textContent = '--:--';
      derive.textContent = '';
      ecran.removeAttribute('src');
      pisteEnCours = 0;
      return;
    }
    var p = e.piste;
    // L'aller-retour est deja passe : on en estime la moitie pour le retour.
    var offset = (e.offset_ms + (Date.now() - dernierAppel) / 2) / 1000;

    if (p.id !== pisteEnCours) {
      pisteEnCours = p.id;
      titre.textContent = p.titre || p.source;
      meta.textContent = (p.auteur ? p.auteur + ' · ' : '') +
                         (p.coeurs ? '♥ ' + p.coeurs : 'aucun ♥');
      bAime.classList.toggle('on', !!p.aime);
      pochette.innerHTML = '<span id="glyphe">💿</span>';
      poseVignette(pochette, $('glyphe'), p);
      duree.textContent = p.duree_ms ? mmss(p.duree_ms) : '--:--';
      ecran.classList.remove('muet');
      ecran.src = '/media/' + p.id;
      ecran.currentTime = offset;
      // AUTOPLAY REFUSE = SILENCE INEXPLIQUE : on le DIT plutot que de laisser
      // un ecran noir.
      var essai = ecran.play();
      if (essai && essai.catch) essai.catch(function () { avert.hidden = false; });
      return;
    }
    var ecart = ecran.currentTime - offset;
    derive.textContent = (ecart >= 0 ? '+' : '') + ecart.toFixed(1) + ' s';
    ecoule.textContent = mmss(offset * 1000);
    if (p.duree_ms) jauge.style.width = Math.min(100, offset * 1000 / p.duree_ms * 100) + '%';
    // ON SE REPLACE SANS RIEN DEMANDER : une radio ne se met pas en pause pour
    // attendre un auditeur en retard.
    if (Math.abs(ecart) > DERIVE_MAX) ecran.currentTime = offset;
  }

  function poseFile(pistes) {
    file.innerHTML = '';
    var l = (pistes || []).filter(function (p) { return p.id !== pisteEnCours; });
    if (!l.length) {
      file.innerHTML = '<li class="vide">Rien d\'autre en attente — proposez un titre.</li>';
      return;
    }
    l.forEach(function (p, i) {
      var li = document.createElement('li');
      if (p.ecarte) li.className = 'ecarte';
      var rg = document.createElement('span'); rg.className = 'rg'; rg.textContent = i + 2;
      var vg = document.createElement('span'); vg.className = 'vg';
      var g = document.createElement('span');
      g.textContent = p.ecarte ? '⚠' : (p.en_cache ? '🎬' : '⏬');
      vg.appendChild(g);
      poseVignette(vg, g, p);
      var nm = document.createElement('span'); nm.className = 'nm';
      var b = document.createElement('b');
      // textContent : le titre vient d'un service tiers.
      b.textContent = p.titre || p.source;
      var s = document.createElement('small');
      s.textContent = p.ecarte ? (p.raison || 'écartée')
                    : (p.en_cache ? (p.coeurs ? '♥ ' + p.coeurs : '') : 'récupération…');
      nm.appendChild(b); nm.appendChild(s);
      var dr = document.createElement('span'); dr.className = 'dr';
      dr.textContent = p.duree_ms ? mmss(p.duree_ms) : '';
      li.appendChild(rg); li.appendChild(vg); li.appendChild(nm); li.appendChild(dr);
      file.appendChild(li);
    });
  }

  function poseChat(phrases) {
    if (!phrases || !phrases.length) return;
    // ON NE RAMENE EN BAS QUE SI L'ON Y ETAIT : sinon on arrache la lecture a
    // qui remonte le fil.
    var colle = chat.scrollTop + chat.clientHeight >= chat.scrollHeight - 8;
    phrases.forEach(function (p) {
      curseurChat = Math.max(curseurChat, p.ID || p.id || 0);
      var d = document.createElement('div'); d.className = 'ph';
      var b = document.createElement('b'); b.textContent = p.Pseudo || p.pseudo || '?';
      var s = document.createElement('span');
      // textContent : le corps vient d'un membre, il ne devient jamais du
      // balisage. C'est ici la seule barriere, et elle suffit.
      s.textContent = ' ' + (p.Corps || p.corps || '');
      d.appendChild(b); d.appendChild(s);
      chat.appendChild(d);
    });
    if (colle) chat.scrollTop = chat.scrollHeight;
  }

  function sonde() {
    dernierAppel = Date.now();
    json('/api/v1/radio/current?depuis=' + curseurChat).then(function (r) {
      pose(r.corps);
      poseChat(r.corps.chat);
    }).catch(function () { /* une sonde ratee n'est pas une panne */ });
    json('/api/v1/radio/playlist').then(function (r) {
      poseFile(r.corps.pistes);
    }).catch(function () {});
  }

  bAime.addEventListener('click', function () {
    if (!pisteEnCours) return;
    nom();
    var poser = !bAime.classList.contains('on');
    json('/api/v1/radio/pistes/' + pisteEnCours + '/coeur',
         { method: poser ? 'POST' : 'DELETE' }).then(function (r) {
      if (r.corps.piste) {
        bAime.classList.toggle('on', r.corps.piste.aime);
        meta.textContent = (r.corps.piste.auteur ? r.corps.piste.auteur + ' · ' : '') +
                           (r.corps.piste.coeurs ? '♥ ' + r.corps.piste.coeurs : 'aucun ♥');
      }
    });
  });

  // LE RECALAGE EST L'INVERSE D'UNE COMMANDE : il abandonne sa position pour
  // rejoindre celle du serveur.
  $('recaler').addEventListener('click', function () {
    pisteEnCours = 0; avert.hidden = true; sonde();
  });
  bJouer.addEventListener('click', function () {
    avert.hidden = true;
    var e = ecran.play();
    if (e && e.catch) e.catch(function () { avert.hidden = false; });
  });

  dire.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' || !dire.value.trim()) return;
    nom(); // on ne se nomme qu'au moment de parler
    var corps = dire.value; dire.value = '';
    json('/api/v1/radio/chat', { method: 'POST', body: JSON.stringify({ corps: corps }) })
      .then(function (r) {
        if (r.code === 429) dire.placeholder = 'Laissez souffler l’antenne…';
        else if (r.corps.phrase) poseChat([r.corps.phrase]);
      });
  });

  $('proposer').addEventListener('submit', function (e) {
    e.preventDefault();
    var champ = $('source'), s = champ.value.trim();
    if (!s) return;
    nom(); // proposer, c'est signer
    json('/api/v1/radio/propositions', { method: 'POST', body: JSON.stringify({ source: s }) })
      .then(function (r) {
        var m = $('retour');
        if (r.code === 409) m.textContent = 'Cette piste a déjà été refusée.';
        else if (r.code >= 400) m.textContent = r.corps.error || 'Refusé.';
        else {
          champ.value = '';
          m.textContent = r.corps.neuve
            ? 'Proposée — en attente de validation par le sysop.'
            : 'Déjà connue : elle est dans la file ou à l’antenne.';
        }
      });
  });

  sonde();
  setInterval(sonde, PERIODE);
})();
