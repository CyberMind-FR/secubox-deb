// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

(function () {
  'use strict';

  // MODES COMPACTS (#1131m/#1131o) : la même page sert de widget incorporé.
  //   /mini  → lecteur + playlist + antenne, resserré (fenêtre détachée).
  //   /micro → UNIQUEMENT le lecteur, à la taille d'une carte du carrousel
  //            (widget du rail BBS). Le CSS fait le reste d'après ces classes.
  (function () {
    var mini = location.pathname === '/mini' || location.pathname === '/micro';
    var micro = location.pathname === '/micro';
    if (!mini) return;
    var pose = function () {
      if (mini) document.body.classList.add('mini');
      if (micro) document.body.classList.add('micro');
    };
    document.documentElement.classList.add('mini');
    if (micro) document.documentElement.classList.add('micro');

    // THÈME HÉRITÉ DE L'HÔTE (#1233). Encadrée, la radio décidait seule de son
    // clair/sombre : le cardlet du Hall restait en sombre sur un Hall clair.
    // La feuille de style sait déjà répondre à data-theme ; il manquait
    // seulement de le poser. On n'accepte que deux valeurs — une valeur libre
    // venue de l'URL n'a rien à faire dans un attribut du document.
    try {
      var t = new URLSearchParams(location.search).get('theme');
      if (t === 'dark' || t === 'light') {
        document.documentElement.setAttribute('data-theme', t);
      }
    } catch (e) { /* sans URLSearchParams, on garde le thème du système */ }

    // Le Hall dit ensuite le thème par MESSAGE (#1243) : recharger le cadre
    // pour changer une couleur couperait le direct. On applique sans recharger.
    addEventListener('message', function (ev) {
      var d = ev.data;
      if (!d || d.sbx !== 'theme') return;
      if (d.theme === 'dark' || d.theme === 'light') {
        document.documentElement.setAttribute('data-theme', d.theme);
      }
    });
    if (document.body) pose();
    else document.addEventListener('DOMContentLoaded', pose);
  })();

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
  // SameSite=Lax REFUSAIT LE COOKIE DANS LE HALL, et c'est ce qui bloquait la
  // lecture (#1251). Encadre par hall.gk2.net, le micro-lecteur est un contexte
  // TIERS : le navigateur rejette purement et simplement un cookie Lax ou
  // Strict pose la. Sans `sbx_radio`, le serveur ne reconnait plus l'auditeur
  // et rend 401 sur /media et /vignette — un lecteur muet, sans message.
  // Le podcaster passait parce qu'il n'a besoin d'aucun cookie : c'est ce
  // contraste qui a mis sur la piste.
  //
  // Sur un poste ayant deja visite la radio en direct, Firefox accorde l'acces
  // au stockage partitionne et la panne ne se voyait PAS — d'ou un defaut qui
  // ne se manifestait que sur telephone et sur TV.
  //
  // None exige Secure, donc HTTPS. En clair on retombe sur Lax : mieux vaut un
  // cookie premier-partie qui fonctionne qu'un cookie que le navigateur jette.
  function poseCookie(n, v) {
    var tiers = location.protocol === 'https:' ? ';SameSite=None;Secure' : ';SameSite=Lax';
    document.cookie = n + '=' + encodeURIComponent(v) + ';path=/;max-age=31536000' + tiers;
  }
  // SAFARI/iOS BLOQUE LE COOKIE TIERS QUOI QU'ON FASSE (#1254).
  //
  // SameSite=None ne suffit pas : la prevention de pistage refuse purement et
  // simplement les cookies tiers. Encadree dans le Hall depuis un iPhone ou
  // une TV, la radio ne recevait donc plus son identifiant, et /media rendait
  // 401 — un lecteur muet.
  //
  // CE QUE CET IDENTIFIANT EST REELLEMENT : un nombre que LA PAGE SE DONNE AU
  // HASARD. Il n'authentifie rien, il ATTRIBUE des gestes entre gens qui se
  // connaissent. Le porter en parametre plutot qu'en cookie ne retire donc
  // aucune protection — c'est exactement la meme valeur, par un autre canal.
  //
  // On le garde aussi en localStorage : partitionne dans un cadre, il reste
  // stable pour CE contexte, ce qui suffit a ne pas changer d'identite a
  // chaque rechargement.
  var monID = cookie('sbx_radio');
  if (!monID) {
    try { monID = localStorage.getItem('sbx_radio_id') || ''; } catch (e) { monID = ''; }
  }
  if (!monID) {
    monID = String(Math.floor(Math.random() * 9e15) + 1e3);
  }
  poseCookie('sbx_radio', monID);
  try { localStorage.setItem('sbx_radio_id', monID); } catch (e) {}

  // avecID : joint l'identifiant a une URL du service. Utilise partout ou le
  // cookie etait le seul porteur.
  function avecID(url) {
    if (!monID) return url;
    return url + (url.indexOf('?') >= 0 ? '&' : '?') + 'a=' + encodeURIComponent(monID);
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
  var lecteur = document.querySelector('.lecteur');
  var titre = $('titre'), meta = $('meta'), jauge = $('jauge');
  var ecoule = $('ecoule'), duree = $('duree'), derive = $('derive');
  var file = $('file'), chat = $('chat'), dire = $('dire');
  var attente = $('attente');
  var estMicro = document.documentElement.classList.contains('micro');

  // ROTATION ANTENNE / PLAYLIST EN MICRO (#1263).
  //
  // Sous 520 px la carte n'a la place que d'UN panneau : elle montrait donc
  // toujours l'antenne, et la playlist n'existait pas pour qui regarde depuis
  // l'accueil. On alterne — un temps ce qui se dit, un temps ce qui vient.
  //
  // Le SURVOL suspend : on ne lit pas une liste qui s'echappe, et on ne tape
  // pas un message dans un champ qui va disparaitre. La saisie en cours
  // suspend aussi, pour la meme raison, et c'est plus fort que le survol : on
  // peut ecrire sans que le curseur reste sur la carte.
  if (estMicro) (function () {
    var vue = 'antenne', pause = false;
    function pose() {
      document.body.classList.toggle('vue-playlist', vue === 'playlist');
      document.body.classList.toggle('vue-antenne', vue === 'antenne');
    }
    document.addEventListener('mouseenter', function () { pause = true; }, true);
    document.addEventListener('mouseleave', function () { pause = false; }, true);
    document.addEventListener('focusin', function () { pause = true; });
    document.addEventListener('focusout', function () { pause = false; });
    pose();
    setInterval(function () {
      var champ = document.activeElement;
      if (pause || (champ && champ.tagName === 'INPUT')) return;
      vue = (vue === 'antenne') ? 'playlist' : 'antenne';
      pose();
    }, 8000);
  })();
  var microNext = $('micro-next'), microLast = $('micro-last'), microStatus = $('micro-status');
  var avert = $('avert'), bAime = $('aime'), bJouer = $('jouer');

  // AUTOPLAY REFUSE : ON ARME, ON N'ACCUSE PAS (#1253).
  //
  // Firefox n'implemente pas la delegation `allow="autoplay"` — il le dit
  // lui-meme dans la console — donc encadree dans le Hall, la radio est jugee
  // sur SA propre interaction, qui n'a pas eu lieu. Le refus est normal, pas
  // une panne : le podcaster ne le rencontre jamais parce qu'il ne tente rien
  // avant un clic.
  //
  // On retient donc l'intention et on relance au PREMIER geste, quel qu'il
  // soit — c'est ce geste qui accorde l'autorisation. Le bandeau ne s'affiche
  // que si la relance echoue A SON TOUR : afficher un avertissement qu'un
  // simple clic va effacer, c'est inquieter pour rien.
  var relanceArmee = false;
  function armeRelance() {
    if (relanceArmee) return;
    relanceArmee = true;
    var geste = function () {
      document.removeEventListener('pointerdown', geste, true);
      document.removeEventListener('keydown', geste, true);
      relanceArmee = false;
      if (!veutJouer || !ecran.paused) return;
      var e = ecran.play();
      if (e && e.catch) e.catch(function () { avert.hidden = false; });
    };
    document.addEventListener('pointerdown', geste, true);
    document.addEventListener('keydown', geste, true);
  }

  // ── ANNONCE À LA BARRE DU HALL (#1246) ────────────────────────────────────
  //
  // Le Hall ne peut pas toucher notre média : origines différentes. On ANNONCE
  // notre état, il COMMANDE. Une radio n'a ni précédent ni suivant — c'est un
  // direct : ces commandes sont simplement ignorées plutôt que de faire semblant.
  function annonceHall(fin) {
    if (parent === window || !ecran) return;
    try {
      parent.postMessage({
        sbx: 'media', id: 'radio',
        titre: (titre && titre.textContent) || 'Radio', sous: (meta && meta.textContent) || '',
        joue: !ecran.paused, t: ecran.currentTime || 0, d: ecran.duration || 0,
        fin: !!fin
      }, '*');
    } catch (e) {}
  }
  ['play', 'pause', 'ended'].forEach(function (ev) {
    if (ecran) ecran.addEventListener(ev, function () { annonceHall(); });
  });
  // Battement : sans lui, la barre considérerait le direct mort au bout de dix
  // secondes sans événement et retirerait la rangée.
  setInterval(function () { if (ecran && !ecran.paused) annonceHall(); }, 2000);

  addEventListener('message', function (ev) {
    var d = ev.data;
    if (!d || d.sbx !== 'cmd' || !ecran) return;
    if (d.action === 'toggle') {
      if (ecran.paused) {
        // Le geste a eu lieu dans le HALL, pas ici : Firefox ne le transmet
        // pas au cadre. On retient l'intention et on relance au premier geste
        // recu de ce cote — sinon la barre repond « ❚❚ » a un lecteur muet.
        veutJouer = true;
        var e = ecran.play();
        if (e && e.catch) e.catch(function () { armeRelance(); });
      } else ecran.pause();
    } else if (d.action === 'stop') { ecran.pause(); annonceHall(true); }
    // prev / next : un direct ne se parcourt pas. On ne fait pas semblant.
  });

  // ── LE VOLUME ─────────────────────────────────────────────────────────────
  //
  // La <video> joue SANS controle natif (pas de `controls`) : sans ce cablage,
  // l'auditeur ne peut ni baisser ni couper le son. `ecran.volume` est une
  // propriete de l'ELEMENT — elle survit aux changements de piste (`ecran.src`),
  // il suffit de la poser. Le choix est RETENU d'une session a l'autre : regler
  // le volume a chaque visite serait une corvee.
  var bMuet = $('muet'), curseurVol = $('volume');
  function iconeVol() {
    var coupe = ecran.muted || ecran.volume === 0;
    bMuet.textContent = coupe ? '🔇' : '🔊';
    bMuet.classList.toggle('muet', coupe);
  }
  (function () {
    var v = parseFloat(localStorage.getItem('sbx_radio_vol'));
    if (!isFinite(v) || v < 0 || v > 1) v = 1;
    ecran.volume = v; curseurVol.value = String(v);
    // Le SILENCE aussi est RETENU d'une visite/refresh a l'autre (#radiofix) :
    // dans le BBS, le lecteur est un iframe qui recharge a chaque navigation ;
    // sans persistance, il se re-allumait tout seul.
    ecran.muted = localStorage.getItem('sbx_radio_muet') === '1';
    iconeVol();
  })();
  curseurVol.addEventListener('input', function () {
    var v = parseFloat(curseurVol.value);
    if (!isFinite(v)) return;
    ecran.volume = v;
    if (v > 0) ecran.muted = false; // toucher le curseur, c'est vouloir entendre
    localStorage.setItem('sbx_radio_vol', String(v));
    iconeVol();
  });
  bMuet.addEventListener('click', function () {
    ecran.muted = !ecran.muted;
    localStorage.setItem('sbx_radio_muet', ecran.muted ? '1' : '0');
    iconeVol();
  });

  var pisteEnCours = 0, curseurChat = 0, dernierAppel = Date.now();
  // INTENTION lecture/pause RETENUE entre les refresh (#radiofix). Défaut : on
  // joue (une radio qu'on ouvre, on l'écoute) ; si l'auditeur a mis en pause,
  // on RESTE en pause au rechargement au lieu de relancer le son tout seul.
  var veutJouer = localStorage.getItem('sbx_radio_play') !== '0';

  function json(url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    // L'EN-TETE D'INTENTION : un site tiers ne peut pas le poser sur une
    // requete inter-origines, alors que le cookie, lui, serait joint tout seul.
    opts.headers['X-Sbx-Radio'] = '1';
    if (opts.body) opts.headers['Content-Type'] = 'application/json';
    return fetch(avecID(url), opts).then(function (r) {
      return r.json().catch(function () { return {}; })
        .then(function (d) { return { code: r.status, corps: d }; });
    });
  }

  // sbxToken() lit le sbx_token pose par la connexion BBS (#1166 B4) — le
  // MEME localStorage que le hub et les autres webui (voir
  // secubox-hub/www/shared/api-utils.js:getToken). '' si absent : la radio
  // ne DEVINE ni ne FABRIQUE jamais d'identite, elle ne fait que relayer ce
  // que le navigateur possede deja.
  function sbxToken() {
    try { return localStorage.getItem('sbx_token') || ''; } catch (e) { return ''; }
  }

  // LE MÉDIA CONNAÎT SA VRAIE DURÉE — on la rapporte (#1131z). Sans elle, le
  // serveur coupe à 4 min tout titre de durée inconnue et « saute » au suivant.
  // Le premier lecteur qui charge les métadonnées la transmet ; le serveur ne
  // remplit que le vide. Une fois par piste.
  var dureeReportee = {};
  ecran.addEventListener('loadedmetadata', function () {
    var id = pisteEnCours;
    if (!id || dureeReportee[id]) return;
    var d = ecran.duration;
    if (!isFinite(d) || d <= 0) return;
    dureeReportee[id] = true;
    json('/api/v1/radio/pistes/' + id + '/duree',
         { method: 'POST', body: JSON.stringify({ ms: Math.round(d * 1000) }) })
      .catch(function () { /* une durée non transmise n'est pas une panne */ });
  });

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
    img.src = avecID('/vignette/' + p.id);
  }

  function pose(e) {
    if (!e || e.silence) {
      ecran.classList.add('muet');
      lecteur.classList.remove('joue');
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
      lecteur.classList.add('joue');
      ecran.src = avecID('/media/' + p.id);
      ecran.currentTime = offset;
      // On ne relance QUE si l'auditeur veut jouer (intention retenue). S'il a
      // mis en pause, on prépare la piste sans la lancer — l'état survit au
      // refresh de l'iframe BBS (#radiofix).
      if (veutJouer) {
        // AUTOPLAY REFUSE = SILENCE INEXPLIQUE : on le DIT plutot que de laisser
        // un ecran noir.
        var essai = ecran.play();
        if (essai && essai.catch) essai.catch(function () { bJouer.textContent = '▶'; armeRelance(); });
      } else {
        bJouer.textContent = '▶'; bJouer.title = 'Écouter';
      }
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

  // poseFile : 2 pistes DÉJÀ DIFFUSÉES (le journal d'antenne RÉEL, `passe`), la
  // piste en cours, 3 À VENIR (la file FIGÉE du serveur, `avenir`). Fini l'ordre
  // d'ajout deviné : « passé » = ce qui est vraiment passé, « à venir » = ce qui
  // va vraiment passer, dans l'ordre (#radiofix). `d` = {pistes, passe, avenir}.
  function poseFile(d) {
    file.innerHTML = '';
    d = d || {};
    var toutes = d.pistes || [];
    var courante = null;
    for (var k = 0; k < toutes.length; k++) { if (toutes[k].id === pisteEnCours) { courante = toutes[k]; break; } }
    // `passe` est le plus récent d'abord ; sa 1re entrée est la lecture EN COURS
    // (on vient de la journaliser) — on l'écarte, puis on garde 2 précédents et
    // on les remet dans l'ordre chronologique (plus ancienne en haut).
    var pas = (d.passe || []).slice();
    if (pas.length && courante && pas[0].id === courante.id) pas.shift();
    var precedents = pas.slice(0, 2).reverse();
    var avenir = (d.avenir || []).slice(0, 3);
    if (!courante && !precedents.length && !avenir.length) {
      file.innerHTML = '<li class="vide">Rien en attente — proposez un titre.</li>';
      return;
    }
    var vues = [];
    precedents.forEach(function (p, i) { vues.push({ p: p, rel: -(precedents.length - i) }); });
    if (courante) vues.push({ p: courante, rel: 0 });
    avenir.forEach(function (p, i) { vues.push({ p: p, rel: i + 1 }); });
    vues.forEach(function (it) {
      var p = it.p, rel = it.rel;
      var li = document.createElement('li');
      li.className = rel < 0 ? 'passe' : (rel === 0 ? 'encours' : 'avenir');
      if (p.ecarte) li.className += ' ecarte';
      var rg = document.createElement('span'); rg.className = 'rg';
      rg.textContent = rel === 0 ? '▶' : (rel < 0 ? '↺' : '+' + rel);
      var vg = document.createElement('span'); vg.className = 'vg';
      var g = document.createElement('span');
      g.textContent = p.ecarte ? '⚠' : (p.en_cache ? '🎬' : '⏬');
      vg.appendChild(g);
      poseVignette(vg, g, p);
      var nm = document.createElement('span'); nm.className = 'nm';
      var b = document.createElement('b');
      b.textContent = p.titre || p.source; // titre d'un tiers : jamais du balisage
      var s = document.createElement('small');
      s.textContent = rel === 0 ? 'en cours'
                    : p.ecarte ? (p.raison || 'écartée')
                    : (p.en_cache ? (p.coeurs ? '♥ ' + p.coeurs : '') : 'récupération…');
      nm.appendChild(b); nm.appendChild(s);
      var dr = document.createElement('span'); dr.className = 'dr';
      dr.textContent = p.duree_ms ? mmss(p.duree_ms) : '';
      li.appendChild(rg); li.appendChild(vg); li.appendChild(nm); li.appendChild(dr);
      file.appendChild(li);
    });
    // MICRO : une seule ligne « prochain titre » (#1131u).
    if (estMicro && microNext) {
      var nx = null;
      for (var z = 0; z < vues.length; z++) { if (vues[z].rel === 1) { nx = vues[z].p; break; } }
      if (!nx) for (var z2 = 0; z2 < vues.length; z2++) { if (vues[z2].rel > 0) { nx = vues[z2].p; break; } }
      microNext.textContent = nx ? ('→ ' + (nx.titre || nx.source)) : '';
    }

  }

  // poseAttente : les propositions EN ATTENTE, chacune avec un bouton de vote.
  // Le backend compte déjà un cœur sur une proposition (#1131g) ; ici on
  // l'expose aux auditeurs. Construction DOM pure (createElement + listener) :
  // la CSP interdit tout style et tout onclick en ligne.
  // La file d'attente est COMPACTE et ne montre que 3 titres à la fois, en
  // ROTATION automatique (#1131j) : une longue file ne doit pas pousser
  // l'antenne et le lecteur hors de l'écran. On garde la liste complète et on
  // fait défiler une fenêtre de 3. `sonde` rafraîchit la liste (cœurs à jour),
  // le minuteur avance la fenêtre.
  var propos = [], propOffset = 0;
  function poseAttente(props) {
    // TOP-DOWN PAR LES VOTES (#1131k) : les titres les plus soutenus d'abord —
    // le vote sert à faire remonter ce que l'antenne veut entendre. À égalité,
    // l'ordre d'arrivée (id) départage, stable d'un rafraîchissement à l'autre.
    propos = (props || []).slice().sort(function (a, b) {
      return (b.coeurs || 0) - (a.coeurs || 0) || (a.id - b.id);
    });
    if (propOffset >= propos.length) propOffset = 0;
    rendAttente();
  }
  function voteProposition(p) {
    var li = document.createElement('li');
    var nm = document.createElement('span'); nm.className = 'nm';
    var b = document.createElement('b');
    b.textContent = p.titre || p.source; // titre d'un tiers : jamais du balisage
    var s = document.createElement('small');
    s.textContent = p.auteur || 'en attente';
    nm.appendChild(b); nm.appendChild(s);
    var vote = document.createElement('button');
    vote.type = 'button';
    vote.className = 'vote' + (p.aime ? ' on' : '');
    vote.textContent = '♥ ' + (p.coeurs || 0);
    vote.setAttribute('aria-label', 'Voter pour ce titre');
    vote.addEventListener('click', function () {
      nom(); // voter, c'est signer
      var poser = !vote.classList.contains('on');
      json('/api/v1/radio/propositions/' + p.id + '/coeur',
           { method: poser ? 'POST' : 'DELETE' }).then(function (r) {
        if (r.corps && r.corps.piste) {
          vote.classList.toggle('on', r.corps.piste.aime);
          vote.textContent = '♥ ' + (r.corps.piste.coeurs || 0);
        }
      }).catch(function () { /* un vote raté n'est pas une panne */ });
    });
    li.appendChild(nm); li.appendChild(vote);
    return li;
  }
  function rendAttente() {
    attente.innerHTML = '';
    var n = propos.length;
    if (!n) {
      attente.innerHTML = '<li class="vide">Aucun titre en attente — proposez-en un.</li>';
      return;
    }
    for (var i = 0; i < Math.min(3, n); i++) {
      attente.appendChild(voteProposition(propos[(propOffset + i) % n]));
    }
    if (n > 3) {
      var more = document.createElement('li');
      more.className = 'plusattente';
      more.textContent = '… ' + n + ' en attente · défilement';
      attente.appendChild(more);
    }
  }

  function poseChat(phrases) {
    if (!phrases || !phrases.length) return;
    // SAISIE EN HAUT → on PRÉPEND : le message neuf apparaît juste sous le champ,
    // les précédents descendent et s'estompent (l'animation CSS .ph fait le
    // reste). Plus de défilement à gérer : le neuf est toujours en vue (#1131v).
    phrases.forEach(function (p) {
      curseurChat = Math.max(curseurChat, p.ID || p.id || 0);
      var d = document.createElement('div'); d.className = 'ph';
      var b = document.createElement('b'); b.textContent = p.Pseudo || p.pseudo || '?';
      var s = document.createElement('span');
      // textContent : le corps vient d'un membre, il ne devient jamais du
      // balisage. C'est ici la seule barriere, et elle suffit.
      s.textContent = ' ' + (p.Corps || p.corps || '');
      d.appendChild(b); d.appendChild(s);
      chat.insertBefore(d, chat.firstChild);
    });
    // On ne garde que les dernières lignes en vie : une antenne éphémère n'est
    // pas un journal, et un DOM sans borne finirait par ramer.
    while (chat.childNodes.length > 40) chat.removeChild(chat.lastChild);
    // MICRO : une seule ligne « dernier message » (#1131u).
    if (estMicro && microLast) {
      var last = phrases[phrases.length - 1];
      microLast.textContent = '💬 ' + (last.Pseudo || last.pseudo || '?') + ' · ' +
                              (last.Corps || last.corps || '');
    }
  }

  function sonde() {
    dernierAppel = Date.now();
    json('/api/v1/radio/current?depuis=' + curseurChat).then(function (r) {
      pose(r.corps);
      poseChat(r.corps.chat);
    }).catch(function () { /* une sonde ratee n'est pas une panne */ });
    json('/api/v1/radio/playlist').then(function (r) {
      poseFile(r.corps);
    }).catch(function () {});
    json('/api/v1/radio/propositions').then(function (r) {
      poseAttente(r.corps.propositions);
    }).catch(function () {});
    // #1131ah : statut d'AUDIENCE en emojis dans l'espace libre du micro.
    if (estMicro && microStatus) {
      json('/api/v1/radio/stats').then(function (r) {
        var c = r.corps || {};
        microStatus.textContent = '🎶 ' + (c.pistes || 0) + ' · 🗳️ ' + (c.propositions || 0) +
          ' · 👥 ' + (c.auditeurs || 0) + ' · 👁️ ' + (c.visites || 0);
      }).catch(function () {});
    }
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
  // ▶ / ❚❚ : bascule lecture/pause (#1131ad). Le direct continue côté serveur ;
  // reprendre resynchronise (la dérive est corrigée par `pose`). Pour REJOINDRE
  // le direct après une pause longue, le bouton ⟳ (recaler) est là.
  bJouer.addEventListener('click', function () {
    avert.hidden = true;
    if (ecran.paused) {
      veutJouer = true; localStorage.setItem('sbx_radio_play', '1');
      var e = ecran.play();
      if (e && e.catch) e.catch(function () { avert.hidden = false; });
    } else {
      veutJouer = false; localStorage.setItem('sbx_radio_play', '0');
      ecran.pause();
    }
  });
  ecran.addEventListener('play', function () { bJouer.textContent = '❚❚'; bJouer.title = 'Pause'; });
  ecran.addEventListener('pause', function () { bJouer.textContent = '▶'; bJouer.title = 'Écouter'; });

  // ⧉ DÉTACHER (#1131ae) : dans la barre média du micro-lecteur — ouvre le
  // lecteur dans une fenêtre persistante, qui survit à la navigation BBS.
  var bDetach = $('detach');
  if (bDetach) bDetach.addEventListener('click', function () {
    window.open('/mini', 'sbxradio',
      'width=380,height=580,menubar=no,toolbar=no,location=no,resizable=yes');
  });

  dire.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' || !dire.value.trim()) return;
    nom(); // on ne se nomme qu'au moment de parler
    var corps = dire.value; dire.value = '';
    var options = { method: 'POST', body: JSON.stringify({ corps: corps }) };
    // MEMBRE CONNU (#1166 B4) : on joint le sbx_token pour que ce message,
    // en plus de rejoindre le chat d'ambiance comme toujours, atteigne AUSSI
    // la timeline du morceau en cours — c'est le BBS, jamais cette page, qui
    // decide au nom de qui il persiste (voir jetonSbxDepuisRequete cote
    // serveur). Sans jeton, le message reste un chat d'ambiance ordinaire.
    var jeton = sbxToken();
    if (jeton) options.headers = { 'Authorization': 'Bearer ' + jeton };
    json('/api/v1/radio/chat', options)
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
  // La fenêtre des titres en attente défile toute seule (#1131j) — un cran
  // toutes les 4 s dès qu'il y a plus de 3 propositions.
  setInterval(function () {
    if (propos.length > 3) {
      propOffset = (propOffset + 1) % propos.length;
      rendAttente();
    }
  }, 4000);

  // ── REJOUER LA TIMELINE (#1166 B5) ────────────────────────────────────────
  //
  // Pas encore de vue de réécoute dans cette page — ce hook est le seul point
  // d'entrée à câbler le jour où elle existe : GET
  // /api/v1/radio/replay/{piste}/timeline rend `{comments:[…]}`, chaque
  // commentaire portant offset_ms, pour réafficher le chat au bon instant
  // pendant le replay d'une piste (pisteID = l'ID numérique de la piste, pas
  // le content_id du spine BBS — l'API le résout elle-même côté serveur).
  //
  // function chargeReplayTimeline(pisteID) {
  //   return fetch('/api/v1/radio/replay/' + pisteID + '/timeline')
  //     .then(function (r) { return r.json(); })
  //     .then(function (d) { return d.comments || []; });
  // }
})();
