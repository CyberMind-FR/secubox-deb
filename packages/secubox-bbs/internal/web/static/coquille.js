// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: BBS — le rail dépliable de la coquille.
//
// SANS JAVASCRIPT, LE RAIL RESTE UTILISABLE : à partir de la tablette il est
// affiché en permanence par la feuille de style, et sur téléphone la barre
// basse porte déjà les cinq destinations principales. Ce script n'ajoute qu'un
// confort — dérouler les salons sur un petit écran — jamais un passage obligé.
// Thème clair/sombre PARTAGÉ avec la rédaction (#1092). La coquille lisait le
// papier par défaut et IGNORAIT le choix « nuit » posé sur l'accueil (même clé
// localStorage, mais aucun code pour l'appliquer côté coquille) : un fil ouvert
// restait donc clair pendant que la gazette était sombre. On applique la même
// clé (av-theme) et le même basculement, dans son PROPRE bloc — la bascule du
// rail ci-dessous sort tôt quand il n'y a pas de rail, ce qui aurait sauté le
// thème s'il avait vécu là.
(function () {
  var r = document.documentElement;
  try { var sv = localStorage.getItem('av-theme'); if (sv) r.setAttribute('data-theme', sv); } catch (e) {}
  // EMBARQUEMENT HALL (#1175). Le BBS reste identique en vhost réel ; encadré par
  // le Hall (seul autorisé via frame-ancestors), il masque son entête — la barre
  // du Hall la remplace — et SYNCHRONISE le thème passé par le Hall (?theme=).
  try {
    if (window.top !== window.self) { r.classList.add('sbx-embed'); }
    var qt = new URLSearchParams(location.search).get('theme');
    if (qt === 'dark' || qt === 'light') {
      r.setAttribute('data-theme', qt);
      try { localStorage.setItem('av-theme', qt); } catch (e) {}
    }
  } catch (e) {}

  // ── LES LIENS EXTERNES PASSENT PAR LE SURF (#1358) ──────────────────────────
  //
  // La matrice SBXOS : embarque dans le Hall, un lien qui SORT de la box ne
  // quitte pas le Hall — il s'ouvre A TRAVERS le proxy surf (pisteurs coupes,
  // pubs retirees), en overlay, sans perdre le fil qu'on lisait.
  //
  // DE L'EXTERIEUR, RIEN N'EST INTERCEPTE. Le meme BBS ouvert en direct (hors
  // Hall) garde ses liens standards : on ne detourne que ce qu'on peut rendre,
  // et hors du Hall il n'y a pas de gateway surf a qui parler.
  if (r.classList.contains('sbx-embed')) {
    var _BOX = /(^|\.)(gk2\.secubox\.in|gk2\.net|secubox\.in)$/i;
    // OBJET MEDIA (#1227) : « voir » et « diffuser » ne partent PAS au surf — ils
    // pilotent le Hall (lecteur / broadcast). On les laisse au handler dédié
    // ci-dessous ; le « souverain » (href ytsas) reste, lui, capté plus bas comme
    // n'importe quel service de la box (→ sbx:ouvre-hote).
    document.addEventListener('click', function (e) {
      var mo = e.target && e.target.closest ? e.target.closest('a[data-voir],a[data-diff],a[data-souverain]') : null;
      if (!mo) return;
      e.preventDefault();
      var titre = mo.getAttribute('data-titre') || '';
      try {
        if (mo.hasAttribute('data-souverain')) {
          // RAPATRIEMENT SOUVERAIN (#1227) : on demande au Hall d'enfiler la
          // capture (ytsas add+conserve). Retour visuel discret ; l'objet
          // montrera la source montée aux vues suivantes (re-résolution).
          parent.postMessage({ sbx: 'souverain', url: mo.getAttribute('data-souverain') || '', titre: titre }, '*');
          mo.textContent = '⤓ rapatriement…'; mo.setAttribute('aria-disabled', 'true');
        } else {
          parent.postMessage({
            sbx: mo.hasAttribute('data-voir') ? 'voir' : 'diffuser',
            url: mo.getAttribute('href') || '', titre: titre
          }, '*');
        }
      } catch (err) {}
    }, true);
    document.addEventListener('click', function (e) {
      var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
      if (!a) return;
      if (a.hasAttribute('data-voir') || a.hasAttribute('data-diff') || a.hasAttribute('data-souverain')) return; // objet média → handler dédié
      var href = a.getAttribute('href') || '';
      if (!/^https?:\/\//i.test(href)) return;        // relatif = interne
      var u; try { u = new URL(href, location.href); } catch (err) { return; }
      // MEME HOTE = navigation interne du BBS : on laisse faire.
      if (u.hostname === location.hostname) return;
      e.preventDefault();
      if (_BOX.test(u.hostname)) {
        // AUTRE SERVICE DE LA BOX (MetaNews, etc.) : on RESTE dans le Hall — on
        // lui demande d'embarquer ce service a cette adresse, plutot que de le
        // « debed » dans un onglet. C'est la matrice SBXOS.
        try { parent.postMessage({ sbx: 'ouvre-hote', hote: u.hostname, url: u.href }, '*'); } catch (err) {}
      } else {
        // HORS BOX : par le surf.
        try { parent.postMessage({ sbx: 'surf', url: u.href }, '*'); } catch (err) {}
      }
    }, true);
  }
  function theme() {
    var cur = r.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light');
    var nxt = cur === 'dark' ? 'light' : 'dark';
    r.setAttribute('data-theme', nxt);
    try { localStorage.setItem('av-theme', nxt); } catch (e) {}
  }
  document.addEventListener('click', function (e) {
    var t = e.target.closest('[data-act="theme"]');
    if (t) { e.preventDefault(); theme(); }
  });
  document.addEventListener('keydown', function (e) {
    var tag = (e.target && e.target.tagName) || '';
    if (e.key === 't' && tag !== 'INPUT' && tag !== 'TEXTAREA') theme();
  });
})();

// ── MENU CONTEXTUEL DE LA MÉGABAR (#1266b) ─────────────────────────────────────
// Embarqué dans le Hall, le BBS PUBLIE sa nav (Forums, Média, Bibliothèque…) au
// menu contextuel de la mégabar, comme le fait un vhost embarqué — sinon la
// navigation du service restait captive de son rail. Le Hall renvoie le choix
// (`contexte-choix`), on y navigue. Rien hors Hall (parent === window).
(function () {
  if (parent === window) return;
  function publie() {
    var navs = document.querySelectorAll('.rail a.nav, #rail a.nav');
    if (!navs.length) navs = document.querySelectorAll('a.nav');
    var items = [];
    Array.prototype.forEach.call(navs, function (a) {
      var href = a.getAttribute('href') || '';
      if (!href || href.charAt(0) === '#') return;
      var ic = a.querySelector('.ic'), n = a.querySelector('.n');
      var label = (a.textContent || '').replace(/\s+/g, ' ').trim();
      if (ic && ic.textContent) label = label.replace(ic.textContent, '').trim();
      if (n && n.textContent) label = label.split(n.textContent).join('').trim();
      items.push({
        cle: href, label: label || href,
        icon: (ic && ic.textContent ? ic.textContent.trim() : '💬'),
        badge: (n && n.textContent ? n.textContent.trim() : '')
      });
    });
    if (items.length) {
      try { parent.postMessage({ sbx: 'contexte', id: 'bbs', titre: 'BBS', items: items }, '*'); } catch (e) {}
    }
  }
  // La nav est rendue côté serveur : présente à chaque page (le BBS navigue en
  // PLEINE page). On RE-PUBLIE de façon fiable — DOMContentLoaded, pageshow
  // (retour bfcache), et deux relances courtes : cliquer un lien INTERNE recharge
  // le cadre, et sans ces relances le menu contextuel de la mégabar restait vide
  // le temps que la nav se re-rende (#1266b — « le clic dans le BBS perd le menu »).
  function publieBis() { publie(); }
  if (document.readyState !== 'loading') publieBis();
  else document.addEventListener('DOMContentLoaded', publieBis);
  addEventListener('pageshow', publieBis);
  setTimeout(publieBis, 400);
  setTimeout(publieBis, 1500);
  addEventListener('message', function (ev) {
    var d = ev.data;
    if (d && d.sbx === 'contexte-demande') { publie(); return; } // le Hall (re)demande la nav
    if (!d || d.sbx !== 'contexte-choix' || !d.cle) return;
    try { location.href = d.cle; } catch (e) {}
  });
})();

(function () {
  var bascule = document.querySelector('.menu-bascule');
  var rail = document.getElementById('rail');
  if (!bascule || !rail) return;

  function pose(ouvert) {
    document.body.classList.toggle('rail-ouvert', ouvert);
    bascule.setAttribute('aria-expanded', String(ouvert));
  }

  bascule.addEventListener('click', function () {
    pose(!document.body.classList.contains('rail-ouvert'));
  });

  // Refermer après avoir choisi : sur téléphone le rail recouvre la lecture,
  // et le laisser ouvert obligerait à un second geste pour voir ce qu'on vient
  // de demander.
  rail.addEventListener('click', function (e) {
    if (e.target.closest('a')) pose(false);
  });

  // Échap referme — c'est ce qu'on essaie d'abord devant un panneau ouvert.
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && document.body.classList.contains('rail-ouvert')) {
      pose(false);
      bascule.focus();
    }
  });
})();

// ── Envoi d'une piece jointe depuis l'editeur ────────────────────────────
//
// SANS JAVASCRIPT, L'ENVOI RESTE POSSIBLE : la page « Mon compte » porte un
// formulaire classique, et l'adresse rendue se colle a la main dans le message.
// Ce script ne fait qu'eviter cet aller-retour.
(function () {
  function poser(zone, url) {
    var i = zone.selectionStart;
    // Une ligne a soi : colle en fin de phrase, l'adresse se retrouverait dans
    // le texte et le lecteur s'afficherait au milieu d'une ligne.
    var av = zone.value.slice(0, i).replace(/\s*$/, '');
    var ap = zone.value.slice(i);
    zone.value = av + (av ? '\n\n' : '') + url + '\n' + ap;
    zone.focus();
    zone.setSelectionRange(av.length + url.length + 2, av.length + url.length + 2);
  }

  document.querySelectorAll('.editor').forEach(function (bloc) {
    var bouton = bloc.querySelector('.joindre');
    var zone = bloc.querySelector('textarea');
    var champ = bloc.querySelector('input[type=file]');
    // LA ZONE DE TEXTE SEULE EST INDISPENSABLE : c'est la que l'adresse se pose.
    // Le trombone et l'enregistreur sont deux outils independants — exiger les
    // deux, comme le faisait la garde precedente, aurait fait taire
    // l'enregistreur sur tout editeur livre sans trombone.
    if (!zone) return;

    // ── ENVOI D'UN FICHIER DEJA SUR LA MACHINE ──────────────────────────────
    if (bouton && champ) {
      bouton.addEventListener('click', function () { champ.click(); });

      champ.addEventListener('change', function () {
        if (!champ.files || !champ.files[0]) return;
        var f = new FormData();
        f.append('fichier', champ.files[0]);
        f.append('csrf', bouton.dataset.csrf || '');
        bouton.disabled = true;
        var libelle = bouton.textContent;
        bouton.textContent = '…';
        fetch('/f/envoi', {
          method: 'POST', body: f, headers: { 'Accept': 'application/json' },
        }).then(function (r) { return r.json(); })
          .then(function (j) {
            if (j.ok) poser(zone, j.url);
            // L'ERREUR EST DITE, pas avalee : un envoi refuse en silence donne
            // l'impression que le bouton ne marche pas.
            else alert('Envoi refusé : ' + (j.error || 'raison inconnue'));
          })
          .catch(function (e) { alert('Envoi impossible : ' + e.message); })
          .finally(function () {
            bouton.disabled = false;
            bouton.textContent = libelle;
            champ.value = '';
          });
      });
    }

    // ── COLLER UNE IMAGE (Ctrl/⌘+V d'une capture d'écran) ───────────────────
    //
    // Une zone de texte ne sait pas recevoir une image collée : le presse-papier
    // porte un FICHIER, pas du texte, et le collage natif ne fait rien — d'où
    // l'impression que « le copier-coller ne marche pas » dans l'éditeur. On
    // intercepte donc le collage d'une image et on l'envoie par le MÊME chemin
    // que le trombone (/f/envoi), puis on pose son adresse. Le collage de TEXTE
    // n'est pas touché : le comportement natif de la zone reste en place.
    zone.addEventListener('paste', function (e) {
      var items = (e.clipboardData && e.clipboardData.items) || [];
      var fichier = null;
      for (var k = 0; k < items.length; k++) {
        if (items[k].kind === 'file' && items[k].type.indexOf('image/') === 0) {
          fichier = items[k].getAsFile();
          break;
        }
      }
      if (!fichier) return; // pas une image : le collage natif du texte fait le travail
      e.preventDefault();
      var csrf = (bouton && bouton.dataset.csrf) || '';
      if (!csrf) {
        var form = zone.closest('form');
        var champCsrf = form && form.querySelector('input[name="csrf"]');
        if (champCsrf) csrf = champCsrf.value;
      }
      var f = new FormData();
      f.append('fichier', fichier);
      f.append('csrf', csrf);
      fetch('/f/envoi', {
        method: 'POST', body: f, headers: { 'Accept': 'application/json' },
      }).then(function (r) { return r.json(); })
        .then(function (j) {
          if (j.ok) poser(zone, j.url);
          else alert('Image collée refusée : ' + (j.error || 'raison inconnue'));
        })
        .catch(function (err) { alert('Collage impossible : ' + err.message); });
    });

    // ── NOTE VOCALE ET NOTE VIDEO ───────────────────────────────────────────
    //
    // MEME CHEMIN QUE LE TROMBONE : meme envoi vers `/f/envoi`, meme insertion
    // de l'adresse par `poser`. Enregistrer produit un fichier comme un autre —
    // ouvrir un second chemin d'envoi aurait double les garde-fous a tenir, et
    // l'un des deux aurait fini par diverger de l'autre.
    bloc.querySelectorAll('.enregistrer').forEach(function (b) {
      var video = b.dataset.mode === 'video';
      var rec = null, flux = null, morceaux = [], tic = null;
      var icone = b.textContent;

      // LE FORMAT EST NEGOCIE, PAS SUPPOSE. Firefox sait ecrire de l'Ogg/Opus,
      // Chrome souvent seulement du WebM. On prend le premier format que le
      // navigateur declare savoir produire, plutot que d'en imposer un qui
      // echouerait chez la moitie des gens.
      function choisi() {
        var l = video
          ? ['video/webm;codecs=vp9,opus', 'video/webm;codecs=vp8,opus', 'video/webm']
          : ['audio/ogg;codecs=opus', 'audio/webm;codecs=opus', 'audio/webm'];
        for (var i = 0; i < l.length; i++) {
          if (window.MediaRecorder && MediaRecorder.isTypeSupported(l[i])) return l[i];
        }
        return '';
      }

      // LE MICRO ET LA CAMERA SE RELACHENT EXPLICITEMENT. Sans cela la diode
      // reste allumee apres l'envoi, et c'est le genre de detail qui fait
      // douter de tout le reste.
      function libere() {
        if (flux) { flux.getTracks().forEach(function (t) { t.stop(); }); flux = null; }
        if (tic) { clearInterval(tic); tic = null; }
        b.classList.remove('en-cours');
        b.textContent = icone;
      }

      b.addEventListener('click', function () {
        if (rec && rec.state === 'recording') { rec.stop(); return; }
        if (!navigator.mediaDevices || !window.MediaRecorder) {
          alert("Ce navigateur ne sait pas enregistrer. Le trombone reste "
              + "disponible pour envoyer un fichier deja enregistre.");
          return;
        }
        var type = choisi();
        navigator.mediaDevices
          .getUserMedia(video ? { audio: true, video: true } : { audio: true })
          .then(function (s) {
            flux = s;
            morceaux = [];
            rec = new MediaRecorder(flux, type ? { mimeType: type } : undefined);
            rec.ondataavailable = function (e) { if (e.data.size) morceaux.push(e.data); };
            rec.onstop = function () {
              var mime = rec.mimeType || type || (video ? 'video/webm' : 'audio/ogg');
              libere();
              if (!morceaux.length) return;
              var ext = mime.indexOf('ogg') >= 0 ? 'ogg' : 'webm';
              var nom = (video ? 'video-' : 'vocal-') + Date.now() + '.' + ext;
              var f = new FormData();
              f.append('fichier', new Blob(morceaux, { type: mime }), nom);
              f.append('csrf', b.dataset.csrf || (bouton && bouton.dataset.csrf) || '');
              b.disabled = true;
              b.textContent = '…';
              fetch('/f/envoi', {
                method: 'POST', body: f, headers: { 'Accept': 'application/json' },
              }).then(function (r) { return r.json(); })
                .then(function (j) {
                  if (j.ok) poser(zone, j.url);
                  else alert('Envoi refusé : ' + (j.error || 'raison inconnue'));
                })
                .catch(function (e) { alert('Envoi impossible : ' + e.message); })
                .finally(function () { b.disabled = false; b.textContent = icone; });
            };
            rec.start();
            var t0 = Date.now();
            b.classList.add('en-cours');
            tic = setInterval(function () {
              var n = Math.floor((Date.now() - t0) / 1000);
              b.textContent = '■ ' + Math.floor(n / 60) + ':'
                            + String(n % 60).padStart(2, '0');
            }, 250);
          })
          .catch(function () {
            // ON DIT OU AUTORISER, pas « erreur ». Le refus de permission est le
            // cas de loin le plus frequent, et le seul sur lequel on peut agir.
            alert("Micro ou caméra refusé. Autorisez l'accès à ce site dans les "
                + "réglages du navigateur, puis réessayez.");
          });
      });
    });
  });
})();

/* QUEL VOLET EST SOUS LES YEUX AU CHARGEMENT.
 *
 * Les deux existent toujours ; on ne fait que placer le regard. Le serveur
 * pose `volet-liste` quand c'est la liste qui porte le contenu — sur un forum,
 * ce sont les fils. Partout ailleurs, la vue.
 *
 * `scrollLeft` et non `scrollIntoView` : ce dernier fait aussi defiler les
 * ancetres, et sur une coquille en hauteur fixe il decalait toute la page.
 *
 * Sans animation au chargement : un glissement au premier affichage donne
 * l'impression d'avoir touche l'ecran par erreur. */
(function voletInitial() {
  var corps = document.querySelector('.corps');
  if (!corps || corps.scrollWidth <= corps.clientWidth) { return; }
  var liste = corps.querySelector('.liste');
  var vue = corps.querySelector('.vue');
  // UN ELEMENT SELECTIONNE DANS LA LISTE L'EMPORTE SUR LE MARQUEUR.
  //
  // Le serveur pose `volet-liste` des qu'on est dans un forum — y compris
  // quand un fil est OUVERT. On atterrissait donc sur la liste apres avoir
  // choisi un fil, et il fallait glisser a la main pour lire ce qu'on venait
  // de demander.
  //
  // `aria-current="page"` est deja pose par les gabarits sur l'element choisi :
  // sa presence dit que la vue porte quelque chose de precis, et c'est un
  // signal plus sur qu'un marqueur de page.
  var choisi = liste && liste.querySelector('[aria-current="page"]');
  var cible = (corps.classList.contains('volet-liste') && !choisi) ? liste : vue;
  if (!cible) { return; }
  var avant = corps.style.scrollBehavior;
  corps.style.scrollBehavior = 'auto';
  corps.scrollLeft = cible.offsetLeft - corps.offsetLeft;
  corps.style.scrollBehavior = avant;

  // GLISSER DES LE CHOIX, sans attendre le chargement de la page suivante.
  //
  // Le lien navigue, donc la vue ne se remplira qu'apres l'aller-retour ; mais
  // deplacer le regard tout de suite fait sentir que le geste a ete pris en
  // compte. Sans cela, on tape et rien ne bouge pendant le temps du reseau —
  // et l'on tape une seconde fois.
  liste && liste.addEventListener('click', function (e) {
    if (!e.target.closest('a')) { return; }
    if (corps.scrollWidth <= corps.clientWidth) { return; }
    // ON RETIRE LE FOCUS DU LIEN QU'ON VIENT DE QUITTER.
    //
    // Le navigateur garde l'element focalise dans le champ de vision : le lien
    // tape reste dans la liste, et des qu'un autre evenement provoque un
    // recalcul, il RAMENE le volet de la liste sous les yeux — un retour que
    // personne n'a demande, au milieu de la lecture.
    var lien = e.target.closest('a');
    if (lien && lien.blur) { lien.blur(); }
    corps.scrollTo({ left: vue.offsetLeft - corps.offsetLeft, behavior: 'smooth' });
  }, { passive: true });

  // ──────────────────────────────────────────────────────────────────────────
  // LIGHTBOX (#1180) : les images jointes aux messages sont volontairement
  // affichées agrandies, mais une capture pleine résolution mérite le plein
  // écran. Un clic sur `img.jointe` ouvre un calque ; clic ou touche Échap le
  // ferme. Délégation sur le document : marche pour tout message, même chargé
  // après coup. On ignore les <video>/<audio> (leurs contrôles priment).
  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!t || t.tagName !== 'IMG' || !t.classList.contains('jointe')) { return; }
    var src = t.getAttribute('src');
    if (!src) { return; }
    e.preventDefault();
    var box = document.createElement('div');
    box.className = 'lightbox';
    var grand = document.createElement('img');
    grand.src = src;
    grand.alt = t.getAttribute('alt') || '';
    box.appendChild(grand);
    function surTouche(ev) { if (ev.key === 'Escape') { fermer(); } }
    function fermer() {
      box.remove();
      document.removeEventListener('keydown', surTouche);
    }
    box.addEventListener('click', fermer);
    document.addEventListener('keydown', surTouche);
    document.body.appendChild(box);
  }, false);
})();
