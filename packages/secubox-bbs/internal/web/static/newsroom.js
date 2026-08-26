/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
   Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
   AletheiaVox newsroom — interactions de l'accueil (#1056 stage 1).

   CSP STRICTE (script-src 'self', pas d'unsafe-inline) : aucun onclick ni style
   en ligne. Les actions passent par des attributs data-* et UNE délégation de
   clic, comme coquille.js. La lecture audio joue le VRAI média du fil
   (media-src 'self' autorise /media/ep/… local) ; la vidéo renvoie à la page du
   fil, qui intègre le lecteur avec sa propre politique. Rien n'est feint. */

// EMBARQUEMENT HALL (#1175). L'accueil est un template autonome (charge
// newsroom.js, PAS coquille.js) : la détection d'embed vit donc AUSSI ici.
// Encadré par le Hall (seul autorisé), le BBS masque son entête (barre Hall
// unique) et synchronise le thème (?theme=). Les widgets imbriqués qui
// re-encadrent d'autres vhosts (radio /micro) sont masqués en embed : le
// chaînage hall>bbs>radio casse leur frame-ancestors et déclenche des 401
// (cookies SameSite non transmis en iframe cross-site) — l'auth imbriquée
// relève du coffre avatar, différé.
(function () {
  try {
    var r = document.documentElement;
    if (window.top !== window.self) {
      r.classList.add('sbx-embed');
      // On RETIRE la colonne droite du DOM (pas juste display:none) : sinon
      // l'iframe radio /micro CONTINUE de charger + sonder ses endpoints
      // authentifiés → cascade de 401 (cookies SameSite non transmis). Le retirer
      // stoppe net radio.js.
      var rr = document.querySelector('.rail.rr'); if (rr) rr.remove();
      // ON VISE LE LECTEUR, PAS SON CONTENEUR (#1260). `avradio` est reutilise
      // par `avrail` ET par le rail de l'accueil : retirer la seule colonne
      // droite en laissait passer une copie. Encadre dans le Hall — surtout en
      // apercu — ce second lecteur rejoint la meme diffusion que la cardlet
      // radio, et l'auditeur entend DEUX FOIS le direct, legerement decale.
      Array.prototype.slice.call(
        document.querySelectorAll('.radiowidget, iframe.radioframe')
      ).forEach(function (n) { n.remove(); });
    }
    var qt = new URLSearchParams(location.search).get('theme');
    if (qt === 'dark' || qt === 'light') {
      r.setAttribute('data-theme', qt);
      try { localStorage.setItem('av-theme', qt); } catch (e) {}
    }
    // Le parametre ne donne que le theme d'ARRIVEE. Les bascules SUIVANTES du
    // Hall arrivaient sans etre entendues : le Hall passait en clair, le cadre
    // restait sombre (#1268). On applique sans rien recharger — recharger
    // couperait le son et remettrait la page au debut.
    addEventListener('message', function (ev) {
      var d = ev.data;
      if (!d || d.sbx !== 'theme') return;
      if (d.theme === 'dark' || d.theme === 'light') {
        r.setAttribute('data-theme', d.theme);
        try { localStorage.setItem('av-theme', d.theme); } catch (e) {}
      }
    });
  } catch (e) {}
})();
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  /* ondes décoratives (style posé par script = autorisé ; attribut style en HTML = non) */
  $$(".wave").forEach(function (w) {
    for (var i = 0; i < 34; i++) {
      var b = document.createElement("i");
      b.style.height = (15 + Math.abs(Math.sin(i * 0.7)) * 70) + "%";
      w.appendChild(b);
    }
  });

  /* thème papier / nuit (persistant) */
  try { var sv = localStorage.getItem("av-theme"); if (sv) document.documentElement.setAttribute("data-theme", sv); } catch (e) {}
  function theme() {
    var r = document.documentElement;
    var cur = r.getAttribute("data-theme") || (matchMedia("(prefers-color-scheme:dark)").matches ? "dark" : "light");
    var nxt = cur === "dark" ? "light" : "dark";
    r.setAttribute("data-theme", nxt);
    try { localStorage.setItem("av-theme", nxt); } catch (e) {}
  }

  /* filtres */
  function filt(el) {
    $$(".type").forEach(function (x) { x.classList.remove("on"); });
    el.classList.add("on");
    var f = el.getAttribute("data-f");
    $$(".dossier").forEach(function (c) { c.style.display = (f === "all" || c.getAttribute("data-k") === f) ? "" : "none"; });
  }
  function rub(el) { $$(".rub").forEach(function (x) { x.classList.remove("on"); }); el.classList.add("on"); }

  /* lecteur audio RÉEL + mini-lecteur */
  var audio = null, card = null, raf = null, lastBtn = null;
  function fmt(t) { t = Math.floor(t || 0); return Math.floor(t / 60) + ":" + ("0" + (t % 60)).slice(-2); }
  function paint() {
    if (!audio || !card) return;
    var d = audio.duration || 0, c = audio.currentTime || 0;
    $("#mini-prog").style.width = (d ? c / d * 100 : 0) + "%";
    $("#mini-time").textContent = fmt(c);
    var bars = card.querySelectorAll(".wave i");
    for (var i = 0; i < bars.length; i++) bars[i].style.height = (15 + Math.abs(Math.sin((i + c) * 0.6)) * 72) + "%";
    raf = requestAnimationFrame(paint);
  }
  function visualStop() {
    if (card) { card.classList.remove("playing"); var b = card.querySelector(".play"); if (b) b.textContent = "▶"; }
    if (raf) cancelAnimationFrame(raf);
  }
  function ensure() {
    if (audio) return;
    audio = new Audio();
    audio.addEventListener("play", function () { $("#miniplay").textContent = "❚❚"; if (card) { card.classList.add("playing"); card.querySelector(".play").textContent = "❚❚"; } paint(); });
    audio.addEventListener("pause", function () { $("#miniplay").textContent = "▶"; visualStop(); });
    audio.addEventListener("ended", function () { visualStop(); if (!playNext()) miniClose(); });
  }
  /* ÉCOUTE EN CONTINU : à la fin d'un extrait, on enchaîne sur le lecteur audio
     suivant dans le fil de la page (ordre du DOM = ordre de la rédaction). Rend
     faux quand il n'y a plus de suivant, pour que le mini-lecteur se ferme. */
  function playNext() {
    // Tous les lecteurs de la page, dans l'ordre du DOM : dossiers de la
    // rédaction OU épisodes d'un flux dans la médiathèque. Enchaîner sur le
    // suivant donne la lecture continue d'un livre audio, chapitre après
    // chapitre, puis le flux suivant.
    var players = $$('.play[data-media]');
    if (!lastBtn) return false;
    var i = players.indexOf(lastBtn);
    if (i < 0 || i + 1 >= players.length) return false;
    play(players[i + 1]);
    return true;
  }
  function playPrev() {
    var players = $$('.play[data-media]');
    if (!lastBtn) return;
    var i = players.indexOf(lastBtn);
    // Avant 3 s : piste précédente ; sinon on revient au début de la piste.
    if (audio && audio.currentTime > 3) { audio.currentTime = 0; return; }
    if (i > 0) play(players[i - 1]);
  }
  function playFeed(btn) {
    var sec = btn.closest('.podfeed');
    if (!sec) return;
    var first = sec.querySelector('.play[data-media]');
    if (first) play(first);
  }
  function play(btn) {
    var url = btn.getAttribute("data-media");
    if (!url) { var h = btn.getAttribute("data-href"); if (h) location.href = h; return; }
    lastBtn = btn;
    var c = btn.closest(".dossier") || btn.closest(".podfeed") || btn.closest(".ep");
    ensure();
    if (card === c && !audio.paused) { audio.pause(); return; }
    if (audio.src !== new URL(url, location.href).href) audio.src = url;
    visualStop(); card = c;
    $("#mini").classList.add("show");
    $("#mini-t").textContent = btn.getAttribute("data-title") || "";
    $("#mini-s").textContent = btn.getAttribute("data-sub") || "";
    audio.play().catch(function () { var h = btn.getAttribute("data-href"); if (h) location.href = h; });
  }
  // POP-OUT : ouvre un lecteur dans une FENÊTRE séparée qui continue de jouer
  // pendant qu'on navigue dans la fenêtre principale (la lecture d'un onglet ne
  // s'interrompt pas quand un AUTRE onglet change de page). On passe le flux (ou
  // la piste), l'épisode courant et sa position ; le lecteur reprend là.
  function popout() {
    if (!lastBtn) return;
    var media = lastBtn.getAttribute("data-media") || "";
    var feed = lastBtn.getAttribute("data-feed") || "";
    var t = Math.floor(audio ? audio.currentTime : 0);
    var q = feed ? "feed=" + encodeURIComponent(feed) : "src=" + encodeURIComponent(media);
    q += "&t=" + t;
    var m = media.match(/\/media\/ep\/(\d+)/);
    if (m) q += "&ep=" + m[1];
    q += "&title=" + encodeURIComponent(lastBtn.getAttribute("data-title") || "");
    window.open("/player?" + q, "sbxplayer",
      "width=460,height=620,menubar=no,toolbar=no,location=no,resizable=yes");
    if (audio) audio.pause();
    miniClose();
  }
  /* Détache le widget radio en fenêtre persistante (#1131m) : elle survit à la
     navigation BBS, donc l'écoute ne se coupe pas quand on change de page. */
  /* Charge l'embed vidéo DANS la carte, au clic seulement (#1131x) : la
     vignette cède la place à un <iframe> vers l'URL d'intégration (youtube-
     nocookie / peertube, déjà autorisés par frame-src). Rien n'est contacté
     avant le clic. */
  function cardPlay(t) {
    var url = t.getAttribute("data-embed");
    if (!url) return;
    var prev = t.closest(".prev") || t.parentNode;
    var f = document.createElement("iframe");
    f.className = "cardframe";
    f.src = url;
    f.setAttribute("allow", "accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share");
    f.setAttribute("referrerpolicy", "strict-origin-when-cross-origin");
    f.setAttribute("allowfullscreen", "");
    prev.textContent = "";
    prev.appendChild(f);
  }
  function radioPopout(t) {
    var url = t.getAttribute("data-url");
    if (url) window.open(url, "sbxradio",
      "width=380,height=580,menubar=no,toolbar=no,location=no,resizable=yes");
  }
  function miniToggle() { if (!audio) return; audio.paused ? audio.play() : audio.pause(); }
  function miniClose() { if (audio) audio.pause(); $("#mini").classList.remove("show"); }
  function drop() { var d = $("#dropin"); if (d) { d.focus(); d.scrollIntoView({ behavior: "smooth", block: "center" }); } }

  /* UNE délégation pour toutes les actions */
  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-act]");
    if (!t) return;
    var a = t.getAttribute("data-act");
    if (a === "play") { e.preventDefault(); play(t); }
    else if (a === "playfeed") { e.preventDefault(); playFeed(t); }
    else if (a === "filt") filt(t);
    else if (a === "rub") rub(t);
    else if (a === "theme") theme();
    else if (a === "drop") { e.preventDefault(); drop(); }
    else if (a === "mini") miniToggle();
    else if (a === "prev") playPrev();
    else if (a === "next") { if (!playNext() && audio) audio.currentTime = audio.duration || 0; }
    else if (a === "popout") popout();
    else if (a === "radiopop") { e.preventDefault(); radioPopout(t); }
    else if (a === "cardplay") { if (t.getAttribute("data-embed")) { e.preventDefault(); cardPlay(t); } }
    else if (a === "mini-close") miniClose();
    else if (a === "cartop") {
      // `scrollingElement` et non `window` : en embarqué c'est le document de
      // l'iframe qui défile, et il n'a pas toujours le même porteur de scroll
      // selon le navigateur. Le comportement doux est ignoré si le visiteur a
      // demandé moins d'animation — remonter reste instantané, jamais bloqué.
      var doux = !matchMedia("(prefers-reduced-motion: reduce)").matches;
      (document.scrollingElement || document.documentElement)
        .scrollTo({ top: 0, behavior: doux ? "smooth" : "auto" });
    }
    else if (a === "carprev") { carHold(); carScrollByCards(-1); }
    else if (a === "carnext") { carHold(); carScrollByCards(1); }
  });
  document.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === "k") { e.preventDefault(); drop(); }
    if (e.target && e.target.tagName === "INPUT") return;
    if (e.key === "t") theme();
  });

  // « Déposer une source » : si le champ de la barre porte une URL, on ouvre le
  // composeur pré-rempli (dossier LOCAL jusqu'à publication) au lieu de chercher.
  var dropForm = document.querySelector("form.drop");
  if (dropForm) dropForm.addEventListener("submit", function (e) {
    var el = $("#dropin"); if (!el) return;
    var v = (el.value || "").trim();
    if (/^https?:\/\//i.test(v)) { e.preventDefault(); location.href = "/nouveau?src=" + encodeURIComponent(v); }
  });

  /* ── Carrousel « À la une » (#1104) : flèches, points, clavier, sync au
     défilement. Purement présentation : aucune donnée nouvelle, il rejoue les
     mêmes dossiers que le fil vertical ci-dessous. ── */
  var cartrack = $("#cartrack"), cardots = $("#cardots");
  function carCards() { return cartrack ? $$(".ccard", cartrack) : []; }
  function carScrollByCards(dir) {
    if (!cartrack) return;
    var c = cartrack.querySelector(".ccard");
    var step = (c ? c.offsetWidth + 14 : 220) * 1.5;
    cartrack.scrollBy({ left: dir * step, behavior: carAnim });
  }
  function carSync() {
    if (!cartrack || !cardots) return;
    var cards = carCards(); if (!cards.length) return;
    var mid = cartrack.scrollLeft + cartrack.clientWidth / 2, best = 0, bd = 1e9;
    cards.forEach(function (c, j) { var cc = c.offsetLeft + c.offsetWidth / 2, dd = Math.abs(cc - mid); if (dd < bd) { bd = dd; best = j; } });
    $$("button", cardots).forEach(function (d, j) { d.classList.toggle("on", j === best); });
    var pv = $('[data-act="carprev"]'), nx = $('[data-act="carnext"]');
    if (pv) pv.disabled = cartrack.scrollLeft <= 2;
    if (nx) nx.disabled = cartrack.scrollLeft + cartrack.clientWidth >= cartrack.scrollWidth - 2;
  }
  /* Auto-défilement (#1104) : avance toutes les 5 s, revient au début en fin de
     piste. En pause au survol / focus et 9 s après une interaction ; désactivé
     si moins-d'animation est demandé ou s'il n'y a qu'une carte. */
  var carTimer = null, carResume = null;
  var carReduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  // Le carrousel tourne POUR TOUT LE MONDE (#1131al) ; « réduire les
  // animations » ne coupe pas la rotation, il la rend INSTANTANÉE (pas de
  // défilement animé) — on respecte la préférence sans figer le carrousel.
  var carAnim = carReduce ? "auto" : "smooth";
  function carAtEnd() { return cartrack && cartrack.scrollLeft + cartrack.clientWidth >= cartrack.scrollWidth - 2; }
  function carTick() { if (!cartrack) return; if (carAtEnd()) cartrack.scrollTo({ left: 0, behavior: carAnim }); else carScrollByCards(1); }
  function carStop() { if (carTimer) { clearInterval(carTimer); carTimer = null; } }
  function carPlay() { if (!cartrack || carCards().length < 2) return; carStop(); carTimer = setInterval(carTick, 5000); }
  function carHold() { carStop(); clearTimeout(carResume); carResume = setTimeout(carPlay, 9000); }
  // L'AUTO-DÉFILEMENT NE DÉPEND QUE DE LA PISTE (#1131s) : le carrousel tourne
  // PARTOUT où il apparaît, même sans pastilles. Auparavant tout — y compris
  // carPlay — était sous `cartrack && cardots` : une vue sans #cardots restait
  // figée. Les pastilles ne sont plus qu'un ORNEMENT optionnel.
  if (cartrack) {
    if (cardots) carCards().forEach(function (card, j) {
      var b = document.createElement("button");
      b.type = "button"; b.setAttribute("aria-label", "Aller au dossier " + (j + 1));
      b.addEventListener("click", function () { carHold(); card.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" }); });
      cardots.appendChild(b);
    });
    var craf;
    cartrack.addEventListener("scroll", function () { cancelAnimationFrame(craf); craf = requestAnimationFrame(carSync); });
    cartrack.addEventListener("keydown", function (e) {
      if (e.key === "ArrowRight") { e.preventDefault(); carHold(); carScrollByCards(1); }
      else if (e.key === "ArrowLeft") { e.preventDefault(); carHold(); carScrollByCards(-1); }
    });
    cartrack.addEventListener("mouseenter", carStop);
    cartrack.addEventListener("mouseleave", carPlay);
    cartrack.addEventListener("focusin", carStop);
    cartrack.addEventListener("focusout", carPlay);
    window.addEventListener("resize", carSync);
    document.addEventListener("visibilitychange", function () { document.hidden ? carStop() : carPlay(); });
    carSync();
    carPlay();
  }
})();
