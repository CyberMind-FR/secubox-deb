/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
   Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
   AletheiaVox newsroom — interactions de l'accueil (#1056 stage 1).

   CSP STRICTE (script-src 'self', pas d'unsafe-inline) : aucun onclick ni style
   en ligne. Les actions passent par des attributs data-* et UNE délégation de
   clic, comme coquille.js. La lecture audio joue le VRAI média du fil
   (media-src 'self' autorise /media/ep/… local) ; la vidéo renvoie à la page du
   fil, qui intègre le lecteur avec sa propre politique. Rien n'est feint. */
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
    else if (a === "mini-close") miniClose();
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
})();
