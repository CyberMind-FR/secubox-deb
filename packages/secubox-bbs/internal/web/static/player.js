/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
   Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
   Lecteur détaché #1056 — fenêtre séparée. Joue une playlist (un flux) ou une
   piste, avec précédent / suivant / lecture continue. Comme cette fenêtre est
   un DOCUMENT à part, sa lecture ne s'interrompt pas quand la fenêtre
   principale change de page. CSP stricte : data-* + délégation, pas d'inline.
   Utilise la Media Session API pour les touches média du système. */
(function () {
  "use strict";
  var $ = function (s) { return document.querySelector(s); };
  var audio = $("#pl-audio");
  var eps = Array.prototype.slice.call(document.querySelectorAll(".pl-ep"));
  var wrap = $(".pl-wrap");
  var idx = -1;

  function fmt(t) { t = Math.floor(t || 0); return Math.floor(t / 60) + ":" + ("0" + (t % 60)).slice(-2); }

  function load(i, autoplay, at) {
    if (i < 0 || i >= eps.length) return;
    idx = i;
    var li = eps[i];
    audio.src = li.getAttribute("data-src");
    var title = li.getAttribute("data-title") || "";
    $("#pl-now-t").textContent = title;
    $("#pl-now-s").textContent = (i + 1) + " / " + eps.length;
    eps.forEach(function (e) { e.classList.remove("on"); });
    li.classList.add("on");
    li.scrollIntoView({ block: "nearest" });
    document.title = "♪ " + title;
    if (typeof at === "number" && at > 0) {
      audio.currentTime = 0;
      audio.addEventListener("loadedmetadata", function once() {
        audio.currentTime = at; audio.removeEventListener("loadedmetadata", once);
      });
    }
    if (autoplay) audio.play().catch(function () {});
    if ("mediaSession" in navigator) {
      navigator.mediaSession.metadata = new MediaMetadata({ title: title });
    }
  }
  function next() { if (idx + 1 < eps.length) load(idx + 1, true); }
  function prev() {
    if (audio.currentTime > 3) { audio.currentTime = 0; return; }
    if (idx > 0) load(idx - 1, true);
  }

  audio.addEventListener("timeupdate", function () {
    var d = audio.duration || 0, c = audio.currentTime || 0;
    $("#pl-prog").style.width = (d ? c / d * 100 : 0) + "%";
    $("#pl-time").textContent = fmt(c);
  });
  audio.addEventListener("play", function () { $("#pl-play").textContent = "❚❚"; });
  audio.addEventListener("pause", function () { $("#pl-play").textContent = "▶"; });
  audio.addEventListener("ended", next);

  document.addEventListener("click", function (e) {
    var li = e.target.closest(".pl-ep");
    if (li) { load(eps.indexOf(li), true); return; }
    var b = e.target.closest("[data-act]");
    if (!b) return;
    var a = b.getAttribute("data-act");
    if (a === "toggle") { audio.paused ? audio.play() : audio.pause(); }
    else if (a === "next") next();
    else if (a === "prev") prev();
  });
  var seek = $("#pl-seek");
  if (seek) seek.addEventListener("click", function (e) {
    var r = seek.getBoundingClientRect();
    if (audio.duration) audio.currentTime = (e.clientX - r.left) / r.width * audio.duration;
  });
  if ("mediaSession" in navigator) {
    navigator.mediaSession.setActionHandler("nexttrack", next);
    navigator.mediaSession.setActionHandler("previoustrack", prev);
  }

  // Reprise : épisode et position passés par le pop-out.
  var startEp = wrap.getAttribute("data-start-ep");
  var startT = parseInt(wrap.getAttribute("data-start-t") || "0", 10) || 0;
  var start = 0;
  if (startEp) {
    for (var i = 0; i < eps.length; i++) {
      if (eps[i].getAttribute("data-ep") === startEp) { start = i; break; }
    }
  }
  if (eps.length) load(start, true, startT);
})();
