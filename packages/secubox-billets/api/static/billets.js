// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Thème clair/sombre PARTAGÉ avec la rédaction du BBS (#1092/#1094) : MÊME clé
// localStorage (`av-theme`) et même bascule, pour qu'un lecteur qui passe la
// gazette du BBS en nuit retrouve billets en nuit — les deux faces publiques
// AletheiaVox partagent la préférence. Sans JS la page reste en clair (défaut
// de newsroom.css), le bouton ne fait qu'ajouter le confort du basculement.
(function () {
  var r = document.documentElement;
  try { var sv = localStorage.getItem('av-theme'); if (sv) r.setAttribute('data-theme', sv); } catch (e) {}
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

// Progressive enhancement for emoji reactions: intercept the reaction form
// submit, POST it, and swap the #reactions fragment in place. With JS disabled
// the same forms POST normally and the server 303-redirects back to the billet
// (graceful degradation). Loaded from /static (CSP script-src 'self') — no
// inline script. (In deploy, a vendored htmx.min.js can drive the same
// fragment endpoint; this tiny shim avoids an external dependency.)
(function () {
  "use strict";
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!form || !form.classList || !form.classList.contains("react")) return;
    e.preventDefault();
    fetch(form.action + "?fragment=1", {
      method: "POST",
      body: new FormData(form),
      headers: { "HX-Request": "1" },
      credentials: "same-origin"
    }).then(function (r) { return r.text(); }).then(function (html) {
      var cur = document.getElementById("reactions");
      if (!cur) return;
      var tmp = document.createElement("div");
      tmp.innerHTML = html;
      var next = tmp.querySelector("#reactions");
      if (next) cur.replaceWith(next);
    }).catch(function () { form.submit(); });
  });
})();

// Republier: Mastodon needs the visitor's instance (remembered in localStorage),
// and "copy link" uses the clipboard. Both are progressive — the other share
// links are plain server-rendered anchors that work with JS off.
(function () {
  "use strict";
  document.addEventListener("click", function (e) {
    var btn = e.target;
    if (!btn || !btn.classList) return;
    var menu = btn.closest ? btn.closest(".share-menu") : null;
    if (!menu) return;
    var url = menu.getAttribute("data-url") || location.href;
    var title = menu.getAttribute("data-title") || document.title;
    if (btn.classList.contains("share-mastodon")) {
      var inst = null;
      try { inst = localStorage.getItem("billets_mastodon"); } catch (x) {}
      inst = prompt("Votre instance Mastodon (ex : mastodon.social)", inst || "");
      if (!inst) return;
      inst = inst.replace(/^https?:\/\//, "").replace(/\/+$/, "");
      try { localStorage.setItem("billets_mastodon", inst); } catch (x) {}
      var text = encodeURIComponent(title + " " + url);
      window.open("https://" + inst + "/share?text=" + text, "_blank", "noopener");
    } else if (btn.classList.contains("share-copy")) {
      if (navigator.clipboard) {
        navigator.clipboard.writeText(url).then(function () {
          btn.textContent = "Lien copié ✓";
          setTimeout(function () { btn.textContent = "Copier le lien"; }, 1500);
        });
      }
    }
  });
})();

// Communiqué embed: the poster shows a still snapshot vignette; clicking it
// swaps in the real (already-sanitized) embed iframe held in a <template>. CSP
// is script-src 'self' — this delegated handler lives here, no inline JS. With
// JS off the vignette stays (still a valid poster); the permalink still links out.
(function () {
  "use strict";
  document.addEventListener("click", function (e) {
    var btn = e.target.closest && e.target.closest("[data-load-embed]");
    if (!btn) return;
    e.preventDefault();
    var frame = btn.closest(".comm-embed");
    if (!frame) return;
    var tpl = frame.querySelector("template.comm-embed-html");
    if (!tpl || !("content" in tpl)) return;
    var holder = document.createElement("div");
    holder.className = "comm-embed-live";
    holder.appendChild(tpl.content.cloneNode(true));
    btn.replaceWith(holder);
  });
})();

// Lightbox: click a gallery vignette to view the full image, zoomable, with
// keyboard/arrow navigation within the same billet's gallery. With JS disabled
// the .gallery-item links open the full image directly (graceful degradation).
(function () {
  "use strict";
  var overlay = null, imgEl = null, items = [], idx = 0;

  function build() {
    overlay = document.createElement("div");
    overlay.className = "lightbox";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.innerHTML =
      '<button class="lb-close" aria-label="Fermer">✕</button>' +
      '<button class="lb-nav lb-prev" aria-label="Précédente">‹</button>' +
      '<img class="lb-img" alt="">' +
      '<button class="lb-nav lb-next" aria-label="Suivante">›</button>';
    document.body.appendChild(overlay);
    imgEl = overlay.querySelector(".lb-img");
    overlay.addEventListener("click", function (e) {
      if (e.target === overlay || e.target.classList.contains("lb-close")) close();
      else if (e.target.classList.contains("lb-prev")) step(-1);
      else if (e.target.classList.contains("lb-next")) step(1);
      else if (e.target === imgEl) imgEl.classList.toggle("zoomed");
    });
  }

  function show() {
    var it = items[idx];
    if (!it) return;
    imgEl.classList.remove("zoomed");
    imgEl.src = it.getAttribute("data-full");
    imgEl.alt = it.getAttribute("data-alt") || "";
    var multi = items.length > 1;
    overlay.querySelector(".lb-prev").style.display = multi ? "" : "none";
    overlay.querySelector(".lb-next").style.display = multi ? "" : "none";
  }
  function step(d) { idx = (idx + d + items.length) % items.length; show(); }
  function open(gallery, start) {
    if (!overlay) build();
    items = Array.prototype.slice.call(gallery.querySelectorAll(".gallery-item"));
    idx = start; show();
    overlay.classList.add("open");
    document.body.classList.add("lb-lock");
  }
  function close() {
    if (!overlay) return;
    overlay.classList.remove("open");
    document.body.classList.remove("lb-lock");
    imgEl.src = "";
  }

  document.addEventListener("click", function (e) {
    var link = e.target.closest && e.target.closest(".gallery-item");
    if (!link) return;
    var gallery = link.closest("[data-lightbox]");
    if (!gallery) return;
    e.preventDefault();
    var all = Array.prototype.slice.call(gallery.querySelectorAll(".gallery-item"));
    open(gallery, all.indexOf(link));
  });
  document.addEventListener("keydown", function (e) {
    if (!overlay || !overlay.classList.contains("open")) return;
    if (e.key === "Escape") close();
    else if (e.key === "ArrowLeft") step(-1);
    else if (e.key === "ArrowRight") step(1);
  });
})();

// Carrousel « À la une » (#1104) : flèches, points, clavier, sync au défilement.
// Autonome (billets.js est chargé en `defer` → DOM prêt). Aucun style inline.
(function () {
  var track = document.getElementById("cartrack"), dots = document.getElementById("cardots");
  if (!track) return;
  var cards = [].slice.call(track.querySelectorAll(".ccard"));
  var prev = document.querySelector('[data-act="carprev"]'), next = document.querySelector('[data-act="carnext"]');
  function step(dir) {
    var c = track.querySelector(".ccard");
    var w = c ? c.offsetWidth + 14 : 220;
    track.scrollBy({ left: dir * w * 1.5, behavior: "smooth" });
  }
  if (prev) prev.addEventListener("click", function () { step(-1); });
  if (next) next.addEventListener("click", function () { step(1); });
  if (dots) cards.forEach(function (card, j) {
    var b = document.createElement("button");
    b.type = "button"; b.setAttribute("aria-label", "Billet " + (j + 1));
    b.addEventListener("click", function () { card.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" }); });
    dots.appendChild(b);
  });
  function sync() {
    if (!cards.length) return;
    var mid = track.scrollLeft + track.clientWidth / 2, best = 0, bd = 1e9;
    cards.forEach(function (c, j) { var cc = c.offsetLeft + c.offsetWidth / 2, dd = Math.abs(cc - mid); if (dd < bd) { bd = dd; best = j; } });
    if (dots) [].slice.call(dots.children).forEach(function (d, j) { d.classList.toggle("on", j === best); });
    if (prev) prev.disabled = track.scrollLeft <= 2;
    if (next) next.disabled = track.scrollLeft + track.clientWidth >= track.scrollWidth - 2;
  }
  var raf;
  track.addEventListener("scroll", function () { cancelAnimationFrame(raf); raf = requestAnimationFrame(sync); });
  track.addEventListener("keydown", function (e) {
    if (e.key === "ArrowRight") { e.preventDefault(); step(1); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); step(-1); }
  });
  window.addEventListener("resize", sync);
  sync();
})();
