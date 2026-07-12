// SPDX-License-Identifier: LicenseRef-CMSD-1.0
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
