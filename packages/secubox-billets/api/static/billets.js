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
