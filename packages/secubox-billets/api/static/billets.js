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
