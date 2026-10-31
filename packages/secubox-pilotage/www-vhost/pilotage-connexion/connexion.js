// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// Connexion au vhost d'une box légère (#3126, L5 tâche 5, R-L5-25 C1c) : le code à usage unique arrive dans le fragment (jamais
// envoyé au serveur par le navigateur, jamais dans un journal), il est retiré de l'adresse puis échangé contre le jeton du vhost,
// gardé dans le localStorage de CETTE origine. Aucun identifiant n'est demandé ici.
(function () {
  "use strict";
  var etat = document.getElementById("etat");
  var p = new URLSearchParams(location.hash.slice(1));
  var code = p.get("code") || "";
  var retour = p.get("retour") || "";
  history.replaceState(null, "", location.pathname);
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(code)) { etat.textContent = "Code de connexion absent : ouvrez cette box depuis le pilotage du maître."; return; }
  if (!/^\/[a-z0-9][a-z0-9_-]{0,63}\/$/.test(retour)) { retour = ""; }
  fetch("/api/v1/auth/echanger", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: code }),
    credentials: "omit", cache: "no-store" })
    .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
    .then(function (j) {
      try { localStorage.setItem("sbx_token", j.access_token); } catch (e) { /* stockage refusé */ }
      location.replace(retour || "/");   // #3302 : sans destination, l'accueil de l'administration
    })
    .catch(function () { etat.textContent = "Code refusé ou expiré : recommencez depuis le pilotage du maître."; });
})();
