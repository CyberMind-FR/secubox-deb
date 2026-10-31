// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
// #3324 : état des modules de la box légère et « Démarrer » (action service-demarrer du pilotage). Jeton : sbx_token de cette origine.
(function () {
  "use strict";
  var etat = document.getElementById("etat"), liste = document.getElementById("liste");
  function jeton() { try { return localStorage.getItem("sbx_token") || ""; } catch (e) { return ""; } }
  function appel(chemin, methode) {
    return fetch("/api/v1/pilotage-vhost/modules" + chemin, { method: methode || "GET", credentials: "omit", cache: "no-store",
      headers: { "Authorization": "Bearer " + jeton() } });
  }
  function ligne(m) {
    var li = document.createElement("li"), nom = document.createElement("a"), pastille = document.createElement("span");
    nom.href = "/" + m.module + "/"; nom.textContent = m.module;
    pastille.className = "pastille " + (m.etat === "actif" ? "actif" : "arrete");
    pastille.textContent = m.etat === "actif" ? "actif" : "arrêté (profil léger)";
    li.append(nom, pastille);
    if (m.etat !== "actif") {
      var b = document.createElement("button");
      b.textContent = "Démarrer";
      b.addEventListener("click", function () {
        b.disabled = true; b.textContent = "Démarrage…";
        appel("/" + encodeURIComponent(m.module) + "/demarrer", "POST")
          .then(function (r) { return r.json().then(function (j) { return [r.ok, j]; }); })
          .then(function (x) { b.textContent = x[0] ? "Demandé — " + (x[1].etat || "") : "Refusé : " + (x[1].detail || ""); setTimeout(lire, 8000); })
          .catch(function () { b.textContent = "Erreur réseau"; b.disabled = false; });
      });
      li.append(b);
    }
    return li;
  }
  function lire() {
    appel("", "GET").then(function (r) {
      if (r.status === 401) { etat.textContent = "Session expirée : repassez par « Ouvrir » dans la Flotte du maître."; return null; }
      return r.ok ? r.json() : Promise.reject(r.status);
    }).then(function (j) {
      if (!j) { return; }
      liste.replaceChildren.apply(liste, j.modules.map(ligne));
      var n = j.modules.filter(function (m) { return m.etat === "actif"; }).length;
      etat.textContent = n + " actif(s) sur " + j.modules.length + " — box " + j.box;
    }).catch(function (e) { etat.textContent = "État illisible (" + e + ")."; });
  }
  lire();
})();
