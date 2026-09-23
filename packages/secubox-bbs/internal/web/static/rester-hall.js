// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox-Deb :: BBS — un lien de source reste DANS le Hall (#1323).
//
// LE PROBLEME. Les liens de sources de la salle de redaction portent
// `target="_blank"` : ils ouvrent un onglet reel. Embarque dans le Hall, c'est
// un aller sans retour — on perd la mosaique, la barre media et tout ce qui
// joue, pour lire un article. Et surtout on sort du relais : la page est alors
// chargee EN DIRECT par le navigateur, sans passer par le BiB, donc sans
// coupure des pisteurs ni cloisonnement par origine. Le lien de sortie annule
// la protection que tout le reste met en place.
//
// CE QU'ON FAIT. Encadre, on demande au Hall d'ouvrir l'adresse dans son
// surfeur (`{sbx:'surf', url}`) : la megabarre reste, le relais fait son
// travail. Hors cadre — la page BBS ouverte directement — le lien garde son
// comportement d'origine : cette page doit rester utilisable seule.
//
// ON NE DETOURNE QUE L'EXTERIEUR. Un lien vers le BBS lui-meme, ou vers un
// autre service de la box, n'a rien a faire dans le surfeur : il s'ouvre
// normalement, et le Hall le suit deja.
(function () {
  "use strict";
  // Le script peut etre inclus par deux gabarits d'une meme page : on
  // n'installe l'ecouteur qu'une fois, sinon un clic partirait en double.
  if (window.__sbxResterHall) { return; }
  window.__sbxResterHall = true;

  var SUFFIXE = ".gk2.secubox.in";

  function estChezNous(h) {
    h = (h || "").toLowerCase();
    return h === location.hostname ||
           h.slice(-SUFFIXE.length) === SUFFIXE ||
           h.slice(-".gk2.net".length) === ".gk2.net";
  }

  document.addEventListener("click", function (ev) {
    // Hors cadre : on ne touche a rien.
    if (parent === window) { return; }
    // Un clic deja traite, un bouton du milieu, ou un modificateur (ouvrir
    // dans un onglet est alors un choix DELIBERE) : on laisse faire.
    if (ev.defaultPrevented || ev.button !== 0 ||
        ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) { return; }
    var a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
    if (!a) { return; }
    var u;
    try { u = new URL(a.href, location.href); } catch (e) { return; }
    if (u.protocol !== "http:" && u.protocol !== "https:") { return; }
    if (estChezNous(u.hostname)) { return; }
    ev.preventDefault();
    try {
      parent.postMessage({ sbx: "surf", url: u.href }, "*");
    } catch (e) {
      // Le Hall ne repond pas : plutot que d'avaler le clic, on rend au lien
      // son comportement. Un lien qui ne fait rien est pire qu'un onglet.
      window.open(u.href, "_blank", "noopener");
    }
  }, true);
})();
