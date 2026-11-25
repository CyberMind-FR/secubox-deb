// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
// Repères visuels partagés des cartes de campagne (#3919). Script classique : pose window.SbxReperes,
// ne touche pas au DOM au chargement. Copie identique dans secubox-ai (www/ai) et secubox-waf-ng (www/actor).
(function (w) {
  "use strict";

  var CLASSES = {
    proxy_loue: ["🔁", "proxy loué"],
    hebergeur: ["🏢", "hébergeur / cloud"],
    acces: ["🏠", "accès grand public"],
    mobile_partage: ["🛰️", "mobile ou satellite"],
    cdn: ["🌐", "CDN"],
    relais_vie_privee: ["🕶️", "relais de vie privée"],
    scanner_recherche: ["🔬", "scanner de recherche"],
    inconnu: ["❔", "inconnu"]
  };

  var FAMILLES = {
    collecte: ["📚", "Collecte"],
    messagerie: ["✉️", "Mots de passe sur la messagerie"],
    acces_distant: ["🚪", "Balayage des leurres de service"],
    balayage_web: ["🕷️", "Balayage des sites web"],
    autre: ["❔", "Autre activité"]
  };

  var ETATS = {
    rotation: ["🌀", "rotation"],
    bannie: ["🛑", "bannie"],
    observee: ["👁️", "observée"],
    inactive: ["💤", "inactive"]
  };

  // Drapeau à partir d'un code pays à deux lettres (indicateurs régionaux) ; code invalide : drapeau blanc.
  function drapeau(code) {
    var c = typeof code === "string" ? code.toUpperCase() : "";
    if (!/^[A-Z]{2}$/.test(c)) return "🏳️";
    return String.fromCodePoint(0x1F1E6 + c.charCodeAt(0) - 65, 0x1F1E6 + c.charCodeAt(1) - 65);
  }

  // Nom d'une carte : libellé de famille, suivi de la première cible (suffixe .secubox.in retiré) pour « collecte ».
  function nomCarte(famille, cibles) {
    var f = Object.prototype.hasOwnProperty.call(FAMILLES, famille) ? FAMILLES[famille] : FAMILLES.autre;
    if (famille === "messagerie") return f[1];
    var premiere = Array.isArray(cibles) && cibles.length ? String(cibles[0]) : "";
    premiere = premiere.replace(/\.secubox\.in$/, "");
    return premiere ? f[1] + " : " + premiere : f[1];
  }

  // Puce : <span class="puce" title="libellé" aria-label="libellé suffixe">emoji libellé suffixe</span>.
  function puce(doc, repere, suffixe) {
    var libelle = repere[1];
    var fin = suffixe ? " " + suffixe : "";
    var el = doc.createElement("span");
    el.setAttribute("class", "puce");
    el.setAttribute("title", libelle);
    el.setAttribute("aria-label", libelle + fin);
    el.textContent = repere[0] + " " + libelle + fin;
    return el;
  }

  w.SbxReperes = {
    CLASSES: CLASSES, FAMILLES: FAMILLES, ETATS: ETATS,
    drapeau: drapeau, nomCarte: nomCarte, puce: puce
  };
})(window);
