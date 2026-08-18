// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: BBS — barre d'outils de l'editeur.
//
// L'editeur a l'air d'un traitement de texte mais ECRIT DU MARKDOWN. Ce qui
// part sur le disque est donc du texte, lisible dans dix ans avec `less`, et le
// serveur n'a jamais a assainir du HTML recu d'un navigateur.
//
// Sans JavaScript, la zone de saisie reste utilisable telle quelle : les
// boutons sont un confort, pas un passage oblige.
//
// CHAQUE BLOC `.editor` EST CABLE SEPAREMENT, a sa propre zone de saisie.
// La premiere version cherchait `#tools` et `textarea[name="body"]` — un
// identifiant unique et un nom fige. Cela tenait tant qu'une page ne portait
// qu'un editeur nomme « body » ; la messagerie interne en a un second, nomme
// « corps », et il serait reste sans barre d'outils, ou pire aurait pilote la
// zone de l'autre editeur si les deux avaient cohabite.
(function () {
  function cable(zone) {
    var tools = zone.querySelector('.tools');
    var area = zone.querySelector('textarea');
    if (!tools || !area) return;

    function entoure(marque) {
      var d = area.selectionStart, f = area.selectionEnd, v = area.value;
      var sel = v.slice(d, f) || 'texte';
      area.value = v.slice(0, d) + marque + sel + marque + v.slice(f);
      area.focus();
      area.setSelectionRange(d + marque.length, d + marque.length + sel.length);
    }

    function prefixe(p) {
      var d = area.selectionStart, v = area.value;
      var deb = v.lastIndexOf('\n', d - 1) + 1;
      area.value = v.slice(0, deb) + p + v.slice(deb);
      area.focus();
      area.setSelectionRange(d + p.length, d + p.length);
    }

    tools.addEventListener('click', function (e) {
      var b = e.target.closest('button');
      if (!b) return;
      if (b.dataset.w) entoure(b.dataset.w);
      else if (b.dataset.p) prefixe(b.dataset.p.replace('&gt;', '>'));
      else if (b.dataset.lien) {
        // Le schema est verifie A NOUVEAU cote serveur : ce controle-ci n'est
        // qu'une politesse envers celui qui tape, jamais une garde.
        var u = prompt('Adresse du lien (http, https ou mailto)');
        if (!u) return;
        var d = area.selectionStart, f = area.selectionEnd;
        var sel = area.value.slice(d, f) || 'texte';
        area.value = area.value.slice(0, d) + '[' + sel + '](' + u + ')' + area.value.slice(f);
        area.focus();
      }
    });
  }

  var zones = document.querySelectorAll('.editor');
  for (var i = 0; i < zones.length; i++) cable(zones[i]);
})();
