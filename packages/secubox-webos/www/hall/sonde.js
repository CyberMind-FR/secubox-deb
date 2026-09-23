/*
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  SecuBox #1351 — LA GARDE DES SONDES : une lecture refusée cesse d'insister.

  CE QU'ELLE CORRIGE, MESURÉ. Les cartes du Hall interrogent leur API en boucle,
  toutes les deux à trois secondes. Quand la lecture est refusée — pas de
  session, ou verdict LAN qui n'arrive pas — elles recommencent indéfiniment :
  6586 refus en une heure depuis un seul poste, dont 1560 sur la même route.
  La carte reste vide, le journal se noie, et une vraie panne devient
  invisible au milieu du bruit.

  POURQUOI ICI ET PAS DANS CHAQUE CARTE. Il y a douze boucles, écrites douze
  fois. Les corriger une par une, c'est refaire la liste tenue à la main dont
  la treizième carte s'écartera demain. On enveloppe donc `fetch` une seule
  fois, et le test `test_verdict_lan`-style garde que toute carte qui sonde
  charge ce fichier.

  CE N'EST PAS UN SILENCE DÉFINITIF. Une session peut s'ouvrir à tout moment :
  on ESPACE les tentatives au lieu de les arrêter — trente secondes, puis le
  double à chaque refus, jusqu'à cinq minutes. Un retour à 200 remet le
  compteur à zéro. Arrêter pour de bon obligerait à recharger la carte après
  s'être connecté, ce que personne ne devine.

  PORTÉE VOLONTAIREMENT ÉTROITE : même origine, et seulement `/api/v1/`. Tout
  le reste — médias, vignettes, pages — passe intact.
*/
(function () {
  "use strict";
  if (window.SBXSonde) return;

  var ATTENTE_INITIALE = 30000;   // ms avant la première nouvelle tentative
  var ATTENTE_MAX = 300000;       // plafond : cinq minutes
  var ferme = Object.create(null);

  // La CLÉ est le module, pas l'URL complète : un refus sur /api/v1/dpi/stats
  // vaut pour /api/v1/dpi/clients — c'est la même garde côté serveur, et
  // laisser passer les voisines reproduirait la tempête à l'identique.
  function cle(chemin) {
    var m = /^\/api\/v1\/([^/?#]+)/.exec(chemin);
    return m ? m[1] : null;
  }

  function cheminDe(entree) {
    try {
      var u = new URL(typeof entree === "string" ? entree : (entree && entree.url) || "",
                      location.href);
      if (u.origin !== location.origin) return null;   // autre origine : pas notre affaire
      return u.pathname;
    } catch (e) { return null; }
  }

  var vrai = window.fetch.bind(window);

  window.fetch = function (entree, options) {
    var chemin = cheminDe(entree);
    var k = chemin && cle(chemin);
    if (!k) return vrai(entree, options);

    var e = ferme[k];
    if (e && Date.now() < e.jusqu) {
      // ON REND LA MÊME RÉPONSE QUE LE SERVEUR AURAIT RENDUE, sans l'appeler.
      // La carte suit exactement le chemin de code qu'elle suivrait sinon :
      // aucune branche nouvelle à écrire, aucune à oublier.
      return Promise.resolve(new Response(
        '{"detail":"lecture refusee — nouvelle tentative differee (sonde.js)"}',
        { status: 401, headers: { "Content-Type": "application/json" } }));
    }

    return vrai(entree, options).then(function (r) {
      if (r.status === 401 || r.status === 403) {
        var d = ferme[k] ? Math.min(ferme[k].attente * 2, ATTENTE_MAX) : ATTENTE_INITIALE;
        var premier = !ferme[k];
        ferme[k] = { jusqu: Date.now() + d, attente: d };
        if (premier) {
          // La carte PEUT s'en saisir pour dire « connecte-toi pour voir
          // ceci ». Elle n'y est pas obligée : l'événement informe, il
          // n'impose rien — une carte qui l'ignore se comporte comme avant,
          // en moins bruyant.
          try {
            window.dispatchEvent(new CustomEvent("sbx:lecture-refusee",
              { detail: { module: k, statut: r.status } }));
          } catch (x) { /* navigateur sans CustomEvent : tant pis */ }
        }
      } else if (r.ok && ferme[k]) {
        delete ferme[k];            // la session s'est ouverte : on repart
      }
      return r;
    });
  };

  window.SBXSonde = {
    /** Pour les tests et la mise au point : l'état des gardes en cours. */
    etat: function () {
      var o = {};
      Object.keys(ferme).forEach(function (k) {
        o[k] = { restant: Math.max(0, ferme[k].jusqu - Date.now()), attente: ferme[k].attente };
      });
      return o;
    },
    /** Rouvrir tout de suite — à appeler quand une session vient de s'ouvrir. */
    rouvre: function () { ferme = Object.create(null); }
  };
})();
