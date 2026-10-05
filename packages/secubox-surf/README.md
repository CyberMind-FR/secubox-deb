<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-surf

SecuBox Surf — relais de navigation par-origine (le BiB).

Le navigateur de relais du Hall : chaque hôte distant est servi sous une origine propre, `surf-<hote-aplati>.gk2.secubox.in`, ce qui cloisonne cookies et stockage par site visité au lieu de les laisser se rejoindre.

Le relais réécrit les URL absolues du HTML et du CSS vers l'origine de surf, coupe les pisteurs, et sait rejouer une page lourde avec un Chromium sans tête dont il fige le DOM abouti (rendu statique, mis en cache).

MetaNews en dépend : chaque clic sur un lien de source y passe.

Paquet Debian : version `1.0.29-1~bookworm1`, architecture `all`.

## Contenu

- `nginx/` : route nginx
- `surf/` : fichiers du module
- `systemd/` : unités systemd
- `tests/` : tests

## Exécution

- `secubox-surf.service` : SecuBox Surf — relais MITM POC (hors chaîne d'inspection), lance `uvicorn`

## Tests

5 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-surf`.
