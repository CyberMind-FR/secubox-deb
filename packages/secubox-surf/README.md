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

## Charge et privilèges (#3355)

Mesuré sur gk2 : ~60 % d'un cœur en continu, la boucle asyncio occupée par la réécriture des pages. Depuis 1.0.37 :
- `est_pisteur` et la décomposition des URL sont mis en cache (bornés) : une page de 840 Ko se réécrit en ~170 ms au
  lieu de ~630 ms ;
- toute réécriture (HTML, CSS, manifestes, portails, copie figée) et la jarre passent par `asyncio.to_thread` : une
  grosse page ne bloque plus les autres requêtes ;
- la jarre n'écrit plus le bocal entier à chaque cookie : au plus une écriture par 5 s, différée sans perte ;
- l'unité cède le processeur et le disque aux services de la box : `Nice=10`, `CPUWeight=20`, `IOWeight=20`,
  `CPUQuota=50%` ;
- le service ne tourne plus en root : compte système `secubox-surf` (groupe `secubox`, celui de la socket). Rien ne
  l'exigeait : `ip -j addr` est non privilégié, Chromium tourne en `--no-sandbox`, tout s'écrit dans
  `/var/lib/secubox/surf` (le postinst reprend l'état laissé par l'ancien service root).
