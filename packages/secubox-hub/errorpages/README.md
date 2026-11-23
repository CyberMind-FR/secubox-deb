<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Pages d'erreur SecuBox — la mire

Toutes les pages d'erreur de SecuBox ont le même dessin : une mire de
télévision (« Désolé ! Nous rencontrons des difficultés techniques »), le dé
SecuBox à la place de l'ampoule, le code et la phrase dans la mire, une
explication en petit dessous (#3885). Page autonome : CSS et SVG en ligne,
aucune ressource externe, aucun JavaScript, thème sombre suivi, animation
coupée si l'utilisateur réduit les mouvements.

## Un modèle, un générateur

Les pages sont **générées** par `scripts/pages-erreur.py` (modèle + table des
codes). Ne jamais les modifier à la main :

```bash
python3 scripts/pages-erreur.py            # réécrit les pages
python3 scripts/pages-erreur.py --verifier # échoue si une page diffère (test)
```

Garde : `scripts/tests/test_pages_erreur_3885.py`.

| Couche | Fichiers | Codes |
|---|---|---|
| nginx (`secubox-hub`) | `errorpages/<code>.html` → `/etc/secubox/errorpages/` | 404, 421, 500, 502, 503 (se rafraîchit toutes les 15 s), 504 |
| HAProxy (`secubox-haproxy`) | `errors/<code>.http` → `/etc/haproxy/secubox-errors/` (`errorfile` posé par `haproxyctl`) | 400, 403, 408, 500, 502, 503, 504 (502-504 se rafraîchissent toutes les 15 s) |
| sbxwaf (`secubox-waf-ng`) | `secubox-toolbox-ng/cmd/sbxwaf/templates/*.html` (go:embed) | 502, 504 (rafraîchies toutes les 10 s), 503, avertissement 403, bannissement 403 |

## nginx

`nginx/snippets/secubox-errorpages.conf` (500, 502, 503, 504) s'inclut dans
un bloc `server{}`. Après `secubox-waking.conf` s'il est présent : les deux
déclarent `error_page 502 503 504` et nginx retient la première (#2251).

La 404 est **à part** : `nginx/snippets/secubox-errorpages-404.conf`. Le
snippet commun est inclus dans des vhosts où `proxy_intercept_errors on` est
actif (au niveau server par `secubox-waking.conf`, dans les locations de
`secubox-routes.d/` du vhost principal) ; une `error_page 404` y remplacerait
le 404 JSON d'une API par cette page HTML. N'inclure le snippet 404 que dans
un vhost sans aucune interception : seuls les 404 produits par nginx (fichier
statique absent) y sont habillés.

## HAProxy

Un `errorfile` est une réponse HTTP brute (en-têtes, ligne vide, corps). Il
doit tenir dans le tampon (`tune.bufsize`, 16 384 octets par défaut, non
réglé) : le test exige moins de 12 Ko par fichier (~5 Ko aujourd'hui).
