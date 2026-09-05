<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Vhosts nginx box-local de gk2 (sauvegarde versionnée)

Ces server-blocks nginx **ne sont possédés par aucun paquet** : ils vivent
seulement sur gk2 (`/etc/nginx/sites-enabled/`). Ils sont ici pour être
**reproductibles** (source de vérité), sans en faire un paquet ni redéployer —
la box tourne déjà ces fichiers à l'identique.

## Ce que c'est

Presque tous servent un **site metablogizer** (`root /srv/metablogizer/sites/<nom>`) :

| Vhost | Domaine | Sert |
|---|---|---|
| `anibal-amiot.conf` | anibal-amiot.com | sites/anibal-amiot (**partenaire — ne jamais modifier le contenu du site**) |
| `ganimed.fr.conf` | ganimed.fr | sites/ganimed |
| `aletheiavox.eu.conf` | aletheiavox.eu | sites/aletheia |
| `lldh.ganimed.fr.conf` | lldh.ganimed.fr | sites/lldh |
| `lldh360.ganimed.fr.conf` | lldh360.ganimed.fr | sites/lldh360 |
| `chess.ganimed.fr.conf` | chess.ganimed.fr | sites/chess |
| `wall.ganimed.fr.conf` | wall.ganimed.fr | sites/wall |
| `ckwa.gk2.conf` | ckwa.gk2.secubox.in | sites/ckwa |
| `meta-dork-aggregator.gk2.conf` | dork.gk2.secubox.in | sites/meta-dork-a |
| `git.gk2.conf` | git.gk2.secubox.in | sites/git |
| `lldh.gk2-redirect.conf` | lldh.gk2… | 301 → lldh.ganimed.fr |
| `companion.conf` | companion.gk2.secubox.in | portail `/data/companion/www` (hors metablogizer) |

Le **contenu** de chaque site est déjà versionné à part (chaque
`/srv/metablogizer/sites/<nom>/` est un dépôt git, tiré/poussé par le webhook
metablogizer). Cette sauvegarde ne couvre QUE le routage nginx.

## Réinstaller un vhost sur une box

```sh
cp deploy/gk2/nginx-sites/<vhost>.conf /etc/nginx/sites-available/
ln -sf ../sites-available/<vhost>.conf /etc/nginx/sites-enabled/<vhost>.conf
nginx -t && systemctl reload nginx
```

## Pourquoi pas un paquet

Ce sont des domaines **spécifiques à gk2** (pas de la fonctionnalité secubox
générique) : les figer dans un paquet imposerait de le maintenir à chaque ajout
de site. À terme, l'option propre serait un générateur dans metablogizer
(`vhost-sync` depuis le domaine déclaré par chaque site) ; en attendant, cette
sauvegarde tient lieu de source de vérité.
