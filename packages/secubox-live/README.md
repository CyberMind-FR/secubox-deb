<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# secubox-live — page publique de l'état du réseau (#3351)

Page publique en direct (`live.<domaine>`, sur le maître `live.secubox.in`) : nœuds du maillage, WAF, menaces,
DPI, cartes du monde, historique depuis la mise en production, développement (GitHub), feuille de route.

## Ce qui est publié — et ce qui ne l'est jamais

| Publié | Jamais publié |
|---|---|
| nom réel des nœuds (gk1…), matériel (inventaire du pilotage), état, CPU %, mémoire %, durée de marche | adresse IP, adresse privée ou de maillage |
| comptes agrégés : menaces par catégorie, par minute, par jour ; bans actifs | adresse des attaquants ou des visiteurs, user-agent |
| pays (code ISO) des attaques et des visites, agrégés | nom d'appareil, de compte, de personne (le DPI ne garde que les usages) |
| PR, issues, CI de GitHub (API publique) | secret, jeton |

`collecte.nettoyer` est la dernière garde : toute chaîne qui contient une adresse IPv4/IPv6 valide est retirée avant
l'écriture (test `test_jamais_d_adresse_ni_de_secret_dans_l_etat`). Une source absente donne `null` : la page affiche
« indisponible », jamais une valeur inventée.

## Sources (lecture seule, sur le maître)

| Section | Source | Sans elle |
|---|---|---|
| nœuds | `/var/lib/secubox/pilotage/pilotage.db` (lecture seule immutable, groupe `secubox-pilotage`) + le maître via `/proc` | `null` |
| menaces, WAF dernière heure, attaques par jour, bans par jour | `/var/log/secubox/waf/waf-threats.log*` (lignes JSON de sbxwaf) | `null` |
| pays des attaques | GeoLite2-Country (`python3-geoip2`) | `null` |
| visites par jour et par pays, requêtes du jour | `/var/cache/secubox/metrics/vhost_stats.json` (secubox-metrics) | `null` |
| bans actifs | `/var/cache/secubox/waf/nft-etat.json` | `null` |
| DPI | `/var/cache/secubox/dpi/resume-rapport.json` (usages seulement) | `null` |
| sites publiés | `/etc/secubox/haproxy.toml` (vhosts actifs) | `null` |
| développement | API publique GitHub, sans jeton, cache 10 min (`/var/cache/secubox/live/github.json`) | dernier relevé, sinon `null` |
| disponibilité 30 j | aucune source à ce jour | toujours `null` |
| mise en production | `mise_en_production` de `/etc/secubox/live.toml`, sinon naissance de `/etc/secubox` (`stat %W`) | `null` |

## Fonctionnement

- `secubox-live-collecte.timer` (toutes les minutes) → `secubox-live-collecte` (compte `secubox-live`, groupes `secubox`
  et `secubox-pilotage`, AppArmor enforce) → `/var/cache/secubox/live/etat.json` (0644, écriture atomique).
- `secubox-live.service` : API FastAPI sur `/run/secubox/live.sock`, sans authentification, une seule route
  `GET /etat` (et `/sante`), aucune écriture, réseau Unix seulement.
- nginx `live.*` (port 9080) : la page (CSP stricte, `script-src 'self'`), `/api/v1/live/etat` (GET seulement, cookies et
  `Authorization` retirés, débit limité), tout le reste en 404.

## Exposition

Rien n'est exposé par défaut (`domaine = ""`). Sur le maître :

```
# /etc/secubox/live.toml
domaine = "live.secubox.in"
mise_en_production = "AAAA-MM-JJ"   # facultatif
sudo secubox-live-exposer           # nginx -t, puis route sbxwaf, puis vhost HAProxy (sbxwaf_inspector)
```

`[roles]` et `[materiels]` (nom = valeur) complètent l'inventaire ; `[[feuille_de_route]]` (nom, etat) s'affiche tel quel.
