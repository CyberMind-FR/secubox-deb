<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# secubox-live — page publique de l'état du réseau (#3351)

Page publique en direct (`live.<domaine>`, sur le maître `live.secubox.in`) : nœuds du maillage, WAF, types de
menaces, cartes du monde, historique depuis la mise en production, développement (GitHub), feuille de route.

## Ce qui est publié — et ce qui ne l'est jamais

| Publié | Jamais publié |
|---|---|
| nom réel des seuls nœuds de `noeuds_publics` (liste blanche, vide = aucun), matériel (inventaire du pilotage), état, CPU %, mémoire %, durée de marche par classe (< 24 h, jours, semaines arrondies) | adresse IP, adresse privée ou de maillage |
| comptes agrégés : menaces par catégorie, par minute, par jour ; bans actifs | adresse des attaquants ou des visiteurs, user-agent |
| pays (code ISO) des attaques et des visites, agrégés | nom d'appareil, de compte, de personne ; aucune donnée DPI (décision du propriétaire) |
| PR, issues, CI de GitHub (API publique) | secret, jeton |

`collecte.filtrer` ne garde que les champs de `CHAMPS` (liste blanche) ; `collecte.nettoyer` est la dernière garde : toute chaîne qui contient une adresse IPv4/IPv6 valide est retirée avant
l'écriture (test `test_jamais_d_adresse_ni_de_secret_dans_l_etat`). Une source absente donne `null` : la page affiche
« indisponible », jamais une valeur inventée.

## Sources (lecture seule, sur le maître)

| Section | Source | Sans elle |
|---|---|---|
| nœuds | `/var/lib/secubox/pilotage/pilotage.db` (`mode=ro`, groupe `secubox-pilotage`) + le maître via `/proc` | `null` |
| menaces, WAF dernière heure, attaques par jour | `/var/log/secubox/waf/waf-threats.log`, `.1` (incréments : position + inode) et, au rattrapage, les rotations `.N.gz` (lecture en flux) | `null` |
| bans par jour, bans actifs | `/var/lib/secubox/waf/bans.jsonl` (journal ban/unban de sbxwaf, append-only, celui qu'il relit au démarrage ; incréments) | `null` |
| pays des attaques | GeoLite2-Country (`python3-geoip2`) | `null` |
| visites par jour et par pays, requêtes du jour | `/var/cache/secubox/metrics/vhost_stats.json` (secubox-metrics, 30 jours glissants), totaux par jour persistés dans `/var/cache/secubox/live/visites-etat.json` (0600, 400 jours) | `null` |
| sites publiés | `/etc/secubox/haproxy.toml` (vhosts actifs) | `null` |
| développement | API publique GitHub, sans jeton, cache 10 min (`/var/cache/secubox/live/github.json`) | dernier relevé, sinon `null` |
| disponibilité 30 j | aucune source à ce jour | toujours `null` |
| mise en production | `mise_en_production` de `/etc/secubox/live.toml`, sinon naissance de `/etc/secubox` (`stat %W`) | `null` |

## Fonctionnement

- `secubox-live-collecte.timer` (toutes les minutes) → `secubox-live-collecte` (compte `secubox-live`, groupe
  `secubox-pilotage` seulement, AppArmor enforce ; `pilotage.db-shm` en lecture seule suffit en `mode=ro`) → `/var/cache/secubox/live/etat.json` (0644, écriture atomique). Une source en erreur donne
  `null` sans arrêter les autres.
- nginx, rendu par l'exposeur depuis `/usr/share/secubox/live/live.vhost.conf.in` : `listen 9080` (comme boutique et hall : sbxwaf joint l adresse hôte ; 9080 fermé par nftables côté WAN/LAN),
  `server_name` exact, HSTS, CSP stricte ; la page et `/etat.json` servis en **statique** (cache 15 s), aucune
  API, GET/HEAD seulement, tout le reste en 404.

## Historique

Totaux par jour persistés dans `/var/cache/secubox/live/menaces-etat.json` (0600, 400 jours au plus) : une rotation ne
les efface jamais. **Rattrapage** : au premier passage, ou si un journal présent commence avant le premier jour mesuré,
toutes les rotations sont relues ; chaque jour garde le maximum de l'ancien total et du recompte (pas de double
compte). Un jour antérieur à la première mesure d'une source vaut `null` (« non mesuré », grisé sur la page), jamais
0 ; le cumul démarre au premier jour mesuré. Le premier jour mesuré peut être partiel (la rotation quotidienne ne tombe
pas à minuit). Le journal d'audit de sbxwaf (`/var/log/secubox/waf/audit.log`) ne porte que les réévaluations, pas
les bans : la source des bans est `bans.jsonl`. L'état n'en garde qu'une empreinte tronquée par adresse, le temps
du ban.

## Page

Après les tuiles, la section « Comprendre ces chiffres » (`<details>`, ouverte au premier affichage, choix du visiteur
retenu dans son navigateur) explique requêtes, menaces, bloquées, bans (1 h, 4 h, 24 h, 7 jours, levés à l'échéance),
bans actifs, l'écart entre ces chiffres, les pics, la vie privée et les jours gris. Chaque tuile et chaque légende de
l'historique porte une infobulle (`title`). Texte statique dans `index.html`, aucun `innerHTML`.

## ACL de lecture

`secubox-live-acl` (root, liste de chemins figée, aucun argument) pose `u:secubox-live:r` sur les sources et
l'ACL par défaut de leurs dossiers ; il tourne au configure et avant **chaque** collecte (`ExecStartPre=+`).
Mode d'écriture des producteurs, vérifié dans leur source :

| Fichier | Producteur | Écriture | Lecture par secubox-live |
|---|---|---|---|
| `vhost_stats.json` | secubox-metrics | `.tmp` puis `os.replace`, mode selon l'umask (0644) | ACL par défaut du dossier, héritée |
| `bans.jsonl` | sbxwaf | append-only 0640, jamais tourné | ACL de fichier + ACL par défaut du dossier |
| `waf-threats.log*` | sbxwaf | append, rotation quotidienne, `.N.gz` (7) | ACL par défaut + reposée à chaque collecte |
| `haproxy.toml` | haproxyctl | réécrit en place | ACL de fichier reposée à chaque collecte |

## Exposition

Rien n'est exposé par défaut (`domaine = ""`). Sur le maître :

```
# /etc/secubox/live.toml
domaine = "live.secubox.in"
mise_en_production = "AAAA-MM-JJ"   # facultatif
noeuds_publics = ["gk2", "gk4"]  # liste blanche
sudo secubox-live-exposer           # AppArmor obligatoire, nginx -t, route sbxwaf (échec = tout retiré), vhost HAProxy
```

`[roles]` et `[materiels]` (nom = valeur) complètent l'inventaire ; `[[feuille_de_route]]` (nom, etat) s'affiche tel quel.

La purge (`apt purge secubox-live`) retire la route sbxwaf (seulement si elle pointe encore vers le port 9080) et le
vhost HAProxy du domaine retenu par l'exposeur dans `/var/lib/secubox-live/domaine`.
