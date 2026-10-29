<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->
# secubox-pilotage — maître du pilotage distant (#3126, L1 « Voir »)

Reçoit des agents (`secubox-pilotage-agent`) des box du maillage et d'Auto-Load leurs relevés TR-181 et leurs notifications, tient l'inventaire
par box (SQLite) et l'expose à l'administrateur. Lecture seule : Get, GetSupportedDM, Notify et `Device.X_SECUBOX_Releve.Mesurer()`.

## Exécution
| Élément | Valeur |
|---|---|
| Service | `secubox-pilotage.service`, utilisateur `secubox-pilotage`, `/usr/sbin/secubox-pilotage-api` (lance par `secubox-pilotage.socket` et `secubox-pilotage-canal.socket`) |
| Administration | `/run/secubox/pilotage.sock` (0660, groupe `secubox`, créée par systemd) ; nginx `/api/v1/pilotage/` (`secubox-routes.d/pilotage.conf`), toutes les routes `require_jwt` ; module dédié de l'agrégateur (`DEDICATED_MODULES`) |
| Canal | `/run/secubox/pilotage-canal.sock` (0660, groupe `www-data`, créée par systemd), jamais exposée hors de l'écouteur nginx |
| Processus | une seule boucle asyncio, les deux applis en `lifespan="on"` (les files sont en mémoire, la relève est partagée) ; code de sortie 1 si l'une ne démarre pas |
| Données | `/var/lib/secubox/pilotage/` (0750 `secubox-pilotage`), préparé par le postinst par descripteur (`init_donnees.py`) : systemd-tmpfiles refuse ce chemin |
| Audit | `/var/log/secubox/audit.log` (propriétaire et droits inchangés) ; AppArmor en ajout seul ; ACL `u:secubox-pilotage:rw-` posée par `secubox-pilotage-audit-acl` (reposée après chaque rotation par l'unité de l'écouteur) |
| AppArmor | `secubox-pilotage-api`, enforce |
| Menu | aucune entrée propre : le panneau « Pilotage » est dans la page Flotte de secubox-annuaire ; paquet `hors-arbre` des méta-paquets (installé à la demande) |

## Écouteurs de tunnel
`secubox-pilotage-ecoute` (root) rend `/etc/nginx/conf.d/secubox-pilotage-canal.conf` : un `server` par IP de tunnel présente,
`10.10.0.1:8472` (wg-mesh) et `10.64.0.1:8472` (wg-autoload), `client_max_body_size 256k`, `proxy_read_timeout 60s`, 4 connexions par adresse.
L'identité d'une box est `X-Real-IP` = l'adresse du pair TCP (`$realip_remote_addr`) ; le realip hérité de `secubox-hub` / `secubox-realip`
est neutralisé dans le `server` (sinon un `X-Forwarded-For` forgé usurperait n'importe quelle box). Fichier retiré si `nginx -t` échoue
(sans rechargement) ; nginx rechargé seulement si le rendu change. `net.ipv4.ip_nonlocal_bind=1` est livré par le paquet.

Il pose, dans la chaîne `input` de `inet filter` (base unifiée de secubox-hardening) ET de `inet secubox_filter`, juste avant la règle `drop`
(donc après les règles de ban), à chaud (`nft insert ... handle`) et dans `/etc/nftables.conf` :

    iifname "wg-mesh" ip saddr 10.10.0.0/24 tcp dport 8472 accept
    iifname "wg-autoload" ip saddr 10.64.0.0/16 tcp dport 8472 accept

Aucune table connue : le script le dit sur stderr et ne pose rien. `secubox-pilotage-ecoute --retirer` (appelé par le prerm) retire fichier nginx
et règles. Déclencheurs : `secubox-pilotage-ecoute.path` (changement de `wg_mesh.json` ou de `pairs-publics.json`) et `.timer` (5 min).

## Inventaire
Toutes les 60 s, un GET `Device.` par box en ligne. Une passe complète remplace l'inventaire de la box (chemins disparus purgés) ; une passe
tronquée, en erreur, avec une source en échec (`failed`) ou au-delà de 5 000 paramètres ajoute sans rien effacer (`inventaire_partiel`).
Un paramètre refusé seul (chemin hors `Device.` ou de plus de 256 caractères, valeur non JSON) n'entre pas, sans rendre la passe partielle.
Une valeur de plus de 64 Kio de JSON est **tronquée**, jamais jetée (début d'une liste, d'un objet ou d'une chaîne) ; son chemin figure dans
`inventaire_tronques` de `GET /boxes/{x}`. Seules les lignes changées sont écrites (une relève identique n'écrit que `inventaire_le`).
Au plus 10 000 lignes par box : au-delà, les plus anciennes parmi celles absentes de la passe courante partent.

## Tests
`cd packages/secubox-pilotage && python3 -m pytest -q`
