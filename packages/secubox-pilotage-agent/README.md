<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->
# secubox-pilotage-agent

Agent de pilotage distant d'une box SecuBox (#3126, livraison L1 « Voir », lecture seule). Binaire Go unique
`/usr/sbin/sbx-pilotage-agent`, bibliothèque standard seule, `CGO_ENABLED=0`.

## Fonctionnement

- **Connexion sortante uniquement** vers le maître (nginx `10.10.0.1:8472` sur `wg-mesh`, ou `10.64.0.1:8472`
  sur `wg-autoload`), interrogation longue. L'agent n'ouvre **aucun port d'écoute**.
- Répond à Get et GetSupportedDM (modèle TR-181 : système, services systemd, paquets, exposition, maillage,
  pilotage), notifie les événements (boucle de relances, mémoire basse, swap, démarrage) et réalise
  l'Operate `Device.X_SECUBOX_Releve.Mesurer()` (10 à 300 s, un seul à la fois).
- Toute autre commande est refusée (L1 : lecture seule). Jamais la ligne de commande d'un processus (`comm`).
- Le maître est choisi ainsi : `PILOTAGE_MAITRE` s'il est posé ; sinon `wg-mesh` en `10.10.0.0/24`, puis
  `wg-autoload` en `10.64.0.0/16` ; sinon l'agent attend et revérifie toutes les 300 s. L'adresse de sortie
  est celle de l'interface du maillage dont la plage contient le maître.
  `PILOTAGE_MAITRE` n'accepte qu'une IP littérale parmi `10.10.0.1`, `10.64.0.1`, `127.0.0.1` (pas de nom
  d'hôte : pas de DNS sous le profil ; pas d'IPv6 : ni `AF_INET6` dans l'unité ni `inet6` dans le profil). Une valeur
  refusée est journalisée une fois, puis l'agent attend l'arrêt sans réessayer : la corriger, puis redémarrer l'unité.
- **Sur le maître lui-même** (gk2 : `wg-mesh` en `10.10.0.1`, `wg-autoload` en `10.64.0.1`), l'agent ne se pilote pas
  par son propre canal en L1 (R35) : il journalise une fois « cette box porte l'adresse du maître », puis attend l'arrêt
  sans jamais contacter le canal (qui refuserait `.1` et écrirait une ligne d'audit à chaque essai).
- **Limite connue** : le maître est choisi au démarrage seulement. Si l'adresse du tunnel change ou disparaît
  durablement, le canal recule jusqu'à 300 s et réessaie sans fin, sans refaire ce choix ni sortir en échec :
  `Restart=on-failure` n'y peut rien, seul un redémarrage de l'unité (`systemctl restart secubox-pilotage-agent`)
  refait le choix du maître.

## Configuration (`/etc/secubox/pilotage-agent.env`, facultatif)

Voir `conf/pilotage-agent.env` (installé en exemple sous `/usr/share/doc/secubox-pilotage-agent/`) :
`PILOTAGE_MAITRE`, `PILOTAGE_RELEVE_INTERVALLE_S` (30, de 5 à 300), `PILOTAGE_MEMOIRE_SEUIL_MO` (200),
`PILOTAGE_SWAP_SEUIL_PCT` (80), `PILOTAGE_BOUCLE_RELANCES` (3), `PILOTAGE_BOUCLE_FENETRE_S` (600).

`/etc/secubox` appartient au compte partagé `secubox` (R12, R36) : le fichier est lu par l'agent lui-même au démarrage,
pas par systemd (pas d'`EnvironmentFile=`), par descripteur et sans suivre aucun lien. Il doit être un fichier régulier
`root:root`, sans droit d'écriture pour le groupe ni les autres (`0644`), à un seul lien physique ; sinon il est ignoré en
entier, avec une ligne de journal. Même règle pour le drapeau « mains liées » `/etc/secubox/pilotage/mains-liees` : non
fiable, il vaut « non » (ligne de journal à chaque refus nouveau). Le paquet ne crée rien sous `/etc/secubox`.
Limite connue, pour L2 : le compte `secubox` peut encore renommer, dans `/etc/secubox`, un autre fichier `root:root` à
la place de ceux-ci ; l'état « mains liées » de L2 devra vivre hors d'un dossier inscriptible par `secubox`.

## Durcissement

Utilisateur `secubox-pilotage-agent`, `NoNewPrivileges`, `ProtectSystem=strict`, `ReadOnlyPaths=/`, aucune capacité,
`IPAddressDeny=any` (sauf `10.10.0.1`, `10.64.0.1`, localhost), `MemoryMax=32M`, profil AppArmor enforce
(`apparmor/usr.sbin.sbx-pilotage-agent`). `AF_NETLINK` est autorisé en plus d'`AF_INET AF_UNIX` : le runtime
Go lit les adresses des interfaces par netlink.

## Développement

```
go vet ./... && go test -race ./...
pytest -q tests
dpkg-buildpackage -b -us -uc     # natif ; arm64 sur une box (pas de -a croisé : dh_strip)
```
