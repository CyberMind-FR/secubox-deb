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
  est celle de l'interface retenue.

## Configuration (`/etc/secubox/pilotage-agent.env`, facultatif)

Voir `conf/pilotage-agent.env` (installé en exemple sous `/usr/share/doc/secubox-pilotage-agent/`) :
`PILOTAGE_MAITRE`, `PILOTAGE_RELEVE_INTERVALLE_S` (30), `PILOTAGE_MEMOIRE_SEUIL_MO` (200),
`PILOTAGE_SWAP_SEUIL_PCT` (80), `PILOTAGE_BOUCLE_RELANCES` (3), `PILOTAGE_BOUCLE_FENETRE_S` (600).

## Durcissement

Utilisateur `secubox-pilotage`, `NoNewPrivileges`, `ProtectSystem=strict`, `ReadOnlyPaths=/`, aucune capacité,
`IPAddressDeny=any` (sauf `10.10.0.1`, `10.64.0.1`, localhost), `MemoryMax=32M`, profil AppArmor enforce
(`apparmor/usr.sbin.sbx-pilotage-agent`). `AF_NETLINK` est autorisé en plus d'`AF_INET AF_UNIX` : le runtime
Go lit les adresses des interfaces par netlink.

## Développement

```
go vet ./... && go test -race ./...
pytest -q tests
dpkg-buildpackage -b -us -uc     # natif ; arm64 sur une box (pas de -a croisé : dh_strip)
```
