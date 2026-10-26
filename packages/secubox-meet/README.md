<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->
# secubox-meet

Visioconférence **La Suite Meet** (v1.34.0) et **LiveKit** (1.13.10) dans un conteneur LXC non
privilégié (`meet`, 10.100.0.195 sur `br-lxc`, données dans `/data/lxc/meet`). Le conteneur porte
postgresql, redis, livekit, le backend Meet et un nginx interne ; l'hôte ne fait que router.

## Noms publics

| Nom | Rôle | Cible |
|---|---|---|
| `visio.<domaine>` | Meet (pages, API, WebSocket) | `10.100.0.195:80` |
| `livekit.<domaine>` | signalisation LiveKit (WebSocket) | `10.100.0.195:7880` |

Les noms sont obtenus par `secubox-domaine visio` et `secubox-domaine livekit` ; aucun nom de box
n'est livré. Chaîne : HAProxy (TLS 1.3) → `sbxwaf` → nginx hôte (`:9080`) → conteneur. Le postinst
déclare la route WAF (`secubox-waf-route`) et le vhost HAProxy ; il ne contourne jamais le WAF.

## Installation et provisionnement

`apt install secubox-meet` pose le paquet, puis démarre **en arrière-plan** l'unité
`secubox-meet-provision.service` : création du conteneur (debootstrap trixie), compilation du front
dans le conteneur, environnement Python, LiveKit. Comptez **15 à 30 minutes** et un accès réseau.
Suivi : `journalctl -u secubox-meet-provision -f` pendant le provisionnement, puis `meetctl status` et
`meetctl logs <unité>`. L'unité s'arrête dès que `/etc/secubox/meet/.lxc-provisioned` existe ; après un échec
elle réessaie toute seule.

## Ports média

Les médias passent par **7881/TCP** et **7882/UDP**, que l'installation **n'ouvre jamais** : c'est
une décision d'exposition. Elle se prend depuis la page `/meet/` ou par
`meetctl media-expose --apply` (DNAT vers le conteneur, table `inet secubox-meet`, fichier
`/etc/nftables.d/secubox-meet-dnat.nft`). `meetctl media-expose --revoke` retire la règle et la
publication des ports ; `meetctl media-expose` seul donne l'état.

- Box derrière le maillage : le **maître** relaie les ports publiés (`/var/lib/secubox/ports-publics.d/meet.json`).
- Box exposée directement : voir #3160.

Chaque ouverture ou fermeture est inscrite au journal d'audit (`/var/log/secubox/audit.log`).

## Réunions, connexions, statistiques (#3182)

Trois onglets de `/meet/`, réservés à l'administrateur :

| Route (`/api/v1/meet/…`) | Contenu |
|---|---|
| `GET /reunions` | salles de Meet (accès, propriétaire, création, dernière réunion), état en direct ; cache 30 s |
| `GET /connexions?jours=1..30&salle=&issue=` | participants en direct (cache 15 s) et historique, une ligne par session |
| `GET /stats?periode=7\|30\|365` | réunions, temps de visio, participants, pic, médiane, échecs, par jour, transport, motifs, appareils, salles |
| `POST /clore` `{salle, confirmer: "meet"}` | met fin à une réunion en cours (LiveKit `DeleteRoom`), audité |

- **Relevé** : `secubox-meet-activite.timer` (5 min, root) lance `meetctl activite-collecte` : pseudos des comptes de
  Meet, puis journal de LiveKit après le dernier curseur, dans `/var/lib/secubox/meet/activite.db` (root:secubox 0640),
  que l'API lit en lecture seule.
- **Vie privée** : aucune adresse IP conservée ; un compte apparaît sous son pseudo, toute autre personne « invité » ;
  le nom tapé dans Meet n'est ni affiché ni gardé. Sessions effacées après 30 jours, totaux par jour gardés 12 mois.
- **LiveKit** : `meetctl en-direct`, `meetctl reunions` et `meetctl clore <salle>` signent un jeton HS256 avec
  `/etc/secubox/secrets/meet/livekit-secret` ; l'API n'y a jamais accès.

## Connexion (OIDC)

Les usagers se connectent par le fournisseur OIDC du Hall (émetteur `https://hall.<domaine>/oidc`).

- `meetctl oidc-enregistrer` enregistre le client `meet` (adresse de rappel
  `https://visio.<domaine>/api/v1.0/callback/`) ; le secret est écrit en `0600` dans
  `/etc/secubox/secrets/meet/` et jamais affiché.
- `meetctl oidc-verifier` contrôle l'enregistrement sans révéler le secret.
- Détail du fournisseur : `docs/OIDC-FOURNISSEUR.md`.

## Mise à jour

La version de Meet et de LiveKit est figée dans `conf/meet.version` (exemple installé dans
`/usr/share/doc/secubox-meet/examples/`). Une mise à jour du paquet rejoue le provisionnement **en
arrière-plan** (`secubox-meet-rerendu.service`, suivi : `journalctl -u secubox-meet-rerendu`) : nouveau rendu
des configurations et des secrets, reconstruction si la version de Meet a changé, puis relance des seuls services
dont une entrée a changé. `meetctl install` fait de même au premier plan. **Sauvegardez la base avant une mise
à jour qui change de version de Meet** (le conteneur n'a pas `sudo`) :

```
lxc-attach -n meet -P /data/lxc -- runuser -u postgres -- pg_dump meet > meet-$(date +%F).sql
```

Un nouveau secret OIDC (`meetctl oidc-enregistrer`) est porté jusqu'au conteneur s'il tourne (nouveau rendu sans
construction) ; à l'arrêt, la réponse le dit (`"applique": false`) et l'enregistrement suivant, conteneur démarré,
l'applique.

## Désinstallation

- `remove` : arrête et désactive les unités, révoque les ports média (`media-expose --revoke`), coupe le
  démarrage automatique du conteneur (`meetctl autostart off`), l'arrête et retire les liens `sites-enabled`.
  Une réinstallation le réarme (`meetctl autostart on`) et le redémarre.
- `purge` : supprime en plus `/etc/secubox/meet`, `/etc/secubox/secrets/meet`, la publication
  `meet.json` et le client OIDC `meet`.
- **Jamais** supprimés : le conteneur et `/data/lxc/meet` (les données des salles). Le retrait
  complet est une opération manuelle volontaire.

## Fichiers

| Chemin | Rôle |
|---|---|
| `sbin/meetctl` | seule surface privilégiée (sudo `secubox` → `meetctl`) |
| `lib/meet/` | provisionnement du conteneur |
| `api/activite.py` | activité de la visio : relevé du journal, en direct, réunions, statistiques |
| `nginx/` | vhosts `visio.*`, `livekit.*` et routes `/api/v1/meet/`, `/meet/` |
| `conf/` | `meet.toml.example`, `meet.nft`, `meet.version` |
