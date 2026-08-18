<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-picobrew — suite de brassage, fermentation et distillation (LXC) — Design

**Date :** 2026-07-23
**Statut :** validé (design), prêt pour le plan d'implémentation
**Portage de :** `luci-app-picobrew` + `secubox-app-picobrew` (SecuBox-OpenWrt)

---

## Objectif

Redonner vie à un appareil PicoBrew dont le cloud constructeur est éteint depuis 2020, et lui
adjoindre les outils nécessaires pour gérer **fermentation** et **distillation** de bout en bout —
le tout dans un seul LXC, piloté depuis un panel SecuBox unique.

## Contexte (vérifié, 2026-07-23)

### Une divergence à corriger

| | Ce que ça fait |
|---|---|
| OpenWrt `secubox-app-picobrew` | `picobrewctl` crée un LXC (rootfs Alpine) et y clone un serveur PicoBrew |
| Debian `secubox-picobrew` v1.0.0 | **Squelette hôte** : `api/main.py` (992 lignes) = contrôleur de fermentation à capteurs 1-Wire/I2C/USB. **Aucun LXC, aucun serveur PicoBrew** |

Les deux ne partagent que le nom. Ce design réaligne le paquet Debian sur son intention d'origine
**sans jeter** le contrôleur de fermentation : il déménage dans le LXC et gagne un volet distillation.

### Faits d'environnement

- LXC existants sur gk2 ; motif des appliances en `10.100.0.1x0` (lyrion .100, mqtt .110,
  peertube .120, photoprism .130, frigate .140 — vérifié : `/data/lxc/frigate/config`)
  → **`10.100.0.150` libre et cohérente** pour picobrew.
- Upstream retenu : **`chiefwigms/picobrew_pico`** (Flask, actif 05/2026, 155 ★) — couvre
  **Pico S/C/Pro, Z Series, Zymatic**. Le fork `CyberMind-FR/picobrew-server` est écarté : Zymatic
  uniquement, dernier commit 01/2026.
- L'upstream **exige une réécriture DNS** de `picobrew.com` (`address=/picobrew.com/<IP serveur>`) :
  l'appareil ne sait parler qu'à ce domaine.
- La **série Z impose HTTPS** → terminaison TLS devant Flask (qui écoute en clair sur `:80`).

## Décisions actées

1. **Tout dans un LXC Debian** (pas Alpine comme l'OpenWrt, pas Docker comme l'upstream) : service
   natif avec sa propre unit systemd, conformément à la doctrine du dépôt.
2. **Depuis GitHub latest, puis figé.** On clone la dernière version *à l'installation*, puis on
   **enregistre le SHA**. Aucune mise à jour implicite : uniquement sur `picobrewctl update`
   explicite. Un changement upstream ne doit jamais survenir **en plein brassage**, sur une machine
   qui chauffe du moût.
3. **Drop-in DNS actif par défaut.** Le cloud PicoBrew est mort : réécrire `picobrew.com` localement
   ne casse rien, il n'y a plus rien à casser. Réserve notée : si le domaine était un jour
   re-déposé par un tiers, l'override le masquerait — mais l'appareil est inutilisable sans lui.
4. **Le contrôleur de fermentation n'est pas jeté** : il devient `sbx-stillwatch` dans le LXC.
5. **Héberger l'éprouvé, écrire le manquant** : picobrew_pico + CraftBeerPi 4 pour les fonctions
   connues ; nous n'écrivons que la couche capteurs/coupes.
6. **Point d'entrée unique** : le panel SecuBox agrège l'état des services et renvoie vers les UI
   tierces par vhosts. On les encadre, on ne les réécrit pas.

## Architecture

```text
Appareil PicoBrew ──"picobrew.com"──► Unbound ──► LXC picobrew (10.100.0.150)
                                   (drop-in actif)   │
                                                     ├─ picobrew_pico  : l'appareil (Flask + TLS série Z)
                                                     ├─ CraftBeerPi 4  : fermentation (recettes, relais)
                                                     └─ sbx-stillwatch : NOUS (capteurs + coupes)

Admin ──► admin.gk2/picobrew/ ──► panel ──sudo──► picobrewctl ──lxc-attach──► LXC
```

Le webui n'effectue **jamais** d'action privilégiée en direct : il délègue à `picobrewctl` via un
sudoers à commande exacte (règle du dépôt : panel non privilégié → ctl root unique et audité).

## Composants

| Chemin | Rôle |
|---|---|
| `sbin/picobrewctl` | ctl root audité : `create` / `start` / `stop` / `status` / `update` / `logs` |
| `lib/picobrew/install-lxc.sh` | Provisionne le LXC Debian, venv Python, units systemd internes |
| `api/main.py` | **Réécrit** : API de gestion fine, délègue au ctl ; expose l'état agrégé |
| `www/picobrew/index.html` | Panel : état des 3 services, actions, capteurs, coupes |
| `nginx/picobrew.conf` | Reverse-proxy du panel + vhosts vers les UI tierces |
| `conf/unbound-picobrew.conf` | Drop-in DNS `picobrew.com` → `10.100.0.150` (actif par défaut) |
| `sudoers.d/secubox-picobrew` | Grant exact panel → `picobrewctl` |

### `sbx-stillwatch` — la seule brique que nous écrivons

Reprend les 992 lignes existantes et les étend. Découpage en unités testables isolément :

| Fichier | Rôle | Dépendances |
|---|---|---|
| `sensors.py` | Détection + lecture 1-Wire DS18B20 / I2C / USB | matériel |
| `sessions.py` | Sessions, courbes, journalisation | stockage |
| `alerts.py` | Seuils et alarmes | sessions |
| `cuts.py` | **Fonction pure** : découpage têtes/cœur/queues, ABV | aucune |

`cuts.py` est pur (température + volume + temps → verdict de coupe), donc entièrement testable sans
matériel ni alambic — c'est là que vit la logique délicate.

## Distillation : surveiller et guider, ne pas actionner

**Limite posée délibérément.** CraftBeerPi actionne les relais de **fermentation** : une cuve qui
dérive de 2 °C donne une bière moyenne, le risque est acceptable. Sur une **colonne à distiller**,
une actuation autonome qui se trompe est un incident. `stillwatch` matérialise les coupes, calcule
l'ABV, déclenche les alarmes et **trace** tout ; la décision de coupe reste humaine.

Les premières fractions concentrent le méthanol et les congénères indésirables : un outil qui
afficherait une simple température sans matérialiser les coupes donnerait une fausse assurance.
La matérialisation des coupes est donc une **exigence**, pas un confort.

La réglementation de la distillation domestique variant fortement selon les pays, le module n'en
présume rien et n'active aucun comportement spécifique à une juridiction.

## Livraison en trois phases

Chaque phase est utilisable seule.

1. **L'appareil revit** : LXC + picobrew_pico + TLS série Z + drop-in DNS + panel + ctl.
2. **`stillwatch` fermentation** : migration des capteurs, sessions, alertes dans le LXC.
3. **Distillation + CraftBeerPi 4** : `cuts.py`, ABV, alarmes ; puis CraftBeerPi.
   **Porte de réévaluation** en début de phase 3 : si `stillwatch` couvre déjà le besoin de
   fermentation à l'usage, CraftBeerPi n'est pas installé (YAGNI).

## Tests

- **`cuts.py`** (le cœur) : jeux de courbes réelles — montée en température, palier de cœur,
  bascule en queues ; cas dégradés (capteur qui décroche, valeurs aberrantes, redémarrage en cours
  de session).
- **`sensors.py`** : détection sans matériel (mocks), lecture d'un DS18B20 simulé, capteur absent.
- **`picobrewctl`** : idempotence de `create`, `status` sans LXC, `update` qui refuse de tourner
  pendant une session active.
- **DNS** : le drop-in résout bien `picobrew.com` vers le LXC et ne casse aucune autre zone.

## Hors périmètre (YAGNI)

Recettes BeerXML, pilotage du PicoStill, compte cloud PicoBrew, actuation autonome d'un alambic,
intégration Tilt/iSpindel (à réévaluer après la phase 2).

## Risques connus

| Risque | Traitement |
|---|---|
| Upstream qui change en plein brassage | SHA figé ; `update` explicite, refusé si session active |
| Série Z sans TLS valide | Certificat auto-signé généré à l'install, terminaison nginx dans le LXC |
| `picobrew.com` re-déposé par un tiers | Override local assumé ; l'appareil est inutilisable sans |
| 3 UI hétérogènes | Panel SecuBox = point d'entrée unique ; les UI tierces sont encadrées, pas réécrites |
| Fausse assurance en distillation | Coupes matérialisées et tracées ; aucune actuation autonome |
| Capteur qui décroche en session | `cuts.py` traite les valeurs aberrantes ; alarme plutôt que verdict silencieux |
