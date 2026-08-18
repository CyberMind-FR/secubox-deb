<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Module WALL · Gestion modem Quectel EP06-E (capteur d'intercepteur)

**Date** : 2026-05-20
**Référence** : CM-WALL-EP06-2026-05
**Layer SecuBox** : WALL
**Doctrine** : OPAD (Off-Path Active Defense) · boucle OODA
**Statut** : Spec reçue de l'opérateur — implémentation à scoper avec l'auteur
avant exécution car des prérequis sont manquants dans le repo (cf. §0).

---

## 0. Prérequis manquants (à clarifier avant implémentation)

La spec assume que ce qui suit existe déjà — vérification au 2026-05-20 :
**aucun de ces artefacts n'est dans le repo**.

| Artefact | Statut | Notes |
|---|---|---|
| `wall_rbs_sensor.py` | absent | aucun fichier portant ce nom |
| `class Observer(Protocol)` | absent | aucune classe `Observer` typée Protocol |
| `CellObservation` dataclass | absent | grep retourne zéro résultat |
| `NeighbourObservation` dataclass | absent | idem |
| Verdict engine (`LIKELY_ROGUE`/`SUSPECT`) | absent | pas d'orientation OODA implémentée |
| `secubox-wall` package | absent | seul `secubox-vortex-firewall` existe (nftables, pas RBS) |

Le seul code OPAD existant est `common/secubox_core/opad/models.py` (policy /
protocol / DNS race modes), et les docs doctrinaux à `doctrine/opad/`. Aucun
capteur cellulaire n'a été commité.

**Conséquence** : avant d'implémenter EP06, soit l'auteur fournit la branche
contenant le framework WALL (sensor + Observer + CellObservation + orientation),
soit le scope de cette spec doit être étendu pour le scaffolder aussi.

---

## 1. Mission (verbatim)

Implémenter un module SecuBox, couche **WALL**, qui pilote un modem **Quectel
EP06-E** (mPCIe) et l'utilise comme **capteur de détection d'intercepteur**
(fausse station de base) selon la doctrine **OPAD** et la boucle **OODA**.

Le modem joue deux rôles :

- **Observe** : il rapporte la cellule sur laquelle il campe et ses voisines.
- **Act** : il applique des mitigations strictement **locales et hors-chemin**
  (verrou RAT, détachement RF).

Le module DOIT s'intégrer au capteur existant `wall_rbs_sensor.py` : la classe
`Ep06Observer` implémente le `Protocol` `Observer` et émet des `CellObservation`.

---

## 2. Invariant doctrinal (OPAD) — non négociable

1. **Métadonnées réseau / état propre uniquement.** Le module lit *ce que le
   modem entend* (cellules diffusées) et *son propre état*. Il ne capte JAMAIS
   d'identifiant d'abonné tiers (IMSI/TMSI). Le modem n'est pas un sniffer
   promiscuous : il ne voit que les diffusions de cellules et sa propre session.
2. **Pas de port diag/QCDM pour la capture de paging.** Interdiction d'ouvrir le
   port diagnostic pour décoder des messages de paging/identité. Seules les
   commandes AT de télémétrie cellulaire et de configuration sont autorisées.
3. **Act hors-chemin.** Aucune émission offensive, aucun brouillage. Les seules
   actions sont : reconfigurer *ce modem-ci*, journaliser, alerter.
4. **Preuve structurelle.** Le schéma de données n'a aucun champ d'identifiant
   d'abonné (cf. `CellObservation`). Exposer
   `CAPTURES_SUBSCRIBER_IDENTIFIERS = False` et le tester (cf. §6).

---

## 3. Contexte matériel & système

- **Module** : Quectel EP06-E, LTE Cat-6, format mPCIe, signalisation USB.
- **Énumération Linux** : pilote `option` (ports série `/dev/ttyUSB0..3`),
  `qmi_wwan` (interface réseau `wwanX` pour QMI). Le port AT est généralement
  `ttyUSB2` (à confirmer dynamiquement, ne pas le coder en dur).
- **Identité firmware** attendue de `ATI` : `Quectel EP06 Revision: EP06ELARxxAxxM4G`.
- **Pilotage data** (optionnel) : `qmicli`/libqmi ou ModemManager. Le module de
  détection n'en dépend PAS — il ne lui faut que le port AT.
- **Mode USB** : `AT+QCFG="usbnet",0` (QMI/PPP, défaut), `1` (ECM), `2` (MBIM).
  Ne pas le modifier sans raison : un mauvais réglage peut faire disparaître le
  port AT.

---

## 4. Livrables

### 4.1 Gestion du cycle de vie du modem (`Ep06Modem`)

- Détection/énumération USB de l'EP06-E, **mapping dynamique** du port AT
  (sonder chaque `ttyUSB*` avec `AT` → attendre `OK`).
- Bring-up : `ATE0` (echo off), vérifier `ATI`, `AT+QGMR` (révision firmware),
  `AT+CPIN?` (état SIM), `AT+CFUN?` (état RF).
- Enregistrement réseau : `AT+COPS?`, `AT+CREG?`, `AT+CEREG?`, `AT+QNWINFO`.
- Santé : `AT+CSQ` (signal), `AT+QTEMP` (température), `AT+QNETDEVSTATUS`.

### 4.2 Observe — télémétrie cellulaire (`Ep06Observer(Observer)`)

- Interroger périodiquement `AT+QENG="servingcell"` et `AT+QENG="neighbourcell"`.
- **Parser la cellule servante** (LTE) selon l'ordre vérifié (cf. §5) ; convertir
  **ID de cellule et TAC depuis l'hexadécimal** ; mapper vers `CellObservation`
  (`rat`, `mcc`, `mnc`, `cid`, `area_code`=TAC/LAC, `arfcn`=EARFCN, `rx_power_dbm`
  =RSRP en LTE / RXlev en GSM).
- **Voisines** : ne fournissent que RAT + EARFCN + PCID + mesures (pas d'identité
  complète). Les modéliser en `NeighbourObservation` partielle, utile pour les
  heuristiques *pression de rétrogradation* et *RAT inattendue*, mais NE PAS
  fabriquer de `CellObservation.key` factice à partir d'une voisine.
- Gérer GSM/WCDMA/LTE : le préfixe RAT de la réponse QENG détermine le parseur.

### 4.3 Act — mitigations hors-chemin (`Ep06Actuator(Actuator)`)

Réagir à un verdict `LIKELY_ROGUE`/`SUSPECT` du moteur d'orientation par des
actions **locales à ce modem** uniquement :

- **Refuser la 2G / forcer LTE** : `AT+QCFG="nwscanmode",3,1` (verrou RAT).
- **Détachement RF** (mode avion) : `AT+CFUN=4` ; retour : `AT+CFUN=1`.
- **Verrou de bande** (optionnel) : `AT+QCFG="band",...` — sauvegarder la valeur
  d'origine (`AT+QCFG="band"`) avant toute modification, et la restaurer.
- Toute action est réversible et journalisée. Aucune action n'émet vers le réseau.

### 4.4 Concurrence & robustesse

- Le port AT est **mono-accès** : sérialiser toutes les commandes via un mux
  (lock/queue) `async` ; une seule commande en vol à la fois.
- Timeouts, lecture jusqu'à `OK`/`ERROR`/`+CME ERROR`, reprise sur déconnexion USB.
- Aucune valeur d'énumération codée en dur sans l'avoir vérifiée sur le module
  cible (les jeux de bandes/bandes diffèrent entre EP06-A/E).

### 4.5 API FastAPI (montage dans le routeur WALL)

Exposer un `APIRouter` (préfixe `/wall/ep06`) :

- `GET /status` — état modem + `captures_subscriber_identifiers`.
- `GET /servingcell` — dernière `CellObservation` servante.
- `GET /neighbours` — voisines mesurées.
- `POST /mitigate/lte-only` / `POST /mitigate/rf-off` / `POST /restore` — actions
  hors-chemin, journalisées, réversibles.

---

## 5. Référence AT vérifiée (EP06-E)

**Cellule servante LTE** (champs dans l'ordre) :

```text
+QENG: "servingcell",<state>,"LTE",<FDD|TDD>,<MCC>,<MNC>,<cellID:HEX>,<PCID>,
       <EARFCN>,<band>,<UL_BW>,<DL_BW>,<TAC:HEX>,<RSRP>,<RSRQ>,<RSSI>,<SINR>,<srxlev>
```

Exemple réel :

```text
+QENG: "servingcell","NOCONN","LTE","FDD",250,02,BCCB07,123,2850,7,5,5,261D,-113,-13,-80,10,10
```

→ MCC=250, MNC=02, cellID=0xBCCB07, PCID=123, EARFCN=2850, band=7, TAC=0x261D, RSRP=-113.

**Cellule servante GSM** (ordre) :

```text
+QENG: "servingcell",<state>,"GSM",<MCC>,<MNC>,<LAC:HEX>,<cellID:HEX>,<BSIC>,<ARFCN>,...,<RXlev>,...
```

**Voisines** (mesures seules, pas d'identité complète) :

```text
+QENG: "neighbourcell intra","LTE",<EARFCN>,<PCID>,<RSRQ>,<RSRP>,<RSSI>,<SINR>,...
+QENG: "neighbourcell inter","LTE",<EARFCN>,<PCID>,<RSRQ>,<RSRP>,<RSSI>,...
```

À interroger plusieurs fois sur une fenêtre temporelle (les voisines apparaissent
par intermittence).

**Modes de recherche réseau** (levier de mitigation) :

```text
AT+QCFG="nwscanmode",0,1   ; tous modes (AUTO)
AT+QCFG="nwscanmode",1,1   ; GSM seul
AT+QCFG="nwscanmode",2,1   ; WCDMA seul
AT+QCFG="nwscanmode",3,1   ; LTE seul   <-- refuser la 2G
```

(2ᵉ argument `1` = prise d'effet immédiate.)

**État RF** : `AT+CFUN=1` (plein), `AT+CFUN=0` (minimal), `AT+CFUN=4` (RF coupée
/ avion — vérifier la prise en charge sur la révision firmware cible).

**Divers utiles** : `AT+QNWINFO` (bande/RAT courante), `AT+QCAINFO` (agrégation),
`AT+CSQ`, `AT+QTEMP`, `ATI`/`AT+QGMR` (révision).

---

## 6. Critères d'acceptation

1. `Ep06Observer` implémente `Observer` et n'émet QUE des `CellObservation` /
   `NeighbourObservation` — jamais d'identifiant d'abonné.
2. Test : `CellObservation` ne contient aucun champ d'identité d'abonné
   (assertion sur les champs du dataclass).
3. Test : aucune commande AT du module ne lit SMS, répertoire, paging ou diag
   (liste blanche de commandes auditée par un test).
4. Parsing : hex correctement converti (cellID, TAC/LAC) ; un échantillon réel
   de `servingcell` LTE et GSM est correctement décodé (tests de table).
5. `Ep06Actuator` : `lte-only`, `rf-off`, `restore` modifient l'état du modem et
   sont réversibles ; chaque action est journalisée avec horodatage.
6. Concurrence : deux requêtes AT simultanées ne s'entrelacent pas (test du mux).
7. `GET /status` renvoie `captures_subscriber_identifiers: false`.

---

## 7. Hors périmètre (non-goals)

- **PAS** de capture/journalisation d'IMSI/TMSI de terminaux tiers.
- **PAS** d'ouverture du port diag/QCDM pour décodage L3/paging.
- **PAS** d'émission, de brouillage ni d'action dans le chemin de données.
- **PAS** de dépendance dure à ModemManager pour la fonction de détection
  (le port AT suffit).

---

## 8. Mapping vers la grammar SecuBox & packaging

Si le module suit la grammar canonique (`docs/MODULE-GUIDELINES.md`) :

- **Layer grammar** : nouvelle ligne `WALL | <module>ctl cell observe/list/status …`
- **Package candidate name** : `secubox-wall-ep06` (ou `secubox-rbs-sensor` si
  l'auteur préfère scoper plus largement et accueillir d'autres backends modem).
- **Three-fold ctl** :
  - `components` : `modem` (USB+AT port), `observer` (poll loop), `actuator`,
    `host-api`
  - `status` : overall `green` si modem détecté + observer actif + RF on (sauf
    mitigation en cours)
  - `access` : socket FastAPI host-only ; aucune URL exposée publiquement
- **FastAPI** : `/run/secubox/wall-ep06.sock` ; routes sous `/api/v1/wall-ep06/`
  (en plus du `/wall/ep06/` mentionné dans la spec — à arbitrer).
- **Pas de LXC** : le modem est un device USB host, pas un service à containeriser.
  L'install est donc plus simple que grafana/yacy/rustdesk (pas d'install-lxc.sh).
- **Deps Debian** : `python3-serial` (ou `python3-pyserial`), `python3-fastapi`,
  `python3-uvicorn`, `usbutils`. Pas de QMI/ModemManager en dur.

Toutes ces décisions sont à valider avec l'auteur avant la première ligne de code.
