<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# `secubox-iot-hub` — IoT Command Center WebUI (MESH layer)

**Réf.**       CyberMind-GK2 / SecuBox-Deb · IoT Hub WebUI
**Module**     `secubox-iot-hub` (MESH — bridge et UI multi-connecteur)
**Dépend de**  `secubox-zigbee` · `secubox-mqtt` (déjà spécifiés)
**Intégré dans** SecuBox WebUI — sous-module `/ui/iot/` monté dans le shell principal
**Licence**    CMSD-1.0 · LicenseRef-CMSD-1.0 · juridiction Chambéry
**Version**    SecuBox-Deb v2.4.0
**Statut** : spec reçue 2026-05-20 — saved verbatim. Implementation deferred until
the underlying modules (zigbee/mqtt/sentinelle/ep06/rds) are at v2.4.0 alignment.

---

## 1. Intention du commandement

Créer un **IoT Command Center multi-connecteur** qui :

1. S'intègre dans la **SecuBox WebUI** existante comme un sous-module
   monté à `/ui/iot/` et affiché dans la nav principale SecuBox comme
   onglet `IOT HUB`.

2. Unifie en **un seul dashboard à onglets** tous les connecteurs IoT
   actuels et planifiés de SecuBox-Deb, chacun avec son onglet dédié :

   | Onglet            | Module source          | Statut        |
   |-------------------|----------------------|---------------|
   | Vue d'ensemble    | (agrégat)             | à implémenter |
   | Zigbee            | `secubox-zigbee`      | à implémenter |
   | Topologie RF      | `secubox-zigbee`      | à implémenter |
   | MQTT              | `secubox-mqtt`        | à implémenter |
   | SENTINELLE-GSM    | `secubox-sentinelle`  | **PROMPTÉ** — stub si absent |
   | EP06 LTE          | `secubox-ep06`        | **PROMPTÉ** — stub si absent |
   | RDS               | `secubox-rds`         | **PROMPTÉ** — stub si absent |
   | Postures OPAD     | (transversal WALL)    | à implémenter |
   | API FastAPI       | (ROOT)                | à implémenter |
   | Stack · systemd   | (BOOT)                | à implémenter |
   | Journal           | (AUTH→WALL)           | à implémenter |

3. Consomme **uniquement** l'API FastAPI SecuBox (`/api/v1/*`) — pas
   d'appel direct à Mosquitto, z2m, ou autre depuis le browser.

4. Est **offline-first** : zéro CDN, zéro dépendance réseau externe.
   Tout le JS/CSS est servi par le backend FastAPI depuis `/usr/share/secubox/iot-hub/`.

5. Respecte à la lettre la **Charte Light 3 SecuBox** :
   Space Grotesk + JetBrains Mono · palette 6 modules · bande 6px ROOT→MESH→MIND.

---

## 2. Hard limits

- Zéro dépendance CDN : pas de `fonts.googleapis.com`, pas de `cdnjs`,
  pas de `jsdelivr`. Toutes les polices et assets sont bundlés dans le paquet.
- Pas de framework JS externe (React, Vue, Angular). Vanilla JS ES2020+.
- Pas d'accès direct MQTT depuis le browser (pas de websocket Mosquitto).
  Toutes les données transitent par `/api/v1/`.
- Pas d'iframe pour SENTINELLE, EP06, RDS : ce sont des onglets natifs
  du hub qui affichent des données via leur propre `/api/v1/<module>`.
  Si le module est absent, l'onglet affiche un stub « module non installé ».
- User systemd : `secubox` non-root.
- Licence CMSD-1.0 sur tout code CyberMind original.
- `permit_join` ne peut être activé depuis l'UI que si la posture OPAD
  est NORMAL. En DÉGRADÉ ou LOCKDOWN, le bouton est disabled + tooltip.

---

## 3. Périmètre

**In scope :**

- Paquet Debian `secubox-iot-hub` complet
- Frontend HTML/CSS/JS statique servi par FastAPI
- FastAPI router `/api/v1/iot-hub` (agrégat + websocket SSE)
- Onglets : Overview, Zigbee, Topology, MQTT, SENTINELLE stub, EP06 stub,
  RDS stub, OPAD, API Explorer, Stack, Journal
- Intégration dans la nav SecuBox WebUI (injection dans `navigation.json`)
- Service worker optionnel pour mise en cache offline
- Tests pytest du router d'agrégation

**Out of scope :**

- Implémentation des modules SENTINELLE-GSM, EP06, RDS (déjà promptés)
- Backend WebSocket natif Mosquitto
- Application mobile
- Mode multi-tenant / multi-box

(Pour le détail complet : architecture §4-5, FastAPI routes §5, onglets adaptatifs
§6, charte CSS §7, debian/control §8, systemd unit §9, tests §10, livrables §11,
DoD §12, annexes — voir le PROMPT d'opérateur original.)
