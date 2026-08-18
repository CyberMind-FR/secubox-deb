<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Module SecuBox « SENTINELLE-GSM » — capteur off-path détection faux BTS

**Réf.** CyberMind / SecuBox-Deb · capteur off-path de détection de faux BTS (IMSI-catcher)
**Codename** `SENTINELLE-GSM` (renommable)
**Paquet Debian proposé** `secubox-sentinelle-gsm`
**Layer SecuBox canonique** MIND (analyse/détection, `#3D35A0`) → alimente WALL/OPAD (réaction)
**Amont** Oros42/IMSI-catcher (CC0-1.0) + `gr-gsm` + SDR RTL-SDR
**Licence cible** CMSD-1.0 (`LicenseRef-CMSD-1.0`, juridiction Chambéry)
**Cible version** SecuBox-Deb v2.4.0
**Statut** : spec reçue verbatim de l'opérateur 2026-05-20 — à différencier de `secubox-rbs-sensor` (#236, EP06 modem-based, layer WALL).

---

## Distinction avec `secubox-rbs-sensor` (#236)

| Aspect | `secubox-rbs-sensor` (#236) | `secubox-sentinelle-gsm` (cette spec) |
|---|---|---|
| Layer | WALL (réaction) | **MIND** (analyse) → feeds WALL/OPAD |
| Backend | Quectel EP06-E mPCIe modem | **SDR RTL-SDR** + gr-gsm |
| Source de signal | AT+QENG servingcell/neighbour (le modem rapporte ce qu'il entend) | démod GSM broadcast via gr-gsm → GSMTAP/UDP |
| Capacité | identifie sa propre cellule + voisines mesurées | inventaire complet des cellules + scoring d'anomalies |
| Acte | RAT lock, RF detach (off-path mitigation) | aucun (sensor seul — la réaction est déléguée à WALL/OPAD) |
| Modem TX | inerte mais existe (modem est aussi TX) | **RX only** par construction (SDR) |

Les deux modules **se complètent** : EP06 fournit le verrou actuator + une vue per-session, SENTINELLE-GSM fournit l'inventaire passif et le scoring multi-cellules. Tous deux émettent dans la chaîne d'observations WALL.

---

## 1. Mission (intention du commandement)

Doter SecuBox d'un **capteur radio passif** capable de **détecter la présence d'un IMSI-catcher / faux BTS (Stingray)** dans le voisinage RF, et de remonter une alerte qualifiée dans la chaîne MIND → WALL/OPAD.

Le module **ne capture pas les abonnés** : il surveille les **anomalies de cellules** (downgrade de chiffrement, BTS fantôme, tempête de re-localisation, abus de *Identity Request*, etc.). Tout identifiant éventuellement observé est **anonymisé par défaut**. C'est un **récepteur uniquement** (RX) : il n'émet jamais, il n'impersonne aucune cellule, il ne déchiffre pas le trafic de tiers.

Cette posture est l'incarnation directe de la doctrine OPAD : un capteur passif est par construction *off-path*.

---

## 2. Périmètre — *HARD LIMITS* (non négociables)

**DANS le périmètre :**

- Réception passive du *broadcast* GSM (BCCH/CCCH, GSMTAP) via SDR.
- Calcul d'un **score d'anomalie** par cellule observée et émission d'alertes.
- Établissement d'une **baseline opérateur** locale (cellules légitimes attendues).
- Anonymisation/pseudonymisation des identifiants (cf. §6).

**HORS périmètre (à refuser même si pratique) :**

- ❌ Toute **émission RF** / faux BTS / cellule leurre / *paging* actif → ce serait un IMSI-catcher offensif (illégal, hors doctrine).
- ❌ **Déchiffrement** du trafic de tiers (A5/1, A5/3…) ou interception de correspondances.
- ❌ **Pistage d'individu** : pas de fonctionnalité « suivre l'IMSI X de la personne Y ». L'option amont `-m/--imsi` n'est exposée **que** pour un appareil **possédé et consenti** (test/labo), jamais comme primitive de tracking.
- ❌ Stockage d'IMSI/IMEI/TMSI **en clair** hors mode labo explicite (cf. §6).

Toute PR qui franchit ces lignes est rejetée d'office.

---

## 3. Cadre légal & éthique (à intégrer au code et à la doc)

> CyberMind n'est pas conseil juridique — les points ci-dessous sont des **garde-fous d'ingénierie** à faire valider par un conseil avant tout déploiement réel hors labo.

- **Atteinte au secret des correspondances** (Code pénal, art. 226-15) et **détention d'équipements d'interception** (art. 226-3) : le module reste en réception/détection d'anomalies et **anonymise** ; il ne reconstitue ni ne stocke de correspondance.
- **Équipements radio** : conformité ARCEP/CPCE pour le matériel RX utilisé. Aucune émission.
- **RGPD/CNIL** : un IMSI/TMSI est une **donnée personnelle**. Privacy-by-design obligatoire (anonymisation par défaut, minimisation, rétention courte, finalité = sécurité défensive).
- **Garde-fous techniques imposés (cf. §6) :** mode `LAB`/`PROD` explicite, anonymisation HMAC par défaut, rétention paramétrable courte, bannière de consentement au premier lancement, journal d'audit des changements de mode.

Le module doit afficher un **avertissement légal** (FR/DE/ZH) au premier démarrage et dans l'UI, rappelant l'usage défensif/recherche et la responsabilité de l'opérateur.

---

## 4. Positionnement dans la stack canonique

```text
AUTH → WALL → BOOT → MIND → ROOT → MESH
                      ▲
              SENTINELLE-GSM (capteur off-path)
                      │  alertes qualifiées
                      ▼
              WALL / OPAD (corrélation, réaction)
```

- **MIND** héberge le capteur, l'analyse, le scoring, la baseline et l'API.
- **WALL/OPAD** consomme les alertes (corrélation avec les 8 invariants OPAD, entrée dans la matrice de menaces CSPN — cf. §10).
- Bande de gradient UI : conserver ROOT→MESH→MIND ; surfaçage des alertes en couleur **MIND `#3D35A0`**, criticité haute en **WALL `#9A6010`**.

---

## 5. Architecture technique

### 5.1 Chaîne de traitement (tout en RX)

```text
[SDR RTL-SDR] → grgsm_livemon(_headless) → GSMTAP/UDP 127.0.0.1:4729 (lo)
                                                  │
                              secubox-gsm-sentinelle (analyseur Python)
                              ├─ parse GSMTAP (scapy)         [§6 anonymisation]
                              ├─ baseline + heuristiques      [§6 scoring]
                              ├─ persistance SQLite           [chiffrée au repos]
                              └─ FastAPI + WebSocket          [§7]
              grgsm_scanner → balayage périodique des ARFCN (inventaire cellules)
```

**Choix d'architecture imposé :** l'analyseur **écoute en UDP sur `lo:4729`** (mode « port », sans `root`), alimenté par `grgsm_livemon_headless`. **Ne pas** utiliser le mode `-s/--sniff` de l'outil amont (il exige root/suid). Cela permet de faire tourner l'analyseur en **utilisateur non privilégié**.

### 5.2 Briques amont réutilisées

- `grgsm_livemon_headless -f <freq>` : démodulation → GSMTAP.
- `grgsm_scanner` : inventaire ARFCN/CID/LAC/MCC/MNC/Pwr (alimente la baseline).
- Logique d'extraction GSMTAP inspirée de `simple_IMSI-catcher.py` (CC0), **réécrite** côté SecuBox pour intégrer anonymisation + scoring (ne pas appeler le script tel quel).

### 5.3 Découplage des unités systemd

- `secubox-gsm-livemon@<freq>.service` (templated) — démodulateur.
- `secubox-gsm-sentinelle.service` — analyseur + API.
- `secubox-gsm-scanner.timer` — balayage périodique (alimente la baseline).

---

## 6. Spécification fonctionnelle — détection & confidentialité

### 6.1 Heuristiques de détection de faux BTS (score 0–100 par cellule)

Pondérer et documenter chaque signal :

1. **Downgrade de chiffrement** : cellule annonçant **A5/0** (pas de chiffrement) ou forçant A5/1 là où l'opérateur fait du A5/3.
2. **BTS fantôme** : `CID/LAC` absent de la baseline, apparaissant avec **puissance anormalement élevée**.
3. **Incohérence d'identité** : `MCC/MNC` ne correspondant pas à l'opérateur attendu sur l'ARFCN observé.
4. **Tempête de re-localisation** : changements de `LAC` fréquents forçant des *Location Updating*.
5. **Abus d'`Identity Request (IMSI)`** : sollicitations répétées de l'IMSI (signature classique d'IMSI-catcher).
6. **Voisinage anormal** : liste de cellules voisines vide/incohérente, paramètres de re-sélection (C1/C2) aberrants.
7. **`T3212` anormal** (timer de mise à jour périodique) hors plage opérateur.
8. **ARFCN orphelin** : porteuse hors plan de fréquences connu de l'opérateur local.

Sortie : par cellule → `{arfcn, cid, lac, mcc, mnc, pwr, ciphers, score, raisons[]}`. Au-delà d'un seuil configurable → **alerte** vers WALL/OPAD.

### 6.2 Confidentialité (privacy-by-design — obligatoire)

- **Mode `PROD` (défaut)** : aucun IMSI/IMEI/TMSI en clair. Stocker uniquement `HMAC-SHA256(identifiant, clé_locale)` tronqué (clé générée à l'install, jamais exportée). Objectif : compter/dédupliquer sans ré-identifier.
- **Mode `LAB`** : autorise l'observation en clair, **uniquement** après bannière de consentement + entrée au journal d'audit ; destiné aux tests avec SIM/appareils possédés.
- **Rétention** : fenêtre glissante paramétrable (défaut court, ex. 24 h) ; purge automatique.
- **Minimisation** : par défaut on conserve les **métadonnées de cellules** et les **scores**, pas les identifiants d'abonnés.
- **SQLite chiffrée au repos** (réutiliser le mécanisme de chiffrement disque/secret-store SecuBox existant ; ne pas réinventer).

---

## 7. Intégration SecuBox — API & UI

### 7.1 Endpoints FastAPI

- `GET  /api/v1/sensor/gsm/status` — état SDR, démodulateur, fréquence courante, mode PROD/LAB.
- `GET  /api/v1/sensor/gsm/cells` — cellules observées + scores + raisons.
- `GET  /api/v1/sensor/gsm/alerts` — alertes actives/historisées.
- `POST /api/v1/sensor/gsm/scan` — déclenche un `grgsm_scanner` (sweep).
- `GET  /api/v1/sensor/gsm/baseline` · `PUT …/baseline` — gérer la baseline opérateur.
- `GET  /api/v1/sensor/gsm/config` · `PUT …/config` — fréquence, seuils, rétention, mode.
- `POST /api/v1/sensor/gsm/mode` — bascule PROD↔LAB (exige confirmation + audit).
- `WS   /ws/sensor/gsm/live` — flux temps réel cellules/alertes.

Auth : réutiliser AUTH (RBAC SecuBox). La bascule en mode LAB exige un rôle élevé.

### 7.2 UI / Charte

- Surfaçage dans le tableau de bord MIND ; respecter **Space Grotesk + JetBrains Mono**, couleur MIND `#3D35A0`, criticité haute WALL `#9A6010`, bande gradient gauche 6px.
- Optionnel : intégration au **SecuBox Eye Remote** (RPi Zero 2W + HyperPixel 2.1 Round 480×480) comme afficheur de criticité GSM (jauge + œil Monogramme G).

### 7.3 Wiki

- Fiche module **FR/DE/ZH** (52-page wiki) : principe, installation, cadre légal, heuristiques, API.

---

## 8. Matériel cible

| Cible | SDR | Statut |
|---|---|---|
| MOCHAbin (Armada 7040) | RTL-SDR Blog v4 (USB) | recommandé (déjà *shipped*) |
| ESPRESSObin v7/Ultra | RTL-SDR (USB) | supporté |
| SecuBox Eye Remote (RPi Zero 2W) | RTL-SDR (USB-OTG) | capteur portable (option) |
| VM x86_64 | — | **passthrough USB requis**, sinon non applicable |

SDR de référence : **RTL-SDR Blog v4** + antenne adaptée bande GSM900/1800. Documenter le `udev`/firmware. **Aucune émission** : pas besoin de matériel TX.

---

## 9. Packaging & durcissement

### 9.1 Debian (`debian/`)

- `control` — `Depends:` `gr-gsm, rtl-sdr, librtlsdr0, python3-numpy, python3-scipy, python3-scapy, python3-fastapi, python3-uvicorn` (+ deps SecuBox communes).
- `copyright` — **CMSD-1.0** ; mentionner l'amont Oros42/IMSI-catcher en **CC0-1.0** (compatible redistribution).
- `postinst` — installe règle `udev` RTL-SDR (accès non-root), génère la clé HMAC locale, active les units.
- `secubox-sentinelle-gsm.install` / `*.service` / `*.timer`.

### 9.2 Durcissement systemd (analyseur)

- `User=secubox-gsm` (non privilégié), `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `RestrictAddressFamilies=AF_INET AF_UNIX`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, `CapabilityBoundingSet=` (vide pour l'analyseur en mode port).
- Démodulateur : accès USB via groupe `plugdev`/règle udev, **pas de suid**.

---

## 10. CSPN / OPAD

- Ajouter à la **matrice de menaces 36** une entrée *« Interception GSM de proximité / faux BTS »* avec `SENTINELLE-GSM` comme **contrôle de détection**.
- Vérifier l'alignement avec les **8 invariants OPAD** : le capteur est strictement *off-path* (RX only) — documenter explicitement l'invariant « pas d'émission ».
- Fournir la **cible de sécurité** partielle (fonction de sécurité, hypothèses, biens sensibles = baseline + clé HMAC + journaux).

---

## 11. Tests & validation

- **Unitaires** : parsing GSMTAP, anonymisation HMAC (déterminisme + non-réversibilité), moteur de scoring (jeux de trames synthétiques).
- **Intégration** : rejeu de captures GSMTAP enregistrées (pcap) → vérifier alertes attendues sans matériel.
- **Labo (mode LAB, consenti)** : SIM/appareil possédés ; valider downgrade A5/0 et signature *Identity Request* sur banc maîtrisé.
- **Non-régression confidentialité** : test qui **échoue** si un IMSI en clair atteint la base en mode PROD.
- **CI** : lint, tests, build paquet ; pas de matériel requis (rejeu pcap).

---

## 12. Livrables attendus de l'agent

1. Arborescence `secubox-sentinelle-gsm/` (paquet Debian complet, `debian/` inclus, en-têtes CMSD-1.0).
2. `src/` analyseur Python (parse GSMTAP, anonymisation, scoring, baseline, persistance).
3. `api/` routeur FastAPI + WebSocket (§7.1).
4. Units systemd + timer + règle udev (§9).
5. `tests/` (§11) + jeux de pcap synthétiques.
6. Doc wiki FR/DE/ZH + avertissement légal multilingue (§3).
7. Entrée matrice menaces CSPN + note d'alignement OPAD (§10).
8. `CLAUDE.md`/`AGENTS.md` du sous-module (cohérent avec l'existant).
9. `CHANGELOG` ciblant `v2.4.0`.

**Critères d'acceptation :** tourne en utilisateur non privilégié ; aucun IMSI en clair en mode PROD ; aucune émission RF ; alertes corrélables côté WALL/OPAD ; build paquet OK en CI sans matériel.

---

## 13. Annexes

### 13.1 Aide-mémoire amont (RX only)

```text
grgsm_scanner                         # inventaire cellules → baseline
grgsm_livemon_headless -f 925.4M      # démodulation → GSMTAP lo:4729
# analyseur SecuBox : écoute UDP 4729 (PAS de mode sniff/suid)
```

### 13.2 Attribution

- **Amont :** Oros42/IMSI-catcher — licence **CC0-1.0** (domaine public, compatible CMSD-1.0).
- **gr-gsm** (velichkov) — décodage GSM.
- Logique de détection de faux BTS : inspirée des approches publiques type SnoopSnitch/CellularPrivacy (heuristiques), réimplémentée.

### 13.3 Rappel doctrine

> SENTINELLE-GSM **écoute le silence des cellules**, pas les gens. Off-path par nature, défensif par conception, anonyme par défaut.
