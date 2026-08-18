<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Intégration WiFi mPCIe & Mesh — MochaBin / SecuBox-Deb

| | |
|---|---|
| **Réf.** | CM-MESH-MPCIE-2026-06 |
| **Module** | MESH (paire complémentaire MESH↔AUTH) |
| **Cible matérielle** | Globalscale MochaBin-5G (Marvell Armada 7040, quad Cortex-A72 @ 1.4 GHz) |
| **Statut** | DRAFT — matrice radio **FIGÉE sur stock réel** ; statut BLE acté |
| **Version** | **v0.2.1-draft** |
| **Date** | 2026-06-02 |
| **Doctrine liée** | CM-WALL-OPAD-2026-05 (extension plan RF) |
| **Programme** | Gondwana-Air — pilote Maurienne |
| **Licence** | LicenseRef-CMSD-1.0 (FR faisant foi) |

> **Changelog v0.2.0 → v0.2.1**
>
> - **Modules blindés « S305-8946-1A4C » identifiés = MT7632U** (point ouvert n°6 résolu).
> - Précision méthode : l'énumération USB observée est un **artefact de l'adaptateur mPCIe→USB** (broches USB seules) ; le bus natif est tranché par l'**ID puce** (MT7632U = silicium USB), pas par ce test.
> - MT7632U = **USB-interface** → placement **USB3 *ou* mPCIe au choix** (USB2 dans le slot).
> - Topologie : **multi-radio par nœud** actée (doublon / failover / tri-radio).
> - Repli backhaul mt76 (MT7632U) documenté si 802.11s sous ath10k déçoit.
>
> **Changelog v0.1.0 → v0.2.0**
>
> - Décision carte **figée** d'après inventaire matériel réel (cf. §3).
> - QCA9880 (WLE900VX ×3) retenu en backhaul ; MT7632U (mt76, USB) et AR9271 (ath9k_htc, USB) retenus en accès/mesh.
> - MT7615 / ath9k mPCIe **abandonnés** (non détenus).
> - **Statut BLE acté (§3bis) : trou matériel confirmé** — à sourcer.
> - Point ouvert « 802.11s sous ath10k » promu en **item de validation n°1**.

---

## 1. SITUATION — contrainte matérielle structurante

Le slot mini-PCIe de la MochaBin n'est **pas** un slot WiFi neutre :

- **Mini-PCIe 3.0 (×1, USB2.0 et I2C)** — lane PCIe ×1 réelle, plus USB2.0 et I2C.
- **Slot SIM partagé** entre le mini-PCIe et les deux M.2.
- **Un seul slot mPCIe** → **une seule radio mPCIe**.

### Conséquences

1. Pas de dual-radio mPCIe dédié → la 2ᵉ radio passe par **USB3.0** (2 ports dispo) ou par DBDC sur une seule carte.
2. Lane PCIe ×1 réelle → carte WiFi **PCIe native** possible. Contrôleur PCIe Armada 7040 mainline.
3. **Carte stock NXP (Globalscale/88W9xxx) écartée pour le rôle mesh** : `nxpwifi`/`mwifiex` n'expose pas de mode `mesh point` exploitable, firmware opaque.

---

## 2. MISSION

Intégrer une radio mPCIe pilotée **mainline** sur SecuBox-Deb, opérant un **mesh chiffré auditable** (module MESH), exposé via l'**API FastAPI**, configuré en **TOML**, conforme aux **invariants OPAD**, livré en **`.deb`**, déployable sur le pilote Maurienne.

---

## 3. MATRICE RADIO — FIGÉE (stock réel, inventaire 2026-06-02)

### Radios retenues

| Pièce | Chipset | Driver | Forme | Capacité | Rôle figé |
|---|---|---|---|---|---|
| **Compex WLE900VX ×3** | QCA9880, 3×3 11ac | `ath10k_pci` | mPCIe | AP + mesh, perf | **Backhaul mesh (radio mPCIe principale)** |
| **MediaTek MT7632U** (clé Ciotco, `0e8d:7632`) | MT7612-class, 2×2 11ac bi-bande | `mt76x2u` (in-kernel) | USB | AP + 802.11s **mûr** | **Accès client / mesh (2ᵉ radio)** |
| **Atheros AR9271** (ThinkPenguin) | AR9271, 1×1 11n | `ath9k_htc` | USB | AP + mesh, **firmware-free** | **Voie auditabilité maximale (alt. accès)** |

### Radios secondaires / écartées

| Pièce | Chipset | Statut |
|---|---|---|
| **Compex WLE650V5-18 ×1** | QCA6174 (2×2 11ac **+ BT**) | **Combo de prototypage BT/intégration uniquement** — QCA6174 faible en AP/mesh (orienté STA). Ne pas retenir comme radio de production. |
| **Carte Globalscale (NXP 88W9xxx)** | NXP | **Écartée** (pas de mesh point ; firmware opaque) |
| **5× modules blindés « S305-8946-1A4C »** | **MT7632U** (identifié) | = MT7632U **mPCIe USB-interface** (cf. note ci-dessous). Mêmes capacités que la clé Ciotco. **À confirmer : les 5 strictement identiques** (marquage/FCC). |

> **Note — bus natif des MT7632U (mPCIe et clé).** L'énumération en `0e8d:7632` (USB)
> observée au banc provient de l'**adaptateur mPCIe→USB**, qui ne câble que les broches
> USB du connecteur — ce test seul ne prouve donc PAS le bus d'une carte. Ce qui le
> tranche est l'**ID puce** : MT7632**U** = silicium **USB**, sans PHY PCIe. Conséquence :
> sur adaptateur, sur port **USB3**, ou dans le slot **mPCIe** (broches USB2.0 du slot),
> ces modules restent **USB** → **plafond ~480 Mbps brut (~300 utiles)** dans le slot mPCIe.
> Vérification définitive d'un éventuel module PCIe : `lspci` **dans un vrai slot mPCIe**,
> jamais sur l'adaptateur USB.

### Décision

- **Backhaul** : **WLE900VX / QCA9880 / `ath10k_pci`** sur le slot mPCIe (carte **PCIe**, exploite la lane — un seul par nœud).
- **Accès & mesh client** : **MT7632U / `mt76x2u`** (USB-interface) — favori, 802.11s mt76 mûr ; **OU AR9271 / `ath9k_htc`** si l'auditabilité prime (firmware-free, 11n).
- **Placement MT7632U** : **USB3 *ou* mPCIe au choix** (USB-interface). **Reco : USB3** (alim/énumération plus propres, libère le mPCIe pour le WLE900VX). Adaptateur mPCIe→USB = **banc uniquement**, pas la prod.
- **Repli backhaul** : si 802.11s sous ath10k déçoit (point ouvert n°1), basculer le backhaul sur **MT7632U en mPCIe (USB2)** — mt76 mesh plus mûr, au prix du plafond USB2.
- MT7615 et toute carte ath9k mPCIe : **abandonnés** (non détenus).

### Réserves de validation

- **ath10k 802.11s/HWMP** : maturité historiquement variable — **item de validation n°1** (cf. §9).
- **MT7632U** : variantes signalées instables (driver qui plante, `wlan` absente malgré `mt76x2u`) — **valider l'exemplaire détenu** au banc.

---

## 3bis. STATUT BLE — TROU MATÉRIEL CONFIRMÉ ⚠

Requis par le sous-module `secubox-mesh-bt` (relais BT Mesh + onboarding QR+BLE + double-auth LESC).

| Pièce détenue | Verdict BLE |
|---|---|
| 3Com SL-10208 (2003) | ❌ BT 1.x, **pré-BLE** |
| Belkin F8T012 | ❌ BT 2.0, **pas de LE** |
| MT7632U (Ciotco) — moitié BT | ❌ support mainline = vieux staging `btmtk_usb` (**noyaux 3.11–3.13** seulement, retiré) ; BT 4.x. **Inutilisable sur Debian ARM64 actuelle.** |
| WLE650V5 (QCA6174) — BT | ⚠ BT 4.1 — **LESC à confirmer** ; sert au prototypage d'intégration, pas de garantie production |

**Conclusion : aucun contrôleur BLE 5.x / LESC exploitable en stock.**

**Action requise (bloquant S2/S3 de `secubox-mesh-bt`) :**

- **Option A** — sourcer un contrôleur **BLE 5.x mainline** (`btmtk` MT7921/7922, ou CSR8510, ou nRF/HCI propre) supportant **LE Secure Connections**.
- **Option B** — **ESP32 (en stock)** comme **front-end BLE** (device Improv canonique), le MochaBin restant le plan de contrôle. Voie cohérente avec `secubox-mesh-bt`.

---

## 4. TOPOLOGIE (révisée stock — multi-radio par nœud)

**Capacité d'accueil d'un nœud** : 1 slot mPCIe (PCIe) + 2 ports USB3.0 → jusqu'à **3 radios par nœud**.

| Lien | Radio | Voie | Bande | Note |
|---|---|---|---|---|
| **Backhaul mesh** | WLE900VX (ath10k) | **mPCIe / PCIe** | 5 GHz | 3×3 — **3 antennes U.FL requises** (vérifier stock pigtails) |
| **Accès client + mesh client** | MT7632U (mt76) | **USB3** | 2.4/5 GHz | 802.11s mt76 mûr ; placement USB3 recommandé |
| **2ᵉ accès / scan passif** | MT7632U (mt76) *ou* AR9271 (ath9k_htc) | **USB3** | 2.4 GHz | tri-radio ; ath9k_htc = firmware-free |
| **Backhaul fixe (points Sponsor-a-Port)** | — | filaire | — | 4× GbE + SFP+/SFP en épine dorsale entre nœuds fixes |

**Doublons / failover** : stock confortable (3× WLE900VX, 6× MT7632U) — radio de secours montable à chaud sur USB3, ou nœud **tri-radio actif** (backhaul + accès 5 GHz + accès 2.4 GHz/scan) selon classe de nœud.

Variantes selon classe de nœud (TOML `[backhaul] mode = dbdc|wired|shared`).

---

## 5. PILE MESH

- **Backhaul** : **802.11s natif (mac80211 + HWMP)** en première intention ; `batman-adv` par-dessus **optionnel**.
- **Chiffrement** : **WPA3-SAE Mesh** (`wpa_supplicant` `mode=5`, `key_mgmt=SAE`). ⚠ Maturité SAE-mesh dépendante du chipset → **point ouvert** (§9).
- **Accès client** : `hostapd` + **Passpoint / Hotspot 2.0** (`hs20`, ANQP, RSN) — ancrage roaming Gondwana-Air. Couche `did:plc`/MirrorNet au-dessus.

---

## 6. PILE LOGICIELLE & NOYAU

- **DTS / overlay** : node PCIe mPCIe + GPIO reset/`W_DISABLE` + alim 3.3 V (volet noyau, hors module logiciel).
- **Drivers à valider** : `ath10k_pci` (QCA9880), `mt76x2u` (MT7632U), `ath9k_htc` (AR9271). Firmware redistribuables packagés, hash épinglés.
- **Régulatoire** : `wireless-regdb` + CRDA, **domaine FR verrouillé** dans le BUNDLE (puissance, DFS 5 GHz).

---

## 7. INTÉGRATION SecuBox-Deb (module MESH)

### Pattern 3-broches

| Broche | Rôle |
|---|---|
| **CTL** | Orchestration `hostapd` / `wpa_supplicant`, état RF, rotation de clés |
| **LXC** | Isolation du plan de contrôle mesh |
| **BUNDLE** | `.deb` : drivers + firmwares (ath10k/mt76/ath9k_htc) + regdb + templates TOML |

Mapping : **MESH↔AUTH**.

### Configuration TOML (extrait)

```toml
[radio.backhaul]
phy    = "phy0"
driver = "ath10k_pci"    # QCA9880 / WLE900VX (mPCIe)
iface  = "wlan-bh"

[radio.access]
phy    = "phy1"
driver = "mt76x2u"       # MT7632U (USB) | alt: ath9k_htc (AR9271, firmware-free)
iface  = "wlan-ap"

[reg]
country = "FR"
dfs     = true

[mesh]
mesh_id = "gondwana-air"
band    = "5g"
freq    = 5180
sae_password_ref = "file:///etc/secubox/secrets/mesh-sae"

[ap]
ssid = "Gondwana-Air"
hs20 = true
anqp = true

[backhaul]
mode = "wired"           # dbdc | wired | shared

[opad]
reactive = false
```

### API FastAPI / Uvicorn (pas de RPCD)

```
GET  /mesh/peers          # pairs 802.11s + métriques HWMP
GET  /mesh/rf             # état radios (backhaul + access)
POST /mesh/key/rotate     # rotation SAE — PFS 24 h (L2 Routing Twins)
GET  /ap/clients          # clients associés + état Passpoint
POST /reg/domain          # bascule domaine régulatoire (verrouillé FR)
```

### OPAD appliqué au plan RF

Observation passive par défaut ; réaction (dé-auth, bascule canal, quarantaine pair) **hors chemin de données**, opt-in, journalisée. Matrice de menaces RF (rogue mesh peer, evil-twin Passpoint, déni DFS, injection HWMP) — pendant RF de CM-WALL-OPAD-2026-05.

---

## 8. PHASAGE PILOTE (Maurienne)

| Phase | Objectif | Critère de sortie |
|---|---|---|
| 0 — Caractérisation | identifier modules inconnus, valider exemplaires | `iw list` AP+mesh sur QCA9880, MT7632U, AR9271 ; MT7632U stable |
| 1 — Bench | 1 MochaBin + WLE900VX | 802.11s 2-nœuds chiffré SAE (ath10k) |
| 2 — Liaison | 3 nœuds | débit/saut ; HWMP + bascule de chemin |
| 3 — Accès | `hostapd` HS2.0 sur radio USB | roaming Passpoint inter-nœuds |
| 4 — Terrain | BYOH / Sponsor-a-Port | BUNDLE durci, profils TOML par classe de nœud |
| 5 — CSPN | Gel de cible | dossier rédigé, points ouverts documentés |

---

## 9. POINTS OUVERTS

1. **802.11s/HWMP sous ath10k (QCA9880)** — **item de validation n°1**, bloquant choix backhaul. Repli : MT7632U (mt76) en backhaul si ath10k mesh insuffisant.
2. **Stabilité MT7632U** — exemplaire détenu à valider (variantes instables connues).
3. **Maturité WPA3-SAE Mesh** — bloquant CSPN, à instrumenter en phase 1.
4. **Contrôleur BLE 5.x / LESC** — **trou matériel confirmé (§3bis)**, bloquant `secubox-mesh-bt` S2/S3. Sourcer (Option A) ou ESP32 front-end (Option B).
5. **Antennes** — compter pigtails U.FL vs 3×3 (WLE900VX = 3 antennes).
6. **MT7632U ×5 strictement identiques ?** — confirmer marquage/FCC (sinon `lspci` en slot mPCIe réel pour lever tout doute PCIe). *Identification chipset résolue (= MT7632U).*

---

*CyberMind — Gérald Kerma — Notre-Dame-du-Cruet (73130). Document interne, version FR faisant foi. LicenseRef-CMSD-1.0.*
