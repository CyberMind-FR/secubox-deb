<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# CLAUDE.md — module `secubox-mesh`

> Emplacement cible : `packages/secubox-mesh/CLAUDE.md`
> Réf. spec : CM-MESH-MPCIE-2026-06 **v0.2.1-draft** (2026-06-02) · Cible : MochaBin-5G (Armada 7040) · Licence : LicenseRef-CMSD-1.0
> Spec complète : [`docs/specs/CM-MESH-MPCIE-2026-06.md`](../../docs/specs/CM-MESH-MPCIE-2026-06.md)

Ce fichier est le contexte opérationnel de l'agent pour construire le module **MESH** de SecuBox-Deb
(WiFi mPCIe + mesh 802.11s + AP Passpoint). Lis-le entièrement avant toute action.

## ⚠ Update v0.2.1 (2026-06-02) — matrice radio FIGÉE sur stock réel

La spec a été figée d'après l'inventaire matériel réel. Conséquences pour le code agent :

- **Backhaul mesh** : **WLE900VX / QCA9880 / `ath10k_pci`** (mPCIe PCIe natif, 3×3 5 GHz, 3 antennes U.FL requises).
- **Accès client / mesh client** : **MT7632U / `mt76x2u`** (USB-interface, placement USB3 recommandé — alim/énumération plus propres, libère le mPCIe pour le WLE900VX). Alternative : **AR9271 / `ath9k_htc`** (firmware-free, 1×1 11n) pour auditabilité maximale.
- **Topologie multi-radio par nœud** : 1 mPCIe (PCIe) + 2 USB3.0 → jusqu'à 3 radios. Tri-radio possible (backhaul + accès 5 GHz + accès 2.4 GHz/scan).
- **MT7615 et ath9k mPCIe : ABANDONNÉS** (non détenus).
- **Carte Globalscale (NXP 88W9xxx)** : écartée pour le mesh (pas de `mesh point`, firmware opaque).
- **Repli backhaul documenté** : si 802.11s sous ath10k déçoit (point ouvert n°1), basculer le backhaul sur **MT7632U mt76 en mPCIe (USB2)** — mt76 mesh plus mûr, au prix du plafond ~480 Mbps brut.
- **Modules blindés « S305-8946-1A4C » = MT7632U** (point ouvert n°6 résolu). USB-interface, comportement identique à la clé Ciotco.

Le code reste **agnostique du chipset** (driver/bande/backhaul = paramètres TOML) mais le `mesh.toml` template par défaut reflète désormais le stock retenu (backhaul = `ath10k_pci`, access = `mt76x2u`).

### Items de validation prioritaires (§9 de la spec)

1. **802.11s/HWMP sous ath10k (QCA9880)** — item de validation **n°1**, bloquant choix backhaul. Le code DOIT être prêt au repli mt76 sans refactor (driver agnostique).
2. **Stabilité MT7632U** — exemplaire détenu à valider (variantes signalées instables — driver qui plante, `wlan` absente malgré `mt76x2u`).
3. **Maturité WPA3-SAE Mesh** — bloquant CSPN, à instrumenter en phase 1 (log WARN au démarrage déjà prévu).
4. **Antennes U.FL** : 3 pigtails requis pour le WLE900VX 3×3 — vérifier stock.

---

## 0. Contexte agent

Tu construis un module SecuBox-Deb. SecuBox-Deb est un appliance Debian ARM64 souverain.
Conventions héritées du dépôt `secubox-deb` (ne PAS dévier) :

- **Plan de contrôle** : FastAPI + Uvicorn. **Jamais de RPCD.**
- **Config** : TOML lu via `tomllib` (Python ≥ 3.11), **lecture seule au runtime**.
- **Packaging** : `.deb` / `apt` (jamais `.ipk`/`opkg`). `debhelper` (`dh`).
- **Pattern 3-broches** : `CTL` (orchestration) / `LXC` (isolation) / `BUNDLE` (paquet `.deb`).
- **Mapping module** : MESH ↔ AUTH (paire complémentaire).
- **Doctrine** : OPAD (CM-WALL-OPAD-2026-05) — voir garde-fous §2.

---

## 1. Definition of Done

Le module est terminé quand TOUT ce qui suit est vrai :

1. `apt build` produit un `.deb` installable (`secubox-mesh_*.deb`) sans erreur `lintian` bloquante.
2. Après install : `systemctl status secubox-mesh` actif, Uvicorn écoute en local.
3. Les 5 endpoints répondent (cf. §5) ; `GET /mesh/rf` renvoie l'état radio réel via `iw`.
4. La config se charge depuis `/etc/secubox/mesh.toml` ; aucun secret en clair n'y figure.
5. Le domaine régulatoire est **verrouillé FR** au `postinst` (`iw reg set FR`).
6. `iw list` du nœud confirme les modes `AP` **et** `mesh point` sur le PHY retenu.
7. Bring-up 802.11s 2-nœuds chiffré SAE fonctionnel (script `mesh-up`).
8. En-têtes de licence `LicenseRef-CMSD-1.0` sur chaque fichier source.

---

## 2. Garde-fous (NON négociables)

- **Carte non figée** : le choix matériel (`ath9k` AR9580 *vs* `mt7615` DBDC) n'est **PAS** tranché.
  → Code **agnostique du chipset**. Driver, bande, mode backhaul = **paramètres TOML**, jamais en dur.
- **OPAD = passif par défaut** : aucune action RF offensive (dé-auth, kick, bascule canal) déclenchée
  automatiquement. Toute réaction est **opt-in explicite** et journalisée. Observation par défaut.
- **Secrets** : le mot de passe SAE ne vit jamais dans le TOML. Champ `sae_password_ref` = URI
  (`vault://...` ou chemin `file://` à droits `0600`). Résolution au runtime uniquement.
- **WPA3-SAE Mesh = POINT OUVERT** : signale explicitement dans le code (commentaire + log WARN au
  démarrage) que la maturité SAE-mesh dépend du chipset et reste à valider CSPN. Ne pas masquer.
- **Régulatoire** : domaine FR verrouillé ; DFS respecté. Aucun override sauf appel `POST /reg/domain`
  authentifié (et même là, garder FR par défaut).
- **Pas d'appel réseau sortant** depuis le module hors plan mesh/AP.

---

## 3. Arborescence à créer

```
packages/secubox-mesh/
├── CLAUDE.md                      # ce fichier
├── pyproject.toml
├── secubox_mesh/
│   ├── __init__.py
│   ├── api.py                     # router FastAPI (CTL)
│   ├── models.py                  # schémas pydantic
│   ├── config.py                  # loader TOML + résolution secrets
│   ├── rf.py                      # wrappers iw / état radio
│   ├── mesh.py                    # 802.11s : join/leave/peers (HWMP)
│   ├── ap.py                      # génération conf hostapd (Passpoint/HS2.0)
│   └── supplicant.py              # génération conf wpa_supplicant (mode=5 SAE)
├── conf/
│   ├── mesh.toml                  # template de config (BUNDLE)
│   ├── hostapd.conf.j2
│   └── wpa_supplicant-mesh.conf.j2
├── scripts/
│   └── mesh-up                    # bring-up bench 2-nœuds (idempotent)
├── systemd/
│   └── secubox-mesh.service
└── debian/
    ├── control
    ├── rules
    ├── changelog
    ├── compat
    ├── secubox-mesh.postinst
    └── secubox-mesh.install
```

---

## 4. Schéma TOML (`conf/mesh.toml`)

```toml
# /etc/secubox/mesh.toml — LicenseRef-CMSD-1.0
schema_version = 1

[radio]
phy    = "phy0"
driver = "ath9k"        # ath9k | mt7615e | mt76x2e | ath10k_pci  (agnostique)
iface  = "wlan0"

[reg]
country = "FR"          # verrouillé ; ne pas surcharger sans /reg/domain
dfs     = true

[mesh]
enabled  = true
mesh_id  = "gondwana-air"
band     = "5g"         # 2g | 5g
freq     = 5180         # MHz
sae_password_ref = "file:///etc/secubox/secrets/mesh-sae"   # JAMAIS en clair

[ap]
enabled = true
ssid    = "Gondwana-Air"
band    = "2g"          # si DBDC : accès 2g, backhaul 5g
hs20    = true
anqp    = true

[backhaul]
mode = "wired"          # dbdc | wired | shared   (cf. spec §4)

[opad]
reactive = false        # passif par défaut — NE PAS mettre true par défaut
```

---

## 5. Contrat API (FastAPI — `api.py`)

| Méthode | Route | Rôle | Notes |
|---|---|---|---|
| GET | `/mesh/peers` | Pairs 802.11s + métriques HWMP | via `iw dev <iface> station dump` |
| GET | `/mesh/rf` | État radio : canal, puissance, DFS, domaine | via `iw dev` / `iw reg get` |
| POST | `/mesh/key/rotate` | Rotation SAE | aligné PFS 24 h (L2 Routing Twins) |
| GET | `/ap/clients` | Clients associés + état Passpoint | via `hostapd_cli all_sta` |
| POST | `/reg/domain` | Bascule domaine régulatoire | défaut FR ; authentifié ; journalisé |

Réponses typées pydantic (`models.py`). Pas d'I/O bloquante dans le handler — `asyncio.to_thread`
pour les appels `subprocess`.

### Stub de référence `api.py`

```python
# packages/secubox-mesh/secubox_mesh/api.py — LicenseRef-CMSD-1.0
from __future__ import annotations
import asyncio
from fastapi import APIRouter, HTTPException
from .config import load_config
from .models import RFState, Peer, APClient, RegRequest
from . import rf, mesh, ap

router = APIRouter(prefix="", tags=["mesh"])
_cfg = load_config()  # /etc/secubox/mesh.toml

@router.get("/mesh/peers", response_model=list[Peer])
async def mesh_peers() -> list[Peer]:
    return await asyncio.to_thread(mesh.list_peers, _cfg.radio.iface)

@router.get("/mesh/rf", response_model=RFState)
async def mesh_rf() -> RFState:
    return await asyncio.to_thread(rf.state, _cfg.radio.iface)

@router.post("/mesh/key/rotate")
async def mesh_key_rotate() -> dict:
    # PFS 24h — rotation SAE. OPEN POINT: maturité SAE-mesh selon chipset.
    return await asyncio.to_thread(mesh.rotate_key, _cfg)

@router.get("/ap/clients", response_model=list[APClient])
async def ap_clients() -> list[APClient]:
    return await asyncio.to_thread(ap.clients, _cfg.radio.iface)

@router.post("/reg/domain")
async def reg_domain(req: RegRequest) -> dict:
    # Garde-fou : FR par défaut. Journaliser tout changement.
    return await asyncio.to_thread(rf.set_domain, req.country, _cfg)
```

### Stub `config.py` (TOML + secrets)

```python
# secubox_mesh/config.py — LicenseRef-CMSD-1.0
from __future__ import annotations
import tomllib, logging
from pathlib import Path
from urllib.parse import urlparse
from .models import Config

log = logging.getLogger("secubox.mesh")
CONFIG_PATH = Path("/etc/secubox/mesh.toml")

def load_config(path: Path = CONFIG_PATH) -> Config:
    with path.open("rb") as f:
        raw = tomllib.load(f)
    cfg = Config.model_validate(raw)
    if cfg.opad.reactive:
        log.warning("OPAD reactive=true — réaction RF active, hors posture passive par défaut")
    log.warning("SAE-mesh: maturité dépendante du chipset (%s) — POINT OUVERT CSPN",
                cfg.radio.driver)
    return cfg

def resolve_secret(ref: str) -> str:
    u = urlparse(ref)
    if u.scheme == "file":
        p = Path(u.path)
        if (p.stat().st_mode & 0o077):
            raise PermissionError(f"{p}: droits trop ouverts, exiger 0600")
        return p.read_text().strip()
    if u.scheme == "vault":
        raise NotImplementedError("backend vault:// à implémenter")
    raise ValueError(f"sae_password_ref non supporté: {ref}")
```

---

## 6. Templates conf (Jinja2)

### `conf/wpa_supplicant-mesh.conf.j2`

```ini
# 802.11s + WPA3-SAE mesh — généré, ne pas éditer
ctrl_interface=/run/wpa_supplicant
network={
    ssid="{{ mesh.mesh_id }}"
    mode=5
    frequency={{ mesh.freq }}
    key_mgmt=SAE
    sae_password="{{ sae_password }}"
    ieee80211w=2
}
```

### `conf/hostapd.conf.j2` (extrait Passpoint/HS2.0)

```ini
interface={{ radio.iface }}
ssid={{ ap.ssid }}
country_code={{ reg.country }}
hw_mode={{ 'a' if ap.band == '5g' else 'g' }}
ieee80211w=2
wpa=2
wpa_key_mgmt=SAE
{% if ap.hs20 %}
hs20=1
interworking=1
{% endif %}
```

---

## 7. Bring-up bench (`scripts/mesh-up`, idempotent)

```bash
#!/usr/bin/env bash
# mesh-up — bench 802.11s 2-nœuds — LicenseRef-CMSD-1.0
set -euo pipefail
IFACE="${1:-wlan0}"; FREQ="${2:-5180}"; MESHID="${3:-gondwana-air}"
iw reg set FR
ip link set "$IFACE" down || true
iw dev "$IFACE" set type mp
ip link set "$IFACE" up
# SAE via wpa_supplicant (conf générée par le module) — voir supplicant.py
echo "iface=$IFACE freq=$FREQ mesh_id=$MESHID prêt ; vérifier: iw dev $IFACE station dump"
```

---

## 8. Packaging `.deb`

### `debian/control`

```
Source: secubox-mesh
Section: net
Priority: optional
Maintainer: Gérald Kerma <root@cybermind.fr>
Build-Depends: debhelper-compat (= 13), dh-python, python3-all
Standards-Version: 4.6.2

Package: secubox-mesh
Architecture: arm64
Depends: ${python3:Depends}, ${misc:Depends},
 python3-fastapi, python3-uvicorn, python3-jinja2,
 iw, wpasupplicant, hostapd, wireless-regdb, crda
Description: SecuBox-Deb MESH module (802.11s + Passpoint AP, OPAD)
```

### `debian/secubox-mesh.postinst` (verrou régulatoire + service)

```bash
#!/bin/sh
set -e
case "$1" in
  configure)
    iw reg set FR || true            # verrou régulatoire FR
    install -d -m 0700 /etc/secubox/secrets
    deb-systemd-helper enable secubox-mesh.service >/dev/null || true
    deb-systemd-invoke start secubox-mesh.service  >/dev/null || true
    ;;
esac
#DEBHELPER#
```

### `systemd/secubox-mesh.service`

```ini
[Unit]
Description=SecuBox-Deb MESH control plane (FastAPI/Uvicorn)
After=network.target

[Service]
ExecStart=/usr/bin/uvicorn secubox_mesh.app:app --host 127.0.0.1 --port 8743
Restart=on-failure
# CTL/LXC : durcissement
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/run /etc/secubox

[Install]
WantedBy=multi-user.target
```

---

## 9. Ordre des tâches

1. Échafauder l'arborescence (§3) + `pyproject.toml` + en-têtes licence.
2. `models.py` (Config + DTO) → `config.py` (loader + `resolve_secret`).
3. `rf.py` (wrappers `iw`), puis `api.py` (5 endpoints, `to_thread`).
4. `mesh.py` / `ap.py` / `supplicant.py` + templates Jinja2.
5. `scripts/mesh-up` + unit systemd.
6. `debian/` complet ; build `.deb` ; `lintian`.
7. Tests d'acceptation (§1) ; logguer le WARN SAE-mesh.

---

## 10. Hors périmètre (NE PAS faire)

- DTS / overlay PCIe MochaBin (traité séparément, hors module logiciel).
- Couche L3 MirrorNet / `did:plc` / HamCoin.
- Toute réaction RF offensive activée par défaut.
- Tout choix matériel câblé en dur.

---

*CyberMind — Gérald Kerma. Document interne, FR faisant foi. LicenseRef-CMSD-1.0.*
