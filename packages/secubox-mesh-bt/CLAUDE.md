<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# CLAUDE.md — sous-module `secubox-mesh-bt`

> Emplacement cible : `packages/secubox-mesh-bt/CLAUDE.md`
> Réf. spec : CM-MESH-MPCIE-2026-06 **v0.2.1-draft** (annexe BT) · Cible : MochaBin-5G · Licence : LicenseRef-CMSD-1.0
> Dépend de : `secubox-mesh` (CM-MESH-MPCIE-2026-06)
> Spec complète : [`docs/specs/CM-MESH-MPCIE-2026-06.md`](../../docs/specs/CM-MESH-MPCIE-2026-06.md)

Sous-module Bluetooth/BLE de SecuBox-Deb. Trois sous-systèmes, **un seul flux unifié**. Lis tout avant d'agir.

## ⚠ Update v0.2.1 (2026-06-02) — TROU MATÉRIEL BLE confirmé (bloquant S2/S3)

La spec a été figée et le bilan inventaire BLE est sans appel :

| Pièce détenue | Verdict |
|---|---|
| 3Com SL-10208 (2003) | ❌ BT 1.x, **pré-BLE** |
| Belkin F8T012 | ❌ BT 2.0, **pas de LE** |
| MT7632U (Ciotco) — moitié BT | ❌ support mainline = vieux staging `btmtk_usb` (noyaux 3.11–3.13 seulement, retiré) ; BT 4.x. **Inutilisable sur Debian ARM64 actuelle.** |
| WLE650V5 (QCA6174) — BT | ⚠ BT 4.1 — **LESC à confirmer** ; prototypage uniquement, pas de garantie production |

**Conclusion : aucun contrôleur BLE 5.x / LESC exploitable en stock.**

### Décision à prendre avant d'implémenter S2/S3

- **Option A** — sourcer un contrôleur **BLE 5.x mainline** :
  - `btmtk` MT7921/7922 (chipsets WiFi+BT combo récents, BT 5.2)
  - CSR8510 USB dongle (BT 4.0+, LESC ok, mainline `btusb`)
  - nRF52 dev kit avec firmware HCI (BlueZ propre, contrôle total)
- **Option B** — **ESP32 en front-end BLE** (en stock) : device Improv-canonical, MochaBin reste plan de contrôle. Voie cohérente avec `secubox-mesh-bt`. Le sous-module devient ALORS un **proxy GATT-over-USB-serial** ou **GATT-over-network** vers l'ESP32.

**Tant que cette décision n'est pas tranchée :**

- **S1 (BT Mesh relay/proxy)** : reste implémentable si un contrôleur BT 4.x suffit (à valider — bluetooth-meshd exige BLE 4.x minimum).
- **S2 (BLE WiFi provisioning)** et **S3 (Double-auth QR+BLE)** : **BLOQUÉS** sur le choix Option A/B.

L'agent qui démarre cette issue doit explicitement valider quelle option a été retenue (issue tracking séparée) AVANT d'écrire `gatt.py`, `oob.py`, `session.py`.

### Conséquences architecturales

- **Option A retenue** : l'arborescence et le code décrits ci-dessous restent valides. Le contrôleur BLE 5.x est local au MochaBin (HCI direct).
- **Option B retenue (ESP32 front-end)** : `gatt.py` devient un client (pas un serveur) parlant à l'ESP32 via USB-serial ou UDP/TCP. Le flux QR+nonce+LESC-OOB reste piloté par le MochaBin, mais le pairing radio se passe sur l'ESP32. Refactor mineur.

---

## 0. Contexte agent

Conventions héritées de `secubox-deb` (ne PAS dévier) :

- Plan de contrôle : **FastAPI + Uvicorn**. Jamais de RPCD.
- Config : **TOML** (`tomllib`), lecture seule au runtime.
- Packaging : **`.deb`/`apt`**, `debhelper` (`dh`).
- Pattern **3-broches** : CTL / LXC / BUNDLE.
- Mapping : ce module chevauche **MESH↔AUTH** (c'est sa nature même).
- Doctrine **OPAD** : relais = actif/opt-in ; scan = passif par défaut.

### Voie matérielle

Sur carte combo mPCIe WiFi+BT, le **WiFi emprunte la lane PCIe x1** et le **BT la ligne USB2.0** du même slot.
Sinon, dongle BT sur USB3.0. → Le code ne suppose **aucun** transport matériel particulier : `hci` paramétré en TOML.

---

## 1. Les trois sous-systèmes (et leur unification)

| # | Sous-système | Rôle | Face |
|---|---|---|---|
| **S1** | **BT Mesh relay/proxy** | Nœud relais/proxy Bluetooth Mesh (`bluetooth-meshd`) + scan présence BLE passif | MESH |
| **S2** | **BLE WiFi provisioning** | Pousser identifiants/profil Passpoint en BLE → client **s'auto-connecte** au mesh WiFi | MESH↔AUTH |
| **S3** | **Double-auth QR+BLE** | QR = canal OOB (substitut NFC) ; proximité BLE = « tap » ; QR+BLE = 2 facteurs | AUTH |

**Flux unifié (QR affiché par le nœud, scanné par le téléphone) :**

1. Le nœud crée une **session éphémère** : nonce `N`, données d'appairage **OOB LE Secure Connections**, TTL court.
2. Il rend un **QR** = `{ble_addr, svc_uuid, N, oob_data, expiry[, did:plc]}`.
3. Le client scanne → possède `N` + `oob_data`, se connecte en BLE au `ble_addr`.
4. **Appairage LESC-OOB** avec les données du QR (rôle « NFC-like » : le QR EST le porteur OOB). Lie le canal visuel au canal radio → anti-relais/anti-evil-twin.
5. **Garde RSSI** : proximité au-dessus d'un seuil = intention « tap » (garde douce, cf. §2).
6. **Challenge-réponse** GATT chiffré dérivé de `N` (facteur QR) ; l'appairage de proximité = facteur possession → **2 facteurs requis**.
7. Succès → push **identifiant par-client** (PSK dédié ou profil Passpoint/EAP) → le client rejoint `Gondwana-Air`.
8. Optionnel : URL de fin d'onboarding (style Improv) → enregistrement MirrorNet / `did:plc`.

---

## 2. Garde-fous (NON négociables)

- **LE Secure Connections uniquement.** Rejeter tout appairage *legacy*/« Just Works » non authentifié. Pas de downgrade.
- **RSSI n'est PAS une garantie cryptographique.** C'est un signal d'intention + anti-relais grossier (RSSI est usurpable). La sécurité vient du couple OOB-LESC + challenge lié au nonce. **Documenter honnêtement** (commentaire + log) — même rigueur que le point ouvert SAE-mesh et le gap Angluin–Valiant.
- **QR à usage unique + TTL court** (défaut 60 s). Rejouer un QR expiré/consommé = refus.
- **Double facteur réellement requis** : QR (`N`) **ET** appairage de proximité doivent réussir, liés par `N`. L'un sans l'autre = échec.
- **Identifiant poussé = par-client.** Jamais le mot de passe SAE maître du mesh. PSK/profil dédié, révocable.
- **Secrets hors TOML** : `oob`, clés, PSK générés au runtime ; jamais persistés en clair.
- **OPAD** : relais Mesh BT et appairage = **actifs/opt-in**, journalisés. Scan présence BLE = **passif par défaut**, aucune action déclenchée.
- **Pas de pairing automatique silencieux** : toute session d'onboarding est initiée explicitement (API), jamais en réponse à une pub BLE entrante.

---

## 3. Arborescence à créer

```
packages/secubox-mesh-bt/
├── CLAUDE.md
├── pyproject.toml
├── secubox_mesh_bt/
│   ├── __init__.py
│   ├── api.py            # router FastAPI (CTL)
│   ├── models.py         # schémas pydantic (Session, Peer, Client...)
│   ├── config.py         # loader TOML
│   ├── btmesh.py         # S1 : bluetooth-meshd (relay/proxy), scan passif
│   ├── gatt.py           # S2/S3 : serveur GATT (provisioning + auth)
│   ├── oob.py            # LESC-OOB : génération/validation données d'appairage
│   ├── session.py        # sessions éphémères (nonce, TTL, état)
│   ├── qr.py             # encodage payload QR + rendu PNG/SVG
│   └── provision.py      # push credential/profil Passpoint → client
├── conf/
│   └── mesh-bt.toml
├── systemd/
│   └── secubox-mesh-bt.service
└── debian/
    ├── control
    ├── rules
    ├── changelog
    ├── compat
    ├── secubox-mesh-bt.postinst
    └── secubox-mesh-bt.install
```

---

## 4. Schéma TOML (`conf/mesh-bt.toml`)

```toml
# /etc/secubox/mesh-bt.toml — LicenseRef-CMSD-1.0
schema_version = 1

[transport.bt]
hci = "hci0"            # contrôleur BT (USB2 du combo mPCIe, ou dongle USB3)

[bt.mesh]               # S1
enabled = true
role    = "proxy"       # proxy | relay | friend | lpn  (relay/proxy = OPAD actif)
scan_presence = true    # scan passif BLE (observation seule)

[bt.onboard]            # S2
enabled        = true
ssid           = "Gondwana-Air"
credential_mode = "per_client_psk"   # per_client_psk | passpoint_profile
return_url     = ""     # optionnel : fin d'onboarding MirrorNet

[bt.auth]               # S3
rssi_gate_dbm  = -55    # seuil proximité « tap » (garde douce, non crypto)
nonce_ttl_s    = 60     # TTL QR à usage unique
require_lesc   = true   # LE Secure Connections obligatoire (ne pas désactiver)
did_plc_hook   = false  # liaison L1 Auth Twins / MirrorNet (optionnel)

[opad]
reactive = false        # passif par défaut
```

---

## 5. Contrat API (FastAPI — `api.py`)

| Méthode | Route | Rôle |
|---|---|---|
| GET  | `/bt/mesh/role`            | rôle Mesh BT courant + état `bluetooth-meshd` |
| POST | `/bt/mesh/relay`           | activer/désactiver relais (OPAD opt-in, journalisé) |
| GET  | `/bt/scan`                 | scan présence BLE **passif** (observation) |
| POST | `/bt/onboard/session`      | créer une session ; renvoie payload QR + QR rendu |
| GET  | `/bt/onboard/session/{id}` | état de session (machine à états Improv-like) |
| GET  | `/bt/clients`              | clients appairés/provisionnés (révocables) |
| DELETE | `/bt/clients/{id}`       | révoquer un client (révoque PSK/profil) |

### Stub `api.py`

```python
# secubox_mesh_bt/api.py — LicenseRef-CMSD-1.0
from __future__ import annotations
import asyncio
from fastapi import APIRouter, HTTPException
from .config import load_config
from .models import Session, SessionState, Peer, Client, RelayRequest
from . import btmesh, session as sess, qr

router = APIRouter(prefix="/bt", tags=["mesh-bt"])
_cfg = load_config()

@router.get("/scan", response_model=list[Peer])
async def scan() -> list[Peer]:
    # Passif : observation seule, aucune action OPAD.
    return await asyncio.to_thread(btmesh.scan_presence, _cfg.transport.bt.hci)

@router.post("/mesh/relay")
async def relay(req: RelayRequest) -> dict:
    # OPAD : action active explicite, journalisée.
    return await asyncio.to_thread(btmesh.set_relay, req.enabled, _cfg)

@router.post("/onboard/session", response_model=Session)
async def onboard_session() -> Session:
    # Crée nonce + OOB-LESC + TTL ; rend le QR (canal OOB, substitut NFC).
    s = await asyncio.to_thread(sess.create, _cfg)
    s.qr = qr.render(s.payload)
    return s

@router.get("/onboard/session/{sid}", response_model=SessionState)
async def onboard_state(sid: str) -> SessionState:
    st = await asyncio.to_thread(sess.state, sid)
    if st is None:
        raise HTTPException(404, "session inconnue ou expirée")
    return st

@router.get("/clients", response_model=list[Client])
async def clients() -> list[Client]:
    return await asyncio.to_thread(btmesh.provisioned_clients)
```

### Squelette `session.py` (le cœur de la double-auth)

```python
# secubox_mesh_bt/session.py — LicenseRef-CMSD-1.0
from __future__ import annotations
import os, time, secrets, logging
from dataclasses import dataclass, field
from . import oob

log = logging.getLogger("secubox.mesh-bt")
_SESSIONS: dict[str, "Sess"] = {}

@dataclass
class Sess:
    sid: str
    nonce: bytes            # facteur QR
    oob_data: dict          # LESC-OOB (Confirm/Random) — canal NFC-like via QR
    expiry: float
    state: str = "auth_required"   # Improv-like : auth_required→authorized→provisioning→provisioned/error

def create(cfg) -> "Sess":
    if not cfg.bt.auth.require_lesc:
        raise ValueError("require_lesc=false interdit : LESC obligatoire")
    sid = secrets.token_urlsafe(8)
    s = Sess(
        sid=sid,
        nonce=os.urandom(32),                 # usage unique
        oob_data=oob.generate(cfg.transport.bt.hci),
        expiry=time.time() + cfg.bt.auth.nonce_ttl_s,
    )
    _SESSIONS[sid] = s
    log.warning("RSSI gate=%ddBm : garde d'INTENTION, non garantie crypto",
                cfg.bt.auth.rssi_gate_dbm)
    return s

def verify(sid: str, qr_proof: bytes, rssi_dbm: int, cfg) -> bool:
    s = _SESSIONS.get(sid)
    if s is None or time.time() > s.expiry:
        return False                           # rejeu / expiré
    if rssi_dbm < cfg.bt.auth.rssi_gate_dbm:   # garde douce de proximité
        log.info("session %s : hors seuil proximité", sid)
        return False
    # Facteur QR (nonce) ET facteur possession (appairage LESC-OOB) — les deux requis.
    ok = secrets.compare_digest(qr_proof, _expected_proof(s.nonce))
    s.state = "authorized" if ok else "error"
    return ok
```

---

## 6. GATT (`gatt.py`)

Réutiliser les **UUID Improv Wi-Fi** pour le sous-ensemble provisioning (compatibilité apps clientes existantes), + une caractéristique custom pour le challenge lié au QR :

| Caractéristique | UUID | Props | Rôle |
|---|---|---|---|
| `prov-state`     | Improv state    | read/notify | machine à états onboarding |
| `prov-error`     | Improv error    | read/notify | erreurs |
| `prov-rpc`       | Improv RPC cmd  | write       | soumettre WiFi / identify / device-info |
| `prov-result`    | Improv RPC res  | read/notify | résultat + URL de fin |
| `auth-challenge` | custom 128-bit  | write       | réponse au challenge dérivé du nonce QR |

> Note : payload Improv RPC > 20 octets → fragmenter sur plusieurs paquets BLE (gérer le reassembly).

---

## 7. Packaging `.deb`

### `debian/control`

```
Package: secubox-mesh-bt
Architecture: arm64
Depends: ${python3:Depends}, ${misc:Depends},
 python3-fastapi, python3-uvicorn, python3-dbus, python3-qrcode,
 bluez, bluez-meshd
Recommends: secubox-mesh
Description: SecuBox-Deb BT submodule — Mesh relay + BLE WiFi onboarding + QR/BLE double-auth (OPAD)
```

### `debian/secubox-mesh-bt.postinst`

```bash
#!/bin/sh
set -e
case "$1" in
  configure)
    install -d -m 0700 /etc/secubox/secrets
    deb-systemd-helper enable secubox-mesh-bt.service >/dev/null || true
    deb-systemd-invoke start secubox-mesh-bt.service  >/dev/null || true
    ;;
esac
#DEBHELPER#
```

### `systemd/secubox-mesh-bt.service`

```ini
[Unit]
Description=SecuBox-Deb BT control plane (mesh relay + onboarding + auth)
After=bluetooth.target network.target
Requires=bluetooth.target

[Service]
ExecStart=/usr/bin/uvicorn secubox_mesh_bt.app:app --host 127.0.0.1 --port 8744
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/run /etc/secubox

[Install]
WantedBy=multi-user.target
```

---

## 8. Definition of Done

1. `.deb` `secubox-mesh-bt` installable, `lintian` sans blocage.
2. `systemctl status secubox-mesh-bt` actif ; Uvicorn écoute en local (8744).
3. `bluetoothctl` confirme l'adaptateur ; `bluetooth-meshd` joignable (D-Bus).
4. `POST /bt/onboard/session` renvoie un QR valide (payload + rendu).
5. **Bout-en-bout** : scan QR → appairage **LESC-OOB** → challenge lié au nonce → push credential → client rejoint `Gondwana-Air` automatiquement.
6. QR rejoué/expiré refusé ; appairage legacy refusé ; client révocable.
7. Log WARN explicite : RSSI = garde d'intention, non crypto.
8. En-têtes `LicenseRef-CMSD-1.0` partout.

---

## 9. Ordre des tâches

1. Échafaudage + `pyproject.toml` + licences.
2. `models.py` → `config.py`.
3. `session.py` + `oob.py` (cœur double-auth) avec tests unitaires (rejeu, TTL, double facteur).
4. `gatt.py` (UUID Improv + `auth-challenge`) ; reassembly > 20 o.
5. `qr.py` ; `provision.py` (per-client PSK / profil Passpoint).
6. `btmesh.py` (D-Bus `bluetooth-meshd`, scan passif).
7. `api.py` (endpoints, `to_thread`).
8. `debian/` + unit ; build `.deb` ; tests DoD §8.

---

## 10. Hors périmètre (NE PAS faire)

- App cliente mobile (séparée ; l'app scanne le QR et parle GATT).
- Couche L3 MirrorNet / HamCoin (seul le hook `did_plc_hook` optionnel est prévu).
- Toute action RF/BT offensive activée par défaut.
- Appairage legacy / pairing automatique silencieux.
- Persistance de secrets en clair dans le TOML.

---

*CyberMind — Gérald Kerma. Document interne, FR faisant foi. LicenseRef-CMSD-1.0.*
