<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# IoT Radio Stack — `secubox-mqtt` + `secubox-zigbee` v2.4.0 alignment

**Réf.**       CyberMind-GK2 / SecuBox-Deb · IoT Radio Stack
**Modules**    `secubox-zigbee` (MIND) + `secubox-mqtt` (WALL)
**Cible HW**   MOCHAbin · Marvell Armada 7040 · arm64 · Debian bookworm
**Clé USB**    Sonoff Zigbee 3.0 USB Plus · CC2652P · VID:PID 1a86:55d4
**Licence**    CMSD-1.0 · LicenseRef-CMSD-1.0 · juridiction Chambéry
**Version**    SecuBox-Deb v2.4.0
**Réf. amont** Koenkk/zigbee2mqtt (Apache-2.0) · eclipse-mosquitto/mosquitto (EPL-2.0)
**Statut** : spec reçue 2026-05-20 — **les deux packages existent déjà dans le repo**
mais la spec demande un re-alignement complet (4R double-buffer, FastAPI Z2MBridge,
udev CC2652P, ACL 4 services). Re-scoper avec l'opérateur avant exécution.

---

## 0. Pré-existant dans le repo (à arbitrer)

| Paquet | État actuel | Spec demande |
|---|---|---|
| `secubox-mqtt` | présent (api/, debian/, menu.d/, nginx/, www/) | rewrite vers Mosquitto + ACL 4 services + 4R double-buffer + FastAPI /api/v1/mqtt 6 endpoints |
| `secubox-zigbee` | présent (api/, debian/, menu.d/, nginx/, www/) | rewrite vers zigbee2mqtt + udev CC2652P + FastAPI /api/v1/zigbee 10+ endpoints + Z2MBridge async + Jinja2 z2m config |

À décider avec l'opérateur :

- Soit **rewrite-in-place** des deux packages existants (rupture, bump version majeur)
- Soit **fork en `secubox-mqtt-v2` + `secubox-zigbee-v2`** (cohabitation pendant la transition)
- Soit **diff incrémental** : conserver l'existant et ajouter ce qui manque

---

## 1. Intention du commandement

Intégrer la pile IoT radio dans SecuBox-Deb sous forme de **deux paquets
Debian autonomes** respectant la charte SecuBox :

- **`secubox-mqtt`** (WALL) : broker Mosquitto production, ACL par service,
  TLS optionnel, double-buffer 4R sur la configuration, unit systemd dans le
  chemin Hamiltonien.

- **`secubox-zigbee`** (MIND) : daemon zigbee2mqtt wrappé, udev rule pour
  la clé Sonoff CC2652P sur MOCHAbin, configuration générée par template
  (network_key/pan_id GENERATE), FastAPI router `/api/v1/zigbee`, unit
  systemd `After=secubox-mqtt.service`.

Les deux modules doivent être opérationnels sur MOCHAbin **sans intervention
manuelle** après `apt install secubox-zigbee`. Tout ce qui est variable
(clé réseau, canal, PAN ID) est généré à l'installation ou lu depuis
`/etc/secubox/zigbee.toml`.

---

## 2. Hard limits (ne jamais enfreindre)

- Licence finale **CMSD-1.0** sur tout code original CyberMind.
  Les composants amont conservent leur licence (Apache-2.0, EPL-2.0).
- **Jamais** `allow_anonymous true` dans la config Mosquitto produite.
- **Jamais** `permit_join: true` dans la config z2m produite en production.
- User systemd : `secubox` (non-root). `NoNewPrivileges=true` obligatoire.
- Socket FastAPI : Unix socket `/run/secubox/zigbee.sock` — jamais TCP direct.
- `network_key` et `pan_id` : **toujours GENERATE** si absents du TOML.
  Ne jamais hard-coder une valeur par défaut connue.
- Ne jamais mentionner `Apache-2.0` comme licence du paquet SecuBox.
- Ne jamais référencer CrowdSec Ambassador dans les outputs.

---

## 3. Périmètre (scope)

**In scope :**

- Package `secubox-mqtt` complet (debian/, api/, systemd, config, udev)
- Package `secubox-zigbee` complet (debian/, api/, systemd, config, udev)
- Udev rule Sonoff CC2652P → symlink `/dev/secubox-zgb`
- FastAPI router `/api/v1/zigbee` avec 10 endpoints (§8)
- FastAPI router `/api/v1/mqtt` avec 6 endpoints (§9)
- Configuration Mosquitto production + ACL 4 services
- Template Jinja2 `zigbee2mqtt/configuration.yaml`
- Tests unitaires pytest pour les routers FastAPI
- Wiki page FR (§12)

**Out of scope (livrables séparés déjà planifiés) :**

- Module SENTINELLE-GSM (PROMPT_IMPL déjà produit — voir #237)
- Module EP06 modem LTE (PROMPT_IMPL déjà produit — voir #236)
- Module RDS (PROMPT_IMPL déjà produit)
- WebUI IoT Hub multi-connecteur (PROMPT_IMPL séparé)
- Matter/Thread Border Router (roadmap v2.6)
- Home Assistant add-on (hors scope SecuBox-Deb)

---

## 4. Hardware cible — MOCHAbin Armada 7040

```text
SoC      : Marvell ARMADA 7040 (AP806) · 4× Cortex-A72 · arm64
OS       : Debian bookworm (12) · kernel 6.1.x aarch64
USB      : Sonoff Zigbee 3.0 USB Plus · CC2652P · 1a86:55d4
           → /dev/ttyUSB0 (sans udev) → /dev/secubox-zgb (avec udev)
RAM      : 4 GB DDR4
Flash    : 16 GB eMMC
Réseau   : 5× GbE (Topaz 88E6141 switch + 1 WAN RJ45)
```

**Attention MOCHAbin :** le port USB est en USB 3.0 ; la clé CC2652P
fonctionne en USB 2.0 — pas d'incompatibilité, mais vérifier
`dmesg | grep -i usb` au premier boot pour confirmer l'énumération.

---

## 5. Arborescence cible

```text
packages/
├── secubox-mqtt/
│   ├── api/
│   │   ├── main.py
│   │   └── routers/
│   │       ├── status.py
│   │       ├── acl.py
│   │       └── config.py
│   ├── conf/
│   │   ├── mosquitto.conf.j2       ← template Jinja2
│   │   └── acl.conf.j2
│   ├── debian/
│   │   ├── control
│   │   ├── rules
│   │   ├── postinst
│   │   ├── prerm
│   │   └── secubox-mqtt.service
│   └── tests/
│       └── test_mqtt_api.py
│
└── secubox-zigbee/
    ├── api/
    │   ├── main.py
    │   └── routers/
    │       ├── devices.py
    │       ├── network.py
    │       ├── ota.py
    │       └── config.py
    ├── conf/
    │   ├── zigbee.toml.default     ← valeurs par défaut (GENERATE sentinel)
    │   └── z2m_configuration.yaml.j2
    ├── udev/
    │   └── 99-secubox-zigbee.rules
    ├── debian/
    │   ├── control
    │   ├── rules
    │   ├── postinst
    │   ├── prerm
    │   └── secubox-zigbee.service
    └── tests/
        └── test_zigbee_api.py
```

---

## 6. secubox-mqtt — Spécification

### 6.1 Configuration Mosquitto (template Jinja2)

```text
# /etc/mosquitto/conf.d/secubox.conf  (généré par postinst)
listener 1883 127.0.0.1          # local only par défaut
listener 1883 0.0.0.0            # si mqtt.bind_all=true dans zigbee.toml
allow_anonymous false
password_file /etc/mosquitto/passwd.d/secubox
acl_file /etc/mosquitto/acl.d/secubox.acl
log_type error
log_type warning
log_dest file /var/log/secubox/mqtt.log
max_queued_messages 1000
persistence true
persistence_location /var/lib/secubox/mqtt/
```

### 6.2 ACL par service (4 users minimum)

| User          | Topics autorisés           | Rôle                   |
|---------------|---------------------------|------------------------|
| `z2m`         | `readwrite zigbee2mqtt/#` | zigbee2mqtt daemon     |
| `homeassistant` | `readwrite #`           | bridge HA              |
| `sentinelle`  | `readwrite sentinelle/#`  | SENTINELLE-GSM         |
| `domoticz`    | `readwrite domoticz/#`    | bridge Domoticz        |
| `secubox-api` | `readwrite #`             | API interne FastAPI    |

Mots de passe générés aléatoirement au postinst avec `mosquitto_passwd`.
Stockés dans `/etc/secubox/mqtt-creds.toml` (mode 600, owner secubox).

### 6.3 Double-buffer 4R sur la config

La configuration Mosquitto est un paramètre mutable → double-buffer :

- `active` : config en production (`/etc/mosquitto/conf.d/secubox.conf`)
- `shadow` : config en attente (`/etc/mosquitto/conf.d/secubox.conf.shadow`)
- `Run` : swap atomique shadow→active + `systemctl reload mosquitto`
- `Rollback` : restauration `.conf.bak` + reload
- `Revert` : regénération depuis `zigbee.toml` defaults
- `Rebuild` : regénération complète + recréation users/passwd

---

## 7. secubox-zigbee — Spécification

### 7.1 Udev rule (99-secubox-zigbee.rules)

```udev
# Sonoff Zigbee 3.0 USB Plus (CC2652P)
SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="55d4", \
  SYMLINK+="secubox-zgb", MODE="0660", GROUP="secubox", \
  TAG+="systemd", ENV{SYSTEMD_WANTS}="secubox-zigbee.service"

# ConBee II (fallback)
SUBSYSTEM=="tty", ATTRS{idVendor}=="1cf1", ATTRS{idProduct}=="0030", \
  SYMLINK+="secubox-zgb", MODE="0660", GROUP="secubox"

# CP210x (générique Zigbee)
SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", \
  SYMLINK+="secubox-zgb-alt", MODE="0660", GROUP="secubox"
```

### 7.2 Template z2m configuration.yaml (Jinja2)

```yaml
homeassistant: {{ z2m.homeassistant_discovery | default(true) }}
permit_join: false
mqtt:
  base_topic: zigbee2mqtt
  server: "mqtt://127.0.0.1:1883"
  user: z2m
  password: "{{ mqtt_creds.z2m }}"
  keepalive: 60
serial:
  port: /dev/secubox-zgb
  adapter: zstack
advanced:
  network_key: GENERATE
  pan_id: GENERATE
  channel: {{ z2m.channel | default(20) }}
  ext_pan_id: GENERATE
  log_level: warning
  log_output: ['file']
  log_file: /var/log/secubox/zigbee2mqtt.log
  timestamp_format: 'YYYY-MM-DD HH:mm:ss'
  homeassistant_legacy_entity_attributes: false
frontend:
  enabled: false          # UI z2m native désactivée — on utilise SecuBox WebUI
```

### 7.3 zigbee.toml (configuration SecuBox)

```toml
[zigbee]
channel = 20              # 15, 20, 25, 26 — choisir selon analyse RF
auto_scan_channel = false # si true : postinst choisit le canal le moins chargé
permit_join_timeout = 60  # secondes max pour allow_join via API

[mqtt]
bind_all = false          # true = écoute 0.0.0.0 (bridges externes)
tls_enabled = false       # true = port 8883, certs /etc/secubox/mqtt/

[bridges]
homeassistant = true
domoticz = false
nodered = false
```

### 7.4 Unit systemd secubox-zigbee.service

```ini
[Unit]
Description=SecuBox Zigbee (zigbee2mqtt) — MIND module
Documentation=https://github.com/CyberMind-FR/secubox-deb
After=network.target secubox-zkp-auth.service secubox-mqtt.service
Requires=secubox-mqtt.service
BindsTo=secubox-mqtt.service

[Service]
Type=simple
User=secubox
Group=secubox
WorkingDirectory=/usr/lib/secubox/zigbee
Environment=NODE_ENV=production
ExecStartPre=/usr/lib/secubox/zigbee/scripts/preflight.sh
ExecStart=/usr/bin/node /usr/lib/secubox/zigbee/index.js
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=secubox-zigbee

PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run/secubox /var/lib/secubox/zigbee /var/log/secubox
SupplementaryGroups=dialout secubox
DeviceAllow=/dev/secubox-zgb rw
DeviceAllow=/dev/ttyUSB0 rw

[Install]
WantedBy=multi-user.target
```

**preflight.sh** doit :

1. Vérifier que `/dev/secubox-zgb` existe (ou `/dev/ttyUSB0`)
2. Générer `configuration.yaml` depuis le template Jinja2 si absent
3. Créer `/var/lib/secubox/zigbee/` si absent
4. Exit 0 → z2m démarre ; exit 1 → unit en failed, log explicite

---

## 8. Endpoints FastAPI `/api/v1/zigbee`

Tous les endpoints nécessitent un JWT valide émis par `secubox-zkp-auth`.
Réponses toujours en `application/json`. Erreurs selon RFC 9457.

| Méthode | Path                  | Description                                      |
|---------|-----------------------|--------------------------------------------------|
| GET     | `/health`             | Statut daemon z2m + broker MQTT + symlink USB    |
| GET     | `/devices`            | Liste complète devices avec LQI/bat/last_seen    |
| GET     | `/devices/{id}`       | Détail device (IEEE addr, modèle, capabilities)  |
| DELETE  | `/devices/{id}`       | Remove device du réseau (force_remove possible)  |
| GET     | `/topology`           | Graphe maillage JSON (src/dst/LQI/RSSI/hopcount) |
| GET     | `/network`            | channel, pan_id, ext_pan_id, devices_count       |
| POST    | `/permit_join`        | `{"value": bool, "time": int, "device": str?}`   |
| POST    | `/rename`             | `{"from": "0xABCD", "to": "capteur_salon"}`      |
| POST    | `/bind`               | `{"source": id, "target": id, "cluster": str}`   |
| POST    | `/ota/check`          | Lance vérif OTA pour tous les devices            |
| POST    | `/ota/update/{id}`    | Lance update OTA pour un device spécifique       |
| POST    | `/network/scan`       | Scan canaux RF (résultat async via MQTT)         |
| POST    | `/network/backup`     | Export config + réseau en JSON signé             |

### Implémentation `/devices` (exemple)

```python
# routers/devices.py
from fastapi import APIRouter, Depends, HTTPException
from ..auth import require_jwt
from ..z2m_bridge import Z2MBridge

router = APIRouter(prefix="/devices", tags=["devices"])
bridge = Z2MBridge()  # MQTT pub/sub vers z2m

@router.get("/", response_model=list[DeviceSchema])
async def list_devices(jwt=Depends(require_jwt)):
    """Retourne tous les devices appairés avec LQI, batterie, last_seen."""
    try:
        return await bridge.get_devices()
    except Z2MTimeout:
        raise HTTPException(503, "zigbee2mqtt unreachable")

@router.post("/{device_id}/rename")
async def rename_device(device_id: str, body: RenameBody, jwt=Depends(require_jwt)):
    await bridge.publish(
        f"zigbee2mqtt/bridge/request/device/rename",
        {"from": device_id, "to": body.to}
    )
    return {"status": "ok", "from": device_id, "to": body.to}
```

### Z2MBridge — pattern pub/sub asynchrone

```python
class Z2MBridge:
    """Pont asynchrone FastAPI ↔ zigbee2mqtt via MQTT."""

    async def get_devices(self, timeout=5.0) -> list[dict]:
        """Publie sur bridge/request/devices, attend la réponse sur bridge/response/devices."""
        correlation_id = str(uuid4())
        response = asyncio.Future()
        # subscribe temporaire sur bridge/response/devices
        # publish {"transaction": correlation_id}
        # await response avec timeout
        ...

    async def publish(self, topic: str, payload: dict):
        """Publie un message MQTT vers z2m."""
        ...
```

---

## 9. Endpoints FastAPI `/api/v1/mqtt`

| Méthode | Path            | Description                                  |
|---------|-----------------|----------------------------------------------|
| GET     | `/health`       | Statut broker (pid, clients, msgs/s)         |
| GET     | `/stats`        | Statistiques $SYS (clients, messages, load)  |
| GET     | `/clients`      | Clients connectés (user, ip, subscriptions)  |
| GET     | `/acl`          | ACL actuelle (lecture)                       |
| POST    | `/acl/reload`   | Rechargement ACL sans restart                |
| POST    | `/config/apply` | Run 4R : applique config shadow → active     |
| POST    | `/config/rollback` | Rollback vers backup précédent            |

---

## 10. debian/control — secubox-zigbee

```text
Source: secubox-zigbee
Section: net
Priority: optional
Maintainer: Gérald Kerma / CyberMind <gk@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://cybermind.fr/secubox
Rules-Requires-Root: no

Package: secubox-zigbee
Architecture: all
Depends: ${misc:Depends},
 secubox-core (>= 2.0),
 secubox-mqtt (>= 2.4),
 secubox-zkp-auth (>= 0.3),
 nodejs (>= 18),
 python3-jinja2,
 python3-toml,
 python3-fastapi,
 python3-uvicorn,
 udev
Recommends: secubox-iot-hub
Description: SecuBox Zigbee — Coordinateur RF IoT (MIND module)
 Intègre zigbee2mqtt comme daemon SecuBox, avec udev rule pour la clé
 Sonoff CC2652P / ConBee II sur MOCHAbin Armada 7040. Expose une API
 FastAPI /api/v1/zigbee pour la gestion du réseau maillé Zigbee.
 .
 Fait partie du chemin Hamiltonien SecuBox-Deb v2.4.0 :
 AUTH -> WALL -> BOOT -> MIND -> ROOT -> MESH
 .
 Licence : CMSD-1.0 (code CyberMind) + Apache-2.0 (zigbee2mqtt amont).
 Juridiction : Cour d'appel de Chambéry.
```

---

## 11. debian/postinst — secubox-zigbee (squelette)

```bash
#!/bin/bash
set -e

TOML=/etc/secubox/zigbee.toml
Z2M_CONF=/var/lib/secubox/zigbee/configuration.yaml
LOG=/var/log/secubox
RUNDIR=/run/secubox

case "$1" in
  configure)
    id secubox &>/dev/null || \
      adduser --system --group --no-create-home \
              --home /var/lib/secubox --shell /usr/sbin/nologin secubox

    usermod -aG dialout secubox

    install -d -o secubox -g secubox -m 750 \
      /var/lib/secubox/zigbee \
      "$LOG" "$RUNDIR"

    [ -f "$TOML" ] || install -o secubox -g secubox -m 640 \
      /usr/share/secubox/zigbee/zigbee.toml.default "$TOML"

    if [ ! -f "$Z2M_CONF" ]; then
      python3 /usr/lib/secubox/zigbee/scripts/gen_config.py \
        --toml "$TOML" --out "$Z2M_CONF"
      chown secubox:secubox "$Z2M_CONF"
      chmod 640 "$Z2M_CONF"
    fi

    udevadm control --reload-rules
    udevadm trigger --subsystem-match=tty

    systemctl daemon-reload
    systemctl enable secubox-zigbee.service
    ;;

  abort-upgrade|abort-remove|abort-deconfigure)
    ;;
esac

exit 0
```

---

## 12. Tests pytest obligatoires

```python
# tests/test_zigbee_api.py
import pytest
from fastapi.testclient import TestClient
from api.main import app
from unittest.mock import AsyncMock, patch

client = TestClient(app)

def test_health_no_auth():
    """Sans JWT → 401."""
    r = client.get("/api/v1/zigbee/health")
    assert r.status_code == 401

def test_health_ok(mock_jwt, mock_z2m_online):
    """Avec JWT valide et z2m up → 200."""
    r = client.get("/api/v1/zigbee/health",
                   headers={"Authorization": f"Bearer {mock_jwt}"})
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

def test_permit_join_rejected_in_lockdown(mock_jwt_lockdown):
    """permit_join refusé si posture LOCKDOWN."""
    r = client.post("/api/v1/zigbee/permit_join",
                    json={"value": True, "time": 60},
                    headers={"Authorization": f"Bearer {mock_jwt_lockdown}"})
    assert r.status_code == 403

def test_devices_list(mock_jwt, mock_14_devices):
    r = client.get("/api/v1/zigbee/devices",
                   headers={"Authorization": f"Bearer {mock_jwt}"})
    assert r.status_code == 200
    assert len(r.json()) == 14

def test_rename_device(mock_jwt, mock_z2m_online):
    r = client.post("/api/v1/zigbee/rename",
                    json={"from": "0xABCD1234", "to": "capteur_salon"},
                    headers={"Authorization": f"Bearer {mock_jwt}"})
    assert r.status_code == 200

def test_topology_structure(mock_jwt, mock_topology):
    r = client.get("/api/v1/zigbee/topology",
                   headers={"Authorization": f"Bearer {mock_jwt}"})
    data = r.json()
    assert "nodes" in data
    assert "links" in data
    for link in data["links"]:
        assert "lqi" in link
        assert "source" in link
        assert "target" in link
```

---

## 13. Livrables attendus de l'agent

```text
LIVRABLES secubox-mqtt :
[ ] packages/secubox-mqtt/api/main.py
[ ] packages/secubox-mqtt/api/routers/status.py
[ ] packages/secubox-mqtt/api/routers/acl.py
[ ] packages/secubox-mqtt/api/routers/config.py
[ ] packages/secubox-mqtt/conf/mosquitto.conf.j2
[ ] packages/secubox-mqtt/conf/acl.conf.j2
[ ] packages/secubox-mqtt/debian/control
[ ] packages/secubox-mqtt/debian/rules
[ ] packages/secubox-mqtt/debian/postinst
[ ] packages/secubox-mqtt/debian/prerm
[ ] packages/secubox-mqtt/debian/secubox-mqtt.service
[ ] packages/secubox-mqtt/tests/test_mqtt_api.py

LIVRABLES secubox-zigbee :
[ ] packages/secubox-zigbee/udev/99-secubox-zigbee.rules
[ ] packages/secubox-zigbee/conf/zigbee.toml.default
[ ] packages/secubox-zigbee/conf/z2m_configuration.yaml.j2
[ ] packages/secubox-zigbee/scripts/gen_config.py
[ ] packages/secubox-zigbee/scripts/preflight.sh
[ ] packages/secubox-zigbee/api/main.py
[ ] packages/secubox-zigbee/api/routers/devices.py
[ ] packages/secubox-zigbee/api/routers/network.py
[ ] packages/secubox-zigbee/api/routers/ota.py
[ ] packages/secubox-zigbee/api/routers/config.py
[ ] packages/secubox-zigbee/api/z2m_bridge.py
[ ] packages/secubox-zigbee/api/schemas.py
[ ] packages/secubox-zigbee/debian/control
[ ] packages/secubox-zigbee/debian/rules
[ ] packages/secubox-zigbee/debian/postinst
[ ] packages/secubox-zigbee/debian/prerm
[ ] packages/secubox-zigbee/debian/secubox-zigbee.service
[ ] packages/secubox-zigbee/tests/test_zigbee_api.py
[ ] docs/wiki/secubox-zigbee-mqtt.md  (FR, format wiki SecuBox)
```

---

## 14. Critères d'acceptation (Definition of Done)

- `pytest packages/secubox-zigbee/tests/ -v` → 0 failures
- `pytest packages/secubox-mqtt/tests/ -v` → 0 failures
- `dpkg-buildpackage -us -uc` réussit pour les deux paquets
- `apt install ./secubox-zigbee_2.4.0_all.deb` sur MOCHAbin sans erreur
- Après plug de la clé Sonoff : `ls -la /dev/secubox-zgb` → symlink présent
- `systemctl status secubox-zigbee` → active (running) en moins de 15s
- `curl --unix-socket /run/secubox/zigbee.sock http://localhost/health` → 200
- `mosquitto_pub -h 127.0.0.1 -u z2m -P <pwd> -t 'test' -m 'ok'` → succès
- `mosquitto_pub -h 127.0.0.1 -u invalid -P wrong -t 'test' -m 'x'` → Connection refused

---

## Annexe A — Chemin Hamiltonien et ordering systemd

```text
AUTH (secubox-zkp-auth)
  └→ WALL (secubox-nftables, secubox-mqtt)    ← secubox-mqtt ici
       └→ BOOT (secubox-boot-verify)
            └→ MIND (secubox-sentinelle, secubox-zigbee)  ← secubox-zigbee ici
                 └→ ROOT (secubox-fastapi)
                      └→ MESH (secubox-wireguard, secubox-tailscale)

Shutdown : ordre inverse (MESH → ROOT → MIND → BOOT → WALL → AUTH)
```

## Annexe B — Canaux Zigbee vs Wi-Fi 2.4 GHz

| Canal Zigbee | Fréquence centre | Chevauchement Wi-Fi |
|--------------|-----------------|---------------------|
| 11           | 2405 MHz        | Canal Wi-Fi 1 — éviter si AP ch1 |
| 15           | 2425 MHz        | Pas de chevauchement — OK |
| 20           | 2450 MHz        | Pas de chevauchement — **défaut SecuBox** |
| 25           | 2475 MHz        | Léger ch11 |
| 26           | 2480 MHz        | Pas de chevauchement — OK Europe |

**Défaut SecuBox : canal 20** (compromise entre couverture et interférences).
Si `auto_scan_channel = true` dans `zigbee.toml`, le postinst lance
`python3 scripts/scan_channel.py` (RTL-SDR requis) et choisit le canal
avec le moins d'énergie reçue.
