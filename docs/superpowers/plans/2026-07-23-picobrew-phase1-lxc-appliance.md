# secubox-picobrew — Phase 1 : le LXC qui redonne vie à l'appareil

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** faire revivre un appareil PicoBrew dont le cloud constructeur est éteint, via un LXC Debian hébergeant `picobrew_pico`, piloté par un ctl root audité et un panel SecuBox.

**Architecture :** un LXC Debian (`picobrew`, `10.100.0.140`) provisionné par `picobrewctl` (debootstrap + venv Python + unit systemd interne). Un drop-in Unbound réécrit `picobrew.com` vers ce LXC. Le panel non privilégié délègue toute action root à `picobrewctl` via un sudoers à commande exacte.

**Tech Stack :** Bash (ctl), Python 3.11 + FastAPI (API de gestion), LXC + debootstrap bookworm, Unbound, nginx, pytest.

**Spec :** `docs/superpowers/specs/2026-07-23-picobrew-brewing-suite-design.md`

## Global Constraints

- Conteneur `picobrew`, IP `10.100.0.140/24`, `LXC_PATH=/data/lxc`, bridge `br-lxc`, passerelle `10.100.0.1`.
- Upstream : `https://github.com/chiefwigms/picobrew_pico` — cloné **latest à l'installation**, puis **SHA figé** dans `/var/lib/secubox/picobrew/pinned-sha`.
- **Aucune mise à jour implicite.** `update` est explicite et **refusé si une session est active**.
- **Natif, jamais Docker** : venv Python + unit systemd dans le LXC.
- Drop-in DNS `picobrew.com` → `10.100.0.140` **actif par défaut**.
- Le panel n'exécute **jamais** d'action privilégiée : tout passe par `sudo /usr/sbin/picobrewctl`.
- **Ne JAMAIS chown les parents partagés** : `/run/secubox` reste `1777 root:root`, `/etc/secubox` et `/var/log/secubox` restent `0755`. Créer un sous-répertoire dédié, jamais toucher le parent.
- Tout script shell : `set -uo pipefail` (pas `-e` : il masque les codes de retour des helpers LXC).
- En-tête SPDX `LicenseRef-CMSD-1.0` en tête de chaque fichier créé.
- La phase 1 ne touche **pas** aux capteurs : le contrôleur existant est déplacé intact (Task 2), il sera réactivé en phase 2.

## File Structure

| Fichier | Responsabilité |
|---|---|
| `sbin/picobrewctl` | Seule surface privilégiée : cycle de vie du LXC, install, update, status |
| `lib/stillwatch/legacy_controller.py` | Les 992 lignes de capteurs, **déplacées intactes**, non livrées en phase 1 |
| `api/main.py` | API de gestion mince : délègue au ctl, expose l'état |
| `www/picobrew/index.html` | Panel : état, actions |
| `conf/unbound-picobrew.conf` | Drop-in DNS |
| `debian/secubox-picobrew.sudoers` | Grant exact panel → ctl |
| `tests/test_picobrewctl_guards.sh` | Gardes et validateurs du ctl |
| `tests/test_ctl_config.py` | Génération de la config LXC + logique de SHA/session |
| `tests/test_api_management.py` | API de gestion |

---

### Task 1 : `picobrewctl` — squelette, validateurs, `status`

**Files:**
- Create: `packages/secubox-picobrew/sbin/picobrewctl`
- Test: `packages/secubox-picobrew/tests/test_picobrewctl_guards.sh`

**Interfaces:**
- Produces: `picobrewctl {status [--json]|start|stop|install|update|logs}` ; entrypoint caché `__guard <kind> <value>` (kinds : `sha`, `session`) utilisé par les tests.

- [ ] **Step 1 : écrire le test de gardes qui échoue**

```bash
#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Exercise picobrewctl validators via the hidden __guard entrypoint.
set -u
CTL="$(dirname "$0")/../sbin/picobrewctl"
fail=0
ok() { "$CTL" __guard "$1" "$2" >/dev/null 2>&1 && echo "PASS accept $1 '$2'" || { echo "FAIL should-accept $1 '$2'"; fail=1; }; }
no() { "$CTL" __guard "$1" "$2" >/dev/null 2>&1 && { echo "FAIL should-reject $1 '$2'"; fail=1; } || echo "PASS reject $1 '$2'"; }

# A pinned SHA is exactly 40 lowercase hex chars — anything else could be a
# crafted ref that makes `git checkout` fetch attacker-chosen code.
ok sha "0123456789abcdef0123456789abcdef01234567"
no sha "HEAD"
no sha "main"
no sha "0123456789abcdef0123456789abcdef0123456"      # 39 — trop court
no sha "0123456789ABCDEF0123456789ABCDEF01234567"     # majuscules
no sha "v1.0; rm -rf /"

# Unknown subcommand must not silently succeed.
"$CTL" definitely-not-a-command >/dev/null 2>&1 && { echo "FAIL unknown cmd accepted"; fail=1; } || echo "PASS reject unknown cmd"
exit $fail
```

- [ ] **Step 2 : lancer le test, vérifier qu'il échoue**

Run: `bash packages/secubox-picobrew/tests/test_picobrewctl_guards.sh`
Expected: FAIL — le fichier `sbin/picobrewctl` n'existe pas encore.

- [ ] **Step 3 : implémenter le ctl minimal**

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# SecuBox-Deb :: picobrewctl — cycle de vie du LXC PicoBrew.
#
# `set -e` est volontairement absent : les helpers LXC renvoient des codes non
# nuls attendus (conteneur arrêté, absent), et -e les transformerait en abandon.
set -uo pipefail

readonly CONTAINER="picobrew"
readonly LXC_PATH="/data/lxc"
readonly LXC_BRIDGE="br-lxc"
readonly LXC_IP="10.100.0.140"
readonly LXC_GW="10.100.0.1"
readonly STATE_DIR="/var/lib/secubox/picobrew"
readonly PIN_FILE="$STATE_DIR/pinned-sha"
readonly SESSION_FILE="$STATE_DIR/session.active"
readonly UPSTREAM="https://github.com/chiefwigms/picobrew_pico"

err() { echo "[ERROR] $*" >&2; }

_valid_sha()     { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }
_session_active() { [ -e "$SESSION_FILE" ]; }

lxc_exists()  { [ -d "$LXC_PATH/$CONTAINER/rootfs" ]; }
lxc_running() { local s; s=$(lxc-info -n "$CONTAINER" -P "$LXC_PATH" 2>/dev/null); [[ "$s" == *"State:"*"RUNNING"* ]]; }
lxc_attach()  { local cmd="$1"; shift; lxc-attach -n "$CONTAINER" -P "$LXC_PATH" -- sh -c "$cmd" _ "$@"; }

cmd_status() {
    local installed=false running=false sha="none"
    lxc_exists   && installed=true
    lxc_running  && running=true
    [ -r "$PIN_FILE" ] && sha=$(cat "$PIN_FILE")
    if [ "${1:-}" = "--json" ]; then
        printf '{"installed":%s,"running":%s,"ip":"%s","pinned_sha":"%s","session_active":%s}\n' \
            "$installed" "$running" "$LXC_IP" "$sha" \
            "$(_session_active && echo true || echo false)"
    else
        echo "installed=$installed running=$running ip=$LXC_IP sha=$sha"
    fi
}

cmd_start() { lxc_exists || { err "not installed"; return 1; }; lxc-start -n "$CONTAINER" -P "$LXC_PATH" 2>/dev/null; sleep 1; lxc_running; }
cmd_stop()  { lxc-stop -n "$CONTAINER" -P "$LXC_PATH" 2>/dev/null; ! lxc_running; }
cmd_logs()  { lxc_running || { err "container not running"; return 1; }; lxc_attach 'journalctl -u picobrew --no-pager -n 100'; }

usage() { echo "usage: picobrewctl {install|start|stop|status [--json]|update <sha>|logs}" >&2; }

case "${1:-}" in
    __guard) shift; case "${1:-}" in
                 sha)     _valid_sha "${2:-}" ;;
                 session) _session_active ;;
                 *)       exit 1 ;;
             esac ;;
    status)  shift; cmd_status "${1:-}" ;;
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    logs)    cmd_logs ;;
    *)       usage; exit 1 ;;
esac
```

- [ ] **Step 4 : rendre exécutable, relancer le test**

Run:
```bash
chmod +x packages/secubox-picobrew/sbin/picobrewctl
bash packages/secubox-picobrew/tests/test_picobrewctl_guards.sh
```
Expected: toutes les lignes `PASS`, code de sortie 0.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-picobrew/sbin/picobrewctl packages/secubox-picobrew/tests/test_picobrewctl_guards.sh
git commit -m "feat(picobrew): picobrewctl — squelette, validateurs et status"
```

---

### Task 2 : préserver le contrôleur de capteurs, réécrire l'API de gestion

Les 992 lignes de capteurs ne sont **pas** supprimées : elles sont déplacées pour être reprises telles quelles en phase 2. `api/main.py` devient une API de gestion mince.

**Files:**
- Move: `packages/secubox-picobrew/api/main.py` → `packages/secubox-picobrew/lib/stillwatch/legacy_controller.py`
- Create: `packages/secubox-picobrew/api/main.py`
- Test: `packages/secubox-picobrew/tests/test_api_management.py`

**Interfaces:**
- Consumes: `picobrewctl status --json` (Task 1).
- Produces: `GET /api/v1/picobrew/status` → `{"installed":bool,"running":bool,"ip":str,"pinned_sha":str,"session_active":bool}` ; `POST /api/v1/picobrew/{start,stop}`.

- [ ] **Step 1 : déplacer le contrôleur sans le modifier**

```bash
mkdir -p packages/secubox-picobrew/lib/stillwatch
git mv packages/secubox-picobrew/api/main.py packages/secubox-picobrew/lib/stillwatch/legacy_controller.py
```

- [ ] **Step 2 : écrire le test de l'API qui échoue**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
from unittest.mock import patch
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

def test_status_reflects_ctl_output():
    """L'API ne devine rien : elle relaie le verdict du ctl."""
    payload = json.dumps({"installed": True, "running": False, "ip": "10.100.0.140",
                          "pinned_sha": "0123456789abcdef0123456789abcdef01234567",
                          "session_active": False})
    with patch("api.main._ctl", return_value=(0, payload)):
        r = client.get("/status")
    assert r.status_code == 200
    assert r.json()["installed"] is True and r.json()["running"] is False
    assert r.json()["ip"] == "10.100.0.140"

def test_status_degrades_cleanly_when_ctl_fails():
    """Un ctl indisponible ne doit pas 500 le panel : état inconnu, pas de crash."""
    with patch("api.main._ctl", return_value=(1, "")):
        r = client.get("/status")
    assert r.status_code == 200
    assert r.json()["installed"] is False
    assert r.json()["error"]

def test_start_delegates_to_ctl_and_never_runs_privileged_itself():
    with patch("api.main._ctl", return_value=(0, "")) as m:
        r = client.post("/start")
    assert r.status_code == 200
    assert m.call_args[0][0] == ["start"]
```

- [ ] **Step 3 : lancer le test, vérifier qu'il échoue**

Run: `cd packages/secubox-picobrew && python3 -m pytest tests/test_api_management.py -q`
Expected: FAIL — `ModuleNotFoundError` / `app` introuvable (l'ancien `main.py` a été déplacé).

- [ ] **Step 4 : écrire l'API de gestion**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: PicoBrew — API de gestion.
CyberMind — https://cybermind.fr

Cette API ne fait AUCUNE action privilégiée : elle délègue à picobrewctl via
sudo. C'est la règle du dépôt — une seule surface root, auditée.
"""
import json
import subprocess
from fastapi import APIRouter, FastAPI

CTL = "/usr/sbin/picobrewctl"

app = FastAPI(title="SecuBox PicoBrew")
router = APIRouter()


def _ctl(args: list[str], timeout: int = 20) -> tuple[int, str]:
    """Exécute picobrewctl via sudo. Renvoie (code, stdout).

    Ne lève jamais : un ctl absent, lent ou en erreur doit dégrader le panel,
    pas le faire tomber.
    """
    try:
        p = subprocess.run(["sudo", "-n", CTL, *args],
                           capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


@router.get("/status")
async def status() -> dict:
    rc, out = _ctl(["status", "--json"])
    if rc != 0 or not out:
        return {"installed": False, "running": False, "ip": "", "pinned_sha": "none",
                "session_active": False, "error": "picobrewctl indisponible"}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"installed": False, "running": False, "ip": "", "pinned_sha": "none",
                "session_active": False, "error": "réponse ctl illisible"}


@router.post("/start")
async def start() -> dict:
    rc, _ = _ctl(["start"])
    return {"ok": rc == 0}


@router.post("/stop")
async def stop() -> dict:
    rc, _ = _ctl(["stop"])
    return {"ok": rc == 0}


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


app.include_router(router)
```

- [ ] **Step 5 : relancer le test**

Run: `cd packages/secubox-picobrew && python3 -m pytest tests/test_api_management.py -q`
Expected: `3 passed`.

- [ ] **Step 6 : commit**

```bash
git add -A packages/secubox-picobrew/api packages/secubox-picobrew/lib packages/secubox-picobrew/tests
git commit -m "feat(picobrew): API de gestion déléguant au ctl; contrôleur capteurs préservé pour la phase 2"
```

---

### Task 3 : génération de la config LXC (testable sans LXC)

Le provisionnement réel exige `debootstrap` et les droits root : il n'est pas testable en unitaire. On rend donc **la génération de config** testable séparément, car c'est là que vivent les erreurs silencieuses (mauvaise IP, bridge absent).

**Files:**
- Modify: `packages/secubox-picobrew/sbin/picobrewctl`
- Test: `packages/secubox-picobrew/tests/test_ctl_config.py`

**Interfaces:**
- Produces: `picobrewctl __emit-config` → écrit la config LXC sur stdout (aucun effet de bord).

- [ ] **Step 1 : écrire le test qui échoue**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import subprocess
from pathlib import Path

CTL = str(Path(__file__).resolve().parents[1] / "sbin" / "picobrewctl")

def _emit() -> str:
    p = subprocess.run(["bash", CTL, "__emit-config"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p.stdout

def test_config_pins_the_allocated_ip_and_bridge():
    """Une IP erronée ici = conteneur injoignable, sans erreur visible."""
    cfg = _emit()
    assert "lxc.net.0.ipv4.address = 10.100.0.140/24" in cfg
    assert "lxc.net.0.ipv4.gateway = 10.100.0.1" in cfg
    assert "lxc.net.0.link = br-lxc" in cfg

def test_config_starts_container_automatically():
    """L'appareil doit revivre après un reboot de la box sans geste humain."""
    assert "lxc.start.auto = 1" in _emit()

def test_config_declares_rootfs_and_hostname():
    cfg = _emit()
    assert "lxc.rootfs.path = dir:/data/lxc/picobrew/rootfs" in cfg
    assert "lxc.uts.name = picobrew" in cfg
```

- [ ] **Step 2 : lancer, vérifier l'échec**

Run: `cd packages/secubox-picobrew && python3 -m pytest tests/test_ctl_config.py -q`
Expected: FAIL — `__emit-config` inconnu, code de retour 1.

- [ ] **Step 3 : ajouter `_emit_lxc_config` et son entrypoint**

Insérer avant `usage()` dans `sbin/picobrewctl` :

```bash
_emit_lxc_config() {
    cat <<EOF
lxc.include = /usr/share/lxc/config/debian.common.conf
lxc.arch = linux64
lxc.uts.name = $CONTAINER
lxc.rootfs.path = dir:$LXC_PATH/$CONTAINER/rootfs
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.name = eth0
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW
lxc.start.auto = 1
lxc.start.delay = 5
lxc.cgroup2.memory.max = 1024M
EOF
}
```

Et ajouter la branche dans le `case` (avant `*)`) :

```bash
    __emit-config) _emit_lxc_config ;;
```

- [ ] **Step 4 : relancer**

Run: `cd packages/secubox-picobrew && python3 -m pytest tests/test_ctl_config.py -q`
Expected: `3 passed`.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-picobrew/sbin/picobrewctl packages/secubox-picobrew/tests/test_ctl_config.py
git commit -m "feat(picobrew): génération testable de la config LXC"
```

---

### Task 4 : `install` — provisionner le LXC et picobrew_pico, figer le SHA

**Files:**
- Modify: `packages/secubox-picobrew/sbin/picobrewctl`

**Interfaces:**
- Consumes: `_emit_lxc_config` (Task 3).
- Produces: `picobrewctl install` ; écrit le SHA dans `/var/lib/secubox/picobrew/pinned-sha`.

- [ ] **Step 1 : implémenter `cmd_install`**

Insérer avant `usage()` :

```bash
cmd_install() {
    [ "$(id -u)" -eq 0 ] || { err "root requis"; return 1; }
    mkdir -p "$LXC_PATH/$CONTAINER" "$STATE_DIR"

    if [ ! -x "$LXC_PATH/$CONTAINER/rootfs/bin/bash" ]; then
        echo "[picobrew] debootstrap bookworm…"
        debootstrap --variant=minbase \
            --include=systemd,systemd-sysv,dbus,ca-certificates,iproute2,python3,python3-venv,python3-pip,git,nginx,openssl \
            bookworm "$LXC_PATH/$CONTAINER/rootfs" http://deb.debian.org/debian \
            || { err "debootstrap a échoué"; return 1; }
    fi

    echo "$CONTAINER" > "$LXC_PATH/$CONTAINER/rootfs/etc/hostname"
    printf 'nameserver %s\nnameserver 1.1.1.1\n' "$LXC_GW" > "$LXC_PATH/$CONTAINER/rootfs/etc/resolv.conf"
    _emit_lxc_config > "$LXC_PATH/$CONTAINER/config"

    lxc_running || lxc-start -n "$CONTAINER" -P "$LXC_PATH" 2>/dev/null
    sleep 3

    echo "[picobrew] clonage de picobrew_pico (latest)…"
    lxc_attach 'set -e
        [ -d /opt/picobrew_pico/.git ] || git clone --depth 1 '"$UPSTREAM"' /opt/picobrew_pico
        cd /opt/picobrew_pico
        [ -d .venv ] || python3 -m venv .venv
        .venv/bin/pip install --quiet --upgrade pip
        .venv/bin/pip install --quiet -r requirements.txt' \
        || { err "installation de picobrew_pico échouée"; return 1; }

    # Figer le SHA : une mise à jour upstream ne doit JAMAIS survenir toute
    # seule sur une machine qui chauffe du moût.
    local sha
    sha=$(lxc_attach 'git -C /opt/picobrew_pico rev-parse HEAD' 2>/dev/null | tr -d '\r\n')
    if _valid_sha "$sha"; then
        printf '%s\n' "$sha" > "$PIN_FILE"
        echo "[picobrew] SHA figé : $sha"
    else
        err "SHA upstream illisible — installation abandonnée"
        return 1
    fi

    _install_service_unit
    lxc_attach 'systemctl daemon-reload && systemctl enable --now picobrew' \
        || { err "démarrage du service picobrew échoué"; return 1; }
    echo "[picobrew] installation terminée"
}

_install_service_unit() {
    cat > "$LXC_PATH/$CONTAINER/rootfs/etc/systemd/system/picobrew.service" <<'EOF'
[Unit]
Description=PicoBrew server (picobrew_pico)
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/picobrew_pico
ExecStart=/opt/picobrew_pico/.venv/bin/python server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}
```

Ajouter dans le `case` :

```bash
    install) cmd_install ;;
```

- [ ] **Step 2 : vérifier que le ctl reste syntaxiquement valide et que les gardes passent toujours**

Run:
```bash
bash -n packages/secubox-picobrew/sbin/picobrewctl && echo "syntaxe OK"
bash packages/secubox-picobrew/tests/test_picobrewctl_guards.sh
cd packages/secubox-picobrew && python3 -m pytest tests/test_ctl_config.py -q
```
Expected: `syntaxe OK`, toutes les gardes `PASS`, `3 passed`.

> **Note d'honnêteté :** `install` n'est pas couvert par un test unitaire — il exige `debootstrap`, le réseau et root. Sa validation est manuelle (Task 8, recette de vérification). Les parties *décidables* (config, SHA, gardes) sont elles testées.

- [ ] **Step 3 : commit**

```bash
git add packages/secubox-picobrew/sbin/picobrewctl
git commit -m "feat(picobrew): install — LXC Debian, picobrew_pico en venv, SHA figé"
```

---

### Task 5 : `update` explicite, refusé pendant une session

**Files:**
- Modify: `packages/secubox-picobrew/sbin/picobrewctl`
- Test: `packages/secubox-picobrew/tests/test_ctl_update_guard.py`

**Interfaces:**
- Produces: `picobrewctl update <sha>` ; refuse si `/var/lib/secubox/picobrew/session.active` existe.

- [ ] **Step 1 : écrire le test qui échoue**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Une mise à jour en plein brassage est inacceptable : la machine chauffe du
moût. On vérifie que le refus est inconditionnel et antérieur à toute action."""
import subprocess, os
from pathlib import Path

CTL = str(Path(__file__).resolve().parents[1] / "sbin" / "picobrewctl")
SHA = "0123456789abcdef0123456789abcdef01234567"

def _run(args, session_file):
    env = dict(os.environ, PICOBREW_SESSION_FILE=str(session_file))
    return subprocess.run(["bash", CTL, *args], capture_output=True, text=True, env=env)

def test_update_refuses_while_a_session_is_active(tmp_path):
    s = tmp_path / "session.active"; s.write_text("brewing")
    p = _run(["update", SHA], s)
    assert p.returncode != 0
    assert "session" in (p.stderr + p.stdout).lower()

def test_update_rejects_a_non_sha_ref(tmp_path):
    s = tmp_path / "none"
    p = _run(["update", "main"], s)
    assert p.returncode != 0

def test_update_requires_an_explicit_ref(tmp_path):
    s = tmp_path / "none"
    p = _run(["update"], s)
    assert p.returncode != 0
```

- [ ] **Step 2 : lancer, vérifier l'échec**

Run: `cd packages/secubox-picobrew && python3 -m pytest tests/test_ctl_update_guard.py -q`
Expected: FAIL — `update` non implémenté (usage + exit 1 ne mentionne pas « session »).

- [ ] **Step 3 : rendre le chemin de session surchargeable et implémenter `update`**

Remplacer la ligne `readonly SESSION_FILE=...` par :

```bash
readonly SESSION_FILE="${PICOBREW_SESSION_FILE:-$STATE_DIR/session.active}"
```

Ajouter avant `usage()` :

```bash
cmd_update() {
    local sha="${1:-}"
    [ -n "$sha" ] || { err "SHA requis : picobrewctl update <sha>"; return 1; }
    _valid_sha "$sha" || { err "SHA invalide (40 hex minuscules attendus)"; return 1; }
    if _session_active; then
        err "session de brassage active — mise à jour refusée"
        return 1
    fi
    [ "$(id -u)" -eq 0 ] || { err "root requis"; return 1; }
    lxc_running || { err "conteneur arrêté"; return 1; }
    lxc_attach 'set -e
        cd /opt/picobrew_pico
        git fetch --depth 1 origin "$1"
        git checkout --detach "$1"
        .venv/bin/pip install --quiet -r requirements.txt' _ "$sha" \
        || { err "mise à jour échouée"; return 1; }
    printf '%s\n' "$sha" > "$PIN_FILE"
    lxc_attach 'systemctl restart picobrew'
    echo "[picobrew] mis à jour vers $sha"
}
```

Ajouter dans le `case` :

```bash
    update) shift; cmd_update "${1:-}" ;;
```

- [ ] **Step 4 : relancer**

Run: `cd packages/secubox-picobrew && python3 -m pytest tests/test_ctl_update_guard.py -q`
Expected: `3 passed`.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-picobrew/sbin/picobrewctl packages/secubox-picobrew/tests/test_ctl_update_guard.py
git commit -m "feat(picobrew): update explicite, refusé pendant une session de brassage"
```

---

### Task 6 : drop-in DNS Unbound, actif par défaut

**Files:**
- Create: `packages/secubox-picobrew/conf/unbound-picobrew.conf`
- Test: `packages/secubox-picobrew/tests/test_dns_dropin.py`

**Interfaces:**
- Produces: fichier installé en `/etc/unbound/unbound.conf.d/secubox-picobrew.conf`.

- [ ] **Step 1 : écrire le test qui échoue**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Le cloud PicoBrew est éteint depuis 2020 : l'appareil ne sait parler qu'à
picobrew.com. Sans cette réécriture locale, il reste briqué."""
from pathlib import Path

CONF = Path(__file__).resolve().parents[1] / "conf" / "unbound-picobrew.conf"

def test_dropin_redirects_picobrew_com_to_the_lxc():
    t = CONF.read_text()
    assert "local-zone:" in t and '"picobrew.com."' in t
    assert "10.100.0.140" in t

def test_dropin_is_scoped_to_picobrew_only():
    """Une zone trop large casserait d'autres résolutions."""
    t = CONF.read_text()
    for forbidden in ('local-zone: "." ', 'local-zone: "com."'):
        assert forbidden not in t
```

- [ ] **Step 2 : lancer, vérifier l'échec**

Run: `cd packages/secubox-picobrew && python3 -m pytest tests/test_dns_dropin.py -q`
Expected: FAIL — `FileNotFoundError`.

- [ ] **Step 3 : écrire le drop-in**

```text
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: PicoBrew — réécriture DNS locale.
#
# Le cloud PicoBrew a été éteint par le constructeur en 2020, laissant les
# appareils inutilisables : ils ne savent contacter que picobrew.com. On
# réécrit donc cette zone vers le LXC local, qui parle le même protocole.
#
# Portée volontairement étroite : SEULE picobrew.com est redirigée.
server:
    local-zone: "picobrew.com." redirect
    local-data: "picobrew.com. IN A 10.100.0.140"
```

- [ ] **Step 4 : relancer**

Run: `cd packages/secubox-picobrew && python3 -m pytest tests/test_dns_dropin.py -q`
Expected: `2 passed`.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-picobrew/conf/unbound-picobrew.conf packages/secubox-picobrew/tests/test_dns_dropin.py
git commit -m "feat(picobrew): drop-in DNS Unbound redirigeant picobrew.com vers le LXC"
```

---

### Task 7 : panel webui

**Files:**
- Modify: `packages/secubox-picobrew/www/picobrew/index.html`

- [ ] **Step 1 : remplacer le contenu par le panel**

```html
<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<meta charset="utf-8">
<title>SecuBox — PicoBrew</title>
<style>
  body { background:#0a0a0f; color:#e8e6d9; font-family:system-ui,sans-serif; margin:0; padding:1.5rem; }
  h1 { color:#c9a84c; font-size:1.3rem; margin:0 0 1rem; }
  .kv { display:flex; gap:.6rem; padding:.35rem 0; border-bottom:1px solid #1e1e2a; }
  .k { color:#6b6b7a; min-width:11rem; } .v { color:#e8e6d9; }
  .on { color:#00ff41; } .off { color:#e63946; }
  button { background:#1e1e2a; color:#e8e6d9; border:1px solid #6e40c9; border-radius:4px;
           padding:.45rem .9rem; margin-right:.5rem; cursor:pointer; }
  button:hover { border-color:#00d4ff; }
  .warn { color:#c9a84c; font-size:.82rem; margin-top:1rem; }
</style>
<h1>🍺 PicoBrew</h1>
<div id="state"><div class="kv"><span class="k">chargement…</span></div></div>
<div style="margin-top:1rem">
  <button onclick="act('start')">Démarrer</button>
  <button onclick="act('stop')">Arrêter</button>
  <button onclick="load()">Rafraîchir</button>
</div>
<div class="warn" id="warn"></div>
<script>
const API = '/api/v1/picobrew';
async function load() {
  const el = document.getElementById('state');
  try {
    const d = await (await fetch(API + '/status', {credentials:'same-origin'})).json();
    const b = (x) => x ? '<span class="on">oui</span>' : '<span class="off">non</span>';
    el.innerHTML =
      `<div class="kv"><span class="k">Conteneur installé</span><span class="v">${b(d.installed)}</span></div>` +
      `<div class="kv"><span class="k">En marche</span><span class="v">${b(d.running)}</span></div>` +
      `<div class="kv"><span class="k">Adresse</span><span class="v">${d.ip || '—'}</span></div>` +
      `<div class="kv"><span class="k">Version figée (SHA)</span><span class="v"><code>${(d.pinned_sha||'none').slice(0,12)}</code></span></div>` +
      `<div class="kv"><span class="k">Session de brassage</span><span class="v">${b(d.session_active)}</span></div>`;
    document.getElementById('warn').textContent = d.session_active
      ? 'Session active : les mises à jour sont refusées tant qu\'elle dure.'
      : (d.error || '');
  } catch (e) { el.innerHTML = '<div class="kv"><span class="k off">panel injoignable</span></div>'; }
}
async function act(a) {
  await fetch(API + '/' + a, {method:'POST', credentials:'same-origin'});
  setTimeout(load, 1200);
}
load();
</script>
```

- [ ] **Step 2 : vérifier que le HTML est bien formé**

Run: `python3 -c "import html.parser,sys; p=html.parser.HTMLParser(); p.feed(open('packages/secubox-picobrew/www/picobrew/index.html').read()); print('HTML OK')"`
Expected: `HTML OK`

- [ ] **Step 3 : commit**

```bash
git add packages/secubox-picobrew/www/picobrew/index.html
git commit -m "feat(picobrew): panel — état du LXC, version figée, actions"
```

---

### Task 8 : TLS pour la série Z (nginx dans le LXC)

La série Z ne parle qu'en HTTPS : sans terminaison TLS, un appareil Z ne peut pas s'enregistrer du tout. Flask reste en clair sur `127.0.0.1:80` ; nginx, **dans le LXC**, termine le TLS sur `:443`.

**Files:**
- Modify: `packages/secubox-picobrew/sbin/picobrewctl`
- Test: `packages/secubox-picobrew/tests/test_ctl_tls.py`

**Interfaces:**
- Consumes: `cmd_install` (Task 4).
- Produces: `picobrewctl __emit-nginx` → configuration nginx du LXC sur stdout ; `_ensure_cert` génère un certificat auto-signé si absent.

- [ ] **Step 1 : écrire le test qui échoue**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""La série Z n'accepte que HTTPS. Une terminaison TLS absente ou mal câblée
rend l'appareil inutilisable sans message d'erreur exploitable."""
import subprocess
from pathlib import Path

CTL = str(Path(__file__).resolve().parents[1] / "sbin" / "picobrewctl")

def _emit() -> str:
    p = subprocess.run(["bash", CTL, "__emit-nginx"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p.stdout

def test_nginx_terminates_tls_on_443():
    cfg = _emit()
    assert "listen 443 ssl" in cfg
    assert "ssl_certificate" in cfg and "ssl_certificate_key" in cfg

def test_nginx_proxies_to_the_local_flask_app():
    cfg = _emit()
    assert "proxy_pass http://127.0.0.1:80" in cfg

def test_nginx_does_not_bind_80_which_would_loop_onto_itself():
    """Flask occupe déjà :80 (comportement upstream attendu par Pico/Zymatic).
    Faire écouter nginx sur :80 tout en proxifiant vers 127.0.0.1:80 le ferait
    se parler à lui-même — boucle infinie. nginx ne prend QUE le 443."""
    assert "listen 80" not in _emit()
```

- [ ] **Step 2 : lancer, vérifier l'échec**

Run: `cd packages/secubox-picobrew && python3 -m pytest tests/test_ctl_tls.py -q`
Expected: FAIL — `__emit-nginx` inconnu, code de retour 1.

- [ ] **Step 3 : implémenter la config nginx et la génération de certificat**

Ajouter avant `usage()` dans `sbin/picobrewctl` :

```bash
_emit_nginx_config() {
    cat <<'EOF'
# SecuBox-Deb :: PicoBrew — terminaison TLS pour la série Z.
#
# picobrew_pico écoute déjà en clair sur :80 — c'est le comportement upstream,
# et c'est ce que les Pico/Zymatic attendent. nginx ne prend donc QUE le 443 :
# le faire écouter aussi sur :80 tout en proxifiant vers 127.0.0.1:80 le ferait
# se parler à lui-même (boucle infinie). Les appareils non-Z continuent de
# joindre Flask directement en :80.
server {
    listen 443 ssl;
    server_name picobrew.com _;
    client_max_body_size 32m;
    ssl_certificate     /etc/picobrew/tls/cert.pem;
    ssl_certificate_key /etc/picobrew/tls/key.pem;
    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
EOF
}

_ensure_cert() {
    lxc_attach 'set -e
        mkdir -p /etc/picobrew/tls
        [ -s /etc/picobrew/tls/cert.pem ] && exit 0
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -subj "/CN=picobrew.com" \
            -addext "subjectAltName=DNS:picobrew.com,DNS:*.picobrew.com" \
            -keyout /etc/picobrew/tls/key.pem \
            -out /etc/picobrew/tls/cert.pem >/dev/null 2>&1
        chmod 600 /etc/picobrew/tls/key.pem'
}
```

Ajouter la branche dans le `case` :

```bash
    __emit-nginx) _emit_nginx_config ;;
```

Et, dans `cmd_install`, juste avant `_install_service_unit`, câbler nginx :

```bash
    _ensure_cert || { err "génération du certificat échouée"; return 1; }
    _emit_nginx_config > "$LXC_PATH/$CONTAINER/rootfs/etc/nginx/sites-available/picobrew"
    lxc_attach 'ln -sf /etc/nginx/sites-available/picobrew /etc/nginx/sites-enabled/picobrew
                rm -f /etc/nginx/sites-enabled/default
                nginx -t >/dev/null 2>&1 && systemctl enable --now nginx' \
        || { err "configuration nginx invalide"; return 1; }
```

- [ ] **Step 4 : relancer et vérifier la syntaxe du ctl**

Run:
```bash
bash -n packages/secubox-picobrew/sbin/picobrewctl && echo "syntaxe OK"
cd packages/secubox-picobrew && python3 -m pytest tests/test_ctl_tls.py -q
```
Expected: `syntaxe OK` puis `3 passed`.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-picobrew/sbin/picobrewctl packages/secubox-picobrew/tests/test_ctl_tls.py
git commit -m "feat(picobrew): terminaison TLS dans le LXC pour la série Z"
```

---

### Task 9 : packaging — sudoers, rules, control, postinst, changelog

**Files:**
- Create: `packages/secubox-picobrew/debian/secubox-picobrew.sudoers`
- Modify: `packages/secubox-picobrew/debian/rules`, `debian/control`, `debian/postinst`, `debian/changelog`

- [ ] **Step 1 : créer le sudoers (seule surface privilégiée)**

```text
# Le panel (utilisateur secubox) pilote le LXC PicoBrew via picobrewctl.
# C'est la SEULE surface privilégiée du module.
secubox ALL=(root) NOPASSWD: /usr/sbin/picobrewctl
```

- [ ] **Step 2 : mettre à jour `debian/rules`**

Remplacer le bloc `override_dh_auto_install` par :

```makefile
override_dh_auto_install:
	install -d debian/secubox-picobrew/usr/share/secubox/picobrew/
	cp -r api debian/secubox-picobrew/usr/share/secubox/picobrew/
	install -d debian/secubox-picobrew/usr/share/secubox/www
	[ -d www ] && cp -r www/. debian/secubox-picobrew/usr/share/secubox/www/ || true
	install -d debian/secubox-picobrew/usr/share/secubox/menu.d
	[ -d menu.d ] && cp -r menu.d/. debian/secubox-picobrew/usr/share/secubox/menu.d/ || true
	install -d debian/secubox-picobrew/etc/nginx/secubox.d
	[ -f nginx/picobrew.conf ] && cp nginx/picobrew.conf debian/secubox-picobrew/etc/nginx/secubox.d/ || true
	install -d debian/secubox-picobrew/usr/lib/systemd/system
	cp debian/secubox-picobrew.service debian/secubox-picobrew/usr/lib/systemd/system/

	install -d debian/secubox-picobrew/usr/sbin
	install -m 755 sbin/picobrewctl debian/secubox-picobrew/usr/sbin/picobrewctl

	install -d debian/secubox-picobrew/etc/sudoers.d
	install -m 440 debian/secubox-picobrew.sudoers debian/secubox-picobrew/etc/sudoers.d/secubox-picobrew

	install -d debian/secubox-picobrew/etc/unbound/unbound.conf.d
	install -m 644 conf/unbound-picobrew.conf debian/secubox-picobrew/etc/unbound/unbound.conf.d/secubox-picobrew.conf
```

- [ ] **Step 3 : ajouter les dépendances dans `debian/control`**

Remplacer la ligne `Depends:` par :

```text
Depends: ${misc:Depends}, secubox-core (>= 1.0), python3-uvicorn | python3-pip,
         lxc, debootstrap, sudo
Recommends: unbound
```

- [ ] **Step 4 : durcir le postinst (parents partagés) et recharger Unbound**

Dans `debian/postinst`, remplacer la ligne `install -d -o root -g root -m 1777 /run/secubox` par :

```bash
    # NE JAMAIS chown un parent partagé : d'autres démons en dépendent.
    # On se contente de garantir le mode si le répertoire existe déjà.
    if [ -d /run/secubox ]; then chmod 1777 /run/secubox 2>/dev/null || true
    else install -d -m 1777 /run/secubox; fi
```

Et ajouter, juste avant `#DEBHELPER#` (qui doit rester **seul sur sa ligne** — le placer dans un commentaire le ferait substituer textuellement et casserait le script) :

```bash
    # Le drop-in DNS est actif par défaut : le cloud PicoBrew est éteint
    # depuis 2020, la réécriture locale ne peut donc rien casser.
    if command -v unbound-checkconf >/dev/null 2>&1; then
        unbound-checkconf >/dev/null 2>&1 && systemctl reload unbound 2>/dev/null || true
    fi
```

- [ ] **Step 5 : entrée de changelog**

Ajouter en tête de `debian/changelog` :

```text
secubox-picobrew (2.0.0-1~bookworm1) bookworm; urgency=medium

  * Phase 1 : le module devient un LXC Debian hébergeant picobrew_pico, qui
    redonne vie à un appareil dont le cloud constructeur est éteint depuis 2020.
    Ajoute picobrewctl (seule surface root, auditée via sudoers à commande
    exacte), un drop-in DNS Unbound actif par défaut redirigeant picobrew.com
    vers le LXC, et un panel d'état. La version upstream est figée par SHA à
    l'installation et n'est mise à jour que sur demande explicite, jamais
    pendant une session de brassage.
  * Le contrôleur de fermentation à capteurs est PRÉSERVÉ intact dans
    lib/stillwatch/ ; il sera réactivé dans le LXC en phase 2.

 -- Gerald KERMA <devel@cybermind.fr>  Thu, 23 Jul 2026 15:00:00 +0200
```

- [ ] **Step 6 : construire le paquet et vérifier son contenu**

Run:
```bash
cd packages/secubox-picobrew && dpkg-buildpackage -us -uc -b 2>&1 | tail -3
dpkg-deb -c ../secubox-picobrew_2.0.0-1~bookworm1_all.deb | grep -E "picobrewctl|sudoers|unbound|www/picobrew"
```
Expected: le `.deb` est construit ; la liste contient `/usr/sbin/picobrewctl`, `/etc/sudoers.d/secubox-picobrew`, `/etc/unbound/unbound.conf.d/secubox-picobrew.conf` et `/usr/share/secubox/www/picobrew/index.html`.

- [ ] **Step 7 : vérifier que le postinst résiste à l'expansion debhelper**

Run:
```bash
tmp=$(mktemp -d); dpkg-deb -e ../secubox-picobrew_2.0.0-1~bookworm1_all.deb "$tmp/DEBIAN"
bash -n "$tmp/DEBIAN/postinst" && echo "postinst OK"; rm -rf "$tmp"
```
Expected: `postinst OK` — piège déjà rencontré sur mediaflow : un `#DEBHELPER#` glissé dans un commentaire est substitué textuellement et casse le script.

- [ ] **Step 8 : lancer toute la suite de tests**

Run:
```bash
cd packages/secubox-picobrew && python3 -m pytest tests/ -q && bash tests/test_picobrewctl_guards.sh
```
Expected: tous les tests passent.

- [ ] **Step 9 : commit**

```bash
git add packages/secubox-picobrew/debian packages/secubox-picobrew/sbin
git commit -m "feat(picobrew): packaging phase 1 — sudoers, ctl, drop-in DNS, postinst durci"
```

---

## Recette de vérification manuelle (sur le board)

Le provisionnement réel n'est pas testable en unitaire. Après déploiement :

```bash
sudo picobrewctl install          # debootstrap + clone + venv + service
sudo picobrewctl status --json    # installed:true, running:true, pinned_sha renseigné
dig +short picobrew.com @127.0.0.1   # doit répondre 10.100.0.140
curl -s -o /dev/null -w '%{http_code}\n' http://10.100.0.140/   # attendu : 200
```

Puis mettre l'appareil PicoBrew sous tension et vérifier qu'il s'enregistre dans les journaux :
`sudo picobrewctl logs`.

## Hors périmètre de cette phase

Capteurs, fermentation, distillation (`cuts.py`) et CraftBeerPi : ils font l'objet
des phases 2 et 3, qui auront leur propre plan. Le contrôleur de capteurs
existant est **préservé intact** dans `lib/stillwatch/legacy_controller.py`
(Task 2) — il n'est ni livré ni supprimé en phase 1.
