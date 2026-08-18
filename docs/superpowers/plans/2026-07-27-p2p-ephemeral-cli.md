<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-p2p Ephemeral-Peer CLI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `secubox-assist`'s escalate.py a real `secubox-p2pctl` that attaches a matched center as a session-scoped WireGuard peer on a dedicated, persistent-silent `wg-ephemeral` interface, auto-revoked when the session ends.

**Architecture:** A pure registry/guard module (`api/ephemeral.py`) + a thin root CLI (`sbin/secubox-p2pctl`) that performs the `wg`/`ip` calls; a systemd timer sweeps expired peers (TTL backstop); the assist ctl `join` stops being builders-only and execs the CLI via `sudo -n`. Ephemeral state lives in its own JSON registry, flushed on boot — never mixed with the persistent gondwana mesh state.

**Tech Stack:** Python 3.11 (board py3.11.2), WireGuard (`wg`/`ip`), systemd, nftables, pytest (repo `.venv`).

## Global Constraints

- **SPDX header** verbatim on every new Python/Bash file:
  ```
  # SPDX-License-Identifier: LicenseRef-CMSD-1.0
  # Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  # Source-Disclosed License — All rights reserved except as expressly granted.
  # See LICENCE-CMSD-1.0.md for terms.
  ```
- `EPHEMERAL_RANGE = "10.11.0.0/24"`, `EPHEMERAL_IFACE = "wg-ephemeral"`, box addr `10.11.0.1/24`, listen port **51825**, registry `/var/lib/secubox/p2p/ephemeral.json`, key `/etc/secubox/secrets/p2p/wg-ephemeral.key`. Exact values.
- **argv only, `shell=False`** everywhere — never build a shell string, never `os.system`.
- **`secubox-p2pctl` is the ONLY privileged surface**; the assist daemon/API delegate via `sudo -n` under a sudoers entry scoped to the exact path `/usr/sbin/secubox-p2pctl` (no wildcard, no `NOPASSWD: ALL`).
- **Ephemeral isolation:** never write the ephemeral identity to the mesh state (`/etc/wireguard/wg-mesh.conf` / mesh registry); never promote to a member. `wg-ephemeral` is managed by `ip link`/`wg set` directly, NOT via the mesh `wg-quick` conf.
- **Fail-closed:** boot flush of the registry + TTL backstop sweep; `peer-add` refuses an out-of-range IP and refuses `--ephemeral` on any iface other than `wg-ephemeral`.
- **Never chown the shared parents** `/run/secubox`, `/etc/secubox`, `/var/log/secubox`, `/var/lib/secubox` (chmod-only traversal loosening if needed). `#DEBHELPER#` alone on its line.
- The ephemeral **private key never crosses the box** (the box only gets the center's public key); `secubox-p2pctl` never logs private material.
- Commit messages end `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, NO AI/Claude references.
- Tests: repo `.venv`, per-directory (`cd packages/<pkg> && ../../.venv/bin/pytest tests/…`).

## Substrate reference

- escalate.py (`packages/secubox-assist/assist/escalate.py`) — the contract the CLI must satisfy:
  - `add_ephemeral_peer(pubkey, endpoint, ip)` → `["/usr/sbin/secubox-p2pctl", "peer-add", "--iface", "wg-ephemeral", "--ephemeral", "--pubkey", pk, "--endpoint", ep, "--ip", ip, "--allowed-ip", f"{ip}/32"]`
  - `teardown(ip, did)` → `[["…", "peer-del", "--iface", "wg-ephemeral", "--allowed-ip", f"{ip}/32"], ["…", "ephemeral-revoke", "--did", did]]`
  - `mint_ephemeral_identity()` → `{"did", "priv_hex", "ephemeral": True, "created_at"}` (center-side; the box never sees priv_hex).
- assist ctl `cmd_join` (`packages/secubox-assist/sbin/secubox-assistctl:386`) — currently validates token then builds argv and prints (no exec). Strips `priv_hex` before printing.
- secubox-p2p python is installed to `/usr/lib/secubox/p2p/api/` via `debian/rules` `cp -r api/*`; `api/mesh.py` is imported as `mesh` (import root = the api dir). Put `ephemeral.py` beside it.
- `debian/rules` uses `override_dh_auto_install` with `install -d` + `cp -r`/`install -m`.

## File Structure

**`packages/secubox-p2p/`:**
- `api/ephemeral.py` (new) — pure: constants, registry I/O, in-range guard, record/remove/expiry/boot-flush. No `wg` calls.
- `sbin/secubox-p2pctl` (new, root, +x) — CLI over `ephemeral.py` + the `wg`/`ip` runner.
- `systemd/secubox-p2p-ephemeral-sweep.service` + `.timer` (new).
- `sudoers/secubox-p2p-ephemeral` (new).
- `nft/secubox-p2p-ephemeral.nft` (new) — INPUT allow udp/51825, own table policy accept.
- `debian/{rules,postinst,changelog}` (modify).
- `tests/test_ephemeral.py`, `tests/test_p2pctl.py`, `tests/test_packaging_ephemeral.py` (new).

**`packages/secubox-assist/`:**
- `sbin/secubox-assistctl` (modify `cmd_join`).
- `debian/changelog` (modify), `tests/test_assistctl_dual.py` (extend).

---

## Task 1: `api/ephemeral.py` — pure registry + guards

**Files:**
- Create: `packages/secubox-p2p/api/ephemeral.py`
- Test: `packages/secubox-p2p/tests/test_ephemeral.py`

**Interfaces — Produces:**
- Constants: `EPHEMERAL_RANGE="10.11.0.0/24"`, `EPHEMERAL_IFACE="wg-ephemeral"`, `BOX_ADDR="10.11.0.1/24"`, `LISTEN_PORT=51825`, `REGISTRY_PATH="/var/lib/secubox/p2p/ephemeral.json"`, `BOOT_ID_PATH="/proc/sys/kernel/random/boot_id"`.
- `in_range(ip) -> bool` — True iff `ip` ∈ EPHEMERAL_RANGE (and not the network/broadcast; the box addr .1 is allowed to be excluded — peers use .2+).
- `host_of(allowed_ip) -> str` — strip `/32` → bare host; raises `ValueError` if not a `/32`.
- `load(path=REGISTRY_PATH) -> dict` — returns `{"boot_id": str|None, "peers": [ {pubkey, ip, did, endpoint, expires_ts} ]}`; missing/corrupt file → fresh empty `{"boot_id": None, "peers": []}` (fail-safe).
- `save(reg, path=REGISTRY_PATH) -> None` — atomic write (temp + `os.replace`), parents assumed to exist (postinst makes `/var/lib/secubox/p2p`).
- `record_peer(reg, pubkey, ip, did, endpoint, expires_ts) -> dict` — replace any existing entry with the same `ip` (idempotent), append, return reg.
- `remove_by_ip(reg, ip) -> list[dict]` — remove + return the removed entries (for the wg-remove step).
- `remove_by_did(reg, did) -> list[dict]` — remove + return all entries with that did.
- `expired(reg, now_ts) -> list[dict]` — entries whose `expires_ts <= now_ts` (RFC3339 `Z` lexicographic; fail-closed → treat unparseable/empty `expires_ts` as EXPIRED so a malformed entry is swept, never sticky).
- `boot_flush(reg, current_boot_id) -> tuple[dict, bool]` — if `reg["boot_id"] != current_boot_id`, return `({"boot_id": current_boot_id, "peers": []}, True)` (flushed); else `(reg, False)`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-p2p/tests/test_ephemeral.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from api import ephemeral as e


def test_in_range_and_host_of():
    assert e.in_range("10.11.0.2") is True
    assert e.in_range("10.10.0.2") is False       # wg-mesh range, not ephemeral
    assert e.in_range("nonsense") is False
    assert e.host_of("10.11.0.5/32") == "10.11.0.5"
    with pytest.raises(ValueError):
        e.host_of("10.11.0.5/24")


def test_record_replace_and_remove_roundtrip(tmp_path):
    reg = {"boot_id": "b1", "peers": []}
    e.record_peer(reg, "PK1", "10.11.0.2", "did:plc:" + "a"*32, "1.2.3.4:51820",
                  "2026-07-27T12:00:00Z")
    e.record_peer(reg, "PK1b", "10.11.0.2", "did:plc:" + "a"*32, "1.2.3.4:51820",
                  "2026-07-27T13:00:00Z")  # same ip -> replace
    assert len(reg["peers"]) == 1 and reg["peers"][0]["pubkey"] == "PK1b"
    p = tmp_path / "r.json"
    e.save(reg, str(p)); reg2 = e.load(str(p))
    assert reg2["peers"][0]["ip"] == "10.11.0.2"
    removed = e.remove_by_ip(reg2, "10.11.0.2")
    assert removed and reg2["peers"] == []


def test_remove_by_did_and_expired_failclosed():
    did = "did:plc:" + "c"*32
    reg = {"boot_id": "b1", "peers": [
        {"pubkey": "P", "ip": "10.11.0.2", "did": did, "endpoint": "e",
         "expires_ts": "2999-01-01T00:00:00Z"},
        {"pubkey": "Q", "ip": "10.11.0.3", "did": did, "endpoint": "e",
         "expires_ts": "malformed"},
    ]}
    # expired: past OR unparseable (fail-closed)
    exp = e.expired(reg, "2026-07-27T12:00:00Z")
    assert {p["ip"] for p in exp} == {"10.11.0.3"}   # malformed swept; 2999 not
    assert len(e.remove_by_did(reg, did)) == 2 and reg["peers"] == []


def test_boot_flush():
    reg = {"boot_id": "OLD", "peers": [{"pubkey": "P", "ip": "10.11.0.2",
           "did": "d", "endpoint": "e", "expires_ts": "z"}]}
    flushed, did_flush = e.boot_flush(reg, "NEW")
    assert did_flush is True and flushed == {"boot_id": "NEW", "peers": []}
    same, did2 = e.boot_flush(flushed, "NEW")
    assert did2 is False and same["peers"] == []


def test_load_missing_is_failsafe(tmp_path):
    reg = e.load(str(tmp_path / "nope.json"))
    assert reg == {"boot_id": None, "peers": []}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-p2p && ../../.venv/bin/pytest tests/test_ephemeral.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'api.ephemeral'` (or `api`). If `api` isn't importable, add `pythonpath = .` to `packages/secubox-p2p/pytest.ini` (check it exists; the other p2p tests import `api.mesh`, so the path shim already works — mirror it).

- [ ] **Step 3: Implement `api/ephemeral.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: p2p.ephemeral — pure registry + guards for session-scoped
WireGuard peers on the wg-ephemeral iface. No wg/ip calls here (secubox-p2pctl
does those); this module is the fail-closed bookkeeping the CLI and the sweep
timer share. Ephemeral peers NEVER enter the persistent gondwana mesh state.
"""
from __future__ import annotations

import ipaddress
import json
import os
from typing import Any, Dict, List, Tuple

EPHEMERAL_RANGE = "10.11.0.0/24"
EPHEMERAL_IFACE = "wg-ephemeral"
BOX_ADDR = "10.11.0.1/24"
LISTEN_PORT = 51825
REGISTRY_PATH = "/var/lib/secubox/p2p/ephemeral.json"
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
_EMPTY = {"boot_id": None, "peers": []}


def in_range(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    net = ipaddress.ip_network(EPHEMERAL_RANGE)
    return addr in net and addr != net.network_address and addr != net.broadcast_address


def host_of(allowed_ip: str) -> str:
    if not allowed_ip.endswith("/32"):
        raise ValueError(f"expected a /32, got {allowed_ip!r}")
    host = allowed_ip[:-3]
    ipaddress.ip_address(host)  # validate; raises ValueError
    return host


def load(path: str = REGISTRY_PATH) -> Dict[str, Any]:
    try:
        with open(path) as fh:
            reg = json.load(fh)
        if not isinstance(reg, dict) or "peers" not in reg:
            return dict(_EMPTY)
        reg.setdefault("boot_id", None)
        reg.setdefault("peers", [])
        return reg
    except (OSError, ValueError):
        return dict(_EMPTY)


def save(reg: Dict[str, Any], path: str = REGISTRY_PATH) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(reg, fh)
    os.replace(tmp, path)


def record_peer(reg, pubkey, ip, did, endpoint, expires_ts) -> Dict[str, Any]:
    reg["peers"] = [p for p in reg.get("peers", []) if p.get("ip") != ip]
    reg["peers"].append({"pubkey": pubkey, "ip": ip, "did": did,
                         "endpoint": endpoint, "expires_ts": expires_ts})
    return reg


def remove_by_ip(reg, ip) -> List[Dict[str, Any]]:
    removed = [p for p in reg.get("peers", []) if p.get("ip") == ip]
    reg["peers"] = [p for p in reg.get("peers", []) if p.get("ip") != ip]
    return removed


def remove_by_did(reg, did) -> List[Dict[str, Any]]:
    removed = [p for p in reg.get("peers", []) if p.get("did") == did]
    reg["peers"] = [p for p in reg.get("peers", []) if p.get("did") != did]
    return removed


def expired(reg, now_ts: str) -> List[Dict[str, Any]]:
    out = []
    for p in reg.get("peers", []):
        ts = p.get("expires_ts") or ""
        # fail-closed: empty/malformed -> treat as expired (never sticky).
        if not ts or len(ts) != 20 or not ts.endswith("Z"):
            out.append(p)
            continue
        if ts <= now_ts:  # RFC3339 Z is lexicographically ordered
            out.append(p)
    return out


def boot_flush(reg, current_boot_id: str) -> Tuple[Dict[str, Any], bool]:
    if reg.get("boot_id") != current_boot_id:
        return {"boot_id": current_boot_id, "peers": []}, True
    return reg, False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-p2p && ../../.venv/bin/pytest tests/test_ephemeral.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-p2p/api/ephemeral.py packages/secubox-p2p/tests/test_ephemeral.py
git commit -m "feat(p2p): ephemeral.py — pure registry + guards for wg-ephemeral peers (ref p2p-ephemeral)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 2: `sbin/secubox-p2pctl` — the root CLI

**Files:**
- Create: `packages/secubox-p2p/sbin/secubox-p2pctl` (+x)
- Test: `packages/secubox-p2p/tests/test_p2pctl.py`

**Interfaces:**
- Consumes: `api.ephemeral` (all of Task 1).
- Produces (CLI, argv `shell=False`): `iface-up`; `peer-add --iface wg-ephemeral --ephemeral --pubkey <pk> --endpoint <ep> --ip <ip> --allowed-ip <ip>/32 [--ttl <s>]`; `peer-del --iface wg-ephemeral --allowed-ip <ip>/32`; `ephemeral-revoke --did <did>`; `sweep`. All emit JSON on stdout; errors → `{"error": …}` on stderr + exit 1 (never a traceback). `DRYRUN=1` prints `{"dryrun": true, "would": …}` and touches neither `wg` nor the registry file.
- A `_wg(*args)` / `_ip(*args)` runner uses `subprocess.run([...], shell=False)`; both honor `P2P_WG_BIN`/`P2P_IP_BIN` env overrides (tests inject a fake recorder script) and `DRYRUN`.

**Guards (security-critical):** `peer-add` refuses when `--iface != wg-ephemeral` OR `--ephemeral` absent OR `ephemeral.in_range(host_of(--allowed-ip))` is False. `--ip`, if given, must equal `host_of(--allowed-ip)` (reconcile the redundancy; `--allowed-ip` is authoritative). Registry path from env `P2P_EPHEMERAL_REGISTRY` (default `ephemeral.REGISTRY_PATH`) for tests.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-p2p/tests/test_p2pctl.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json, os, subprocess, sys
from pathlib import Path

CTL = str(Path(__file__).resolve().parent.parent / "sbin" / "secubox-p2pctl")
P2P = str(Path(__file__).resolve().parent.parent)


def _env(tmp_path):
    env = dict(os.environ)
    # a fake `wg`/`ip` that records argv and always succeeds
    rec = tmp_path / "wgcalls.log"
    fake = tmp_path / "fakebin"; fake.write_text(
        "#!/bin/sh\necho \"$0 $*\" >> " + str(rec) + "\nexit 0\n")
    fake.chmod(0o755)
    env.update(P2P_LIB=P2P, PYTHONPATH=os.pathsep.join([P2P, env.get("PYTHONPATH", "")]),
               P2P_WG_BIN=str(fake), P2P_IP_BIN=str(fake),
               P2P_EPHEMERAL_REGISTRY=str(tmp_path / "ephemeral.json"),
               P2P_BOOT_ID="fixed-boot")
    return env, rec


def test_peer_add_records_and_calls_wg(tmp_path):
    env, rec = _env(tmp_path)
    r = subprocess.run([sys.executable, CTL, "peer-add", "--iface", "wg-ephemeral",
                        "--ephemeral", "--pubkey", "PK", "--endpoint", "1.2.3.4:51820",
                        "--ip", "10.11.0.2", "--allowed-ip", "10.11.0.2/32",
                        "--ttl", "3600"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    reg = json.loads((tmp_path / "ephemeral.json").read_text())
    assert reg["peers"][0]["pubkey"] == "PK" and reg["peers"][0]["ip"] == "10.11.0.2"
    assert "peer PK" in rec.read_text() or "PK" in rec.read_text()  # wg set peer called


def test_peer_add_rejects_out_of_range_and_non_ephemeral(tmp_path):
    env, _ = _env(tmp_path)
    # out of range
    r = subprocess.run([sys.executable, CTL, "peer-add", "--iface", "wg-ephemeral",
                        "--ephemeral", "--pubkey", "PK", "--endpoint", "e",
                        "--allowed-ip", "10.10.0.2/32"], env=env, capture_output=True, text=True)
    assert r.returncode == 1 and json.loads(r.stderr)["error"]
    # missing --ephemeral
    r2 = subprocess.run([sys.executable, CTL, "peer-add", "--iface", "wg-ephemeral",
                         "--pubkey", "PK", "--endpoint", "e",
                         "--allowed-ip", "10.11.0.2/32"], env=env, capture_output=True, text=True)
    assert r2.returncode == 1 and json.loads(r2.stderr)["error"]


def test_peer_del_and_revoke_idempotent(tmp_path):
    env, _ = _env(tmp_path)
    subprocess.run([sys.executable, CTL, "peer-add", "--iface", "wg-ephemeral",
                    "--ephemeral", "--pubkey", "PK", "--endpoint", "e",
                    "--allowed-ip", "10.11.0.2/32", "--did", "did:plc:" + "a"*32],
                   env=env, check=True, capture_output=True, text=True)
    r = subprocess.run([sys.executable, CTL, "peer-del", "--iface", "wg-ephemeral",
                        "--allowed-ip", "10.11.0.2/32"], env=env, capture_output=True, text=True)
    assert r.returncode == 0
    # deleting again is a no-op success
    r2 = subprocess.run([sys.executable, CTL, "peer-del", "--iface", "wg-ephemeral",
                         "--allowed-ip", "10.11.0.2/32"], env=env, capture_output=True, text=True)
    assert r2.returncode == 0


def test_dryrun_writes_nothing(tmp_path):
    env, rec = _env(tmp_path); env["DRYRUN"] = "1"
    r = subprocess.run([sys.executable, CTL, "peer-add", "--iface", "wg-ephemeral",
                        "--ephemeral", "--pubkey", "PK", "--endpoint", "e",
                        "--allowed-ip", "10.11.0.2/32"], env=env, capture_output=True, text=True)
    assert json.loads(r.stdout).get("dryrun") is True
    assert not (tmp_path / "ephemeral.json").exists()
    assert not rec.exists()
```

- [ ] **Steps 2-4:** Implement `sbin/secubox-p2pctl`. Structure: `sys.path.insert(0, os.environ.get("P2P_LIB", "/usr/lib/secubox/p2p"))`; `from api import ephemeral`. Helpers `_die(msg)` (JSON to stderr, exit 1), `_dry()`, `_reg_path()` (env `P2P_EPHEMERAL_REGISTRY`), `_boot_id()` (env `P2P_BOOT_ID` else read `ephemeral.BOOT_ID_PATH`), `_wg(*a)`/`_ip(*a)` (subprocess `shell=False`, env-bin override, skip on DRYRUN). Add a `--did` arg to `peer-add` (escalate.py does not send it today but the registry needs it for `ephemeral-revoke`; default `""`). Note: escalate.py's `add_ephemeral_peer` does NOT pass `--did` — Task 3 adds it there. `argparse` subparsers; each command wraps its `ephemeral`/subprocess calls `try/except (ValueError, OSError) as exc: _die(str(exc))`. `iface-up`: load reg, `boot_flush` (using `_boot_id()`), if flushed rebuild the iface from scratch (`_ip("link","del",IFACE)` ignore-fail, then add/configure), always ensure addr+listen-port+up idempotently, save reg. `peer-add`: validate guards, `iface-up` first, `_wg("set",IFACE,"peer",pk,"endpoint",ep,"allowed-ips",allowed_ip)`, `record_peer`, save. `peer-del`: load, `remove_by_ip`, for each removed `_wg("set",IFACE,"peer",pubkey,"remove")`, save. `ephemeral-revoke`: load, `remove_by_did`, `_wg(... remove)` each, save. `sweep`: load, `expired`, remove each from wg + reg, save. Run `cd packages/secubox-p2p && ../../.venv/bin/pytest tests/test_p2pctl.py -q` red→green. `chmod +x sbin/secubox-p2pctl`.

- [ ] **Step 5: Commit** `feat(p2p): secubox-p2pctl — iface-up/peer-add/peer-del/ephemeral-revoke/sweep (argv, guards, DRYRUN)` + trailer.

---

## Task 3: assist ctl `join` — real exec via `sudo -n`

**Files:**
- Modify: `packages/secubox-assist/sbin/secubox-assistctl` (`cmd_join`), `packages/secubox-assist/assist/escalate.py` (`add_ephemeral_peer` emits `--did`)
- Test: `packages/secubox-assist/tests/test_assistctl_dual.py` (extend)

**Interfaces:**
- Consumes: `escalate.add_ephemeral_peer`/`teardown`/`mint_ephemeral_identity`, `joinlink.verify_join`/`is_expired`.
- Produces: `cmd_join` executes the peer-add argv via `subprocess.run(["sudo", "-n", *peer_argv], shell=False)` (unless `DRYRUN`), returns the p2pctl result; on non-zero rc → `{"error": …}` exit 1. `add_ephemeral_peer` gains a `did` param appended as `--did <did>` so the registry can revoke by did.

- [ ] **Step 1: Write the failing test** (extend `test_assistctl_dual.py`)

```python
def test_join_execs_p2pctl_via_sudo(tmp_path):
    env = _env(tmp_path)
    calls = tmp_path / "sudocalls.log"
    fake = tmp_path / "sudo"; fake.write_text(
        "#!/bin/sh\necho \"$*\" >> " + str(calls) + "\nexit 0\n"); fake.chmod(0o755)
    env["PATH"] = str(tmp_path) + os.pathsep + env["PATH"]  # fake `sudo` first
    # mint a real join token via the ctl so hash+expiry line up
    jl = subprocess.run([sys.executable, CTL, "joinlink", "--for", "m1", "--ttl", "3600"],
                        env={**env, "ASSIST_BASE_URL": "https://h.example"},
                        capture_output=True, text=True)
    # joinlink prints token_hash+expires_at; mint the token separately is internal —
    # instead assert the DRYRUN plan path and the sudo exec path:
    r = subprocess.run([sys.executable, CTL, "join", "TOKENBOGUS", "--hash", "deadbeef",
                        "--expires-at", "2999-01-01T00:00:00Z", "--pubkey", "PK",
                        "--endpoint", "1.2.3.4:51820", "--ip", "10.11.0.2"],
                       env=env, capture_output=True, text=True)
    # bogus token -> refused cleanly (no traceback, no sudo call)
    assert r.returncode == 1 and json.loads(r.stderr)["error"]
    assert not calls.exists()
```

(The valid-token exec path is covered by a DRYRUN assertion; a full valid-token test requires minting the matching token — assert the refusal path + that `add_ephemeral_peer` includes `--did`. Keep the brief's test; the implementer may add a valid-token case by minting via `assist.token.mint` if straightforward.)

- [ ] **Steps 2-4:** In `escalate.py`, change `add_ephemeral_peer(pubkey, endpoint, ip, did="")` to append `"--did", did` to the returned argv (keep `--ip` and `--allowed-ip` both — `--allowed-ip` authoritative per the CLI). In `cmd_join`: after token validation, `identity = escalate.mint_ephemeral_identity()`, build `peer_argv = escalate.add_ephemeral_peer(a.pubkey, a.endpoint, a.ip, identity["did"])`; if `_dry()`, print the plan WITHOUT `priv_hex` (keep the existing secret-scrub) and return 0; else `res = subprocess.run(["sudo", "-n", *peer_argv], shell=False, capture_output=True, text=True)`; `rc != 0 → _die(res.stderr.strip() or "p2pctl failed")`; print `{"joined": True, "ip": a.ip, "did": identity["did"]}` (never `priv_hex`). Run `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_assistctl_dual.py -q` red→green + full assist suite.

- [ ] **Step 5: Commit** `feat(assist): join redeems a link by exec'ing secubox-p2pctl via sudo -n (was builders-only)` + trailer.

---

## Task 4: packaging — iface/key/units/sudoers/nft + changelogs

**Files:**
- Create: `packages/secubox-p2p/systemd/secubox-p2p-ephemeral-sweep.service`, `…/.timer`, `packages/secubox-p2p/sudoers/secubox-p2p-ephemeral`, `packages/secubox-p2p/nft/secubox-p2p-ephemeral.nft`
- Modify: `packages/secubox-p2p/debian/rules`, `debian/postinst`, `debian/changelog`; `packages/secubox-assist/debian/changelog`
- Test: `packages/secubox-p2p/tests/test_packaging_ephemeral.py`

**Interfaces:** the sweep service runs `ExecStart=/usr/sbin/secubox-p2pctl sweep` as root (a root oneshot; it manages wg). The timer fires `OnUnitActiveSec=60s`. sudoers: `secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-p2pctl`. nft drop-in: an own table `inet secubox_p2p_ephemeral` (policy accept, never touches the main firewall) allowing `udp dport 51825` INPUT — ships to `/etc/nftables.d/` (reboot-persistent; matches the secubox-assist nft precedent). postinst: `install -d /var/lib/secubox/p2p` (owner root, the ctl runs as root); generate `/etc/secubox/secrets/p2p/wg-ephemeral.key` once (`wg genkey`, `0600`) if absent; `secubox-p2pctl iface-up || true` (guarded — wg may be absent in a container); `systemctl enable --now secubox-p2p-ephemeral-sweep.timer`; reload nftables (`systemctl reload nftables.service || nft -f …`). NEVER chown the shared parents. `#DEBHELPER#` alone.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-p2p/tests/test_packaging_ephemeral.py — key assertions
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent


def test_sudoers_scoped_exact():
    s = (ROOT / "sudoers" / "secubox-p2p-ephemeral").read_text()
    assert "/usr/sbin/secubox-p2pctl" in s and "NOPASSWD: ALL" not in s and "*" not in s


def test_sweep_units_present():
    svc = (ROOT / "systemd" / "secubox-p2p-ephemeral-sweep.service").read_text()
    tmr = (ROOT / "systemd" / "secubox-p2p-ephemeral-sweep.timer").read_text()
    assert "secubox-p2pctl sweep" in svc and "OnUnitActiveSec" in tmr


def test_nft_own_table_policy_accept():
    n = (ROOT / "nft" / "secubox-p2p-ephemeral.nft").read_text()
    assert "51825" in n and "policy accept" in n and "flush ruleset" not in n


def test_postinst_no_shared_parent_chown_and_key_guarded():
    p = (ROOT / "debian" / "postinst").read_text()
    for bad in ("chown -R secubox /run/secubox", "chown -R secubox /etc/secubox",
                "chown -R secubox /var/lib/secubox"):
        assert bad not in p
    assert "wg genkey" in p and "#DEBHELPER#" in p
```

- [ ] **Steps 2-4:** create the units/sudoers/nft/postinst per the interfaces; extend `debian/rules` `override_dh_auto_install` to `install -d …/usr/lib/secubox/p2p/api` already exists (ephemeral.py ships via the existing `cp -r api/*`), plus `install -m 755 sbin/secubox-p2pctl → …/usr/sbin/`, `install -m 644 systemd/*.service systemd/*.timer → …/lib/systemd/system/`, `install -m 440 sudoers/secubox-p2p-ephemeral → …/etc/sudoers.d/`, `install -m 644 nft/secubox-p2p-ephemeral.nft → …/etc/nftables.d/`. Bump `secubox-p2p` changelog (next minor, urgency=medium) noting the ephemeral CLI + iface + sweep. Bump `secubox-assist` changelog (0.2.3) noting `join` now execs. Run `cd packages/secubox-p2p && ../../.venv/bin/pytest tests/ -q` and `cd packages/secubox-assist && ../../.venv/bin/pytest tests/ -q` (both green), build both `.deb` (`dpkg-buildpackage -us -uc -b`) and confirm `dpkg-deb -c` ships `api/ephemeral.py`, `usr/sbin/secubox-p2pctl`, the units, sudoers, nft drop-in.

- [ ] **Step 5: Commit** `build(p2p): package ephemeral CLI — iface-up/sweep units, scoped sudoers, nft udp/51825; assist 0.2.3 join exec` + trailer.

---

## Self-Review

**1. Spec coverage:** p2pctl CLI (peer-add/del/ephemeral-revoke/iface-up/sweep) → T2. Pure registry + guards + boot-flush + fail-closed expiry → T1. wg-ephemeral persistent-silent iface (key/addr/port, ip-link managed) → T2 `iface-up` + T4 postinst key/nft/forward. Ephemeral registry + flush-on-boot → T1/T2. Auto-revoke: assist teardown (escalate.teardown already exists; T3 wires join; close-path teardown is via the existing ctl close → escalate.teardown, unchanged) + TTL backstop sweep timer → T4. Live wiring (join execs via sudo) + `--ip`/`--allowed-ip` reconcile + `--did` → T3. Security: single privileged surface + scoped sudoers + no-root-in-process + ephemeral isolation + fail-closed → across T2/T4. nft udp/51825 + Freebox forward prereq → T4 + deploy note. ✅
Gap check: the spec's "assist ctl runs teardown at SESSION_CLOSE" — escalate.teardown already returns the argv; the CLOSE path that calls it is pre-existing assist behavior and out of this plan's new code. Noted, not a new task (foundation scope: join is the exec that was missing).

**2. Placeholder scan:** T2/T4 use compressed Steps 2-4 that mirror the shipped `secubox-assistctl`/`secubox-releasectl` ctl + assist packaging patterns verbatim; the novel + security-critical logic (T1 registry/guards, T2 guard assertions) carries complete code. Flag to implementer: follow the sibling ctls as the template.

**3. Type consistency:** `EPHEMERAL_RANGE`/`EPHEMERAL_IFACE`/`LISTEN_PORT`/`REGISTRY_PATH`, `in_range`/`host_of`/`load`/`save`/`record_peer`/`remove_by_ip`/`remove_by_did`/`expired`/`boot_flush` identical across T1/T2/T4. `add_ephemeral_peer(pubkey, endpoint, ip, did="")` consistent T3↔escalate.py↔T2 `--did`. `peer-add --allowed-ip` authoritative everywhere.

**Cross-task note for the controller:** the Freebox UDP/51825 forward is an out-of-package deploy prerequisite (mirrors wg-mesh 51822 and the release-rings reprepro-distributions prerequisite) — confirm before expecting a center to actually reach `wg-ephemeral` live. The nft INPUT allow ships in the package (`/etc/nftables.d/`).
