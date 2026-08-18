<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Macro Subsystem (tor-exit) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a service offer propose a vetted, parameterized, AppArmor-confined automation ("macro") so an approved peer can actually consume it — shipping the framework plus one real kind, `tor-exit` (SOCKS-over-mesh).

**Architecture:** Three packages. (A) **secubox-annuaire** gains an optional signed `ServiceOffer.macro = {kind, params}` descriptor that federates. (B) new **secubox-macro** ships a root dispatcher `secubox-macroctl` + vetted `macros.d/tor-exit` plugin + per-kind AppArmor + a tight sudoers allowlist. (C) **secubox-p2p** exposes a mesh-only grant endpoint (authorized by the consumer's self-signed Subscription against an `auto` offer), and the consumer's Activate pulls the credential and runs `macroctl activate`.

**Tech Stack:** Python 3.11, FastAPI, Pydantic v2, nftables (named sets), Tor (SocksPort), AppArmor, Debian packaging, pytest.

## Global Constraints

- SPDX header on every new source file: `# SPDX-License-Identifier: LicenseRef-CMSD-1.0` + the 3-line CyberMind copyright block (copy from any existing `packages/secubox-p2p/api/mesh.py`).
- **No offer-supplied code executes.** Offers carry only an allowlisted `kind` (`^[a-z][a-z0-9-]{1,31}$`) + typed `params`; `macroctl` never runs a shell on offer strings and never execs an unlisted kind.
- **annuaire executes nothing** — it only stores/serves/federates the `macro` descriptor.
- Only `secubox-macroctl` is sudo-allowed for user `secubox` (nothing else).
- `--src-ip` must be a literal IPv4 in `10.10.0.0/24`; reject otherwise.
- nft allows are per-source-IP into one port, in the named set `secubox_macro_torexit`, individually removable; never `0.0.0.0`, never the whole subnet.
- Every grant/revoke appends one line to `/var/log/secubox/audit.log` (append-only).
- Increment 1 = **`auto`-mode macro offers only** (pending deferred — spec §7).
- Version bumps: secubox-annuaire → `0.3.0-1~bookworm1`; secubox-macro → `0.1.0-1~bookworm1`; secubox-p2p → `1.9.0-1~bookworm1`.
- Tests: annuaire under `packages/secubox-annuaire/tests/` (`from annuaire...`); macro under `packages/secubox-macro/tests/`; p2p under `packages/secubox-p2p/tests/` (`from api import ...`, see conftest).
- Both secubox-annuaire and secubox-p2p run as `User=secubox`; node key `/etc/secubox/secrets/annuaire/node.key` (0600 secubox) is the node identity for both.

---

## Package A — secubox-annuaire 0.3.0 (macro descriptor)

### Task 1: `ServiceOffer.macro` descriptor (model + sign/ingest/enrich flow)

**Files:**
- Modify: `packages/secubox-annuaire/annuaire/model.py` (add `MacroDescriptor`, add `macro` field to `ServiceOffer`)
- Test: `packages/secubox-annuaire/tests/test_macro_offer.py`

**Interfaces:**
- Produces: `ServiceOffer.macro: Optional[MacroDescriptor]` where `MacroDescriptor` has `kind: str` (pattern `^[a-z][a-z0-9-]{1,31}$`) and `params: Dict[str, Union[str,int,bool]] = {}`. Default `macro=None`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-annuaire/tests/test_macro_offer.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import tempfile
import pytest
from annuaire.model import ServiceOffer, MacroDescriptor
from annuaire.log import Journal
from annuaire.crypto import generate_keypair
from annuaire.verbs import genesis, offer_service, _get_offers, ingest_offer

DID = "did:plc:" + "a" * 32


def test_macro_descriptor_validates_kind():
    MacroDescriptor(kind="tor-exit", params={"socks_port": 9050})
    with pytest.raises(Exception):
        MacroDescriptor(kind="../evil", params={})
    with pytest.raises(Exception):
        MacroDescriptor(kind="Tor Exit", params={})


def test_offer_without_macro_still_valid():
    o = ServiceOffer(service_id="s" * 64, provider=DID, name="n", kind="api",
                     endpoint="/x", sig="0" * 128, signer_did=DID)
    assert o.macro is None


def test_macro_round_trips_through_offer_and_federation():
    ja = Journal(tempfile.mktemp(suffix=".db"))
    pa, pub = generate_keypair()
    ida = genesis(ja, pa)
    offer_service(ja, pa, ida.did, name="Tor exit", kind="tor-exit",
                  endpoint="http://10.10.0.1/tor", approval_mode="auto",
                  macro={"kind": "tor-exit", "params": {"socks_port": 9050}})
    wire = _get_offers(ja)[0]
    assert wire["macro"]["kind"] == "tor-exit"
    assert wire["macro"]["params"]["socks_port"] == 9050
    # federate into a second journal (self-cert), macro preserved
    jb = Journal(tempfile.mktemp(suffix=".db"))
    genesis(jb, generate_keypair()[0])
    allowed = set(ServiceOffer.model_fields)
    offer = ServiceOffer(**{k: v for k, v in wire.items() if k in allowed})
    ingest_offer(jb, offer, wire["provider_pubkey"])
    assert _get_offers(jb)[0]["macro"]["kind"] == "tor-exit"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-annuaire && python3 -m pytest tests/test_macro_offer.py -q`
Expected: FAIL — `ImportError: cannot import name 'MacroDescriptor'` (and `offer_service` has no `macro` kwarg yet — Task adds it in step 3).

- [ ] **Step 3: Implement the model + thread `macro` through `offer_service`**

In `packages/secubox-annuaire/annuaire/model.py`, add near the other models (all models use `model_config = ConfigDict(extra="forbid")`):

```python
class MacroDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(..., pattern=r"^[a-z][a-z0-9-]{1,31}$")
    params: Dict[str, Union[str, int, bool]] = Field(default_factory=dict)
```

Add `Union` to the existing `from typing import ...` import if absent. Add to `ServiceOffer` (after `description`, before `created_at`):

```python
    macro: Optional[MacroDescriptor] = None
```

In `packages/secubox-annuaire/annuaire/verbs.py`, give `offer_service` a `macro: Optional[Dict] = None` keyword and include it in the constructed `ServiceOffer(... macro=macro ...)` (the signed payload already `model_dump()`s the whole offer, so `macro` is covered by the signature automatically; `_enrich_offer` copies `entry.payload` so it carries `macro` too — no change needed there). Confirm `ingest_offer` reconstructs it (ServiceOffer accepts the `macro` key).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-annuaire && python3 -m pytest tests/test_macro_offer.py -q`
Expected: PASS (3 tests). Then `python3 -m pytest tests/ -q` — all prior tests still green.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/annuaire/model.py packages/secubox-annuaire/annuaire/verbs.py packages/secubox-annuaire/tests/test_macro_offer.py
git commit -m "feat(annuaire): optional signed ServiceOffer.macro descriptor (ref #<issueA>)"
```

### Task 2: `annuairectl offer --macro-kind/--macro-param` + 0.3.0 changelog

**Files:**
- Modify: `packages/secubox-annuaire/sbin/annuairectl` (offer subcommand + cmd_offer)
- Modify: `packages/secubox-annuaire/debian/changelog`

**Interfaces:**
- Consumes: `offer_service(..., macro=...)` from Task 1.

- [ ] **Step 1: Add the CLI flags and pass-through**

In `annuairectl`, in the `offer` subparser (near line 289) add:

```python
    po.add_argument("--macro-kind", help="macro kind, e.g. tor-exit")
    po.add_argument("--macro-param", action="append", metavar="k=v",
                    help="macro param key=value (repeatable; ints/bools auto-typed)")
```

In `cmd_offer`, before calling `offer_service`, build the macro dict:

```python
    macro = None
    if args.macro_kind:
        params = {}
        for kv in (args.macro_param or []):
            if "=" not in kv:
                _die(f"--macro-param expects k=v, got {kv!r}")
            k, v = kv.split("=", 1)
            if v.isdigit():
                v = int(v)
            elif v.lower() in ("true", "false"):
                v = v.lower() == "true"
            params[k] = v
        macro = {"kind": args.macro_kind, "params": params}
```

Pass `macro=macro` into the `offer_service(...)` call.

- [ ] **Step 2: Smoke-test the CLI locally**

Run:
```bash
cd packages/secubox-annuaire && TMP=$(mktemp -d)
ANNUAIRE_LIB="$PWD" ANNUAIRE_DB_PATH=$TMP/a.db ANNUAIRE_KEY_PATH=$TMP/a.key python3 sbin/annuairectl init --isolation-domain gondwana >/dev/null
ANNUAIRE_LIB="$PWD" ANNUAIRE_DB_PATH=$TMP/a.db ANNUAIRE_KEY_PATH=$TMP/a.key python3 sbin/annuairectl offer --name "Tor exit" --kind tor-exit --endpoint "http://10.10.0.1/tor" --mode auto --macro-kind tor-exit --macro-param socks_port=9050
ANNUAIRE_LIB="$PWD" ANNUAIRE_DB_PATH=$TMP/a.db ANNUAIRE_KEY_PATH=$TMP/a.key python3 sbin/annuairectl services --raw | python3 -c "import sys,json;print(json.load(sys.stdin)['services'][0]['macro'])"
rm -rf $TMP
```
Expected: prints `{'kind': 'tor-exit', 'params': {'socks_port': 9050}}`.

- [ ] **Step 3: Bump changelog to 0.3.0**

Prepend to `packages/secubox-annuaire/debian/changelog`:
```
secubox-annuaire (0.3.0-1~bookworm1) bookworm; urgency=medium

  * feat: optional signed ServiceOffer.macro descriptor {kind, params} — lets an
    offer propose a vetted access macro (e.g. tor-exit). Federates in the signed
    payload; annuaire executes nothing. annuairectl offer gains --macro-kind /
    --macro-param. Consumed by secubox-macro + secubox-p2p 1.9.0.

 -- Gerald Kerma <devel@cybermind.fr>  Wed, 01 Jul 2026 10:00:00 +0200
```

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-annuaire/sbin/annuairectl packages/secubox-annuaire/debian/changelog
git commit -m "feat(annuaire): annuairectl offer --macro-kind/--macro-param + 0.3.0 (ref #<issueA>)"
```

---

## Package B — secubox-macro (NEW): dispatcher + tor-exit plugin

### Task 3: scaffold package + `secubox-macroctl` dispatcher

**Files:**
- Create: `packages/secubox-macro/` (debian/control, rules, changelog, compat, postinst, prerm)
- Create: `packages/secubox-macro/sbin/secubox-macroctl`
- Create: `packages/secubox-macro/tests/test_macroctl.py`, `tests/conftest.py`

**Interfaces:**
- Produces (CLI): `secubox-macroctl <kind> <grant|activate|revoke> [--sub DID] [--src-ip IP] [--params JSON] [--cred JSON]`. `grant` prints one JSON object to stdout. Exit 0 ok, non-zero + JSON `{"error":...}` on failure.
- Env override for tests: `MACRO_PLUGIN_DIR` (default `/usr/lib/secubox/macro/macros.d`), `MACRO_AUDIT_LOG` (default `/var/log/secubox/audit.log`), `MACRO_MESH_CIDR` (default `10.10.0.0/24`).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-macro/tests/conftest.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "sbin"))
```
```python
# packages/secubox-macro/tests/test_macroctl.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import json, os, stat, subprocess, sys, pathlib
CTL = str(pathlib.Path(__file__).resolve().parents[1] / "sbin" / "secubox-macroctl")


def _run(args, env):
    return subprocess.run([sys.executable, CTL] + args, capture_output=True, text=True, env=env)


def _env(tmp_path):
    d = tmp_path / "macros.d"; d.mkdir()
    plug = d / "echo"
    plug.write_text("#!/usr/bin/env python3\n"
                    "import json,sys\n"
                    "print(json.dumps({'ok': True, 'argv': sys.argv[1:]}))\n")
    plug.chmod(0o755)
    e = dict(os.environ, MACRO_PLUGIN_DIR=str(d),
             MACRO_AUDIT_LOG=str(tmp_path / "audit.log"),
             MACRO_MESH_CIDR="10.10.0.0/24")
    return e


def test_rejects_unknown_kind(tmp_path):
    r = _run(["nope", "grant"], _env(tmp_path))
    assert r.returncode != 0
    assert "unknown" in (r.stdout + r.stderr).lower() or "error" in (r.stdout + r.stderr).lower()


def test_rejects_path_traversal_kind(tmp_path):
    r = _run(["../secrets", "grant"], _env(tmp_path))
    assert r.returncode != 0


def test_rejects_src_ip_outside_mesh(tmp_path):
    r = _run(["echo", "grant", "--src-ip", "192.168.1.5"], _env(tmp_path))
    assert r.returncode != 0
    assert "mesh" in (r.stdout + r.stderr).lower() or "10.10.0" in (r.stdout + r.stderr)


def test_dispatches_to_plugin_and_audits(tmp_path):
    env = _env(tmp_path)
    r = _run(["echo", "grant", "--sub", "did:plc:" + "a"*32, "--src-ip", "10.10.0.2"], env)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["ok"] is True
    audit = pathlib.Path(env["MACRO_AUDIT_LOG"]).read_text()
    assert "echo" in audit and "grant" in audit


def test_refuses_non_root_owned_or_world_writable_plugin(tmp_path):
    env = _env(tmp_path)
    plug = pathlib.Path(env["MACRO_PLUGIN_DIR"]) / "echo"
    plug.chmod(0o777)  # world-writable → tamper risk
    r = _run(["echo", "grant", "--src-ip", "10.10.0.2"], env)
    assert r.returncode != 0
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-macro && python3 -m pytest tests/ -q`
Expected: FAIL — `secubox-macroctl` does not exist.

- [ ] **Step 3: Implement `secubox-macroctl`**

```python
# packages/secubox-macro/sbin/secubox-macroctl
#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-macroctl — root dispatcher for vetted access macros.

Validates the kind against the installed macros.d allowlist, checks the plugin
is root-owned and not world-writable, validates --src-ip is inside the mesh
CIDR, execs the plugin verb (never via a shell, never eval'ing params), and
appends an audit line. Offers never supply code — only an allowlisted kind and
typed params.
"""
from __future__ import annotations
import argparse, ipaddress, json, os, stat, subprocess, sys, time

PLUGIN_DIR = os.environ.get("MACRO_PLUGIN_DIR", "/usr/lib/secubox/macro/macros.d")
AUDIT_LOG = os.environ.get("MACRO_AUDIT_LOG", "/var/log/secubox/audit.log")
MESH_CIDR = os.environ.get("MACRO_MESH_CIDR", "10.10.0.0/24")
KIND_RE = __import__("re").compile(r"^[a-z][a-z0-9-]{1,31}$")
VERBS = {"grant", "activate", "revoke"}


def _die(msg, code=1):
    sys.stderr.write(json.dumps({"error": msg}) + "\n")
    raise SystemExit(code)


def _audit(rec: dict):
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except Exception:
        pass  # audit best-effort; never block the operation on log failure


def _plugin_path(kind: str) -> str:
    if not KIND_RE.match(kind):
        _die(f"invalid kind {kind!r}")
    p = os.path.join(PLUGIN_DIR, kind)
    if os.path.dirname(os.path.realpath(p)) != os.path.realpath(PLUGIN_DIR):
        _die("kind escapes plugin dir")
    if not os.path.isfile(p):
        _die(f"unknown kind {kind!r}")
    st = os.stat(p)
    if st.st_mode & stat.S_IWOTH:
        _die("plugin is world-writable — refusing (tamper guard)")
    if not (st.st_mode & stat.S_IXUSR):
        _die("plugin not executable")
    return p


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="secubox-macroctl")
    p.add_argument("kind")
    p.add_argument("verb")
    p.add_argument("--sub", default="")
    p.add_argument("--src-ip", default="")
    p.add_argument("--params", default="{}")
    p.add_argument("--cred", default="{}")
    a = p.parse_args(argv)
    if a.verb not in VERBS:
        _die(f"invalid verb {a.verb!r}")
    if a.src_ip:
        try:
            ip = ipaddress.ip_address(a.src_ip)
            if ip not in ipaddress.ip_network(MESH_CIDR):
                _die(f"--src-ip {a.src_ip} not in mesh {MESH_CIDR}")
        except ValueError:
            _die(f"--src-ip {a.src_ip!r} is not a valid IPv4")
    try:
        json.loads(a.params); json.loads(a.cred)
    except ValueError:
        _die("--params/--cred must be JSON")
    plugin = _plugin_path(a.kind)
    cmd = [plugin, a.verb, "--sub", a.sub, "--src-ip", a.src_ip,
           "--params", a.params, "--cred", a.cred]
    proc = subprocess.run(cmd, capture_output=True, text=True)  # no shell
    _audit({"ts": int(time.time()), "kind": a.kind, "verb": a.verb,
            "sub": a.sub, "src_ip": a.src_ip, "rc": proc.returncode})
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.returncode != 0 and proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
```

Note: `time.time()` is allowed here (real CLI, not a workflow script).

- [ ] **Step 4: Create the Debian package skeleton**

Create `packages/secubox-macro/debian/control`:
```
Source: secubox-macro
Section: admin
Priority: optional
Maintainer: Gerald Kerma <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2

Package: secubox-macro
Architecture: all
Depends: ${misc:Depends}, python3, nftables, secubox-core
Recommends: tor
Description: SecuBox vetted access-macro framework + tor-exit kind
 Root dispatcher secubox-macroctl and the vetted tor-exit macro that offers a
 node's Tor SOCKS port to approved mesh peers.
```
Create `debian/compat` = `13`. Create `debian/changelog` with a `secubox-macro (0.1.0-1~bookworm1) bookworm; urgency=medium` entry (mirror the format of an existing package's changelog; one bullet describing the framework + tor-exit). Create `debian/rules`:
```make
#!/usr/bin/make -f
%:
	dh $@

override_dh_auto_install:
	install -d $(CURDIR)/debian/secubox-macro/usr/sbin
	install -m 755 sbin/secubox-macroctl $(CURDIR)/debian/secubox-macro/usr/sbin/
	install -d $(CURDIR)/debian/secubox-macro/usr/lib/secubox/macro/macros.d
	install -m 755 macros.d/tor-exit $(CURDIR)/debian/secubox-macro/usr/lib/secubox/macro/macros.d/
	install -d $(CURDIR)/debian/secubox-macro/etc/sudoers.d
	install -m 440 sudoers.d/secubox-macro $(CURDIR)/debian/secubox-macro/etc/sudoers.d/
	install -d $(CURDIR)/debian/secubox-macro/etc/apparmor.d
	install -m 644 apparmor/secubox-macroctl $(CURDIR)/debian/secubox-macro/etc/apparmor.d/
	install -d $(CURDIR)/debian/secubox-macro/etc/tor/torrc.d
	install -m 644 conf/secubox-macro-tor-exit.conf.example $(CURDIR)/debian/secubox-macro/usr/share/secubox/macro/
```
(The `tor-exit` plugin, sudoers, apparmor, and conf files are created in Tasks 4–5; `dpkg-buildpackage` is only run in Task 8 after they exist.)

- [ ] **Step 5: Run tests + commit**

Run: `cd packages/secubox-macro && python3 -m pytest tests/ -q` → 5 pass.
```bash
git add packages/secubox-macro/sbin packages/secubox-macro/tests packages/secubox-macro/debian
git commit -m "feat(macro): scaffold secubox-macro + secubox-macroctl dispatcher (ref #<issueB>)"
```

### Task 4: `macros.d/tor-exit` plugin

**Files:**
- Create: `packages/secubox-macro/macros.d/tor-exit`
- Test: `packages/secubox-macro/tests/test_tor_exit.py`

**Interfaces:**
- Consumes: invoked by macroctl as `tor-exit <verb> --sub DID --src-ip IP --params JSON --cred JSON`.
- Produces: `grant` prints `{"kind":"tor-exit","endpoint":"<mesh-ip>:<port>"}`; applies nft set add. `revoke` removes it. `activate` writes consumer state.
- Env override for tests: `TOREXIT_NFT` (default `nft`), `TOREXIT_MESH_IP` (default: first wg-mesh IPv4), `TOREXIT_STATE_DIR` (default `/var/lib/secubox/macro/active`), `TOREXIT_SET` (default `secubox_macro_torexit`), `TOREXIT_TABLE` (default `inet secubox_filter`).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-macro/tests/test_tor_exit.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import json, os, subprocess, sys, pathlib
PLUG = str(pathlib.Path(__file__).resolve().parents[1] / "macros.d" / "tor-exit")


def _fake_nft(tmp_path):
    # a fake `nft` that records its argv to a file and exits 0
    d = tmp_path / "bin"; d.mkdir()
    rec = tmp_path / "nft.calls"
    fake = d / "nft"
    fake.write_text("#!/usr/bin/env bash\necho \"$@\" >> " + str(rec) + "\n")
    fake.chmod(0o755)
    return str(fake), rec


def _env(tmp_path):
    fake, rec = _fake_nft(tmp_path)
    return dict(os.environ, TOREXIT_NFT=fake, TOREXIT_MESH_IP="10.10.0.1",
               TOREXIT_STATE_DIR=str(tmp_path / "active"),
               TOREXIT_SET="secubox_macro_torexit", TOREXIT_TABLE="inet secubox_filter"), rec


def _run(args, env):
    return subprocess.run([PLUG] + args, capture_output=True, text=True, env=env)


def test_grant_emits_endpoint_and_adds_set(tmp_path):
    env, rec = _env(tmp_path)
    r = _run(["grant", "--sub", "did:plc:"+"a"*32, "--src-ip", "10.10.0.2",
              "--params", json.dumps({"socks_port": 9050})], env)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["endpoint"] == "10.10.0.1:9050"
    calls = rec.read_text()
    assert "10.10.0.2" in calls and "secubox_macro_torexit" in calls and "add" in calls


def test_revoke_removes_set(tmp_path):
    env, rec = _env(tmp_path)
    r = _run(["revoke", "--sub", "did:plc:"+"a"*32, "--src-ip", "10.10.0.2",
              "--params", "{}"], env)
    assert r.returncode == 0
    assert "delete" in rec.read_text() and "10.10.0.2" in rec.read_text()


def test_activate_writes_state(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["activate", "--cred", json.dumps({"endpoint": "10.10.0.1:9050",
              "service_id": "svc1"})], env)
    assert r.returncode == 0
    st = pathlib.Path(env["TOREXIT_STATE_DIR"]) / "svc1.json"
    assert st.exists() and "10.10.0.1:9050" in st.read_text()
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-macro && python3 -m pytest tests/test_tor_exit.py -q`
Expected: FAIL — plugin missing.

- [ ] **Step 3: Implement `macros.d/tor-exit`**

```python
# packages/secubox-macro/macros.d/tor-exit
#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: macros.d/tor-exit — offer a node's Tor SOCKS to mesh peers.

grant   : nft-allow the subscriber's mesh IP into the Tor SocksPort; emit endpoint.
revoke  : remove that allow.
activate: (consumer side) record the SOCKS endpoint for the operator.
Run only via secubox-macroctl (root, AppArmor-confined). No shell on inputs.
"""
from __future__ import annotations
import argparse, json, os, subprocess, sys

NFT = os.environ.get("TOREXIT_NFT", "nft")
MESH_IP = os.environ.get("TOREXIT_MESH_IP") or ""
STATE_DIR = os.environ.get("TOREXIT_STATE_DIR", "/var/lib/secubox/macro/active")
SET = os.environ.get("TOREXIT_SET", "secubox_macro_torexit")
TABLE = os.environ.get("TOREXIT_TABLE", "inet secubox_filter")


def _mesh_ip() -> str:
    if MESH_IP:
        return MESH_IP
    out = subprocess.run(["ip", "-4", "-o", "addr", "show", "wg-mesh"],
                         capture_output=True, text=True).stdout
    for tok in out.split():
        if "/" in tok and tok.split("/")[0].startswith("10.10.0."):
            return tok.split("/")[0]
    return ""


def _nft(*args) -> int:
    return subprocess.run([NFT, *args]).returncode


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("verb")
    p.add_argument("--sub", default=""); p.add_argument("--src-ip", default="")
    p.add_argument("--params", default="{}"); p.add_argument("--cred", default="{}")
    a = p.parse_args()
    params = json.loads(a.params)
    port = int(params.get("socks_port", 9050))

    if a.verb == "grant":
        ip = _mesh_ip()
        if not ip:
            print(json.dumps({"error": "no wg-mesh ip / tor-exit not provisioned"})); return 2
        # named set element add (idempotent); the base set + rule are created by postinst
        rc = _nft("add", "element", *TABLE.split(), SET, "{", a.src_ip, "}")
        if rc != 0:
            print(json.dumps({"error": "nft add failed"})); return 3
        print(json.dumps({"kind": "tor-exit", "endpoint": f"{ip}:{port}"}))
        return 0
    if a.verb == "revoke":
        _nft("delete", "element", *TABLE.split(), SET, "{", a.src_ip, "}")
        print(json.dumps({"ok": True})); return 0
    if a.verb == "activate":
        cred = json.loads(a.cred)
        os.makedirs(STATE_DIR, exist_ok=True)
        sid = cred.get("service_id", "unknown")
        with open(os.path.join(STATE_DIR, f"{sid}.json"), "w") as fh:
            json.dump(cred, fh)
        print(json.dumps({"ok": True, "socks": cred.get("endpoint")})); return 0
    print(json.dumps({"error": f"unknown verb {a.verb}"})); return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run tests + commit**

Run: `cd packages/secubox-macro && python3 -m pytest tests/ -q` → 8 pass (5 macroctl + 3 tor-exit).
```bash
git add packages/secubox-macro/macros.d/tor-exit packages/secubox-macro/tests/test_tor_exit.py
git commit -m "feat(macro): tor-exit plugin (nft SOCKS-over-mesh grant/revoke/activate) (ref #<issueB>)"
```

### Task 5: AppArmor, sudoers, postinst (Tor SocksPort + nft base set)

**Files:**
- Create: `packages/secubox-macro/sudoers.d/secubox-macro`
- Create: `packages/secubox-macro/apparmor/secubox-macroctl`
- Create: `packages/secubox-macro/conf/secubox-macro-tor-exit.conf.example`
- Create: `packages/secubox-macro/debian/postinst`, `debian/prerm`

- [ ] **Step 1: sudoers (validate offline)**

`packages/secubox-macro/sudoers.d/secubox-macro`:
```
# Allow the secubox service user to invoke ONLY the macro dispatcher as root.
secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-macroctl
```
Validate: `visudo -cf packages/secubox-macro/sudoers.d/secubox-macro` → "parsed OK".

- [ ] **Step 2: AppArmor profile**

`packages/secubox-macro/apparmor/secubox-macroctl` (enforce; mirror the structure of `packages/secubox-eye-square/debian/secubox-eye-square/etc/apparmor.d/secubox-eye-square-helper`):
```
#include <tunables/global>
/usr/sbin/secubox-macroctl {
  #include <abstractions/base>
  #include <abstractions/python>
  /usr/sbin/secubox-macroctl r,
  /usr/bin/python3* rix,
  /usr/lib/secubox/macro/macros.d/* rix,
  /usr/sbin/nft rix,
  /sbin/nft rix,
  /usr/bin/ip rix,
  /etc/tor/torrc.d/ r,
  /var/lib/secubox/macro/** rw,
  /var/log/secubox/audit.log w,
  network inet stream,
  network netlink raw,
}
```

- [ ] **Step 3: Tor SocksPort example + postinst**

`packages/secubox-macro/conf/secubox-macro-tor-exit.conf.example`:
```
# Rendered by postinst into /etc/tor/torrc.d/secubox-macro-tor-exit.conf with the
# node wg-mesh IP substituted. A DEDICATED SocksPort — does not touch existing Tor config.
SocksPort __MESH_IP__:9050
```
`packages/secubox-macro/debian/postinst` (`#!/bin/sh` + `set -e`, `configure` case):
```sh
        install -d -m 0750 /var/lib/secubox/macro/active /var/lib/secubox/macro/grants
        chown -R secubox:secubox /var/lib/secubox/macro 2>/dev/null || true
        # nft base set + rule (only if the secubox_filter table exists)
        if nft list table inet secubox_filter >/dev/null 2>&1; then
            nft list set inet secubox_filter secubox_macro_torexit >/dev/null 2>&1 || \
              nft add set inet secubox_filter secubox_macro_torexit '{ type ipv4_addr; }' 2>/dev/null || true
            nft add rule inet secubox_filter input iifname "wg-mesh" ip saddr @secubox_macro_torexit tcp dport 9050 accept 2>/dev/null || true
        fi
        # Tor SocksPort on the mesh IP (dedicated file; reload tor if present)
        MESH_IP=$(ip -4 -o addr show wg-mesh 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
        if [ -n "$MESH_IP" ] && [ -f /usr/share/secubox/macro/secubox-macro-tor-exit.conf.example ]; then
            sed "s/__MESH_IP__/$MESH_IP/g" /usr/share/secubox/macro/secubox-macro-tor-exit.conf.example > /etc/tor/torrc.d/secubox-macro-tor-exit.conf
            systemctl reload tor 2>/dev/null || systemctl restart tor 2>/dev/null || true
        fi
        apparmor_parser -r -W /etc/apparmor.d/secubox-macroctl 2>/dev/null || true
```
Add a matching `debian/prerm` (`remove` case: `rm -f /etc/tor/torrc.d/secubox-macro-tor-exit.conf`, drop the nft rule best-effort). Also fix the Task-3 rules `override_dh_auto_install` to install the conf to `/usr/share/secubox/macro/` (create the dir) — verify the path matches postinst.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-macro/sudoers.d packages/secubox-macro/apparmor packages/secubox-macro/conf packages/secubox-macro/debian/postinst packages/secubox-macro/debian/prerm packages/secubox-macro/debian/rules
git commit -m "feat(macro): sudoers + AppArmor + postinst (Tor SocksPort, nft base set) (ref #<issueB>)"
```

---

## Package C — secubox-p2p 1.9.0 (grant endpoint + activate + mesh listener + UI)

### Task 6: provider grant endpoint (self-signed Subscription auth)

**Files:**
- Create: `packages/secubox-p2p/api/macro_grant.py` (auth + subprocess wrapper)
- Modify: `packages/secubox-p2p/api/main.py` (mount `POST /api/v1/p2p-macro/grant/{service_id}`)
- Test: `packages/secubox-p2p/tests/test_macro_grant.py`

**Interfaces:**
- Consumes: annuaire self-cert verify (reuse `annuaire_client.did_from_pubkey_hex` from M1) + `registry`/`annuaire_client.get_catalog` (M1) to find the local offer and its `approval_mode`/`macro`.
- Produces (HTTP): `POST /api/v1/p2p-macro/grant/{service_id}` body `{subscriber, service_id, sig, signer_did, subscriber_pubkey}` → 200 `{endpoint,...}` | 403.
- Produces (fn): `authorize_grant(offer, sub_body, verify_fn) -> (ok: bool, reason: str)` (pure, testable).

- [ ] **Step 1: Write the failing test** (pure authorize_grant logic — sig verify injected)

```python
# packages/secubox-p2p/tests/test_macro_grant.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
from api import macro_grant

DID = "did:plc:" + "b" * 32


def _offer(mode="auto", macro=True):
    o = {"service_id": "svc1", "provider": "did:plc:"+"c"*32, "approval_mode": mode}
    if macro:
        o["macro"] = {"kind": "tor-exit", "params": {"socks_port": 9050}}
    return o


def _sub(service_id="svc1", subscriber=DID):
    return {"subscriber": subscriber, "service_id": service_id, "sig": "ok",
            "signer_did": subscriber, "subscriber_pubkey": "deadbeef"}


def test_authorize_ok_when_sig_valid_service_matches_and_auto():
    ok, why = macro_grant.authorize_grant(_offer(), _sub(), verify_fn=lambda s: True)
    assert ok, why


def test_reject_when_sig_invalid():
    ok, why = macro_grant.authorize_grant(_offer(), _sub(), verify_fn=lambda s: False)
    assert not ok and "sig" in why.lower()


def test_reject_when_service_id_mismatch():
    ok, why = macro_grant.authorize_grant(_offer(), _sub(service_id="other"),
                                          verify_fn=lambda s: True)
    assert not ok


def test_reject_when_offer_pending():
    ok, why = macro_grant.authorize_grant(_offer(mode="pending"), _sub(),
                                          verify_fn=lambda s: True)
    assert not ok and "auto" in why.lower()


def test_reject_when_no_macro():
    ok, why = macro_grant.authorize_grant(_offer(macro=False), _sub(),
                                          verify_fn=lambda s: True)
    assert not ok
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_macro_grant.py -q` → FAIL (module missing).

- [ ] **Step 3: Implement `api/macro_grant.py`**

```python
# packages/secubox-p2p/api/macro_grant.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-p2p :: macro_grant

Provider-side authorization + invocation for macro grants. A consumer presents
its self-signed Subscription; we authorize self-certifyingly against an auto
offer, then run `sudo secubox-macroctl <kind> grant`. No federated state needed.
"""
from __future__ import annotations
import json, subprocess
from typing import Callable, Dict, Optional, Tuple


def authorize_grant(offer: Dict, sub: Dict, verify_fn: Callable[[Dict], bool]) -> Tuple[bool, str]:
    """Return (ok, reason). offer = local ServiceOffer dict; sub = presented
    Subscription dict (+subscriber_pubkey). verify_fn(sub) checks the signature
    self-certifyingly (pubkey hashes to subscriber AND sig verifies)."""
    if not offer or not offer.get("macro"):
        return False, "offer has no macro"
    if offer.get("approval_mode") != "auto":
        return False, "only auto-mode macro offers are grantable (pending unsupported)"
    if sub.get("service_id") != offer.get("service_id"):
        return False, "subscription service_id mismatch"
    if not verify_fn(sub):
        return False, "subscription signature invalid (self-cert failed)"
    return True, "ok"


def run_grant(kind: str, sub_did: str, src_ip: str, params: Dict) -> Tuple[Optional[Dict], Optional[str]]:
    """sudo secubox-macroctl <kind> grant ... → (credential_dict, error)."""
    cmd = ["sudo", "-n", "/usr/sbin/secubox-macroctl", kind, "grant",
           "--sub", sub_did, "--src-ip", src_ip, "--params", json.dumps(params)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"
    if p.returncode != 0:
        return None, (p.stderr or p.stdout or "macroctl grant failed").strip()
    try:
        return json.loads(p.stdout), None
    except ValueError:
        return None, "grant produced non-JSON"
```

In `api/main.py` add the endpoint (self-cert verify reuses `annuaire_client.did_from_pubkey_hex`; the ed25519 sig check mirrors annuaire — verify `subscriber_pubkey` hashes to `subscriber` and the sig covers the canonical Subscription payload):

```python
@app.post("/api/v1/p2p-macro/grant/{service_id}")
async def macro_grant_endpoint(service_id: str, req: Request):
    from api import macro_grant, annuaire_client, registry  # noqa: PLC0415
    body = await req.json()
    catalog, _ = annuaire_client.get_catalog()
    offer = next((o for o in catalog if o.get("service_id") == service_id), None)
    if offer is None:
        return JSONResponse({"error": "unknown service"}, status_code=404)

    def _verify(sub):
        pub = sub.get("subscriber_pubkey", "")
        if not pub or annuaire_client.did_from_pubkey_hex(pub) != sub.get("subscriber"):
            return False
        return _verify_subscription_sig(sub, pub)   # ed25519 over canonical payload

    ok, why = macro_grant.authorize_grant(offer, body, _verify)
    if not ok:
        return JSONResponse({"error": why}, status_code=403)
    src_ip = (req.client.host if req.client else "") or req.headers.get("x-real-ip", "")
    cred, err = macro_grant.run_grant(offer["macro"]["kind"], body["subscriber"],
                                      src_ip, offer["macro"].get("params", {}))
    if err:
        return JSONResponse({"error": err}, status_code=502)
    cred["service_id"] = service_id
    return cred
```

Add `_verify_subscription_sig(sub, pub_hex)` next to it: reconstruct the signed payload (`{k:v for k,v in sub if k not in ("sig","signer_did","subscriber_pubkey")}`), canonical-encode it the same way annuaire does (JSON `sort_keys=True, separators=(",",":")`), and ed25519-verify `sub["sig"]` with `cryptography`. (Import `Request`/`JSONResponse` from fastapi if not already.)

- [ ] **Step 4: Run tests + commit**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_macro_grant.py -q` → 5 pass; then `python3 -m pytest tests/ -q` all green.
```bash
git add packages/secubox-p2p/api/macro_grant.py packages/secubox-p2p/api/main.py packages/secubox-p2p/tests/test_macro_grant.py
git commit -m "feat(p2p): macro grant endpoint — self-signed Subscription auth over auto offer (ref #<issueC>)"
```

### Task 7: consumer activate pulls credential + revoke-access + mesh listener

**Files:**
- Modify: `packages/secubox-p2p/api/main.py` (extend `/services/{id}/activate`; add `/services/{id}/revoke-access`)
- Create: `packages/secubox-p2p/nginx/p2p-macro-mesh.conf.tpl` (mesh listener for the grant endpoint)
- Modify: `packages/secubox-p2p/debian/{rules,postinst,postrm}` (render/remove mesh listener)
- Test: extend `packages/secubox-p2p/tests/test_services_endpoints.py`

**Interfaces:**
- Consumes: `macro_grant` (Task 6), `annuaire_client` (M1, node identity + catalog), `registry` (M1 overlay).
- Produces (HTTP): `POST /services/{id}/activate` (now pulls credential for automatable remote offers, runs `sudo macroctl activate`, records overlay + endpoint); `POST /services/{id}/revoke-access` (`sudo macroctl revoke`).

- [ ] **Step 1: Write the failing test** (activate pulls + calls macroctl activate; monkeypatch the pull + subprocess)

```python
def test_activate_remote_macro_pulls_and_runs_activate(client, monkeypatch):
    import api.main as m
    called = {}
    monkeypatch.setattr(m, "_pull_grant", lambda offer: ({"endpoint": "10.10.0.1:9050",
                        "kind": "tor-exit", "service_id": "s2"}, None))
    monkeypatch.setattr(m, "_macroctl_activate", lambda kind, cred: (True, None) or called.setdefault("cred", cred))
    r = client.post("/services/s2/activate")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"
```
(Adapt to the fixture in test_services_endpoints.py; `s2` is the remote tor-exit offer — extend the fixture's catalog to include a `macro` on `s2` and mark it approved.)

- [ ] **Step 2: Run to verify it fails**, then **Step 3: implement**:
  - `_pull_grant(offer)`: build the consumer's self-signed Subscription (`annuaire_client` node identity + sign a `{subscriber, service_id, requested_at}` payload; include `subscriber_pubkey`), POST it to `http://<provider-mesh-ip>:8798/api/v1/p2p-macro/grant/<sid>` (derive provider mesh IP from the offer endpoint / a mesh lookup), return `(cred, err)`. Never raises.
  - `_macroctl_activate(kind, cred)`: `sudo -n /usr/sbin/secubox-macroctl <kind> activate --cred <json>` → `(ok, err)`.
  - Extend `activate_service`: if `offer.macro` and remote → `_pull_grant` → `_macroctl_activate` → on success set overlay active + store the endpoint; return `{status:ok, endpoint}`. Non-macro path unchanged (M1).
  - Add `revoke_access` endpoint: `sudo -n macroctl <kind> revoke --sub <did> --src-ip <our-mesh-ip>` + clear overlay active.
  - Mesh listener `nginx/p2p-macro-mesh.conf.tpl`: mirror #766's annuaire mesh listener but bind `__MESH_IP__:8798`, `allow 10.10.0.0/24; deny all;`, `location = /api/v1/p2p-macro/grant` → `proxy_pass unix:/run/secubox/p2p.sock` (note: this is a prefix; use a `location ~ ^/api/v1/p2p-macro/grant/` regex). postinst renders it with the wg-mesh IP + validates with `nginx -t` (revert on failure, per #766 pattern); postrm removes it; also add the nft allow for tcp dport 8798 on wg-mesh from 10.10.0.0/24 (same drop-in pattern).

- [ ] **Step 4: Run full p2p suite + commit**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/ -q` → all green.
```bash
git add packages/secubox-p2p/api/main.py packages/secubox-p2p/nginx packages/secubox-p2p/debian packages/secubox-p2p/tests/test_services_endpoints.py
git commit -m "feat(p2p): consumer activate pulls macro credential + mesh listener + revoke-access (ref #<issueC>)"
```

### Task 8: UI + p2p 1.9.0 packaging + build all three + live gk2↔c3box demo

**Files:**
- Modify: `packages/secubox-p2p/www/p2p/index.html` (Activate shows SOCKS endpoint; Revoke-access button on active macro rows)
- Modify: `packages/secubox-p2p/debian/changelog` (1.9.0)

- [ ] **Step 1: UI** — in `loadServices()`, for rows where `svc.automatable` and `svc.active`, show the stored SOCKS endpoint (from `GET /services` — extend the merge to surface `activation.overlay[sid].endpoint`) and a "Revoke access" button calling `POST /services/{id}/revoke-access`. `node --check` the extracted script block.

- [ ] **Step 2: changelog 1.9.0** — prepend an entry describing the macro grant endpoint, consumer activate credential-pull, mesh listener (8798), and the UI. `-- Gerald Kerma ... Wed, 01 Jul 2026 ...`.

- [ ] **Step 3: Build all three packages**

```bash
for P in secubox-annuaire secubox-macro secubox-p2p; do
  (cd packages/$P && dpkg-buildpackage -us -uc -b 2>&1 | grep -iE "dpkg-deb: building|error")
done
ls packages/secubox-annuaire_0.3.0-*_all.deb packages/secubox-macro_0.1.0-*_all.deb packages/secubox-p2p_1.9.0-*_all.deb
```

- [ ] **Step 4: Deploy + live demo (gk2 provider, c3box consumer)**

```bash
# deploy all three to gk2 + c3box, restart annuaire + p2p, reload nginx
# gk2: offer a tor-exit service
ssh root@192.168.1.200 'runuser -u secubox -- annuairectl offer --name "Tor exit" --kind tor-exit \
   --endpoint "http://10.10.0.1/tor" --mode auto --macro-kind tor-exit --macro-param socks_port=9050'
# c3box: pull catalog, subscribe (auto→approved), activate → pulls grant from gk2
ssh root@192.168.1.94 'runuser -u secubox -- annuairectl pull http://10.10.0.1:8799; \
   TOKEN=$(python3 -c "import secubox_core.auth as a;print(a.create_token(\"admin\"))"); \
   SID=$(curl -s --unix-socket /run/secubox/p2p.sock http://x/services | python3 -c "import sys,json;print([s[\"service_id\"] for s in json.load(sys.stdin)[\"services\"] if s[\"name\"]==\"Tor exit\"][0]"); \
   curl -s -X POST -H "Authorization: Bearer $TOKEN" --unix-socket /run/secubox/p2p.sock http://x/services/$SID/activate'
# verify on gk2: c3box mesh IP now in the nft set; c3box can reach the SOCKS port
ssh root@192.168.1.200 'nft list set inet secubox_filter secubox_macro_torexit'
ssh root@192.168.1.94 'curl -s --socks5 10.10.0.1:9050 -o /dev/null -w "%{http_code}\n" --max-time 10 https://check.torproject.org/ || echo "socks reachable test"'
```
Expected: gk2's `secubox_macro_torexit` set contains c3box's mesh IP (10.10.0.2); c3box reaches the Tor SOCKS via the mesh. Revoke removes it.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-p2p/www/p2p/index.html packages/secubox-p2p/debian/changelog
git commit -m "feat(p2p): macro UI (SOCKS endpoint + revoke) + 1.9.0 (ref #<issueC>)"
```

---

## Notes for the executor
- Replace `#<issueA/B/C>` with the GitHub issue number(s) created for this work (one umbrella issue is fine; reference it in every commit).
- Run each package's FULL test suite after its tasks; never regress a sibling.
- Tasks 1–2 (annuaire), 3–5 (secubox-macro), 6–8 (p2p) are ordered: p2p Task 6 needs the annuaire `macro` field (Task 1) and the macro package (Tasks 3–5) present for the live demo, but the p2p unit tests mock macroctl so they don't need it installed.
- The live demo (Task 8) is the real proof; if the mesh reverse-path (gk2→c3box) matters, note the parked nft issue — but here gk2 is the PROVIDER and c3box PULLS, so it uses the working consumer→provider direction.
- Do NOT implement pending-mode macros, additional kinds, or transparent consumer routing — all out of scope (spec §1/§9).
