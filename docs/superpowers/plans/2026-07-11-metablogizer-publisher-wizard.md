# MetaBlogizer Publisher Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A guided publish wizard in `secubox-metablogizer` that takes a static site from upload → gitea version → WAF route → TLS cert → portable backup, doing every privileged step through one audited root helper.

**Architecture:** New pure-Python modules under `packages/secubox-metablogizer/api/publish/` (content extraction, routing, certs, backup) + a `api/routers/publish.py` FastAPI router, all running as user `secubox`. Every privileged action (HAProxy vhost, sbxwaf route file, certbot) is delegated to a new root helper `/usr/sbin/secubox-publishctl` invoked via `sudo -n`, gated by a one-line sudoers drop-in. The dead `sync_mitmproxy_routes` (writes the retired mitmproxy-LXC file) is retired; routes now land in the live sbxwaf host file.

**Tech Stack:** Python 3.11 / FastAPI (Unix socket), pytest, bash (root helper), Debian packaging, nginx + HAProxy + Go sbxwaf + gitea + certbot.

## Global Constraints

- Never `waf_bypass`; every published host routes through the `mitmproxy_inspector` HAProxy backend (= Go sbxwaf); nftables stays DEFAULT DROP.
- JWT on every endpoint via `Depends(require_jwt)` (imported `from secubox_core.auth import require_jwt`); Unix socket only, no TCP.
- sbxwaf route file is exactly `/etc/secubox/waf/haproxy-routes.json`; a metablogizer site's route value is `["192.168.1.200", 8900]` (constants `NGINX_BACKEND_IP` / `BASE_PORT` already in `api/main.py`); write then reload sbxwaf.
- Privileged ops go ONLY through `/usr/sbin/secubox-publishctl` (root) via `sudo -n`; the FastAPI process never writes root-owned config directly.
- `/etc/secubox` parent stays `0755`; module config files are `secubox:secubox 0640`; secrets `0700`. No root-owned config a `secubox` daemon must write.
- Site layout: `SITES_ROOT/<name>/` where `SITES_ROOT=/srv/metablogizer/sites`, docroot is `<site>/public/`, gitea repo is `<site>/.git`.
- `git_commit_push(site_dir: Path, message: str) -> {"pushed": bool, "committed": bool, "commit": str|None, "reason": str}` (from `api/webhook.py`) is the versioning primitive — reuse it, do not reimplement.
- No mass daemon restart on gk2: reload only the touched service, validate before reload.
- No Claude Code references in commit messages. End commits with `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`.
- Every new `.py` starts with the SPDX header used across the repo:
  ```python
  # SPDX-License-Identifier: LicenseRef-CMSD-1.0
  # Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  ```
- Domain validation regex (single source of truth, reused by helper + Python):
  `^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`

## File Structure

Inside `packages/secubox-metablogizer/`:
- `sbin/secubox-publishctl` — root helper (bash). Verbs: `vhost-add`, `vhost-del`, `waf-route`, `cert`. Validates every arg.
- `api/publish/__init__.py` — package marker.
- `api/publish/content.py` — safe zip/html extraction into a docroot.
- `api/publish/routing.py` — pure route-file merge + thin `publishctl` invocation wrapper; retires `sync_mitmproxy_routes`.
- `api/publish/certs.py` — wildcard-vs-custom decision + `publishctl cert` wrapper.
- `api/publish/backup.py` — `.sbxsite` pack/unpack (git bundle + manifest).
- `api/routers/__init__.py`, `api/routers/publish.py` — FastAPI router (mounted in `api/main.py`).
- `api/tests/test_publish_content.py`, `test_publish_routing.py`, `test_publish_certs.py`, `test_publish_backup.py`, `test_publishctl.py`.
- `www/metablogizer/index.html` — add the 5-step wizard UI.
- `debian/secubox-metablogizer.install`, `debian/postinst`, `debian/secubox-publish-wizard.sudoers`, `debian/changelog`.

Inside `packages/secubox-publish/`: `api/main.py` (delegate publish to metablogizer; remove direct `/etc/haproxy` + `/etc/nginx` writes), `debian/changelog`.

Inside `packages/secubox-droplet/`: `debian/postinst` (droplet.toml ownership), `debian/changelog`.

---

## Task 1: `secubox-publishctl` root helper + sudoers

The single privileged entry point. Pure bash, strict validation, no `eval`. Must exist before any Python that calls it.

**Files:**
- Create: `packages/secubox-metablogizer/sbin/secubox-publishctl`
- Create: `packages/secubox-metablogizer/debian/secubox-publish-wizard.sudoers`
- Test: `packages/secubox-metablogizer/api/tests/test_publishctl.py`

**Interfaces:**
- Produces: CLI `secubox-publishctl <verb> [args...]` printing one JSON object to stdout `{"ok": bool, "detail": "..."}` and exiting 0 on success, non-zero on validation failure. Verbs:
  - `waf-route <domain> <port>` → merge `{domain: ["192.168.1.200", <port>]}` into `/etc/secubox/waf/haproxy-routes.json`, reload sbxwaf.
  - `vhost-add <domain>` → `haproxyctl vhost add <domain>` (idempotent).
  - `vhost-del <domain>` → remove domain from the route file + `haproxyctl vhost del <domain>`, reload sbxwaf.
  - `cert <domain>` → `{"ok":true,"detail":"wildcard"}` if domain ends `.gk2.secubox.in`; else certbot HTTP-01 then assemble `/etc/haproxy/certs/<domain>.pem`, reload haproxy; on certbot failure exit non-zero with `{"ok":false,"detail":"<err>"}`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-metablogizer/api/tests/test_publishctl.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""secubox-publishctl argument validation (run the script with a fake route file
and mocked nft/haproxy/certbot on PATH — validation must reject junk BEFORE any
privileged call)."""
import json
import os
import subprocess
from pathlib import Path

HELPER = Path(__file__).resolve().parents[2] / "sbin" / "secubox-publishctl"


def _run(args, env):
    return subprocess.run(["bash", str(HELPER), *args], capture_output=True, text=True, env=env)


def _env(tmp_path):
    # Fake bins that just succeed, so a VALID call would pass; validation must
    # fail earlier for bad input.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("haproxyctl", "systemctl", "certbot", "haproxy"):
        p = bindir / name
        p.write_text("#!/bin/bash\nexit 0\n")
        p.chmod(0o755)
    routes = tmp_path / "routes.json"
    routes.write_text("{}")
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["SBX_WAF_ROUTES_FILE"] = str(routes)
    env["SBX_HAPROXY_CERTS_DIR"] = str(tmp_path / "certs")
    return env, routes


def test_waf_route_rejects_bad_domain(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["waf-route", "evil;rm -rf /", "8900"], env)
    assert r.returncode != 0
    assert "ok" in r.stdout and json.loads(r.stdout)["ok"] is False


def test_waf_route_rejects_non_numeric_port(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["waf-route", "good.gk2.secubox.in", "80x"], env)
    assert r.returncode != 0


def test_waf_route_writes_host_backend(tmp_path):
    env, routes = _env(tmp_path)
    r = _run(["waf-route", "zem.gk2.secubox.in", "8900"], env)
    assert r.returncode == 0, r.stderr
    data = json.loads(routes.read_text())
    assert data["zem.gk2.secubox.in"] == ["192.168.1.200", 8900]


def test_cert_wildcard_is_noop_for_gk2(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["cert", "zem.gk2.secubox.in"], env)
    assert r.returncode == 0
    assert json.loads(r.stdout)["detail"] == "wildcard"


def test_unknown_verb_fails(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["frobnicate", "x"], env)
    assert r.returncode != 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-metablogizer && python -m pytest api/tests/test_publishctl.py -q`
Expected: FAIL (helper script does not exist yet → all cases error/non-zero in unexpected ways; `test_waf_route_writes_host_backend` fails to find the file).

- [ ] **Step 3: Write the helper**

```bash
# packages/secubox-metablogizer/sbin/secubox-publishctl
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# SecuBox-Deb :: secubox-publishctl — the ONLY privileged entry point for the
# MetaBlogizer publisher wizard. Runs as root via a tight sudoers rule; the
# FastAPI process (user secubox) never writes root config directly.
set -euo pipefail

WAF_ROUTES_FILE="${SBX_WAF_ROUTES_FILE:-/etc/secubox/waf/haproxy-routes.json}"
HAPROXY_CERTS_DIR="${SBX_HAPROXY_CERTS_DIR:-/etc/haproxy/certs}"
BACKEND_IP="192.168.1.200"
GK2_SUFFIX=".gk2.secubox.in"
DOMAIN_RE='^(([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+)$'

emit() { printf '{"ok":%s,"detail":"%s"}\n' "$1" "$2"; }
die()  { emit false "$1"; exit 1; }

valid_domain() { [[ "$1" =~ $DOMAIN_RE && ${#1} -le 253 ]]; }
valid_port()   { [[ "$1" =~ ^[0-9]+$ && "$1" -ge 1 && "$1" -le 65535 ]]; }

reload_sbxwaf() {
  # sbxwaf hot-reloads the route file; nudge it best-effort, never fatal.
  systemctl reload secubox-waf 2>/dev/null || systemctl reload sbxwaf 2>/dev/null || true
}

waf_route() {
  local domain="$1" port="$2"
  valid_domain "$domain" || die "invalid domain"
  valid_port "$port"     || die "invalid port"
  # Merge with python3 (present) so we never hand-roll JSON.
  python3 - "$WAF_ROUTES_FILE" "$domain" "$BACKEND_IP" "$port" <<'PY'
import json, sys, os
path, domain, ip, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
try:
    data = json.load(open(path))
    if not isinstance(data, dict): raise ValueError
except Exception:
    data = {}
data[domain] = [ip, port]
tmp = path + ".tmp"
json.dump(data, open(tmp, "w"), indent=2, sort_keys=True)
os.replace(tmp, path)
PY
  reload_sbxwaf
  emit true "routed $domain -> $BACKEND_IP:$port"
}

vhost_add() {
  local domain="$1"; valid_domain "$domain" || die "invalid domain"
  haproxyctl vhost add "$domain" >/dev/null 2>&1 || true   # additive, idempotent
  emit true "vhost $domain"
}

vhost_del() {
  local domain="$1"; valid_domain "$domain" || die "invalid domain"
  python3 - "$WAF_ROUTES_FILE" "$domain" <<'PY'
import json, sys, os
path, domain = sys.argv[1], sys.argv[2]
try: data = json.load(open(path))
except Exception: data = {}
data.pop(domain, None)
tmp = path + ".tmp"; json.dump(data, open(tmp,"w"), indent=2, sort_keys=True); os.replace(tmp, path)
PY
  haproxyctl vhost del "$domain" >/dev/null 2>&1 || true
  reload_sbxwaf
  emit true "removed $domain"
}

cert() {
  local domain="$1"; valid_domain "$domain" || die "invalid domain"
  if [[ "$domain" == *"$GK2_SUFFIX" ]]; then
    emit true "wildcard"; return 0
  fi
  mkdir -p "$HAPROXY_CERTS_DIR"
  if ! certbot certonly --non-interactive --agree-tos --standalone \
        --preferred-challenges http -d "$domain" >/dev/null 2>&1; then
    die "certbot failed for $domain"
  fi
  local live="/etc/letsencrypt/live/$domain"
  cat "$live/fullchain.pem" "$live/privkey.pem" > "$HAPROXY_CERTS_DIR/$domain.pem"
  systemctl reload haproxy 2>/dev/null || true
  emit true "issued"
}

[[ $# -ge 1 ]] || die "usage: secubox-publishctl <verb> ..."
verb="$1"; shift
case "$verb" in
  waf-route) [[ $# -eq 2 ]] || die "waf-route <domain> <port>"; waf_route "$1" "$2" ;;
  vhost-add) [[ $# -eq 1 ]] || die "vhost-add <domain>";       vhost_add "$1" ;;
  vhost-del) [[ $# -eq 1 ]] || die "vhost-del <domain>";       vhost_del "$1" ;;
  cert)      [[ $# -eq 1 ]] || die "cert <domain>";            cert "$1" ;;
  *) die "unknown verb: $verb" ;;
esac
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-metablogizer && python -m pytest api/tests/test_publishctl.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Write the sudoers drop-in**

```
# packages/secubox-metablogizer/debian/secubox-publish-wizard.sudoers
# Installed to /etc/sudoers.d/secubox-publish-wizard (mode 0440).
secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-publishctl
```

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-metablogizer/sbin/secubox-publishctl \
        packages/secubox-metablogizer/debian/secubox-publish-wizard.sudoers \
        packages/secubox-metablogizer/api/tests/test_publishctl.py
git commit -m "feat(metablogizer): secubox-publishctl root helper for privileged publish steps

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 2: Safe content extraction (`api/publish/content.py`)

**Files:**
- Create: `packages/secubox-metablogizer/api/publish/__init__.py` (empty)
- Create: `packages/secubox-metablogizer/api/publish/content.py`
- Test: `packages/secubox-metablogizer/api/tests/test_publish_content.py`

**Interfaces:**
- Produces: `extract_archive(docroot: Path, data: bytes, filename: str) -> dict` returning `{"files": int, "bytes": int, "index_present": bool}`. For `*.zip`: clears `docroot` then extracts, rejecting any member whose resolved path escapes `docroot` (raises `ContentError`). For `*.html`: writes bytes to `docroot/index.html`. For any other single file: writes bytes to `docroot/<safe basename>`. `class ContentError(Exception)`.
- Consumes: nothing.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-metablogizer/api/tests/test_publish_content.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import io
import zipfile
from pathlib import Path

import pytest

from publish.content import extract_archive, ContentError


def _zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in members.items():
            z.writestr(name, body)
    return buf.getvalue()


def test_clean_zip_extracts(tmp_path):
    doc = tmp_path / "public"; doc.mkdir()
    res = extract_archive(doc, _zip({"index.html": "<h1>hi</h1>", "css/a.css": "body{}"}), "site.zip")
    assert (doc / "index.html").read_text() == "<h1>hi</h1>"
    assert (doc / "css" / "a.css").exists()
    assert res["index_present"] is True and res["files"] == 2


def test_zip_slip_rejected(tmp_path):
    doc = tmp_path / "public"; doc.mkdir()
    with pytest.raises(ContentError):
        extract_archive(doc, _zip({"../escape.html": "x"}), "evil.zip")
    assert not (tmp_path / "escape.html").exists()


def test_absolute_member_rejected(tmp_path):
    doc = tmp_path / "public"; doc.mkdir()
    with pytest.raises(ContentError):
        extract_archive(doc, _zip({"/etc/passwd": "x"}), "evil.zip")


def test_single_html_becomes_index(tmp_path):
    doc = tmp_path / "public"; doc.mkdir()
    res = extract_archive(doc, b"<h1>solo</h1>", "whatever.html")
    assert (doc / "index.html").read_text() == "<h1>solo</h1>"
    assert res["index_present"] is True


def test_zip_replaces_previous_content(tmp_path):
    doc = tmp_path / "public"; doc.mkdir()
    (doc / "old.html").write_text("old")
    extract_archive(doc, _zip({"index.html": "new"}), "s.zip")
    assert not (doc / "old.html").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-metablogizer && PYTHONPATH=api python -m pytest api/tests/test_publish_content.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'publish'`.

- [ ] **Step 3: Write the implementation**

```python
# packages/secubox-metablogizer/api/publish/content.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Safe extraction of an uploaded static-site archive into a site docroot."""
from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path


class ContentError(Exception):
    """Raised when an upload is unsafe (zip-slip / absolute path)."""


def _safe_join(root: Path, member: str) -> Path:
    # Reject absolute paths and any member that escapes root once resolved.
    if member.startswith("/") or member.startswith("\\"):
        raise ContentError(f"absolute path in archive: {member}")
    target = (root / member).resolve()
    if root.resolve() not in (target, *target.parents):
        raise ContentError(f"path escapes docroot: {member}")
    return target


def extract_archive(docroot: Path, data: bytes, filename: str) -> dict:
    docroot.mkdir(parents=True, exist_ok=True)
    name = (filename or "").lower()
    if name.endswith(".zip"):
        # Validate ALL members before writing anything.
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            members = [m for m in z.infolist() if not m.is_dir()]
            targets = [_safe_join(docroot, m.filename) for m in members]
            # Clear previous content (a zip is a fresh publish; history is in gitea).
            for child in docroot.iterdir():
                if child.name == ".git":
                    continue
                shutil.rmtree(child) if child.is_dir() else child.unlink()
            total = 0
            for m, target in zip(members, targets):
                target.parent.mkdir(parents=True, exist_ok=True)
                blob = z.read(m)
                target.write_bytes(blob)
                total += len(blob)
        return {"files": len(members), "bytes": total,
                "index_present": (docroot / "index.html").exists()}

    # Single file: an .html (or anything) becomes index.html unless it has a
    # concrete non-index basename we should preserve.
    if name.endswith(".html") or "." not in Path(name).name:
        dest = docroot / "index.html"
    else:
        dest = _safe_join(docroot, Path(name).name)
    dest.write_bytes(data)
    return {"files": 1, "bytes": len(data), "index_present": (docroot / "index.html").exists()}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-metablogizer && PYTHONPATH=api python -m pytest api/tests/test_publish_content.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metablogizer/api/publish/__init__.py \
        packages/secubox-metablogizer/api/publish/content.py \
        packages/secubox-metablogizer/api/tests/test_publish_content.py
git commit -m "feat(metablogizer): safe zip/html upload extraction (zip-slip guarded)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 3: Routing (`api/publish/routing.py`) — retire the dead mitmproxy sync

**Files:**
- Create: `packages/secubox-metablogizer/api/publish/routing.py`
- Modify: `packages/secubox-metablogizer/api/main.py` (remove `sync_mitmproxy_routes` and its call sites; the router in Task 6 uses `routing.apply_route`).
- Test: `packages/secubox-metablogizer/api/tests/test_publish_routing.py`

**Interfaces:**
- Consumes: `secubox-publishctl` (Task 1).
- Produces:
  - `merge_route(existing: dict, domain: str, ip: str, port: int) -> dict` — pure; returns a new dict with `existing[domain] = [ip, port]`.
  - `apply_route(domain: str, port: int = 8900, runner=_sudo_publishctl) -> dict` — calls `publishctl vhost-add <domain>` then `publishctl waf-route <domain> <port>`; returns `{"route_ok": bool, "vhost": dict, "waf": dict}`. `runner(verb, *args) -> dict` defaults to a `sudo -n /usr/sbin/secubox-publishctl` subprocess wrapper returning the parsed JSON; injectable for tests.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-metablogizer/api/tests/test_publish_routing.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
from publish.routing import merge_route, apply_route


def test_merge_route_sets_host_backend():
    out = merge_route({"a.gk2.secubox.in": ["192.168.1.200", 8900]},
                      "zem.gk2.secubox.in", "192.168.1.200", 8900)
    assert out["zem.gk2.secubox.in"] == ["192.168.1.200", 8900]
    assert "a.gk2.secubox.in" in out  # additive


def test_merge_route_is_idempotent():
    base = {}
    once = merge_route(base, "z.gk2.secubox.in", "192.168.1.200", 8900)
    twice = merge_route(once, "z.gk2.secubox.in", "192.168.1.200", 8900)
    assert once == twice


def test_apply_route_calls_vhost_then_waf():
    calls = []
    def runner(verb, *args):
        calls.append((verb, args))
        return {"ok": True, "detail": "x"}
    res = apply_route("zem.gk2.secubox.in", 8900, runner=runner)
    assert calls == [("vhost-add", ("zem.gk2.secubox.in",)),
                     ("waf-route", ("zem.gk2.secubox.in", "8900"))]
    assert res["route_ok"] is True


def test_apply_route_reports_failure():
    def runner(verb, *args):
        return {"ok": verb == "vhost-add", "detail": "boom" if verb == "waf-route" else "ok"}
    res = apply_route("zem.gk2.secubox.in", 8900, runner=runner)
    assert res["route_ok"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-metablogizer && PYTHONPATH=api python -m pytest api/tests/test_publish_routing.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'publish.routing'`.

- [ ] **Step 3: Write the implementation**

```python
# packages/secubox-metablogizer/api/publish/routing.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""WAF/HAProxy routing for published sites — all privileged work is delegated
to `secubox-publishctl`. Replaces the retired `sync_mitmproxy_routes` (which
wrote the dead mitmproxy-LXC route file)."""
from __future__ import annotations

import json
import subprocess

PUBLISHCTL = "/usr/sbin/secubox-publishctl"


def merge_route(existing: dict, domain: str, ip: str, port: int) -> dict:
    out = dict(existing)
    out[domain] = [ip, int(port)]
    return out


def _sudo_publishctl(verb: str, *args: str) -> dict:
    try:
        p = subprocess.run(["sudo", "-n", PUBLISHCTL, verb, *args],
                           capture_output=True, text=True, timeout=120)
        try:
            return json.loads(p.stdout.strip() or "{}")
        except json.JSONDecodeError:
            return {"ok": False, "detail": (p.stderr or p.stdout).strip()[:200]}
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"ok": False, "detail": str(e)}


def apply_route(domain: str, port: int = 8900, runner=_sudo_publishctl) -> dict:
    vhost = runner("vhost-add", domain)
    waf = runner("waf-route", domain, str(port))
    return {"route_ok": bool(vhost.get("ok")) and bool(waf.get("ok")),
            "vhost": vhost, "waf": waf}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-metablogizer && PYTHONPATH=api python -m pytest api/tests/test_publish_routing.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Remove the dead sync**

In `packages/secubox-metablogizer/api/main.py`, delete the `def sync_mitmproxy_routes(...)` function (the `~78-134` block) and every call to it. Grep first: `grep -n "sync_mitmproxy_routes" api/main.py` and remove each call (they are best-effort side calls in the site create/upload paths). Also remove the now-unused `MITMPROXY_ROUTES` / `MITMPROXY_IN_ROUTES` constants if no other reference remains (`grep -n MITMPROXY_ api/main.py`).

- [ ] **Step 6: Verify nothing else references it**

Run: `cd packages/secubox-metablogizer && grep -n "sync_mitmproxy_routes\|MITMPROXY_ROUTES\|MITMPROXY_IN_ROUTES" api/main.py`
Expected: no output. Then `PYTHONPATH=api python -c "import ast; ast.parse(open('api/main.py').read()); print('ok')"` → `ok`.

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-metablogizer/api/publish/routing.py \
        packages/secubox-metablogizer/api/tests/test_publish_routing.py \
        packages/secubox-metablogizer/api/main.py
git commit -m "feat(metablogizer): route publishes into the live sbxwaf host file via publishctl

Retires sync_mitmproxy_routes (wrote the retired mitmproxy-LXC file — the zem 421).

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 4: Certificates (`api/publish/certs.py`)

**Files:**
- Create: `packages/secubox-metablogizer/api/publish/certs.py`
- Test: `packages/secubox-metablogizer/api/tests/test_publish_certs.py`

**Interfaces:**
- Consumes: `secubox-publishctl cert` (Task 1).
- Produces: `provision_cert(domain: str, runner=_sudo_publishctl) -> dict` returning `{"mode": "wildcard"|"issued"|"pending", "detail": str}`. `*.gk2.secubox.in` → asks the helper (returns `wildcard`). Custom domain → helper runs certbot; a helper `ok:false` maps to `mode="pending"` (non-fatal). `is_wildcard_domain(domain) -> bool` (pure).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-metablogizer/api/tests/test_publish_certs.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
from publish.certs import provision_cert, is_wildcard_domain


def test_gk2_is_wildcard():
    assert is_wildcard_domain("zem.gk2.secubox.in") is True
    assert is_wildcard_domain("blog.example.com") is False


def test_provision_gk2_returns_wildcard():
    res = provision_cert("zem.gk2.secubox.in", runner=lambda v, *a: {"ok": True, "detail": "wildcard"})
    assert res["mode"] == "wildcard"


def test_provision_custom_issued():
    res = provision_cert("blog.example.com", runner=lambda v, *a: {"ok": True, "detail": "issued"})
    assert res["mode"] == "issued"


def test_provision_custom_failure_is_pending():
    res = provision_cert("blog.example.com", runner=lambda v, *a: {"ok": False, "detail": "certbot failed"})
    assert res["mode"] == "pending"
    assert "certbot" in res["detail"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-metablogizer && PYTHONPATH=api python -m pytest api/tests/test_publish_certs.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'publish.certs'`.

- [ ] **Step 3: Write the implementation**

```python
# packages/secubox-metablogizer/api/publish/certs.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""TLS certificate provisioning for a published domain. *.gk2 subdomains reuse
the existing wildcard cert; custom domains get certbot HTTP-01. All actual work
is done by `secubox-publishctl cert`."""
from __future__ import annotations

from publish.routing import _sudo_publishctl

GK2_SUFFIX = ".gk2.secubox.in"


def is_wildcard_domain(domain: str) -> bool:
    return domain.endswith(GK2_SUFFIX)


def provision_cert(domain: str, runner=_sudo_publishctl) -> dict:
    res = runner("cert", domain)
    if res.get("ok"):
        return {"mode": res.get("detail", "issued"), "detail": res.get("detail", "")}
    return {"mode": "pending", "detail": res.get("detail", "cert failed")}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-metablogizer && PYTHONPATH=api python -m pytest api/tests/test_publish_certs.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metablogizer/api/publish/certs.py \
        packages/secubox-metablogizer/api/tests/test_publish_certs.py
git commit -m "feat(metablogizer): cert provisioning (wildcard for gk2, certbot for custom)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 5: Portable backup (`api/publish/backup.py`)

**Files:**
- Create: `packages/secubox-metablogizer/api/publish/backup.py`
- Test: `packages/secubox-metablogizer/api/tests/test_publish_backup.py`

**Interfaces:**
- Produces:
  - `export_site(site_dir: Path, manifest: dict, out_dir: Path) -> Path` — writes `<out_dir>/<site_dir.name>.sbxsite` = a `tar` of `repo.bundle` (from `git -C site_dir bundle create ... --all`) + `manifest.json`. If `site_dir` has no `.git`, bundle the docroot as a plain tar member `content.tar` instead and set `manifest["has_git"]=False`.
  - `import_site(sbxsite: Path, dest_root: Path) -> dict` — unpacks; if `repo.bundle` present, `git clone repo.bundle <dest_root>/<name>`; else extract `content.tar` into `<dest_root>/<name>/public`. Returns the parsed `manifest`.
  - Round-trip guarantee: `export_site` then `import_site` recreates the docroot content and returns the same manifest dict.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-metablogizer/api/tests/test_publish_backup.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import subprocess
from pathlib import Path

from publish.backup import export_site, import_site


def _git_site(tmp_path) -> Path:
    site = tmp_path / "zem"; (site / "public").mkdir(parents=True)
    (site / "public" / "index.html").write_text("<h1>zem</h1>")
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "PATH": __import__("os").environ["PATH"]}
    subprocess.run(["git", "init", "-q"], cwd=site, check=True, env=env)
    subprocess.run(["git", "add", "-A"], cwd=site, check=True, env=env)
    subprocess.run(["git", "commit", "-qm", "v1"], cwd=site, check=True, env=env)
    return site


def test_export_import_roundtrip_with_git(tmp_path):
    site = _git_site(tmp_path)
    manifest = {"name": "zem", "domain": "zem.gk2.secubox.in", "version": "v1"}
    art = export_site(site, manifest, tmp_path / "out")
    assert art.name == "zem.sbxsite" and art.exists()
    dest = tmp_path / "restored"; dest.mkdir()
    got = import_site(art, dest)
    assert got["domain"] == "zem.gk2.secubox.in"
    assert (dest / "zem" / "public" / "index.html").read_text() == "<h1>zem</h1>"


def test_export_without_git_uses_content_tar(tmp_path):
    site = tmp_path / "plain"; (site / "public").mkdir(parents=True)
    (site / "public" / "index.html").write_text("<h1>plain</h1>")
    art = export_site(site, {"name": "plain", "domain": "plain.gk2.secubox.in"}, tmp_path / "out")
    dest = tmp_path / "r2"; dest.mkdir()
    import_site(art, dest)
    assert (dest / "plain" / "public" / "index.html").read_text() == "<h1>plain</h1>"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-metablogizer && PYTHONPATH=api python -m pytest api/tests/test_publish_backup.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'publish.backup'`.

- [ ] **Step 3: Write the implementation**

```python
# packages/secubox-metablogizer/api/publish/backup.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Portable per-site backup: a .sbxsite tarball holding either a git bundle of
the site's gitea repo (full history) or a plain content tar, plus manifest.json."""
from __future__ import annotations

import json
import subprocess
import tarfile
import tempfile
from pathlib import Path


def export_site(site_dir: Path, manifest: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    name = site_dir.name
    manifest = dict(manifest)
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        has_git = (site_dir / ".git").is_dir()
        manifest["has_git"] = has_git
        if has_git:
            subprocess.run(["git", "-C", str(site_dir), "bundle", "create",
                            str(tdp / "repo.bundle"), "--all"], check=True,
                           capture_output=True)
        else:
            with tarfile.open(tdp / "content.tar", "w") as t:
                t.add(site_dir / "public", arcname="public")
        (tdp / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
        art = out_dir / f"{name}.sbxsite"
        with tarfile.open(art, "w:gz") as t:
            for member in ("repo.bundle", "content.tar", "manifest.json"):
                p = tdp / member
                if p.exists():
                    t.add(p, arcname=member)
    return art


def import_site(sbxsite: Path, dest_root: Path) -> dict:
    dest_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        with tarfile.open(sbxsite, "r:gz") as t:
            t.extractall(tdp)  # trusted operator artifact
        manifest = json.loads((tdp / "manifest.json").read_text())
        name = manifest["name"]
        target = dest_root / name
        if (tdp / "repo.bundle").exists():
            subprocess.run(["git", "clone", "-q", str(tdp / "repo.bundle"), str(target)],
                           check=True, capture_output=True)
        else:
            target.mkdir(parents=True, exist_ok=True)
            with tarfile.open(tdp / "content.tar", "r") as ct:
                ct.extractall(target)
    return manifest
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-metablogizer && PYTHONPATH=api python -m pytest api/tests/test_publish_backup.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metablogizer/api/publish/backup.py \
        packages/secubox-metablogizer/api/tests/test_publish_backup.py
git commit -m "feat(metablogizer): portable .sbxsite backup (git bundle + manifest) with restore

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 6: Wizard router (`api/routers/publish.py`) + mount

**Files:**
- Create: `packages/secubox-metablogizer/api/routers/__init__.py` (empty)
- Create: `packages/secubox-metablogizer/api/routers/publish.py`
- Modify: `packages/secubox-metablogizer/api/main.py` (mount the router)
- Test: `packages/secubox-metablogizer/api/tests/test_publish_router.py`

**Interfaces:**
- Consumes: `publish.content.extract_archive`, `publish.routing.apply_route`, `publish.certs.provision_cert`, `publish.backup.export_site/import_site`, `webhook.git_commit_push`, `require_jwt`, module constants (`SITES_ROOT`, `NGINX_BACKEND_IP`, `BASE_PORT`, `DEFAULT_DOMAIN_SUFFIX`).
- Produces a FastAPI `APIRouter` mounted at prefix `""` on the app, endpoints (all `Depends(require_jwt)`):
  - `POST /publish/wizard` — form-multipart: `name`, optional `domain` (default `<name>.gk2.secubox.in`), `file`. Runs content → version → route → cert; returns `{"steps": {content, version, route, cert}, "domain": ..., "ok": bool}`.
  - `GET /publish/export/{name}` — streams the `.sbxsite`.
  - `POST /publish/import` — multipart `file`; restores; returns manifest.

- [ ] **Step 1: Write the failing test** (router logic with dependencies monkeypatched; no real sudo/git)

```python
# packages/secubox-metablogizer/api/tests/test_publish_router.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import io
import zipfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")
    from secubox_core import config as sbx_config
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    import importlib
    import routers.publish as rp
    importlib.reload(rp)
    # Point the site root at tmp and stub privileged deps.
    monkeypatch.setattr(rp, "SITES_ROOT", tmp_path / "sites")
    (tmp_path / "sites" / "zem" / "public").mkdir(parents=True)
    monkeypatch.setattr(rp, "apply_route", lambda domain, port=8900: {"route_ok": True, "vhost": {}, "waf": {}})
    monkeypatch.setattr(rp, "provision_cert", lambda domain: {"mode": "wildcard", "detail": ""})
    monkeypatch.setattr(rp, "git_commit_push", lambda d, m: {"pushed": True, "committed": True, "commit": "abc", "reason": "ok"})
    # Bypass auth
    from secubox_core.auth import require_jwt
    app = FastAPI()
    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    app.include_router(rp.router)
    return TestClient(app)


def _zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.html", "<h1>zem</h1>")
    return buf.getvalue()


def test_wizard_runs_all_steps(client):
    r = client.post("/publish/wizard",
                    data={"name": "zem"},
                    files={"file": ("site.zip", _zip_bytes(), "application/zip")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["domain"] == "zem.gk2.secubox.in"
    assert body["steps"]["content"]["index_present"] is True
    assert body["steps"]["route"]["route_ok"] is True
    assert body["steps"]["cert"]["mode"] == "wildcard"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-metablogizer && PYTHONPATH=api:../../common python -m pytest api/tests/test_publish_router.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'routers.publish'`.

- [ ] **Step 3: Write the router**

```python
# packages/secubox-metablogizer/api/routers/publish.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""MetaBlogizer publisher wizard: upload -> version -> route -> cert -> backup."""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from secubox_core.auth import require_jwt

from publish.content import extract_archive, ContentError
from publish.routing import apply_route
from publish.certs import provision_cert
from publish.backup import export_site, import_site
from webhook import git_commit_push

# Mirror the constants owned by api/main.py (kept in sync intentionally).
SITES_ROOT = Path("/srv/metablogizer/sites")
DEFAULT_DOMAIN_SUFFIX = ".gk2.secubox.in"
BASE_PORT = 8900

router = APIRouter()


def _site_dir(name: str) -> Path:
    if not name.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "invalid site name")
    d = SITES_ROOT / name
    return d


@router.post("/publish/wizard")
async def publish_wizard(
    name: str = Form(...),
    domain: str = Form(None),
    file: UploadFile = File(...),
    user=Depends(require_jwt),
):
    site = _site_dir(name)
    docroot = site / "public"
    docroot.mkdir(parents=True, exist_ok=True)
    domain = domain or f"{name}{DEFAULT_DOMAIN_SUFFIX}"
    steps: dict = {}

    data = await file.read()
    try:
        steps["content"] = extract_archive(docroot, data, file.filename or "index.html")
    except ContentError as e:
        raise HTTPException(400, f"unsafe upload: {e}")

    steps["version"] = git_commit_push(site, f"publish {name} via wizard")
    steps["route"] = apply_route(domain, BASE_PORT)
    steps["cert"] = provision_cert(domain)

    ok = bool(steps["content"].get("index_present")) and bool(steps["route"].get("route_ok"))
    return {"ok": ok, "domain": domain, "steps": steps}


@router.get("/publish/export/{name}")
async def publish_export(name: str, user=Depends(require_jwt)):
    site = _site_dir(name)
    if not site.exists():
        raise HTTPException(404, "site not found")
    manifest = {"name": name, "domain": f"{name}{DEFAULT_DOMAIN_SUFFIX}",
                "base_port": BASE_PORT}
    out = Path(tempfile.mkdtemp())
    art = export_site(site, manifest, out)
    return FileResponse(str(art), filename=art.name, media_type="application/octet-stream")


@router.post("/publish/import")
async def publish_import(file: UploadFile = File(...), user=Depends(require_jwt)):
    data = await file.read()
    tmp = Path(tempfile.mkdtemp())
    art = tmp / "upload.sbxsite"
    art.write_bytes(data)
    try:
        manifest = import_site(art, SITES_ROOT)
    except Exception as e:  # noqa: BLE001 — surface a clean 400
        raise HTTPException(400, f"import failed: {e}")
    return JSONResponse({"ok": True, "manifest": manifest})
```

- [ ] **Step 4: Mount the router in `api/main.py`**

After the existing `app = FastAPI(...)` and the `from webhook import (...)` block, add:

```python
from routers.publish import router as publish_router
app.include_router(publish_router)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd packages/secubox-metablogizer && PYTHONPATH=api:../../common python -m pytest api/tests/test_publish_router.py -q`
Expected: PASS (1 passed). Then full module suite: `PYTHONPATH=api:../../common python -m pytest api/tests -q` → all pass.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-metablogizer/api/routers/__init__.py \
        packages/secubox-metablogizer/api/routers/publish.py \
        packages/secubox-metablogizer/api/tests/test_publish_router.py \
        packages/secubox-metablogizer/api/main.py
git commit -m "feat(metablogizer): publisher wizard endpoints (wizard/export/import)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 7: Wizard UI (`www/metablogizer/index.html`)

Add a 5-step wizard panel to the existing metablogizer webui (hybrid-dark, `sbx_token` bearer). This task is UI-only; verification is manual/live (Task 11).

**Files:**
- Modify: `packages/secubox-metablogizer/www/metablogizer/index.html`

**Interfaces:**
- Consumes: `POST /api/v1/metablogizer/publish/wizard` (multipart), `GET /api/v1/metablogizer/publish/export/{name}`.

- [ ] **Step 1: Add a "Publish" wizard section**

Add a card with a stepper (Content → Version → Route → Cert → Backup) containing: a site-name input, a domain input (placeholder `<name>.gk2.secubox.in`), a file input accepting `.zip,.html`, a "Publish" button, and a results area. Match the existing panel's markup/classes (reuse the page's `authHeaders()`/`toast()` helpers if present; otherwise read `localStorage.getItem('sbx_token')`).

```html
<!-- inside the main content, following the existing sites card -->
<section class="card" id="publish-wizard">
  <h2>🚀 Publish a site</h2>
  <div class="wizard-steps" id="wiz-steps">
    <span data-step="content">1 · Content</span>
    <span data-step="version">2 · Version</span>
    <span data-step="route">3 · Route</span>
    <span data-step="cert">4 · Cert</span>
    <span data-step="backup">5 · Backup</span>
  </div>
  <div class="form-group"><label>Site name</label>
    <input id="wiz-name" class="form-input" placeholder="zem"></div>
  <div class="form-group"><label>Domain</label>
    <input id="wiz-domain" class="form-input" placeholder="zem.gk2.secubox.in"></div>
  <div class="form-group"><label>Content (.zip or .html)</label>
    <input id="wiz-file" type="file" accept=".zip,.html" class="form-input"></div>
  <button class="btn primary" id="wiz-go">Publish</button>
  <button class="btn" id="wiz-backup" disabled>⬇ Download backup</button>
  <pre id="wiz-result" class="result"></pre>
</section>
<script>
(function () {
  function tok() { try { return localStorage.getItem('sbx_token') || ''; } catch (e) { return ''; } }
  function mark(step, ok) {
    var el = document.querySelector('#wiz-steps [data-step="' + step + '"]');
    if (el) el.classList.add(ok ? 'ok' : 'fail');
  }
  var lastName = '';
  document.getElementById('wiz-go').addEventListener('click', function () {
    var name = document.getElementById('wiz-name').value.trim();
    var domain = document.getElementById('wiz-domain').value.trim();
    var f = document.getElementById('wiz-file').files[0];
    var out = document.getElementById('wiz-result');
    if (!name || !f) { out.textContent = 'name and file required'; return; }
    document.querySelectorAll('#wiz-steps span').forEach(function (s) { s.classList.remove('ok', 'fail'); });
    out.textContent = 'Publishing…';
    var fd = new FormData();
    fd.append('name', name); if (domain) fd.append('domain', domain); fd.append('file', f);
    fetch('/api/v1/metablogizer/publish/wizard', {
      method: 'POST', headers: { 'Authorization': 'Bearer ' + tok() }, body: fd
    }).then(function (r) { return r.json(); }).then(function (d) {
      out.textContent = JSON.stringify(d, null, 2);
      if (d.steps) { ['content','version','route','cert'].forEach(function (s) {
        var v = d.steps[s]; mark(s, s === 'content' ? v.index_present : s === 'route' ? v.route_ok : true);
      }); }
      if (d.ok) { mark('backup', true); lastName = name;
        document.getElementById('wiz-backup').disabled = false; }
    }).catch(function (e) { out.textContent = 'error: ' + e; });
  });
  document.getElementById('wiz-backup').addEventListener('click', function () {
    if (lastName) window.location = '/api/v1/metablogizer/publish/export/' + encodeURIComponent(lastName);
  });
})();
</script>
```

Add matching CSS (reuse existing tokens):

```css
.wizard-steps { display: flex; gap: 8px; margin: 10px 0; flex-wrap: wrap; }
.wizard-steps span { padding: 4px 10px; border: 1px solid var(--border, #1E2A38); border-radius: 6px; font-size: .8rem; opacity: .7; }
.wizard-steps span.ok { border-color: #148C66; color: #148C66; opacity: 1; }
.wizard-steps span.fail { border-color: #C04E24; color: #C04E24; opacity: 1; }
#wiz-result.result { max-height: 240px; overflow: auto; background: var(--bg, #0B0F14); padding: 10px; border-radius: 8px; }
```

- [ ] **Step 2: Validate the HTML/JS parses**

Run: `node --check <(sed -n '/wiz-go.*addEventListener/,/})();/p' packages/secubox-metablogizer/www/metablogizer/index.html)` (or paste the `<script>` body into a `.js` and `node --check`).
Expected: no syntax error.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-metablogizer/www/metablogizer/index.html
git commit -m "feat(metablogizer): publisher wizard UI (5-step stepper)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 8: Retire secubox-publish's unprivileged config writes → delegate

**Files:**
- Modify: `packages/secubox-publish/api/main.py` (remove the direct `/etc/haproxy` + `/etc/nginx` writes + `systemctl reload` around lines `831–892`; the publish action calls metablogizer's wizard).

**Interfaces:**
- Consumes: metablogizer `POST /publish/wizard` via the existing `_call_module("metablogizer", "/publish/wizard", "POST", ...)` helper.

- [ ] **Step 1: Find the offending writes**

Run: `cd packages/secubox-publish && grep -n "haproxy.cfg\|/etc/nginx\|systemctl.*reload\|Path(nginx_conf).write_text\|Path(haproxy_cfg)" api/main.py`
Expected: the lines around 849/854/876/882 that write root config as `secubox`.

- [ ] **Step 2: Replace the provisioning body with delegation**

Locate the function that performs those writes (the publish/deploy handler). Replace its HAProxy/nginx mutation block with a single delegated call. Concretely, the block that builds `nginx_content` / `cfg2` and reloads is removed and replaced by:

```python
    # Provisioning (vhost + WAF route + cert) is owned by metablogizer's
    # publisher wizard, which does it through the secubox-publishctl root
    # helper. secubox-publish runs as an unprivileged user and MUST NOT write
    # /etc/haproxy or /etc/nginx directly (it silently failed before).
    result = await _call_module(
        "metablogizer", "/publish/wizard", "POST",
        {"name": req.name, "domain": getattr(req, "domain", None)},
    )
    return result
```

(Adjust `req` field names to the handler's actual request model; if the handler already has the site content, pass it through the metablogizer upload path instead. Keep the endpoint signature unchanged.)

- [ ] **Step 3: Verify no direct root-config writes remain**

Run: `cd packages/secubox-publish && grep -n "haproxy.cfg\|Path(nginx_conf).write_text\|Path(haproxy_cfg).write_text\|systemctl.*reload.*haproxy" api/main.py`
Expected: no output. Then `python -c "import ast; ast.parse(open('api/main.py').read()); print('ok')"` → `ok`.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-publish/api/main.py
git commit -m "fix(publish): delegate vhost/WAF/cert to metablogizer wizard; drop illegal root-config writes

secubox-publish runs as user secubox and could never write /etc/haproxy or
/etc/nginx or reload services — that was the silent publish failure.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 9: droplet.toml ownership (source fix) + packaging

**Files:**
- Modify: `packages/secubox-droplet/debian/postinst`
- Modify: `packages/secubox-droplet/debian/changelog`

**Interfaces:** none (packaging).

- [ ] **Step 1: Add ownership setup to droplet postinst**

In `packages/secubox-droplet/debian/postinst`, inside the `configure` case, after the user is ensured, add:

```bash
    # The daemon runs as `secubox`; its config must be owned by it, not root.
    # (Shipped historically as root:root 0600 → PermissionError at runtime.)
    if [ ! -e /etc/secubox/droplet.toml ]; then
      install -d -o secubox -g secubox -m 0755 /etc/secubox
      install -o secubox -g secubox -m 0640 /dev/null /etc/secubox/droplet.toml
    else
      chown secubox:secubox /etc/secubox/droplet.toml || true
      chmod 0640 /etc/secubox/droplet.toml || true
    fi
```

- [ ] **Step 2: Bump the droplet changelog**

Prepend a new entry (next version, `~bookworm1`, dated `Sat, 11 Jul 2026`) noting: "postinst now owns /etc/secubox/droplet.toml as secubox:secubox 0640 (was root:root 0600 → PermissionError)."

- [ ] **Step 3: Verify**

Run: `dpkg-parsechangelog -l packages/secubox-droplet/debian/changelog -S Version` → prints the new version; `bash -n packages/secubox-droplet/debian/postinst` → no output.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-droplet/debian/postinst packages/secubox-droplet/debian/changelog
git commit -m "fix(droplet): own /etc/secubox/droplet.toml as secubox (was root:root 0600)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 10: metablogizer packaging (helper + sudoers install) + changelog

**Files:**
- Modify: `packages/secubox-metablogizer/debian/secubox-metablogizer.install`
- Modify: `packages/secubox-metablogizer/debian/postinst`
- Modify: `packages/secubox-metablogizer/debian/changelog`

**Interfaces:** none (packaging).

- [ ] **Step 1: Install the helper + sudoers + new api/publish + api/routers**

Ensure `debian/secubox-metablogizer.install` ships:
- `sbin/secubox-publishctl` → `usr/sbin/`
- `debian/secubox-publish-wizard.sudoers` → `etc/sudoers.d/secubox-publish-wizard`
- the `api/publish/` and `api/routers/` trees are under the already-installed `api/` (confirm the existing `install` line copies all of `api/`; if it enumerates files, add the new modules).

Check the current install file first:
`cat packages/secubox-metablogizer/debian/secubox-metablogizer.install`
and add whatever lines are missing so `secubox-publishctl` lands at `/usr/sbin/secubox-publishctl` (mode 0755) and the sudoers at `/etc/sudoers.d/secubox-publish-wizard` (mode 0440).

- [ ] **Step 2: postinst — perms for helper + sudoers, and config ownership**

In `packages/secubox-metablogizer/debian/postinst` `configure` case add:

```bash
    chmod 0755 /usr/sbin/secubox-publishctl 2>/dev/null || true
    if [ -f /etc/sudoers.d/secubox-publish-wizard ]; then
      chmod 0440 /etc/sudoers.d/secubox-publish-wizard
      visudo -cf /etc/sudoers.d/secubox-publish-wizard >/dev/null 2>&1 || \
        rm -f /etc/sudoers.d/secubox-publish-wizard   # never leave a broken sudoers file
    fi
```

- [ ] **Step 3: Bump the metablogizer changelog**

Prepend a `1.3.0-1~bookworm1` entry dated `Sat, 11 Jul 2026`: "Publisher wizard (upload zip/html → gitea version → sbxwaf route via new secubox-publishctl root helper → cert → portable .sbxsite backup). Retires the dead mitmproxy-LXC route sync (the zem 421)."

- [ ] **Step 4: Verify**

Run: `bash -n packages/secubox-metablogizer/debian/postinst` (no output); `dpkg-parsechangelog -l packages/secubox-metablogizer/debian/changelog -S Version` → `1.3.0-1~bookworm1`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metablogizer/debian/
git commit -m "build(metablogizer): install publishctl + sudoers; changelog 1.3.0

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 11: Live end-to-end verification on gk2

**Files:** none (verification + notes).

**Interfaces:** none.

- [ ] **Step 1: Build + deploy the three packages**

Build `secubox-metablogizer`, `secubox-publish`, `secubox-droplet` (`dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b`) and deploy to `root@192.168.1.200` (`scripts/deploy.sh` or `scp` + `dpkg -i`), OR for a fast loop: `scp` the new `api/`, `sbin/secubox-publishctl`, sudoers, and www into place, then `systemctl restart secubox-metablogizer` (dedicated socket) / restart the aggregator if in-process. Install the sudoers with `visudo -c` validation.

- [ ] **Step 2: Publish a throwaway site end-to-end**

```bash
B=https://admin.gk2.secubox.in
tok=... # an admin sbx_token
printf '<h1>wiztest</h1>' > /tmp/index.html
curl -s -k -X POST -H "Authorization: Bearer $tok" \
  -F name=wiztest -F file=@/tmp/index.html \
  $B/api/v1/metablogizer/publish/wizard | python3 -m json.tool
```
Expected: `ok: true`, `steps.route.route_ok: true`, `steps.cert.mode: "wildcard"`.

- [ ] **Step 3: Prove it routes (200, not 421)**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -k https://wiztest.gk2.secubox.in/
```
Expected: `200` (was `421` before). Confirm the route landed in the LIVE file:
`ssh root@192.168.1.200 'python3 -c "import json;print(json.load(open(\"/etc/secubox/waf/haproxy-routes.json\")).get(\"wiztest.gk2.secubox.in\"))"'`
Expected: `['192.168.1.200', 8900]`.

- [ ] **Step 4: Backup round-trip**

```bash
curl -s -k -H "Authorization: Bearer $tok" $B/api/v1/metablogizer/publish/export/wiztest -o /tmp/wiztest.sbxsite
curl -s -k -X POST -H "Authorization: Bearer $tok" -F file=@/tmp/wiztest.sbxsite \
  $B/api/v1/metablogizer/publish/import | python3 -m json.tool
```
Expected: `ok: true`, manifest returned.

- [ ] **Step 5: Clean up + verify droplet**

Remove the test site + its route (`sudo -n /usr/sbin/secubox-publishctl vhost-del wiztest.gk2.secubox.in`), delete the site dir. Confirm droplet no longer errors: hit the publish overview and confirm no `droplet.toml` PermissionError in `journalctl -u secubox-droplet --since "5 min ago"`.

- [ ] **Step 6: Commit any notes / HISTORY entry**

```bash
git add .claude/HISTORY.md
git commit -m "docs: record publisher wizard live verification on gk2

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```
