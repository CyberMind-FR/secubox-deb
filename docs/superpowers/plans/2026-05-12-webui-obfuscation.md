<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WebUI Obfuscation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lock SecuBox WebUI to `https://admin.<HOSTNAME>.<DOMAIN_SUFFIX>/` only, enforced at both HAProxy and nginx layers, driven by `/etc/default/secubox` as the single source of truth.

**Architecture:** New package `secubox-defaults` ships the env file. `secubox-haproxy` FastAPI exposes three `/webui/*` endpoints that read the env file and return the canonical hostname + escaped regex + a fully-rendered nginx vhost. A new `secubox-render-nginx-webui` script consumes the API to write `/etc/nginx/sites-available/secubox-local` atomically. `haproxyctl` and its Python equivalent inject the strict-regex ACL/`use_backend webui_direct` pair at the top of `frontend http-in` and `frontend https-in`. LAN-direct access on port 9443 is untouched.

**Tech Stack:** Debian packaging (dpkg, debhelper 13), Python 3.11 (FastAPI, pytest), bash, jq, curl, nginx, HAProxy 2.6.

**Spec:** [`2026-05-12-webui-obfuscation-design.md`](../specs/2026-05-12-webui-obfuscation-design.md)

**GitHub issue:** [#44](https://github.com/CyberMind-FR/secubox-deb/issues/44)

---

## File Structure

| Path | Action | Responsibility |
| --- | --- | --- |
| `packages/secubox-defaults/debian/control` | create | Package metadata (Architecture: all, no deps) |
| `packages/secubox-defaults/debian/rules` | create | `dh $@` minimal |
| `packages/secubox-defaults/debian/compat` | create | `13` |
| `packages/secubox-defaults/debian/changelog` | create | initial `1.0.0-1~bookworm1` |
| `packages/secubox-defaults/debian/copyright` | create | Proprietary / ANSSI CSPN candidate |
| `packages/secubox-defaults/debian/install` | create | install map for `etc/default/secubox` |
| `packages/secubox-defaults/debian/conffiles` | create | preserve `/etc/default/secubox` on upgrade |
| `packages/secubox-defaults/debian/postinst` | create | hostname autodetect + dpkg-trigger |
| `packages/secubox-defaults/debian/triggers` | create | declare `secubox-defaults-changed` |
| `packages/secubox-defaults/etc/default/secubox` | create | env file template |
| `packages/secubox-defaults/README.md` | create | package readme |
| `packages/secubox-haproxy/api/webui_identity.py` | create | parse env file + compose regex (LRU cached) |
| `packages/secubox-haproxy/api/main.py` | modify | add 3 endpoints (`/webui/admin-domain`, `/webui/nginx-config`, `/webui/refresh`) |
| `packages/secubox-haproxy/api/templates/secubox-local.nginx.j2` | create | jinja-style template for the rendered vhost (kept in code, not a real Jinja file — see Task 5) |
| `packages/secubox-haproxy/sbin/secubox-render-nginx-webui` | create | bash renderer with snapshot + nginx -t + rollback |
| `packages/secubox-haproxy/sbin/haproxyctl` | modify | inject `acl is_webui_admin` + `use_backend webui_direct` at top of frontends |
| `packages/secubox-haproxy/tests/test_webui_identity.py` | create | unit tests for parsing + regex composition |
| `packages/secubox-haproxy/tests/test_webui_endpoints.py` | create | unit tests for the 3 endpoints |
| `packages/secubox-haproxy/debian/postinst` | modify | trigger `secubox-render-nginx-webui` + `secubox-haproxy-regen-safe` |
| `packages/secubox-haproxy/debian/triggers` | modify | declare `interest secubox-defaults-changed` |
| `tests/integration/test_44_webui_obfuscation.sh` | create | end-to-end test (run on board) |
| `.claude/HISTORY.md` | modify | new Session entry on completion |

---

## Task 1: Scaffold `secubox-defaults` package skeleton

**Files:**

- Create: `packages/secubox-defaults/debian/control`
- Create: `packages/secubox-defaults/debian/rules`
- Create: `packages/secubox-defaults/debian/compat`
- Create: `packages/secubox-defaults/debian/changelog`
- Create: `packages/secubox-defaults/debian/copyright`
- Create: `packages/secubox-defaults/README.md`

- [ ] **Step 1: Create `packages/secubox-defaults/debian/control`**

```text
Source: secubox-defaults
Section: admin
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://secubox.in

Package: secubox-defaults
Architecture: all
Depends: ${misc:Depends}
Description: SecuBox board identity defaults
 Ships /etc/default/secubox, the single source of truth for SECUBOX_HOSTNAME
 and SECUBOX_DOMAIN_SUFFIX. Other SecuBox packages depend on this for the
 canonical admin URL pattern admin.<HOSTNAME>.<SUFFIX>.
```

- [ ] **Step 2: Create `packages/secubox-defaults/debian/rules`**

```makefile
#!/usr/bin/make -f
%:
	dh $@
```

Make it executable:

```bash
chmod +x packages/secubox-defaults/debian/rules
```

- [ ] **Step 3: Create `packages/secubox-defaults/debian/compat`**

```text
13
```

- [ ] **Step 4: Create `packages/secubox-defaults/debian/changelog`**

```text
secubox-defaults (1.0.0-1~bookworm1) bookworm; urgency=medium

  * Initial release: ship /etc/default/secubox with SECUBOX_HOSTNAME and
    SECUBOX_DOMAIN_SUFFIX. Addresses CyberMind-FR/secubox-deb#44.

 -- Gerald KERMA <devel@cybermind.fr>  Tue, 12 May 2026 12:00:00 +0200
```

- [ ] **Step 5: Create `packages/secubox-defaults/debian/copyright`**

```text
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Source: https://github.com/CyberMind-FR/secubox-deb
Upstream-Name: secubox-defaults

Files: *
Copyright: 2026 CyberMind / Gerald KERMA <devel@cybermind.fr>
License: Proprietary
 SecuBox-Deb proprietary licence. ANSSI CSPN candidate.
```

- [ ] **Step 6: Create `packages/secubox-defaults/README.md`**

```markdown
# secubox-defaults

Ships `/etc/default/secubox`, the single source of truth for the SecuBox
board identity:

- `SECUBOX_HOSTNAME` — short board name (e.g. `gk2`).
- `SECUBOX_DOMAIN_SUFFIX` — domain root (e.g. `secubox.in`).

Composed canonical admin URL: `https://admin.${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX}/`.

Consumers (`secubox-haproxy` API, render scripts, …) read this file at startup
and refresh on `dpkg-trigger secubox-defaults-changed`.

After hand-editing `/etc/default/secubox`:

```bash
curl -fsS -X POST --unix-socket /run/secubox/haproxy.sock \
     http://localhost/webui/refresh
/usr/local/bin/secubox-render-nginx-webui
/usr/local/bin/secubox-haproxy-regen-safe
```
```

- [ ] **Step 7: Verify directory layout**

Run:

```bash
find packages/secubox-defaults -type f | sort
```

Expected output:

```text
packages/secubox-defaults/README.md
packages/secubox-defaults/debian/changelog
packages/secubox-defaults/debian/compat
packages/secubox-defaults/debian/control
packages/secubox-defaults/debian/copyright
packages/secubox-defaults/debian/rules
```

- [ ] **Step 8: Commit**

```bash
git add packages/secubox-defaults/
git commit -m "feat(secubox-defaults): scaffold package skeleton (ref #44)"
```

---

## Task 2: `/etc/default/secubox` template + install map + conffile declaration

**Files:**

- Create: `packages/secubox-defaults/etc/default/secubox`
- Create: `packages/secubox-defaults/debian/install`
- Create: `packages/secubox-defaults/debian/conffiles`

- [ ] **Step 1: Create the env file template at `packages/secubox-defaults/etc/default/secubox`**

```sh
# SecuBox board identity — single source of truth.
# Read by secubox-haproxy FastAPI at startup and by render scripts.
#
# Composed canonical admin URL:
#   https://admin.${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX}/
#
# After editing, run:
#   curl -fsS -X POST --unix-socket /run/secubox/haproxy.sock \
#        http://localhost/webui/refresh
#   /usr/local/bin/secubox-render-nginx-webui
#   /usr/local/bin/secubox-haproxy-regen-safe

SECUBOX_HOSTNAME="gk2"
SECUBOX_DOMAIN_SUFFIX="secubox.in"
```

- [ ] **Step 2: Create `packages/secubox-defaults/debian/install`**

```text
etc/default/secubox etc/default
```

- [ ] **Step 3: Create `packages/secubox-defaults/debian/conffiles`**

```text
/etc/default/secubox
```

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-defaults/etc/ packages/secubox-defaults/debian/install packages/secubox-defaults/debian/conffiles
git commit -m "feat(secubox-defaults): ship /etc/default/secubox env file (ref #44)"
```

---

## Task 3: Postinst — hostname autodetect + trigger declaration

**Files:**

- Create: `packages/secubox-defaults/debian/postinst`
- Create: `packages/secubox-defaults/debian/triggers`

- [ ] **Step 1: Create `packages/secubox-defaults/debian/postinst`**

```sh
#!/bin/sh
# secubox-defaults postinst: autodetect SECUBOX_HOSTNAME if empty,
# then activate the secubox-defaults-changed trigger so consumers refresh.
set -e

DEFAULTS=/etc/default/secubox

case "$1" in
    configure)
        if [ ! -f "$DEFAULTS" ]; then
            echo "secubox-defaults: $DEFAULTS missing — package files not installed?" >&2
            exit 1
        fi

        # Source the existing values
        # shellcheck disable=SC1090
        . "$DEFAULTS" 2>/dev/null || true

        if [ -z "${SECUBOX_HOSTNAME:-}" ]; then
            # Autodetect: hostname -s minus any 'secubox-' prefix
            DETECTED=$(hostname -s 2>/dev/null | sed 's/^secubox-//')
            if [ -n "$DETECTED" ]; then
                echo "secubox-defaults: setting SECUBOX_HOSTNAME=$DETECTED (autodetected)"
                sed -i "s/^SECUBOX_HOSTNAME=.*/SECUBOX_HOSTNAME=\"$DETECTED\"/" "$DEFAULTS"
            else
                echo "secubox-defaults: WARNING — SECUBOX_HOSTNAME unset and could not autodetect" >&2
            fi
        fi

        # Activate the trigger so other packages (secubox-haproxy etc.) refresh
        dpkg-trigger secubox-defaults-changed || true
        ;;
esac

#DEBHELPER#

exit 0
```

Make executable:

```bash
chmod +x packages/secubox-defaults/debian/postinst
```

- [ ] **Step 2: Create `packages/secubox-defaults/debian/triggers`**

```text
activate-noawait secubox-defaults-changed
```

- [ ] **Step 3: Verify shell syntax**

Run:

```bash
sh -n packages/secubox-defaults/debian/postinst && echo "syntax OK"
```

Expected: `syntax OK`

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-defaults/debian/postinst packages/secubox-defaults/debian/triggers
git commit -m "feat(secubox-defaults): postinst autodetect + dpkg-trigger (ref #44)"
```

---

## Task 4: `webui_identity` helper module

**Files:**

- Create: `packages/secubox-haproxy/api/webui_identity.py`
- Create: `packages/secubox-haproxy/tests/__init__.py` (if missing)
- Test: `packages/secubox-haproxy/tests/test_webui_identity.py`

- [ ] **Step 1: Write the failing test at `packages/secubox-haproxy/tests/test_webui_identity.py`**

```python
"""
SecuBox-Deb :: webui_identity tests
Author: Gerald KERMA <devel@cybermind.fr>
"""
import textwrap
import pytest
from pathlib import Path

from packages.secubox_haproxy.api import webui_identity as wi


@pytest.fixture(autouse=True)
def _reset_cache():
    wi.invalidate_cache()
    yield
    wi.invalidate_cache()


def _write_defaults(tmp_path, body):
    p = tmp_path / "secubox"
    p.write_text(textwrap.dedent(body))
    return p


def test_parse_basic(monkeypatch, tmp_path):
    p = _write_defaults(tmp_path, """\
        SECUBOX_HOSTNAME="gk2"
        SECUBOX_DOMAIN_SUFFIX="secubox.in"
    """)
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    ident = wi.get_identity()
    assert ident["hostname"] == "gk2"
    assert ident["domain_suffix"] == "secubox.in"
    assert ident["admin_domain"] == "admin.gk2.secubox.in"
    assert ident["regex"] == r"^admin\.gk2\.secubox\.in$"


def test_missing_hostname_raises(monkeypatch, tmp_path):
    p = _write_defaults(tmp_path, """\
        SECUBOX_DOMAIN_SUFFIX="secubox.in"
    """)
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    with pytest.raises(ValueError, match="SECUBOX_HOSTNAME"):
        wi.get_identity()


def test_custom_suffix(monkeypatch, tmp_path):
    p = _write_defaults(tmp_path, """\
        SECUBOX_HOSTNAME="mochabin"
        SECUBOX_DOMAIN_SUFFIX="lan.local"
    """)
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    ident = wi.get_identity()
    assert ident["admin_domain"] == "admin.mochabin.lan.local"
    assert ident["regex"] == r"^admin\.mochabin\.lan\.local$"


def test_comments_and_blank_lines(monkeypatch, tmp_path):
    p = _write_defaults(tmp_path, """\
        # comment
        SECUBOX_HOSTNAME="gk2"

        # another comment
        SECUBOX_DOMAIN_SUFFIX="secubox.in"
    """)
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    ident = wi.get_identity()
    assert ident["hostname"] == "gk2"


def test_invalidate_cache(monkeypatch, tmp_path):
    p = _write_defaults(tmp_path, """\
        SECUBOX_HOSTNAME="gk2"
    """)
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    first = wi.get_identity()
    p.write_text('SECUBOX_HOSTNAME="changed"\n')
    cached = wi.get_identity()
    assert cached["hostname"] == "gk2"  # cache hit
    wi.invalidate_cache()
    refreshed = wi.get_identity()
    assert refreshed["hostname"] == "changed"
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd packages/secubox-haproxy && python -m pytest tests/test_webui_identity.py -v
```

Expected: FAIL with `ModuleNotFoundError: webui_identity`.

- [ ] **Step 3: Write `packages/secubox-haproxy/api/webui_identity.py`**

```python
"""
SecuBox-Deb :: webui_identity
CyberMind — https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Parses /etc/default/secubox and exposes the canonical admin URL + regex.
"""
import re
import shlex
from pathlib import Path
from functools import lru_cache

DEFAULTS_FILE = Path("/etc/default/secubox")


@lru_cache(maxsize=1)
def _parse_defaults() -> dict:
    out: dict = {}
    if not DEFAULTS_FILE.exists():
        return out
    for line in DEFAULTS_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # shlex.split handles quoted values cleanly
        parts = shlex.split(v) if v else []
        out[k.strip()] = parts[0] if parts else ""
    return out


def get_identity() -> dict:
    """Return canonical board identity.

    Raises:
        ValueError: if SECUBOX_HOSTNAME is not set.
    """
    cfg = _parse_defaults()
    host = cfg.get("SECUBOX_HOSTNAME", "")
    suffix = cfg.get("SECUBOX_DOMAIN_SUFFIX", "secubox.in")
    if not host:
        raise ValueError(
            "SECUBOX_HOSTNAME not set in /etc/default/secubox"
        )
    admin = f"admin.{host}.{suffix}"
    regex = "^" + re.escape(admin) + "$"
    return {
        "hostname": host,
        "domain_suffix": suffix,
        "admin_domain": admin,
        "regex": regex,
    }


def invalidate_cache() -> None:
    """Drop the LRU cache so the next get_identity() re-reads the file."""
    _parse_defaults.cache_clear()
```

Also create the missing test scaffolding if needed:

```bash
mkdir -p packages/secubox-haproxy/tests
touch packages/secubox-haproxy/tests/__init__.py
```

The test imports from `packages.secubox_haproxy.api.webui_identity` — adjust import path in test if the actual layout differs. If the API package isn't on `sys.path`, add a `conftest.py` at `packages/secubox-haproxy/tests/conftest.py`:

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
```

And change the test import line from `from packages.secubox_haproxy.api import webui_identity as wi` to `from api import webui_identity as wi`.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd packages/secubox-haproxy && python -m pytest tests/test_webui_identity.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-haproxy/api/webui_identity.py packages/secubox-haproxy/tests/
git commit -m "feat(secubox-haproxy): webui_identity helper + tests (ref #44)"
```

---

## Task 5: `/webui/admin-domain` endpoint

**Files:**

- Modify: `packages/secubox-haproxy/api/main.py` (add endpoint + import)
- Test: `packages/secubox-haproxy/tests/test_webui_endpoints.py`

- [ ] **Step 1: Write the failing test at `packages/secubox-haproxy/tests/test_webui_endpoints.py`**

```python
"""
SecuBox-Deb :: webui endpoints tests
"""
import textwrap
import pytest
from fastapi.testclient import TestClient

from api import main as api_main
from api import webui_identity as wi


@pytest.fixture
def client(tmp_path, monkeypatch):
    p = tmp_path / "secubox"
    p.write_text(textwrap.dedent("""\
        SECUBOX_HOSTNAME="gk2"
        SECUBOX_DOMAIN_SUFFIX="secubox.in"
    """))
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    wi.invalidate_cache()
    return TestClient(api_main.app)


def test_admin_domain_returns_canonical_identity(client):
    r = client.get("/webui/admin-domain")
    assert r.status_code == 200
    data = r.json()
    assert data == {
        "hostname": "gk2",
        "domain_suffix": "secubox.in",
        "admin_domain": "admin.gk2.secubox.in",
        "regex": r"^admin\.gk2\.secubox\.in$",
    }


def test_admin_domain_503_when_unset(client, tmp_path, monkeypatch):
    p = tmp_path / "secubox-empty"
    p.write_text("")
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    wi.invalidate_cache()
    r = client.get("/webui/admin-domain")
    assert r.status_code == 503
    assert "SECUBOX_HOSTNAME" in r.json()["detail"]
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd packages/secubox-haproxy && python -m pytest tests/test_webui_endpoints.py::test_admin_domain_returns_canonical_identity -v
```

Expected: FAIL with `404 Not Found` (endpoint not yet defined).

- [ ] **Step 3: Add the endpoint at the end of `packages/secubox-haproxy/api/main.py`**

```python
# ══════════════════════════════════════════════════════════════════
# WebUI Identity Endpoints (issue #44 — admin.<HOSTNAME>.<SUFFIX> only)
# ══════════════════════════════════════════════════════════════════

from . import webui_identity as _webui_identity  # placed near other imports


@app.get("/webui/admin-domain")
async def webui_admin_domain():
    """Return the canonical admin URL identity for this board.

    Reads /etc/default/secubox. No auth required (info is not secret).
    """
    try:
        return _webui_identity.get_identity()
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
```

If the import style in `main.py` doesn't use relative imports (`from . import`), adjust to absolute: `import webui_identity as _webui_identity` and ensure `webui_identity.py` is in the same package directory (it is, per Task 4).

Verify `HTTPException` is already imported in `main.py` — search for `from fastapi import` near the top. If not present, add `from fastapi import HTTPException`.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd packages/secubox-haproxy && python -m pytest tests/test_webui_endpoints.py::test_admin_domain_returns_canonical_identity tests/test_webui_endpoints.py::test_admin_domain_503_when_unset -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-haproxy/api/main.py packages/secubox-haproxy/tests/test_webui_endpoints.py
git commit -m "feat(secubox-haproxy): GET /webui/admin-domain endpoint (ref #44)"
```

---

## Task 6: `/webui/nginx-config` endpoint (JWT-protected)

**Files:**

- Modify: `packages/secubox-haproxy/api/main.py` (add endpoint + template helper)
- Test: `packages/secubox-haproxy/tests/test_webui_endpoints.py` (append)

- [ ] **Step 1: Append failing tests to `tests/test_webui_endpoints.py`**

```python
def test_nginx_config_requires_jwt(client):
    r = client.get("/webui/nginx-config")
    assert r.status_code in (401, 403)


def test_nginx_config_returns_rendered_vhost(client, monkeypatch):
    # Bypass JWT for this test by overriding the dependency
    from api.main import app
    from api.auth import require_jwt  # adjust import to actual auth module
    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        r = client.get("/webui/nginx-config")
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert r"server_name ~^admin\.gk2\.secubox\.in$;" in body
    assert "listen 0.0.0.0:9080;" in body
    assert "root /usr/share/secubox/www;" in body
    assert "include /etc/nginx/secubox.d/*.conf;" in body
```

If the project's JWT dependency lives elsewhere, replace `from api.auth import require_jwt` with the correct import path (search `main.py` for `Depends(require_jwt)` to find it).

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd packages/secubox-haproxy && python -m pytest tests/test_webui_endpoints.py::test_nginx_config_requires_jwt tests/test_webui_endpoints.py::test_nginx_config_returns_rendered_vhost -v
```

Expected: 2 FAIL (endpoint missing).

- [ ] **Step 3: Add the renderer + endpoint to `packages/secubox-haproxy/api/main.py`**

Place near the previous endpoint:

```python
from fastapi.responses import PlainTextResponse


def _render_nginx_vhost(ident: dict) -> str:
    """Render the secubox-local nginx vhost with strict regex server_name."""
    # Escape literal dots for nginx regex (PCRE-compatible)
    host_esc = ident["hostname"].replace(".", r"\.")
    suffix_esc = ident["domain_suffix"].replace(".", r"\.")
    regex = rf"~^admin\.{host_esc}\.{suffix_esc}$"
    return (
        "# SecuBox WebUI — strict-regex obfuscation (issue #44)\n"
        "# Generated by /api/v1/haproxy/webui/nginx-config — do not edit by hand.\n"
        "server {\n"
        "    listen 0.0.0.0:9080;\n"
        f"    server_name {regex};\n"
        "    root /usr/share/secubox/www;\n"
        "    index index.html;\n"
        "    location / { try_files $uri $uri/ /index.html; }\n"
        "    include /etc/nginx/secubox.d/*.conf;\n"
        "    include /etc/nginx/snippets/api-error.conf;\n"
        "    location /health {\n"
        "        return 200 '{\"status\":\"ok\"}';\n"
        "        add_header Content-Type application/json;\n"
        "    }\n"
        "}\n"
    )


@app.get("/webui/nginx-config", response_class=PlainTextResponse,
         dependencies=[Depends(require_jwt)])
async def webui_nginx_config():
    """Return the rendered nginx vhost for the WebUI (text/plain).

    JWT-protected — callers will write this to /etc/nginx/sites-available/.
    """
    try:
        ident = _webui_identity.get_identity()
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    return _render_nginx_vhost(ident)
```

Verify the `Depends` import (already used elsewhere in `main.py`) and that `require_jwt` is in scope.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd packages/secubox-haproxy && python -m pytest tests/test_webui_endpoints.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-haproxy/api/main.py packages/secubox-haproxy/tests/test_webui_endpoints.py
git commit -m "feat(secubox-haproxy): GET /webui/nginx-config rendered vhost (ref #44)"
```

---

## Task 7: `/webui/refresh` endpoint (JWT-protected)

**Files:**

- Modify: `packages/secubox-haproxy/api/main.py`
- Test: `packages/secubox-haproxy/tests/test_webui_endpoints.py` (append)

- [ ] **Step 1: Append failing test to `tests/test_webui_endpoints.py`**

```python
def test_refresh_invalidates_cache(client, tmp_path, monkeypatch):
    from api.main import app
    from api.auth import require_jwt
    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        # First call seeds the cache via /admin-domain
        r1 = client.get("/webui/admin-domain")
        assert r1.json()["hostname"] == "gk2"
        # Mutate the file under the API's feet
        wi.DEFAULTS_FILE.write_text('SECUBOX_HOSTNAME="changed"\n')
        # Without refresh, the API still sees old value
        r2 = client.get("/webui/admin-domain")
        assert r2.json()["hostname"] == "gk2"
        # Refresh
        r3 = client.post("/webui/refresh")
        assert r3.status_code == 204
        # Now the API sees the new value
        r4 = client.get("/webui/admin-domain")
        assert r4.json()["hostname"] == "changed"
    finally:
        app.dependency_overrides.clear()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd packages/secubox-haproxy && python -m pytest tests/test_webui_endpoints.py::test_refresh_invalidates_cache -v
```

Expected: FAIL (404).

- [ ] **Step 3: Add the endpoint to `packages/secubox-haproxy/api/main.py`**

```python
from fastapi import Response


@app.post("/webui/refresh", status_code=204,
          dependencies=[Depends(require_jwt)])
async def webui_refresh():
    """Invalidate the cached identity. Call after editing /etc/default/secubox."""
    _webui_identity.invalidate_cache()
    return Response(status_code=204)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd packages/secubox-haproxy && python -m pytest tests/test_webui_endpoints.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-haproxy/api/main.py packages/secubox-haproxy/tests/test_webui_endpoints.py
git commit -m "feat(secubox-haproxy): POST /webui/refresh cache invalidation (ref #44)"
```

---

## Task 8: nginx renderer script

**Files:**

- Create: `packages/secubox-haproxy/sbin/secubox-render-nginx-webui`
- Modify: `packages/secubox-haproxy/debian/install` (install to /usr/local/bin/)

- [ ] **Step 1: Create `packages/secubox-haproxy/sbin/secubox-render-nginx-webui`**

```bash
#!/bin/bash
# secubox-render-nginx-webui — render strict-regex WebUI vhost from API
#
# Flow: snapshot → fetch from API → atomic stage → nginx -t → reload,
# with rollback at any failure point.
#
# Issue #44: WebUI Obfuscation
set -euo pipefail

TARGET=/etc/nginx/sites-available/secubox-local
TMP=$(mktemp /tmp/secubox-local.XXXXXX)
SNAP="$TARGET.bak.$(date +%s)"
SOCK=/run/secubox/haproxy.sock

log() { echo "[$(date '+%F %T')] $*" >&2; }

[[ -S "$SOCK" ]] || { log "FATAL: $SOCK missing — is secubox-haproxy.service running?"; exit 2; }

log "Fetch /webui/nginx-config from API"
if ! curl -sf --unix-socket "$SOCK" http://localhost/webui/nginx-config -o "$TMP"; then
    log "API call failed"
    rm -f "$TMP"; exit 3
fi
[[ -s "$TMP" ]] || { log "API returned empty body"; rm -f "$TMP"; exit 3; }

log "Snapshot $TARGET → $SNAP"
[[ -f "$TARGET" ]] && cp -p "$TARGET" "$SNAP"
mv "$TMP" "$TARGET"

if ! nginx -t 2>&1 | grep -q "syntax is ok"; then
    log "nginx -t FAILED — rolling back"
    [[ -f "$SNAP" ]] && cp -p "$SNAP" "$TARGET"
    exit 5
fi

log "Reload nginx"
systemctl reload nginx && log "render OK (snapshot kept: $SNAP)"
```

Make executable:

```bash
chmod +x packages/secubox-haproxy/sbin/secubox-render-nginx-webui
```

- [ ] **Step 2: Verify bash syntax**

```bash
bash -n packages/secubox-haproxy/sbin/secubox-render-nginx-webui && echo "syntax OK"
```

Expected: `syntax OK`.

- [ ] **Step 3: Add an install line to `packages/secubox-haproxy/debian/install`**

Open `packages/secubox-haproxy/debian/install` and append (preserve existing lines):

```text
sbin/secubox-render-nginx-webui usr/local/bin
```

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-haproxy/sbin/secubox-render-nginx-webui packages/secubox-haproxy/debian/install
git commit -m "feat(secubox-haproxy): secubox-render-nginx-webui safe renderer (ref #44)"
```

---

## Task 9: Patch `haproxyctl` to inject regex ACL at frontend top

**Files:**

- Modify: `packages/secubox-haproxy/sbin/haproxyctl`

- [ ] **Step 1: Add a `_fetch_webui_regex` helper near the top of the script**

After the existing `load_config()` function, insert:

```bash
# Fetch the strict-regex pattern from the secubox-haproxy API.
# Fallback: read /etc/default/secubox directly if the API socket is unreachable.
_fetch_webui_regex() {
    local sock=/run/secubox/haproxy.sock
    local regex
    if [[ -S "$sock" ]] && \
       regex=$(curl -sf --max-time 2 --unix-socket "$sock" \
                    http://localhost/webui/admin-domain 2>/dev/null \
                | jq -r '.regex // empty' 2>/dev/null) && \
       [[ -n "$regex" ]]; then
        echo "$regex"; return 0
    fi
    if [[ -f /etc/default/secubox ]]; then
        # shellcheck source=/dev/null
        . /etc/default/secubox
        if [[ -n "${SECUBOX_HOSTNAME:-}" ]]; then
            local suffix="${SECUBOX_DOMAIN_SUFFIX:-secubox.in}"
            local admin="admin.${SECUBOX_HOSTNAME}.${suffix}"
            # Escape literal dots for HAProxy regex
            echo "^${admin//./\\.}\$"
            return 0
        fi
    fi
    return 1
}
```

- [ ] **Step 2: Inject the strict ACL into the `http-in` frontend block**

Find the existing `frontend http-in` heredoc emission in the `generate` sub-command. Right after `mode http`, add the strict-regex pair. Locate this block (similar):

```bash
    cat >> "$CONFIG_DIR/haproxy.cfg" << EOF
frontend http-in
    bind *:${http_port}
    mode http
EOF
```

Append immediately after that heredoc:

```bash
    if webui_regex=$(_fetch_webui_regex); then
        cat >> "$CONFIG_DIR/haproxy.cfg" << EOF
    # WebUI Obfuscation (issue #44) — strict regex from /etc/default/secubox
    acl is_webui_admin hdr(host) -m reg $webui_regex
    use_backend webui_direct if is_webui_admin
EOF
    fi
```

- [ ] **Step 3: Repeat for the `https-in` frontend block**

After the `https-in` heredoc that ends with `mode http`, append the same `if webui_regex=...` block.

- [ ] **Step 4: Skip the admin domain in the per-vhost loop**

In the existing `grep '^\[vhosts\.' "$CONF_PATH" | while read -r line; do` loop (both http-in and https-in copies), add right after `local domain=$(...)`:

```bash
            # WebUI strict-regex already covers admin.${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX}
            if [ -f /etc/default/secubox ]; then
                # shellcheck source=/dev/null
                . /etc/default/secubox
                if [ -n "${SECUBOX_HOSTNAME:-}" ] && [ "$domain" = "admin.${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX:-secubox.in}" ]; then
                    continue
                fi
            fi
```

- [ ] **Step 5: Verify bash syntax**

```bash
bash -n packages/secubox-haproxy/sbin/haproxyctl && echo "syntax OK"
```

Expected: `syntax OK`.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-haproxy/sbin/haproxyctl
git commit -m "feat(haproxyctl): inject strict-regex WebUI ACL at frontend top (ref #44)"
```

---

## Task 10: Python `generate_config()` symmetry

**Files:**

- Modify: `packages/secubox-haproxy/api/main.py` (the existing `generate_config` async function)

- [ ] **Step 1: Locate `generate_config`**

In `packages/secubox-haproxy/api/main.py`, find:

```python
@app.post("/generate", ...)
async def generate_config():
    ...
```

It builds `config_lines` with `frontend http-in` and `frontend https-in` sections.

- [ ] **Step 2: Insert the strict-regex block at the top of each frontend**

Right after the `frontend http-in` / `bind *:{http_port}` / `mode http` lines (and again for `https-in`), insert:

```python
    # WebUI Obfuscation (issue #44) — strict regex from /etc/default/secubox
    try:
        _ident = _webui_identity.get_identity()
        config_lines.append(
            f"    # WebUI Obfuscation (issue #44)\n"
            f"    acl is_webui_admin hdr(host) -m reg {_ident['regex']}\n"
            f"    use_backend webui_direct if is_webui_admin"
        )
    except ValueError:
        # SECUBOX_HOSTNAME not set — skip the strict ACL (legacy behaviour)
        pass
```

(Insert into the actual list-append style used by the existing function — match it.)

- [ ] **Step 3: Skip the admin vhost in the per-vhost loop**

Inside the `for vh in vhosts:` loops that emit per-vhost ACLs, add right before the `if vh.get("enabled"):` check:

```python
        try:
            _admin = _webui_identity.get_identity()["admin_domain"]
            if vh.get("domain") == _admin:
                continue
        except ValueError:
            pass
```

- [ ] **Step 4: Add a test for the symmetry**

Append to `packages/secubox-haproxy/tests/test_webui_endpoints.py`:

```python
def test_generate_includes_strict_webui_acl(client, monkeypatch):
    from api.main import app
    from api.auth import require_jwt
    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        r = client.post("/generate")
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200
    # The generated cfg should contain the strict ACL in both frontends
    # The /generate endpoint either returns the cfg body or writes to disk;
    # adapt depending on actual signature.
    body = r.text if r.headers.get("content-type", "").startswith("text/plain") else ""
    if body:
        assert r"acl is_webui_admin hdr(host) -m reg ^admin\.gk2\.secubox\.in$" in body
        assert "use_backend webui_direct if is_webui_admin" in body
```

If `/generate` writes to a file rather than returning the body, read the resulting cfg in the test:

```python
def test_generate_writes_strict_webui_acl(client, tmp_path, monkeypatch):
    cfg = tmp_path / "haproxy.cfg"
    monkeypatch.setattr(api_main, "HAPROXY_CFG", cfg)  # adjust constant name
    from api.main import app
    from api.auth import require_jwt
    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        r = client.post("/generate")
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200
    text = cfg.read_text()
    assert text.count("acl is_webui_admin hdr(host) -m reg") == 2  # http-in + https-in
    assert text.count("use_backend webui_direct if is_webui_admin") == 2
```

Pick the variant matching the actual `/generate` behaviour.

- [ ] **Step 5: Run tests**

```bash
cd packages/secubox-haproxy && python -m pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-haproxy/api/main.py packages/secubox-haproxy/tests/test_webui_endpoints.py
git commit -m "feat(secubox-haproxy): /generate symmetry with strict WebUI ACL (ref #44)"
```

---

## Task 11: secubox-haproxy postinst — auto-render on dpkg trigger

**Files:**

- Modify: `packages/secubox-haproxy/debian/postinst`
- Create or modify: `packages/secubox-haproxy/debian/triggers`

- [ ] **Step 1: Add a triggers file at `packages/secubox-haproxy/debian/triggers`**

If the file exists, append the line; if not, create it with this single line:

```text
interest-noawait secubox-defaults-changed
```

- [ ] **Step 2: Open `packages/secubox-haproxy/debian/postinst`**

Find the `configure)` / `triggered)` cases. Add a `triggered)` handler if missing:

```sh
    triggered)
        for trig in $2; do
            case "$trig" in
                secubox-defaults-changed)
                    echo "secubox-haproxy: refreshing for $trig"
                    # Best-effort refresh + render
                    curl -fsS -X POST --unix-socket /run/secubox/haproxy.sock \
                         http://localhost/webui/refresh 2>/dev/null || true
                    if [ -x /usr/local/bin/secubox-render-nginx-webui ]; then
                        /usr/local/bin/secubox-render-nginx-webui || \
                            echo "secubox-haproxy: render failed (non-fatal)" >&2
                    fi
                    if [ -x /usr/local/bin/secubox-haproxy-regen-safe ]; then
                        /usr/local/bin/secubox-haproxy-regen-safe || \
                            echo "secubox-haproxy: regen-safe failed (non-fatal)" >&2
                    fi
                    ;;
            esac
        done
        ;;
```

If the script lacks the `case "$1" in` boilerplate, add it accordingly. Final structure:

```sh
case "$1" in
    configure)
        # ... existing configure logic ...
        ;;
    triggered)
        # ... block above ...
        ;;
esac
```

- [ ] **Step 3: Verify shell syntax**

```bash
sh -n packages/secubox-haproxy/debian/postinst && echo "syntax OK"
```

Expected: `syntax OK`.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-haproxy/debian/postinst packages/secubox-haproxy/debian/triggers
git commit -m "feat(secubox-haproxy): dpkg-trigger refresh on secubox-defaults-changed (ref #44)"
```

---

## Task 12: Add dependency from secubox-haproxy on secubox-defaults

**Files:**

- Modify: `packages/secubox-haproxy/debian/control`

- [ ] **Step 1: Open `packages/secubox-haproxy/debian/control`**

Find the `Depends:` line of the binary `Package: secubox-haproxy` stanza. Add `secubox-defaults` to the comma-separated list:

```text
Depends: ${misc:Depends},
         ${python3:Depends},
         python3-fastapi,
         python3-uvicorn,
         haproxy,
         jq,
         secubox-defaults
```

(Preserve actual existing deps; only add `secubox-defaults` if not present.)

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-haproxy/debian/control
git commit -m "build(secubox-haproxy): depend on secubox-defaults (ref #44)"
```

---

## Task 13: Integration test script

**Files:**

- Create: `tests/integration/test_44_webui_obfuscation.sh`

- [ ] **Step 1: Create `tests/integration/test_44_webui_obfuscation.sh`**

```bash
#!/bin/bash
# tests/integration/test_44_webui_obfuscation.sh
# End-to-end test for issue #44 — run on the board (or a VM that mirrors it).
#
# Pre-requisites:
#   - secubox-defaults, secubox-haproxy installed
#   - /etc/default/secubox with SECUBOX_HOSTNAME and SECUBOX_DOMAIN_SUFFIX set
#   - secubox-haproxy.service running
#
# Exit codes:
#   0  all probes succeeded
#   1  one or more probes failed (rollback performed)
#   2  pre-flight check failed (no changes made)
set -euo pipefail

LOG() { echo "[$(date '+%F %T')] $*" >&2; }
FAIL() { LOG "FAIL: $*"; exit 1; }

# Pre-flight
[[ -f /etc/default/secubox ]] || { LOG "missing /etc/default/secubox"; exit 2; }
# shellcheck source=/dev/null
. /etc/default/secubox
[[ -n "${SECUBOX_HOSTNAME:-}" ]] || { LOG "SECUBOX_HOSTNAME unset"; exit 2; }
ADMIN="admin.${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX:-secubox.in}"
LOG "Canonical admin URL: https://$ADMIN/"

# Snapshot
TS=$(date +%s)
SNAP_HA="/etc/haproxy/haproxy.cfg.bak.$TS-test44"
SNAP_NX="/etc/nginx/sites-available/secubox-local.bak.$TS-test44"
cp -p /etc/haproxy/haproxy.cfg "$SNAP_HA"
cp -p /etc/nginx/sites-available/secubox-local "$SNAP_NX" 2>/dev/null || true

restore() {
    LOG "Restoring snapshots"
    cp -p "$SNAP_HA" /etc/haproxy/haproxy.cfg
    [[ -f "$SNAP_NX" ]] && cp -p "$SNAP_NX" /etc/nginx/sites-available/secubox-local
    systemctl reload haproxy nginx || true
}
trap 'restore' ERR

# 1. Render nginx + regen HAProxy
LOG "Render + regen"
/usr/local/bin/secubox-render-nginx-webui
/usr/local/bin/secubox-haproxy-regen-safe

# 2. Positive probe
LOG "Probe https://$ADMIN/"
TITLE=$(curl -ski "https://$ADMIN/?cb=$RANDOM" | grep -oE '<title>[^<]+</title>' | head -1)
[[ "$TITLE" == *"SecuBox Control Center"* ]] || FAIL "admin URL not serving WebUI ($TITLE)"

# 3. Negative probe: gk2.secubox.in (no admin.) should NOT be WebUI
LOG "Probe https://${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX:-secubox.in}/ (should NOT serve WebUI)"
BODY=$(curl -sk "https://${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX:-secubox.in}/" || true)
echo "$BODY" | grep -q "SecuBox Control Center" && FAIL "non-admin host served WebUI"

# 4. LAN-direct still works
LOG "Probe LAN direct https://192.168.1.200:9443/"
TITLE=$(curl -ski "https://192.168.1.200:9443/?cb=$RANDOM" | grep -oE '<title>[^<]+</title>' | head -1)
[[ "$TITLE" == *"SecuBox Control Center"* ]] || FAIL "LAN-direct broken ($TITLE)"

# 5. Random admin.* should be rejected
LOG "Probe https://admin.fake.secubox.in/ (should NOT serve WebUI)"
BODY=$(curl -sk -H "Host: admin.fake.secubox.in" "https://192.168.1.200/" || true)
echo "$BODY" | grep -q "SecuBox Control Center" && FAIL "random admin.X served WebUI"

# 6. Regression spot-checks
LOG "Regression spot-checks"
for d in cpf.gk2.secubox.in arm.gk2.secubox.in lldh.ganimed.fr pub.gk2.secubox.in werdl.gk2.secubox.in 3d.gk2.secubox.in; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$d/?cb=$RANDOM")
    [[ "$code" == "200" ]] || FAIL "regression on $d (HTTP $code)"
done

trap - ERR
LOG "ALL TESTS PASSED — snapshots kept at $SNAP_HA and $SNAP_NX for forensics"
```

Make executable:

```bash
chmod +x tests/integration/test_44_webui_obfuscation.sh
```

- [ ] **Step 2: Verify bash syntax**

```bash
bash -n tests/integration/test_44_webui_obfuscation.sh && echo "syntax OK"
```

Expected: `syntax OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_44_webui_obfuscation.sh
git commit -m "test(infra): integration test for WebUI obfuscation (ref #44)"
```

---

## Task 14: HISTORY.md entry + final commit

**Files:**

- Modify: `.claude/HISTORY.md`

- [ ] **Step 1: Read current HISTORY.md to find the next Session number**

```bash
grep -n "^### Session " .claude/HISTORY.md | head -3
```

Note the highest Session number `N` already present.

- [ ] **Step 2: Insert a new entry right after `## 2026-05-12` (line 5)**

Open `.claude/HISTORY.md` and add the new Session entry immediately under `## 2026-05-12`:

```markdown
### Session <N+1> — WebUI Obfuscation (#44)

**Goal:** Lock the SecuBox WebUI to `https://admin.<HOSTNAME>.<DOMAIN_SUFFIX>/` only, enforced at HAProxy and nginx layers, driven by `/etc/default/secubox`.

**Spec:** `docs/superpowers/specs/2026-05-12-webui-obfuscation-design.md`
**Plan:** `docs/superpowers/plans/2026-05-12-webui-obfuscation.md`

**Changes:**

- New package `secubox-defaults` ships `/etc/default/secubox` (SECUBOX_HOSTNAME + SECUBOX_DOMAIN_SUFFIX).
- `secubox-haproxy` API extended with three endpoints:
  - `GET /webui/admin-domain` — canonical identity + regex
  - `GET /webui/nginx-config` — JWT-protected, rendered nginx vhost
  - `POST /webui/refresh` — JWT-protected cache invalidation
- New `secubox-render-nginx-webui` script: snapshot + fetch from API + nginx -t + reload, with rollback.
- `haproxyctl` (bash) and `generate_config()` (Python) both inject `acl is_webui_admin hdr(host) -m reg ^admin\.<HOSTNAME>\.<SUFFIX>$` + `use_backend webui_direct` at the top of `http-in` and `https-in`. The original `admin.<HOSTNAME>` per-vhost ACL is skipped to avoid double-match.
- `secubox-haproxy` postinst declares `interest secubox-defaults-changed`, triggers refresh + render + regen-safe on dpkg activation.

**Verification:** `tests/integration/test_44_webui_obfuscation.sh` covers positive probe (admin.gk2 = WebUI), negative probes (gk2.secubox.in and admin.fake.secubox.in NOT WebUI), LAN-direct preserved, and regression spot-checks on cpf/arm/lldh/pub/werdl/3d.

**Closes:** #44
```

- [ ] **Step 3: Commit**

```bash
git add .claude/HISTORY.md
git commit -m "docs: HISTORY Session <N+1> — WebUI obfuscation (ref #44)"
```

---

## Task 15: Open PR

**Files:**

- N/A — runs `gh pr create`.

- [ ] **Step 1: Push branch to origin**

```bash
git push -u origin feature/44-webui-obfuscation-admin-hostname-secubox
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --title "feat(security): WebUI obfuscation — admin.<HOSTNAME>.secubox.in only (#44)" \
  --body "$(cat <<'EOF'
## Summary

- New `secubox-defaults` package ships `/etc/default/secubox` (SECUBOX_HOSTNAME + SECUBOX_DOMAIN_SUFFIX)
- `secubox-haproxy` API gains `/webui/admin-domain`, `/webui/nginx-config`, `/webui/refresh`
- `haproxyctl` + Python `generate_config()` inject strict-regex ACL at top of frontends
- `secubox-render-nginx-webui` produces the strict nginx vhost with safe rollback
- Integration test `tests/integration/test_44_webui_obfuscation.sh` covers positive + negative + regression cases

## Test plan

- [ ] `pytest packages/secubox-haproxy/tests/` passes
- [ ] `bash -n` of all new bash scripts succeeds
- [ ] Build packages: `dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b` in `packages/secubox-defaults/` and `packages/secubox-haproxy/`
- [ ] Deploy to board (192.168.1.200), run `tests/integration/test_44_webui_obfuscation.sh`
- [ ] Manually probe `https://admin.gk2.secubox.in/` (200 + WebUI) and `https://gk2.secubox.in/` (NOT WebUI)
- [ ] Verify regression spot-checks: cpf, arm, lldh, pub, werdl, 3d still HTTP 200

Closes #44

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Record the PR URL**

The command output will print the PR URL. Note it for the executing agent.

---

## Acceptance summary

Once every task above is complete and the integration test passes:

1. `https://admin.gk2.secubox.in/` → HTTP 200, WebUI served.
2. `https://gk2.secubox.in/` (no `admin.`) → does NOT serve WebUI (HAProxy + nginx both refuse).
3. `https://192.168.1.200:9443/` → still HTTP 200 with WebUI (LAN escape hatch intact).
4. `haproxy -c -f /etc/haproxy/haproxy.cfg` and `nginx -t` both pass.
5. All sites from Sessions 153–156 (cpf, arm, zkp, lldh, pub, werdl, 3d, 42, c3box, gandalf, live) remain HTTP 200.
6. `pytest packages/secubox-haproxy/tests/` passes.
7. `systemctl restart secubox-haproxy.service` does not corrupt `haproxy.cfg`.

Issue #44 closes on PR merge.
