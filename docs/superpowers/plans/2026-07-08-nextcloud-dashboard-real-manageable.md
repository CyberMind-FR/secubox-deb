# Nextcloud Dashboard — Real Data + Manageable Users Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Nextcloud admin dashboard show real LXC status + real vhost URLs and manage real Nextcloud users (full CRUD) from the WebUI, with a cosmetics/robustness pass.

**Architecture:** The module (`packages/secubox-nextcloud`) is served in-process by `secubox-aggregator` (user `secubox`, `NoNewPrivileges=no`). The fix routes every privileged container op through `sudo nextcloudctl` (a sanctioned helper) instead of raw `lxc-info`/`lxc-attach` that silently fail unprivileged; adds a container port-probe for true reachability; returns the real vhost URL; extends `nextcloudctl` + the API with user CRUD; and reworks the single-file dashboard.

**Tech Stack:** Python 3.11 FastAPI (`api/main.py`), Bash (`sbin/nextcloudctl`), Debian packaging (`sudoers.d`), vanilla JS + the "P31" skin (`www/nextcloud/index.html`). `secubox_core` at `common/` provides `require_jwt` + `get_config`.

## Global Constraints

- **Privilege path:** the API NEVER shells `lxc-info`/`lxc-attach`/`occ` directly. All container ops go through `sudo -n /usr/sbin/nextcloudctl <subcmd>` via a single `ctl()` helper. The sudoers drop-in `secubox ALL=(root) NOPASSWD: /usr/sbin/nextcloudctl` (mode `0440 root:root`) is what makes this work.
- **Fail-safe:** no endpoint returns a 500 on a container/ctl failure — non-zero exit → structured error; container-not-running → HTTP 409 with a clear message. The port-probe is bounded (1.5s) and never raises.
- **Injection guard:** every `uid` (and quota) that reaches a shell — in `nextcloudctl` AND validated again in the API — must match `^[A-Za-z0-9._@-]+$` (uid) / `^(none|default|[0-9]+(\.[0-9]+)?[KMGT]?B?)$` (quota). Reject otherwise (400 in API, non-zero in ctl) BEFORE any interpolation.
- **Real URLs:** the user-facing base URL is the vhost `https://nc.gk2.secubox.in` (config `public_url`, derived from `domain`). NEVER emit `http://localhost:...` as a user-facing URL.
- **XSS:** every backend-supplied string rendered into the dashboard's innerHTML (uid, display name, quota, log lines, occ output, connection URLs) MUST pass through an `esc()` HTML-escape.
- **Auth:** endpoints keep `Depends(require_jwt)`; the dashboard sends the JWT from `localStorage.sbx_token` (existing pattern); a 401 → redirect to the login page.
- **Python tests:** `cd packages/secubox-nextcloud && PYTHONPATH=../../common:. python3 -m pytest tests/ -q`
- **Bash check:** `bash -n packages/secubox-nextcloud/sbin/nextcloudctl`
- **Commit trailer:** every commit ends with `(ref #429)`. No Claude Code references.

---

### Task 1: `nextcloudctl` — user CRUD + detailed list + uid guard + `status --json`

**Files:**
- Modify: `packages/secubox-nextcloud/sbin/nextcloudctl` (the `user` dispatch ~line 868; add helpers near `user_list` ~line 476; `cmd_status` for `--json`)

**Interfaces:**
- Consumes: existing `occ`, `lxc_attach`, `lxc_running`, `log`, `warn`.
- Produces (called by the API's `ctl()` in Task 2/3):
  - `nextcloudctl user list` → JSON array of `{uid, displayname, enabled, quota, last_login}`
  - `nextcloudctl user enable <uid>` / `user disable <uid>`
  - `nextcloudctl user quota <uid> <quota>`
  - `nextcloudctl user add <uid> <display> <password-via-stdin-or-env>` (existing)
  - `nextcloudctl user del <uid>` (existing)
  - `nextcloudctl status --json` → `{"running":bool,"installed":bool,"version":"..","user_count":N}`

- [ ] **Step 1: Add a uid validator + user enable/disable/quota + detailed list**

In `sbin/nextcloudctl`, near the existing user helpers (after `user_list`, ~line 477), add:

```bash
# #429 injection guard: a Nextcloud uid is limited to a safe charset before it
# is ever interpolated into an occ shell command inside the container.
_valid_uid() {
    printf '%s' "$1" | grep -qE '^[A-Za-z0-9._@-]+$'
}
_valid_quota() {
    printf '%s' "$1" | grep -qiE '^(none|default|[0-9]+(\.[0-9]+)?[KMGT]?B?)$'
}

# user_list_detailed: real users with enabled state + quota + last login, JSON.
# occ user:list:detailed emits a YAML-ish structure; prefer its --output=json.
user_list_detailed() {
    occ user:list:detailed --output=json 2>/dev/null || occ user:list --output=json
}

user_enable() {
    _valid_uid "$1" || { echo "invalid uid" >&2; return 2; }
    occ user:enable "$1"
}
user_disable() {
    _valid_uid "$1" || { echo "invalid uid" >&2; return 2; }
    occ user:disable "$1"
}
user_quota() {
    _valid_uid "$1" || { echo "invalid uid" >&2; return 2; }
    _valid_quota "$2" || { echo "invalid quota" >&2; return 2; }
    occ user:setting "$1" files quota "$2"
}
```

- [ ] **Step 2: Wire the new subcommands into the `user` dispatch**

Find the `user)` block (~line 868) and extend it:

```bash
    user)
        sub="$2"
        case "$sub" in
            add) shift 2; user_add "$@" ;;
            del|delete) shift 2; user_del "$@" ;;
            list) user_list_detailed ;;
            enable) shift 2; user_enable "$@" ;;
            disable) shift 2; user_disable "$@" ;;
            quota) shift 2; user_quota "$@" ;;
            *) echo "Usage: nextcloudctl user {add|del|list|enable|disable|quota}"; exit 1 ;;
        esac
        ;;
```

(Keep whatever surrounds it; only the inner `case` gains `enable|disable|quota` and `list` now calls `user_list_detailed`. Verify the existing `user_del`/`user_add` still shift correctly.)

- [ ] **Step 3: Add `status --json`**

Find `cmd_status` (dispatched at `status) cmd_status ;;`). Add a JSON branch at the TOP of `cmd_status` (before its human-readable output):

```bash
cmd_status() {
    if [ "$1" = "--json" ]; then
        local running=false installed=false version="" ucount=0
        lxc_running && running=true
        [ -f "$LXC_PATH/$CONTAINER/config" ] && installed=true
        if [ "$running" = true ]; then
            version=$(occ -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            ucount=$(occ user:list --output=json 2>/dev/null | grep -oE '"[^"]+"\s*:' | wc -l)
        fi
        printf '{"running":%s,"installed":%s,"version":"%s","user_count":%s}\n' \
            "$running" "$installed" "$version" "$ucount"
        return 0
    fi
    # ... existing human-readable status below (unchanged) ...
```

And make the dispatch pass args: change `status) cmd_status ;;` to `status) shift; cmd_status "$@" ;;`.

- [ ] **Step 4: Syntax check + smoke the validators**

Run: `bash -n packages/secubox-nextcloud/sbin/nextcloudctl`
Expected: no output (valid).

Then a quick validator smoke (pure-bash, no container):
```bash
bash -c 'source <(sed -n "/_valid_uid()/,/^}/p;/_valid_quota()/,/^}/p" packages/secubox-nextcloud/sbin/nextcloudctl); _valid_uid "alice" && echo ok1; _valid_uid "a;rm -rf" || echo rej1; _valid_quota "5GB" && echo ok2; _valid_quota "none" && echo ok3; _valid_quota "\$(x)" || echo rej2'
```
Expected: `ok1`, `rej1`, `ok2`, `ok3`, `rej2`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-nextcloud/sbin/nextcloudctl
git commit -m "feat(nextcloud): nextcloudctl user enable/disable/quota + detailed list + status --json + uid guard (ref #429)"
```

---

### Task 2: `api/main.py` — `ctl()` privilege routing + port-probe status + real URLs

**Files:**
- Modify: `packages/secubox-nextcloud/api/main.py` (helpers ~line 20-54; `/status` ~line 56; `/connections` ~line 387)
- Create: `packages/secubox-nextcloud/tests/__init__.py`, `packages/secubox-nextcloud/tests/test_status_urls.py`

**Interfaces:**
- Produces: `ctl(subcmd: list[str], timeout=60, stdin: str|None=None) -> tuple[bool,str,str]`; `lxc_running() -> bool`; `container_reachable() -> bool`; `public_url() -> str`. Consumed by Task 3.

- [ ] **Step 1: Write the failing tests**

Create `packages/secubox-nextcloud/tests/__init__.py` (empty) and `packages/secubox-nextcloud/tests/test_status_urls.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import importlib
import socket

from fastapi.testclient import TestClient


def _load(monkeypatch):
    import api.main as m
    importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    return m


def test_ctl_routes_through_sudo_nextcloudctl(monkeypatch):
    m = _load(monkeypatch)
    seen = {}

    def fake_run(cmd, timeout=30):
        seen["cmd"] = cmd
        return True, "RUNNING", ""

    monkeypatch.setattr(m, "run_cmd", fake_run)
    ok, out, _ = m.ctl(["status", "--json"])
    assert seen["cmd"][:3] == ["sudo", "-n", "/usr/sbin/nextcloudctl"]
    assert seen["cmd"][3:] == ["status", "--json"]


def test_status_running_and_reachable(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True,
        '{"running":true,"installed":true,"version":"29.0.1","user_count":3}', ""))
    monkeypatch.setattr(m, "container_reachable", lambda: True)
    c = TestClient(m.app)
    r = c.get("/status")
    assert r.status_code == 200
    b = r.json()
    assert b["running"] is True and b["reachable"] is True
    assert b["version"] == "29.0.1" and b["user_count"] == 3
    # real URL, never localhost
    assert b["web_url"].startswith("https://") and "localhost" not in b["web_url"]


def test_connections_uses_real_vhost(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "public_url", lambda: "https://nc.gk2.secubox.in")
    c = TestClient(m.app)
    b = c.get("/connections").json()
    assert b["base_url"] == "https://nc.gk2.secubox.in"
    assert b["webdav"].startswith("https://nc.gk2.secubox.in/remote.php/dav/files/")
    assert "localhost" not in b["base_url"]


def test_reachable_probe_is_failsafe(monkeypatch):
    m = _load(monkeypatch)

    def boom(*a, **k):
        raise socket.timeout("nope")

    monkeypatch.setattr(socket, "create_connection", boom)
    assert m.container_reachable() is False  # never raises
```

- [ ] **Step 2: Run to verify fail**

Run: `cd packages/secubox-nextcloud && PYTHONPATH=../../common:. python3 -m pytest tests/test_status_urls.py -q`
Expected: FAIL — `ctl`/`container_reachable`/`public_url` undefined; `/status` lacks `reachable`; URLs are localhost.

- [ ] **Step 3: Add `ctl()`, port-probe, real URL helpers; rewrite the privileged helpers**

In `api/main.py`, replace the direct `lxc_running`/`lxc_attach`/`occ_cmd` (lines ~31-54) — keep `run_cmd` and `lxc_installed` — with:

```python
CTL = "/usr/sbin/nextcloudctl"
CONTAINER_IP = config.get("container_ip", "10.100.0.21")
HTTP_PORT = int(config.get("http_port", 8080) or 8080)
DOMAIN = config.get("domain", "nc.gk2.secubox.in")


def ctl(subcmd: list, timeout: int = 60, stdin: str = None) -> tuple:
    """Run `sudo -n nextcloudctl <subcmd...>`. The ONLY privileged path: the
    aggregator runs as `secubox` (NNP=no) with a NOPASSWD sudoers entry for
    nextcloudctl. Fail-safe: returns (ok, out, err), never raises."""
    cmd = ["sudo", "-n", CTL, *subcmd]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, input=stdin)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "timed out"
    except Exception as e:  # pragma: no cover - defensive
        return False, "", str(e)


def lxc_running() -> bool:
    """Authoritative container state via the privileged helper."""
    ok, out, _ = ctl(["status", "--json"], timeout=20)
    if not ok:
        return False
    try:
        import json
        return bool(json.loads(out).get("running"))
    except Exception:
        return False


def occ_cmd(command: str, timeout: int = 60) -> tuple:
    """Run an occ command via the privileged helper's occ passthrough."""
    return ctl(["occ", *command.split()], timeout=timeout)


def container_reachable() -> bool:
    """True if the Nextcloud container is actually serving on its HTTP port.
    Bounded + fail-safe (never raises)."""
    import socket
    try:
        with socket.create_connection((CONTAINER_IP, 80), timeout=1.5):
            return True
    except Exception:
        return False


def public_url() -> str:
    """The real, user-facing base URL (the WAF-fronted vhost), never localhost."""
    u = config.get("public_url")
    if u:
        return u.rstrip("/")
    return f"https://{DOMAIN}"
```

> Note: `occ_cmd` now routes through `ctl(["occ", ...])`. The `-V` / `user:list` callers already pass a string; `command.split()` tokenises it. If a caller needs quoting (it doesn't today — `-V`, `user:list --output=json`), keep it simple.

- [ ] **Step 4: `/status` — add reachability + real url; drive from ctl**

In the `/status` handler, replace the `web_url` line and add `reachable`. The `version`/`user_count` can now come from a single `status --json` call (cheaper) — rewrite the body:

```python
@app.get("/status")
async def status():
    installed = lxc_installed()
    running = False
    version = ""
    user_count = 0
    ok, out, _ = ctl(["status", "--json"], timeout=20)
    if ok:
        try:
            import json
            s = json.loads(out)
            running = bool(s.get("running"))
            installed = installed or bool(s.get("installed"))
            version = s.get("version", "") or ""
            user_count = int(s.get("user_count", 0) or 0)
        except Exception:
            pass
    reachable = container_reachable() if running else False

    disk_used = "0"
    data_dir = DATA_PATH / "data"
    if data_dir.exists():
        okd, outd, _ = run_cmd(["du", "-sh", str(data_dir)])
        if okd:
            disk_used = outd.split()[0]

    return {
        "module": "nextcloud",
        "enabled": config.get("enabled", True),
        "running": running,
        "reachable": reachable,
        "installed": installed,
        "version": version,
        "http_port": HTTP_PORT,
        "data_path": str(DATA_PATH),
        "domain": DOMAIN,
        "user_count": user_count,
        "disk_used": disk_used,
        "web_url": public_url(),
        "ssl_enabled": config.get("ssl_enabled", False),
        "container_name": LXC_NAME,
    }
```

- [ ] **Step 5: `/connections` — real vhost URLs**

Rewrite `get_connections` to use `public_url()`:

```python
@app.get("/connections", dependencies=[Depends(require_jwt)])
async def get_connections():
    base_url = public_url()
    return {
        "base_url": base_url,
        "caldav": f"{base_url}/remote.php/dav/calendars/<username>/",
        "carddav": f"{base_url}/remote.php/dav/addressbooks/users/<username>/contacts/",
        "webdav": f"{base_url}/remote.php/dav/files/<username>/",
        "davx5_url": f"{base_url}/remote.php/dav",
        "desktop_url": base_url,
        "ios_app": "https://apps.apple.com/app/nextcloud/id1125420102",
        "android_app": "https://play.google.com/store/apps/details?id=com.nextcloud.client",
    }
```

- [ ] **Step 6: Run to verify pass**

Run: `cd packages/secubox-nextcloud && PYTHONPATH=../../common:. python3 -m pytest tests/test_status_urls.py -q`
Expected: PASS (4 tests).

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-nextcloud/api/main.py packages/secubox-nextcloud/tests/
git commit -m "feat(nextcloud): route container ops via sudo nextcloudctl + port-probe status + real vhost URLs (ref #429)"
```

---

### Task 3: `api/main.py` — user CRUD endpoints (add/delete/enable/disable/quota)

**Files:**
- Modify: `packages/secubox-nextcloud/api/main.py` (`/users` ~line 224, add new endpoints)
- Create: `packages/secubox-nextcloud/tests/test_users.py`

**Interfaces:**
- Consumes: `ctl`, `lxc_running`, uid rules.
- Produces: `GET /users`, `POST /user`, `DELETE /user/{uid}`, `POST /user/{uid}/enable|disable`, `POST /user/{uid}/quota`.

- [ ] **Step 1: Write the failing tests**

Create `packages/secubox-nextcloud/tests/test_users.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import importlib
from fastapi.testclient import TestClient


def _load(monkeypatch, running=True):
    import api.main as m
    importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "lxc_running", lambda: running)
    return m


def test_users_list_detailed(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True,
        '[{"uid":"alice","displayname":"Alice","enabled":true,"quota":"5 GB"}]', ""))
    c = TestClient(m.app)
    r = c.get("/users")
    assert r.status_code == 200
    assert r.json()["users"][0]["uid"] == "alice"


def test_create_user_calls_ctl(monkeypatch):
    m = _load(monkeypatch)
    seen = {}
    monkeypatch.setattr(m, "ctl", lambda sub, **k: (seen.setdefault("sub", sub), (True, "created", ""))[1])
    c = TestClient(m.app)
    r = c.post("/user", json={"uid": "bob", "display_name": "Bob", "password": "s3cret!!"})
    assert r.status_code == 200 and r.json()["success"] is True
    assert seen["sub"][:2] == ["user", "add"]


def test_bad_uid_rejected_400(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True, "", ""))
    c = TestClient(m.app)
    for path in ["/user/a;rm/enable", "/user/a b/disable"]:
        assert c.post(path).status_code == 400


def test_user_ops_409_when_not_running(monkeypatch):
    m = _load(monkeypatch, running=False)
    c = TestClient(m.app)
    assert c.post("/user/alice/enable").status_code == 409
    assert c.post("/user", json={"uid": "x", "display_name": "X", "password": "yyyyyyyy"}).status_code == 409


def test_quota_validation(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True, "", ""))
    c = TestClient(m.app)
    assert c.post("/user/alice/quota", json={"quota": "5GB"}).status_code == 200
    assert c.post("/user/alice/quota", json={"quota": "$(x)"}).status_code == 400
```

- [ ] **Step 2: Run to verify fail**

Run: `cd packages/secubox-nextcloud && PYTHONPATH=../../common:. python3 -m pytest tests/test_users.py -q`
Expected: FAIL — endpoints missing / 500.

- [ ] **Step 3: Implement the user CRUD endpoints + validators**

Add near the top of `api/main.py` (after the models) the validators, and add/replace the user endpoints:

```python
import re as _re

_UID_RE = _re.compile(r"^[A-Za-z0-9._@-]+$")
_QUOTA_RE = _re.compile(r"^(none|default|[0-9]+(\.[0-9]+)?[KMGT]?B?)$", _re.I)


def _require_running():
    if not lxc_running():
        raise HTTPException(409, "Nextcloud container is not running")


def _valid_uid(uid: str) -> bool:
    return bool(uid) and bool(_UID_RE.match(uid))


class NewUser(BaseModel):
    uid: str
    display_name: str = ""
    password: str


class QuotaReq(BaseModel):
    quota: str


@app.get("/users", dependencies=[Depends(require_jwt)])
async def get_users():
    _require_running()
    ok, out, err = ctl(["user", "list"], timeout=30)
    if not ok:
        raise HTTPException(500, f"user list failed: {err}")
    import json
    try:
        data = json.loads(out)
    except Exception:
        data = []
    # occ may emit an object {uid: displayname} or a detailed list; normalise.
    if isinstance(data, dict):
        users = [{"uid": k, "displayname": v, "enabled": True, "quota": ""} for k, v in data.items()]
    else:
        users = data
    return {"users": users}


@app.post("/user", dependencies=[Depends(require_jwt)])
async def create_user(req: NewUser):
    _require_running()
    if not _valid_uid(req.uid):
        raise HTTPException(400, "invalid uid")
    ok, out, err = ctl(["user", "add", req.uid, req.display_name or req.uid],
                       stdin=req.password + "\n", timeout=60)
    if not ok:
        raise HTTPException(500, f"create failed: {err or out}")
    return {"success": True}


@app.delete("/user/{uid}", dependencies=[Depends(require_jwt)])
async def delete_user(uid: str):
    _require_running()
    if not _valid_uid(uid):
        raise HTTPException(400, "invalid uid")
    ok, _, err = ctl(["user", "del", uid], timeout=60)
    if not ok:
        raise HTTPException(500, f"delete failed: {err}")
    return {"success": True}


@app.post("/user/{uid}/enable", dependencies=[Depends(require_jwt)])
async def enable_user(uid: str):
    _require_running()
    if not _valid_uid(uid):
        raise HTTPException(400, "invalid uid")
    ok, _, err = ctl(["user", "enable", uid])
    if not ok:
        raise HTTPException(500, f"enable failed: {err}")
    return {"success": True}


@app.post("/user/{uid}/disable", dependencies=[Depends(require_jwt)])
async def disable_user(uid: str):
    _require_running()
    if not _valid_uid(uid):
        raise HTTPException(400, "invalid uid")
    ok, _, err = ctl(["user", "disable", uid])
    if not ok:
        raise HTTPException(500, f"disable failed: {err}")
    return {"success": True}


@app.post("/user/{uid}/quota", dependencies=[Depends(require_jwt)])
async def set_quota(uid: str, req: QuotaReq):
    _require_running()
    if not _valid_uid(uid):
        raise HTTPException(400, "invalid uid")
    if not _QUOTA_RE.match(req.quota or ""):
        raise HTTPException(400, "invalid quota")
    ok, _, err = ctl(["user", "quota", uid, req.quota])
    if not ok:
        raise HTTPException(500, f"quota failed: {err}")
    return {"success": True}
```

> The existing `GET /users` (line ~224) and `POST /user/password` are REPLACED/kept: delete the old `/users` handler (this one supersedes it); keep `POST /user/password`. `NewUser.password` goes to `nextcloudctl user add` via stdin so it never lands in argv/ps.

Update Task 1's `user_add` to read the password from stdin if not given as an arg (so `ctl(..., stdin=...)` works): in `nextcloudctl`, `user_add` should `IFS= read -r pw` from stdin when `$3` is empty and export `OC_PASS`. If `user_add` already takes the password as `$2`/env, adapt the API call to match its real signature — **the implementer must read `user_add`'s actual argument order first** and wire `ctl([...])` + `stdin` accordingly. The test `test_create_user_calls_ctl` only asserts the `["user","add",...]` prefix, so the exact trailing args are the implementer's to match to `user_add`.

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-nextcloud && PYTHONPATH=../../common:. python3 -m pytest tests/ -q`
Expected: PASS (all status/url + user tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-nextcloud/api/main.py packages/secubox-nextcloud/tests/test_users.py
git commit -m "feat(nextcloud): user CRUD endpoints (add/delete/enable/disable/quota) + uid/quota guards + 409-not-running (ref #429)"
```

---

### Task 4: Packaging — sudoers drop-in + postinst + config example

**Files:**
- Create: `packages/secubox-nextcloud/debian/secubox-nextcloud.sudoers`
- Modify: `packages/secubox-nextcloud/debian/rules` (install it), `packages/secubox-nextcloud/debian/postinst` (visudo check), `packages/secubox-nextcloud/conf/nextcloud.toml.example`

**Interfaces:** none (packaging). Produces the runtime sudoers that makes `ctl()` work.

- [ ] **Step 1: Create the sudoers file**

Create `packages/secubox-nextcloud/debian/secubox-nextcloud.sudoers`:
```
# #429 — the aggregator (user secubox) drives the Nextcloud LXC container
# through nextcloudctl. This is the ONLY privileged surface for the module.
secubox ALL=(root) NOPASSWD: /usr/sbin/nextcloudctl
```

- [ ] **Step 2: Install it (mode 0440) in `debian/rules`**

In `debian/rules` `override_dh_auto_install` (or `override_dh_install`), add:
```
	install -D -m 0440 debian/secubox-nextcloud.sudoers \
		debian/secubox-nextcloud/etc/sudoers.d/secubox-nextcloud
```
(Match the file's existing install idiom — see how `sbin/nextcloudctl` is installed.)

- [ ] **Step 3: Validate it in `postinst`**

In `debian/postinst` `configure` branch, add (fail the install if the sudoers is malformed — a broken sudoers is dangerous):
```sh
	if [ -f /etc/sudoers.d/secubox-nextcloud ]; then
		visudo -cf /etc/sudoers.d/secubox-nextcloud >/dev/null || {
			echo "secubox-nextcloud: invalid sudoers, removing" >&2
			rm -f /etc/sudoers.d/secubox-nextcloud
		}
	fi
```

- [ ] **Step 4: Config example gains the real-URL knobs**

Append to `conf/nextcloud.toml.example`:
```toml
# Real user-facing base URL (the WAF-fronted vhost). Overrides the derived
# https://<domain>. Set this to the operator's public Nextcloud URL.
# public_url = "https://nc.gk2.secubox.in"
domain = "nc.gk2.secubox.in"
container_ip = "10.100.0.21"
```
(If `domain`/`container_ip` already exist, only add `public_url` commented + reconcile the values.)

- [ ] **Step 5: Verify**

Run:
```bash
visudo -cf packages/secubox-nextcloud/debian/secubox-nextcloud.sudoers && echo "sudoers OK"
grep -q "sudoers.d/secubox-nextcloud" packages/secubox-nextcloud/debian/rules && echo "rules OK"
grep -q "visudo -cf /etc/sudoers.d/secubox-nextcloud" packages/secubox-nextcloud/debian/postinst && echo "postinst OK"
```
Expected: `sudoers OK`, `rules OK`, `postinst OK`.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-nextcloud/debian/ packages/secubox-nextcloud/conf/nextcloud.toml.example
git commit -m "feat(nextcloud): sudoers drop-in for nextcloudctl + visudo guard + real-URL config knobs (ref #429)"
```

---

### Task 5: Frontend rework — `www/nextcloud/index.html`

**Files:**
- Modify: `packages/secubox-nextcloud/www/nextcloud/index.html`

**Interfaces:**
- Consumes: `GET /status` (`running,reachable,installed,version,user_count,disk_used,web_url`), `GET /connections`, `GET /users` (`{users:[{uid,displayname,enabled,quota,last_login}]}`), `POST /user`, `DELETE /user/{uid}`, `POST /user/{uid}/{enable,disable}`, `POST /user/{uid}/quota`, `POST /user/password`, `GET /storage`, `GET /logs?lines=`, `POST /occ`, `POST /update`, `POST /ssl/enable|disable`, `GET/POST /config`, `POST /uninstall`, plus existing start/stop/restart/install, backups.

- [ ] **Step 1: Add the shared hardening helpers**

In the `<script>`, near the top helpers, add (reuse the existing `API`/`headers()`):

```javascript
function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function toast(msg, kind) {
    let t = document.getElementById('toast');
    if (!t) { t = document.createElement('div'); t.id = 'toast'; document.body.appendChild(t); }
    t.textContent = msg;
    t.className = 'toast ' + (kind || 'info') + ' show';
    clearTimeout(window.__toastT);
    window.__toastT = setTimeout(() => t.classList.remove('show'), 3500);
}
function confirmTyped(word) {
    return prompt('Type "' + word + '" to confirm this irreversible action:') === word;
}
```

Add matching CSS (in `<style>`):
```css
.toast{position:fixed;bottom:1.2rem;right:1.2rem;padding:.7rem 1.1rem;border-radius:10px;
  background:var(--bg-card);border:1px solid var(--border);color:var(--text);opacity:0;
  transform:translateY(8px);transition:all .2s;z-index:50;max-width:min(90vw,360px)}
.toast.show{opacity:1;transform:none}
.toast.success{border-color:var(--green)} .toast.error{border-color:var(--red)}
.bar{height:10px;border-radius:6px;background:var(--border);overflow:hidden}
.bar>span{display:block;height:100%;background:var(--primary)}
.err{color:var(--red);font-size:.8rem} .muted{color:var(--text-dim);font-size:.8rem}
```

- [ ] **Step 2: Harden the `api()` fetch (fail-safe + 401)**

Replace the existing `api()` helper with:

```javascript
async function api(path, opts = {}) {
    try {
        const res = await fetch(API + path, { ...opts, headers: headers() });
        if (res.status === 401) { location.href = '/login.html?redirect=' + encodeURIComponent(location.pathname); return null; }
        const body = res.headers.get('content-type')?.includes('json') ? await res.json() : await res.text();
        if (!res.ok) throw new Error((body && body.detail) || ('HTTP ' + res.status));
        return body;
    } catch (e) {
        return { __error: e.message || 'request failed' };
    }
}
```

- [ ] **Step 3: Real status pill + storage bar**

Replace `loadStatus()` so the pill reflects `running`+`reachable`+`installed`, and show/hide install/start/stop accordingly; and make `loadStorage()` render a bar. Example `loadStatus`:

```javascript
async function loadStatus() {
    const s = await api('/status');
    const pill = document.getElementById('status-pill');
    if (!s || s.__error) { pill.textContent = 'error'; pill.className = 'pill error'; return; }
    let label = 'not installed', cls = 'muted';
    if (s.installed && s.running && s.reachable) { label = 'running'; cls = 'ok'; }
    else if (s.installed && s.running) { label = 'running (unreachable)'; cls = 'warn'; }
    else if (s.installed) { label = 'stopped'; cls = 'error'; }
    pill.textContent = label; pill.className = 'pill ' + cls;
    document.getElementById('nc-version').textContent = esc(s.version || '—');
    document.getElementById('nc-url').innerHTML = s.web_url
        ? `<a href="${esc(s.web_url)}" target="_blank" rel="noopener">${esc(s.web_url)}</a>` : '—';
    document.getElementById('btn-install').style.display = s.installed ? 'none' : '';
    document.getElementById('btn-start').style.display = (s.installed && !s.running) ? '' : 'none';
    document.getElementById('btn-stop').style.display = s.running ? '' : 'none';
}
```

(Add a `#status-pill`, `#nc-version`, `#nc-url` to the header markup, and a `.pill{...}` style with `.ok/.warn/.error/.muted` color variants using `--green/--p31-decay/--red/--text-dim`.)

- [ ] **Step 4: Real users table + full CRUD UI**

Replace `loadUsers()` and add the action functions. Every backend string goes through `esc()`; delete/reset confirm:

```javascript
async function loadUsers() {
    const d = await api('/users');
    const el = document.getElementById('users-body');
    if (!d || d.__error) { el.innerHTML = `<tr><td colspan="5" class="err">${esc(d && d.__error || 'error')}</td></tr>`; return; }
    const rows = (d.users || []).map(u => `<tr>
        <td>${esc(u.uid)}</td>
        <td>${esc(u.displayname || '')}</td>
        <td>${u.enabled === false ? '<span class="err">disabled</span>' : 'enabled'}</td>
        <td>${esc(u.quota || 'default')}</td>
        <td>
          ${u.enabled === false
            ? `<button class="btn" onclick="userOp('${encodeURIComponent(u.uid)}','enable')">Enable</button>`
            : `<button class="btn" onclick="userOp('${encodeURIComponent(u.uid)}','disable')">Disable</button>`}
          <button class="btn" onclick="userQuota('${encodeURIComponent(u.uid)}')">Quota</button>
          <button class="btn" onclick="userReset('${encodeURIComponent(u.uid)}')">Reset pw</button>
          <button class="btn danger" onclick="userDelete('${encodeURIComponent(u.uid)}')">Delete</button>
        </td></tr>`).join('');
    el.innerHTML = rows || '<tr><td colspan="5" class="muted">No users.</td></tr>';
}
async function addUser() {
    const uid = document.getElementById('nu-uid').value.trim();
    const dn = document.getElementById('nu-name').value.trim();
    const pw = document.getElementById('nu-pass').value;
    if (!uid || !pw) { toast('uid and password required', 'error'); return; }
    const r = await api('/user', { method: 'POST', body: JSON.stringify({ uid, display_name: dn, password: pw }) });
    if (r && !r.__error) { toast('User created', 'success'); loadUsers(); } else { toast(r && r.__error || 'failed', 'error'); }
}
async function userOp(uidEnc, op) {
    const r = await api('/user/' + uidEnc + '/' + op, { method: 'POST' });
    toast(r && !r.__error ? op + 'd' : (r && r.__error || 'failed'), r && !r.__error ? 'success' : 'error');
    loadUsers();
}
async function userQuota(uidEnc) {
    const q = prompt('Quota (e.g. 5GB, none, default):', 'default');
    if (q == null) return;
    const r = await api('/user/' + uidEnc + '/quota', { method: 'POST', body: JSON.stringify({ quota: q }) });
    toast(r && !r.__error ? 'Quota set' : (r && r.__error || 'failed'), r && !r.__error ? 'success' : 'error');
    loadUsers();
}
async function userReset(uidEnc) {
    if (!confirm('Reset password for ' + decodeURIComponent(uidEnc) + '?')) return;
    const r = await api('/user/password', { method: 'POST', body: JSON.stringify({ uid: decodeURIComponent(uidEnc) }) });
    toast(r && !r.__error ? 'Password reset' : (r && r.__error || 'failed'), r && !r.__error ? 'success' : 'error');
}
async function userDelete(uidEnc) {
    const uid = decodeURIComponent(uidEnc);
    if (!confirmTyped(uid)) return;
    const r = await api('/user/' + uidEnc, { method: 'DELETE' });
    toast(r && !r.__error ? 'User deleted' : (r && r.__error || 'failed'), r && !r.__error ? 'success' : 'error');
    loadUsers();
}
```

Replace the Users card markup with a `<table>` (thead: User / Name / State / Quota / Actions, `<tbody id="users-body">`) + an add-user form (`#nu-uid`, `#nu-name`, `#nu-pass`, a `Add user` button calling `addUser()`).

- [ ] **Step 5: Real connection URLs + idle-API panels (logs/occ/update/ssl/config/uninstall)**

- `loadConnections()`: render the real URLs from `/connections`, each with a copy button (`navigator.clipboard.writeText`), all `esc()`-wrapped.
- Add cards: **Logs** (`loadLogs()` → `GET /logs?lines=N` into an `esc()`-wrapped `<pre>`, refresh + line-count select), **occ console** (input → `if(confirm(...))` → `POST /occ {command}` → `esc()`-wrapped `<pre>` output), **SSL** (Enable domain input → `POST /ssl/enable {domain}`, Disable → `POST /ssl/disable`), **Config** (`GET /config` fills a form → `POST /config`), **Danger zone**: Update (`confirm` → `POST /update`) and Uninstall (`confirmTyped('nextcloud')` → `POST /uninstall`). Each with toasts + loading/error states.

- [ ] **Step 6: Auto-refresh + wire load on tab/interval**

Add a pausable auto-refresh:
```javascript
let __autoRefresh = null;
function refresh() { loadStatus(); loadStorage(); loadUsers(); loadConnections(); }
function toggleAuto() {
    if (__autoRefresh) { clearInterval(__autoRefresh); __autoRefresh = null; toast('Auto-refresh off'); }
    else { __autoRefresh = setInterval(() => { loadStatus(); loadStorage(); }, 15000); toast('Auto-refresh on'); }
}
document.addEventListener('DOMContentLoaded', refresh);
```

- [ ] **Step 7: Verify the inline JS parses + no unescaped backend strings**

Run:
```bash
cd packages/secubox-nextcloud && python3 - <<'PY'
import re, subprocess, tempfile, os
html = open("www/nextcloud/index.html", encoding="utf-8").read()
src = "\n".join(re.findall(r"<script>(.*?)</script>", html, re.S))
p = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False); p.write(src); p.close()
print("node --check:", subprocess.run(["node", "--check", p.name]).returncode)
os.unlink(p.name)
PY
```
Expected: `node --check: 0`. Then grep-audit that every `innerHTML =` template interpolating a backend field wraps it in `esc(...)` (uid, displayname, quota, log lines, occ output, urls) — no raw `${u.x}` into innerHTML except through `esc()` or `encodeURIComponent()` (the latter only inside `onclick='...(' ... ')'` handler args).

- [ ] **Step 8: Commit**

```bash
git add packages/secubox-nextcloud/www/nextcloud/index.html
git commit -m "feat(nextcloud): dashboard rework — real status/URLs, user CRUD, idle-API panels, toasts + XSS hardening (ref #429)"
```

---

## Self-Review

**Spec coverage:**
- A (real status: sudo nextcloudctl + sudoers + port-probe) → Tasks 1 (`status --json`), 2 (`ctl`/`lxc_running`/`container_reachable`), 4 (sudoers). ✓
- B (real URLs) → Task 2 (`public_url`, `/status`, `/connections`) + Task 4 (config knobs). ✓
- C (real users + CRUD) → Task 1 (nextcloudctl user subcommands) + Task 3 (endpoints) + Task 5 (UI table). ✓
- D (cosmetics + robustness) → Task 5 (pill, storage bar, toasts, auto-refresh, esc/XSS, confirms, fail-safe api, 401, idle-API panels). ✓
- Injection guard → Task 1 (`_valid_uid`/`_valid_quota` in bash) + Task 3 (`_UID_RE`/`_QUOTA_RE` in API). ✓
- Fail-safe / 409-not-running → Task 2 (`ctl` never raises, port-probe bounded) + Task 3 (`_require_running` → 409). ✓

**Placeholder scan:** No TBD/TODO. One deliberate implementer-decision note (Task 3 Step 3: match `ctl(["user","add",...])` trailing args to `user_add`'s real signature) — grounded (read the function first), with the test asserting only the stable prefix.

**Type consistency:** `ctl(subcmd:list,...)->(ok,out,err)` used identically in Tasks 2+3. `lxc_running()->bool`, `container_reachable()->bool`, `public_url()->str` defined in Task 2, consumed in 3. `/users` returns `{users:[...]}` (Task 3) consumed by `loadUsers()` (Task 5). `/status` fields (`running,reachable,installed,version,web_url`) produced in Task 2, consumed in Task 5's `loadStatus()`. uid/quota regexes identical between bash (Task 1) and Python (Task 3).
