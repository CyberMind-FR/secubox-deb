# PeerTube WebUI admin ops Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three admin actions to the PeerTube WebUI — reset admin password, version check, and version upgrade — all executed in the PeerTube LXC via an unprivileged-API → spool → root-unit mechanism.

**Architecture:** The `secubox-peertube` API is unprivileged (`User=secubox`, `NoNewPrivileges`), so privileged in-LXC ops go through a spool: the API writes `/run/secubox/peertube/ops/<id>.request.json`; a root `peertube-ops.path` watches the dir and runs `peertubectl process-ops` (root), which dispatches to `reset-admin-password`/`upgrade` (lxc-attach) and writes `<id>.result.json`; the API polls the result. Version check is unprivileged (PeerTube HTTP API + GitHub releases).

**Tech Stack:** FastAPI (Python 3.11), bash (`peertubectl`), systemd `.path`/`.service`, HTML/JS (vanilla), pytest, shellcheck.

## Global Constraints

- Licence header `LicenseRef-CMSD-1.0` on every new file (Python: SPDX 4-line block; bash: `#!/usr/bin/env bash` + SPDX).
- The API MUST stay unprivileged — no `sudo`, no `lxc-attach` from `api/main.py`; all in-LXC ops go through the spool → root unit. `NoNewPrivileges=true` on `secubox-peertube.service` is preserved.
- Spool dir: `/run/secubox/peertube/ops/` — `0750 secubox:secubox`. Request file `<id>.request.json` chmod `0600`; result file `<id>.result.json` chmod `0640 root:secubox`.
- Op ids are hex tokens (`secrets.token_hex(8)`), never attacker-influenced paths; the API only ever reads/writes `OPS_DIR/<id>.{request,result}.json` with `id` validated `^[0-9a-f]{8,32}$`.
- After a password reset, `peertubectl` MUST rewrite `/etc/secubox/secrets/peertube-admin` (0600) — else `get_admin_token()` (api/main.py:262) breaks for every dashboard write-op.
- Upgrade MUST `pg_dump` before touching anything; abort if the backup fails; on any post-download failure keep/restore the old `peertube-latest` symlink so the running version is unchanged.
- Mutating endpoints (`POST /admin/reset-password`, `POST /upgrade`) require `Depends(require_admin)` (admin role); read endpoints use `Depends(require_jwt)`.
- Do NOT touch `/run/secubox` (1777) or `/etc/secubox` (0755) parent perms — only create `/run/secubox/peertube/ops`.
- PeerTube facts (LXC `peertube` at `/data/lxc`, path `/var/www/peertube`, release `peertube-latest`, OS user `peertube`, service `peertube.service`, `NODE_ENV=production`, `NODE_CONFIG_DIR=/var/www/peertube/config`, current `v8.2.0`, DB `peertube_prod`).
- Tests: API `cd packages/secubox-peertube && PYTHONPATH=<repo>/common <venv>/bin/python3 -m pytest tests/<f> -q` (venv `/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3`). Bash: `shellcheck sbin/peertubectl` + `bash sbin/peertubectl <verb> --dry-run`.

---

## File Structure

- `packages/secubox-peertube/api/main.py` — **modify**: add `OPS_DIR` const, `require_admin` dep, `_spool_op()` + `_read_op_result()` helpers, endpoints `POST /admin/reset-password`, `GET /admin/op/{id}`, `GET /version`, `POST /upgrade`.
- `packages/secubox-peertube/sbin/peertubectl` — **modify**: add verbs `process-ops`, `reset-admin-password`, `upgrade` (+ `--dry-run`), wire into `main()` dispatch + `cmd_help`.
- `packages/secubox-peertube/debian/peertube-ops.path` + `.service` — **new**: root spool watcher.
- `packages/secubox-peertube/debian/rules` — **modify**: install the two new units.
- `packages/secubox-peertube/debian/postinst` — **modify**: create `/run/secubox/peertube/ops` + backups dir + enable `peertube-ops.path`.
- `packages/secubox-peertube/www/peertube/index.html` — **modify**: reset-password button (Users) + version/upgrade card (Maintenance) + polling helper.
- `packages/secubox-peertube/tests/test_ops_api.py`, `tests/test_version.py` — **new**: API tests.

---

## Task 1: API spool plumbing — `require_admin`, `_spool_op`, `GET /admin/op/{id}`

**Files:**
- Modify: `packages/secubox-peertube/api/main.py`
- Test: `packages/secubox-peertube/tests/test_ops_api.py`

**Interfaces:**
- Consumes: existing `require_jwt` (imported from `secubox_core.auth`), `get_config`.
- Produces: `OPS_DIR: Path`; `require_admin(user=Depends(require_jwt))` FastAPI dep; `_spool_op(op: str, **args) -> str` (returns op id); `_read_op_result(op_id: str) -> dict` (returns `{"status": "pending"|...}`); `GET /admin/op/{id}` route.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-peertube/tests/test_ops_api.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Spool plumbing for PeerTube admin ops (#798)."""
import json
from pathlib import Path
from api import main as m


def test_spool_op_writes_request(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "OPS_DIR", tmp_path)
    op_id = m._spool_op("reset-password", password="s3cr3t")
    assert len(op_id) >= 8 and all(c in "0123456789abcdef" for c in op_id)
    req = json.loads((tmp_path / f"{op_id}.request.json").read_text())
    assert req["op"] == "reset-password" and req["id"] == op_id and req["password"] == "s3cr3t"
    assert (tmp_path / f"{op_id}.request.json").stat().st_mode & 0o777 == 0o600


def test_read_op_result_pending_then_done(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "OPS_DIR", tmp_path)
    assert m._read_op_result("abc12345")["status"] == "pending"
    (tmp_path / "abc12345.result.json").write_text(json.dumps({"status": "done", "detail": "ok"}))
    r = m._read_op_result("abc12345")
    assert r["status"] == "done" and r["detail"] == "ok"


def test_read_op_result_rejects_bad_id(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "OPS_DIR", tmp_path)
    assert m._read_op_result("../etc/passwd")["status"] == "error"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-peertube && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/798-peertube-webui-admin-reset-password-vers/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_ops_api.py -v`
Expected: FAIL — `AttributeError: module 'api.main' has no attribute 'OPS_DIR'` / `_spool_op`.

- [ ] **Step 3: Add the plumbing to `api/main.py`**

Near the top of `api/main.py`, after the existing imports (it already imports `json`, `subprocess`, `os`, `Path`, `Depends`, `require_jwt`), add:

```python
import re
import secrets

OPS_DIR = Path("/run/secubox/peertube/ops")
_OP_ID_RE = re.compile(r"^[0-9a-f]{8,32}$")


async def require_admin(user=Depends(require_jwt)):
    """Gate destructive ops to admin-role JWTs. require_jwt already validated the
    token; here we additionally require role == admin (the module otherwise
    accepts any valid SecuBox JWT)."""
    role = (user or {}).get("role") if isinstance(user, dict) else None
    if role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return user


def _spool_op(op: str, **args) -> str:
    """Write an intent file the root peertube-ops.path unit will pick up. Returns
    the op id; the caller polls GET /admin/op/{id}. Unprivileged (no lxc-attach)."""
    op_id = secrets.token_hex(8)
    OPS_DIR.mkdir(parents=True, exist_ok=True)
    req = OPS_DIR / f"{op_id}.request.json"
    req.write_text(json.dumps({"op": op, "id": op_id, **args}))
    os.chmod(req, 0o600)
    return op_id


def _read_op_result(op_id: str) -> dict:
    """Read <id>.result.json; {status: pending} until the root unit writes it."""
    if not _OP_ID_RE.match(op_id or ""):
        return {"status": "error", "detail": "bad op id"}
    res = OPS_DIR / f"{op_id}.result.json"
    if not res.exists():
        return {"status": "pending"}
    try:
        return json.loads(res.read_text())
    except Exception as e:  # pragma: no cover
        return {"status": "error", "detail": f"unreadable result: {e}"}
```

Then add the route (near the other `@router` routes):

```python
@router.get("/admin/op/{op_id}")
async def get_op_result(op_id: str, user=Depends(require_jwt)):
    """Poll the result of a spooled admin op (reset-password / upgrade)."""
    return _read_op_result(op_id)
```

Ensure `HTTPException` is imported (it is used elsewhere in the file; if not, add `from fastapi import HTTPException`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-peertube && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/798-peertube-webui-admin-reset-password-vers/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_ops_api.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-peertube/api/main.py packages/secubox-peertube/tests/test_ops_api.py
git commit -m "feat(peertube): API ops spool plumbing + require_admin (ref #798)"
```

---

## Task 2: `peertubectl process-ops` dispatcher + root spool units + packaging

**Files:**
- Modify: `packages/secubox-peertube/sbin/peertubectl`
- Create: `packages/secubox-peertube/debian/peertube-ops.path`, `packages/secubox-peertube/debian/peertube-ops.service`
- Modify: `packages/secubox-peertube/debian/rules`, `packages/secubox-peertube/debian/postinst`

**Interfaces:**
- Consumes: existing `peertubectl` helpers (`log`/`err`/`lxc-attach` conventions), `OPS_DIR` contract from Task 1 (`/run/secubox/peertube/ops/<id>.request.json` → `<id>.result.json`).
- Produces: `peertubectl process-ops` (iterates request files, dispatches by `.op`, writes result, removes request); a `_write_result <id> <json>` helper + `OPS_DIR` var; the verbs `reset-admin-password`/`upgrade` are added in Tasks 3/5 (Task 2 provides a `ping` op so the mechanism is testable now).

- [ ] **Step 1: Write the failing test (dispatcher via a stub op)**

Create `packages/secubox-peertube/tests/test_process_ops.sh`:

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# process-ops dispatches a request file to a result file (#798).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
export SECUBOX_PEERTUBE_OPS_DIR="$tmp/ops"; mkdir -p "$SECUBOX_PEERTUBE_OPS_DIR"
printf '{"op":"ping","id":"deadbeef"}' > "$SECUBOX_PEERTUBE_OPS_DIR/deadbeef.request.json"
bash "$here/sbin/peertubectl" process-ops
[ -f "$SECUBOX_PEERTUBE_OPS_DIR/deadbeef.result.json" ] || { echo "no result written"; exit 1; }
grep -q '"status": *"done"' "$SECUBOX_PEERTUBE_OPS_DIR/deadbeef.result.json" || { echo "ping not done"; exit 1; }
[ -f "$SECUBOX_PEERTUBE_OPS_DIR/deadbeef.request.json" ] && { echo "request not removed"; exit 1; }
echo "PASS process-ops ping"
```
`chmod +x packages/secubox-peertube/tests/test_process_ops.sh`.

- [ ] **Step 2: Run to verify it fails**

Run: `bash packages/secubox-peertube/tests/test_process_ops.sh`
Expected: FAIL (unknown verb `process-ops` / no result written).

- [ ] **Step 3: Add `process-ops` + helpers to `peertubectl`**

In `sbin/peertubectl`, after the config vars block (after `PUBLIC_HOSTNAME=…`), add:

```bash
OPS_DIR="${SECUBOX_PEERTUBE_OPS_DIR:-/run/secubox/peertube/ops}"
ADMIN_SECRET="${SECUBOX_PEERTUBE_ADMIN_SECRET:-/etc/secubox/secrets/peertube-admin}"

# _write_result <id> <json-string> — atomic result file for the API to poll.
_write_result() {
    local id="$1" body="$2"
    printf '%s' "$body" > "$OPS_DIR/$id.result.json.tmp"
    chmod 0640 "$OPS_DIR/$id.result.json.tmp" 2>/dev/null || true
    mv -f "$OPS_DIR/$id.result.json.tmp" "$OPS_DIR/$id.result.json"
}

# _jq <file> <filter> — read a field from a request file (jq is available on the host).
_jq() { jq -r "$2" < "$1" 2>/dev/null; }
```

Add the dispatcher verb (before `cmd_help`):

```bash
cmd_process_ops() {
    # Root-only: the peertube-ops.path unit runs this when a request appears.
    [ -d "$OPS_DIR" ] || return 0
    local f id op
    for f in "$OPS_DIR"/*.request.json; do
        [ -e "$f" ] || continue
        id="$(basename "$f" .request.json)"
        op="$(_jq "$f" '.op')"
        case "$op" in
            ping)                 _write_result "$id" '{"status":"done","detail":"pong"}' ;;
            reset-admin-password) cmd_reset_admin_password "$f" "$id" ;;
            upgrade)              cmd_upgrade "$f" "$id" ;;
            *)                    _write_result "$id" "{\"status\":\"error\",\"detail\":\"unknown op: $op\"}" ;;
        esac
        rm -f "$f"
    done
}
```

Wire into `main()` dispatch — change the `case` to include `process-ops`:

```bash
        install|status|start|stop|restart|logs|reload) "cmd_${noun}" "$@" ;;
        set-youtube-cookies) cmd_set_youtube_cookies "$@" ;;
        process-ops) cmd_process_ops "$@" ;;
        reset-admin-password) cmd_reset_admin_password "$@" ;;
        upgrade) cmd_upgrade "$@" ;;
```

(Note: `cmd_reset_admin_password` and `cmd_upgrade` are added in Tasks 3 and 5. To keep Task 2's `peertubectl` valid, add temporary stubs now that Tasks 3/5 replace:)

```bash
cmd_reset_admin_password() { local id="${2:-}"; [ -n "$id" ] && _write_result "$id" '{"status":"error","detail":"reset not implemented yet"}'; }
cmd_upgrade()              { local id="${2:-}"; [ -n "$id" ] && _write_result "$id" '{"status":"error","detail":"upgrade not implemented yet"}'; }
```

Add to `cmd_help` usage: `  process-ops                   (root) drain the /run ops spool` .

- [ ] **Step 4: Run test to verify it passes + shellcheck**

Run: `bash packages/secubox-peertube/tests/test_process_ops.sh && shellcheck packages/secubox-peertube/sbin/peertubectl`
Expected: `PASS process-ops ping`; shellcheck clean (or only pre-existing warnings).

- [ ] **Step 5: Create the root spool units**

`packages/secubox-peertube/debian/peertube-ops.path`:

```ini
[Unit]
Description=Watch for spooled PeerTube admin ops (reset-password / upgrade)
Documentation=https://github.com/CyberMind-FR/secubox-deb/issues/798

[Path]
# The unprivileged dashboard drops <id>.request.json here; this root service
# runs peertubectl process-ops to execute them inside the LXC — no sudo, so the
# dashboard keeps NoNewPrivileges (CSPN privilege separation, mirrors #407).
DirectoryNotEmpty=/run/secubox/peertube/ops
Unit=peertube-ops.service

[Install]
WantedBy=paths.target
```

`packages/secubox-peertube/debian/peertube-ops.service`:

```ini
[Unit]
Description=Drain the PeerTube admin-ops spool (root, #798)
Documentation=https://github.com/CyberMind-FR/secubox-deb/issues/798

[Service]
Type=oneshot
# Root (no User=) so peertubectl can lxc-attach into the container. Upgrade can
# take several minutes (download + npm install + DB migration).
TimeoutStartSec=1800
ExecStart=/usr/sbin/peertubectl process-ops
```

Both files start with `# SPDX-License-Identifier: LicenseRef-CMSD-1.0` as the first line? systemd ignores `#` comments — add it as the first line of each.

- [ ] **Step 6: Install units in `debian/rules` + create dirs in `postinst`**

In `debian/rules`, after the cookie-install unit installs (lines ~39-40), add:

```make
	install -m 644 debian/peertube-ops.path debian/secubox-peertube/usr/lib/systemd/system/
	install -m 644 debian/peertube-ops.service debian/secubox-peertube/usr/lib/systemd/system/
```

In `debian/postinst`, in the `configure` case (alongside existing dir creation), add:

```bash
    install -d -o secubox -g secubox -m 0750 /run/secubox/peertube/ops 2>/dev/null || true
    install -d -o peertube -g peertube -m 0750 /var/lib/secubox/peertube/backups 2>/dev/null || true
    deb-systemd-helper enable peertube-ops.path >/dev/null 2>&1 || true
    deb-systemd-invoke start peertube-ops.path >/dev/null 2>&1 || true
```
(`/run` is tmpfs — also add a `tmpfiles.d` line so the dir survives reboot: create `packages/secubox-peertube/debian/secubox-peertube.tmpfiles` with `d /run/secubox/peertube/ops 0750 secubox secubox -` and install it via `dh_installtmpfiles`/`install -m644 … /usr/lib/tmpfiles.d/secubox-peertube.conf` in rules.)

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-peertube/sbin/peertubectl packages/secubox-peertube/debian/peertube-ops.path packages/secubox-peertube/debian/peertube-ops.service packages/secubox-peertube/debian/rules packages/secubox-peertube/debian/postinst packages/secubox-peertube/debian/secubox-peertube.tmpfiles packages/secubox-peertube/tests/test_process_ops.sh
git commit -m "feat(peertube): spool→root ops mechanism (process-ops + path/service) (ref #798)"
```

---

## Task 3: Reset admin password (verb + API + WebUI)

**Files:**
- Modify: `packages/secubox-peertube/sbin/peertubectl` (replace the `cmd_reset_admin_password` stub)
- Modify: `packages/secubox-peertube/api/main.py` (endpoint)
- Modify: `packages/secubox-peertube/www/peertube/index.html` (button)
- Test: `packages/secubox-peertube/tests/test_ops_api.py` (extend)

**Interfaces:**
- Consumes: `_spool_op`, `require_admin`, `OPS_DIR`, `_write_result`, `_jq`, `ADMIN_SECRET` (from Tasks 1-2).
- Produces: `POST /admin/reset-password` (body `{"password"?: str}` → `{"id"}`); `peertubectl reset-admin-password <request-file> <id>`.

- [ ] **Step 1: Write the failing API test**

Append to `tests/test_ops_api.py`:

```python
def test_reset_password_spools_op(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "OPS_DIR", tmp_path)
    import asyncio
    out = asyncio.run(m.reset_password_op(m.ResetPasswordBody(password="hunter2"), user={"role": "admin"}))
    assert out["success"] is True and "id" in out
    import json
    req = json.loads((tmp_path / f"{out['id']}.request.json").read_text())
    assert req["op"] == "reset-password" and req["password"] == "hunter2"


def test_reset_password_generates_when_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "OPS_DIR", tmp_path)
    import asyncio, json
    out = asyncio.run(m.reset_password_op(m.ResetPasswordBody(password=None), user={"role": "admin"}))
    req = json.loads((tmp_path / f"{out['id']}.request.json").read_text())
    assert len(req["password"]) >= 16  # generated strong password
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-peertube && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/798-peertube-webui-admin-reset-password-vers/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_ops_api.py -k reset -v`
Expected: FAIL — `AttributeError: … 'reset_password_op'` / `ResetPasswordBody`.

- [ ] **Step 3: Add the API endpoint**

In `api/main.py` (Pydantic models section), add:

```python
class ResetPasswordBody(BaseModel):
    password: Optional[str] = None
```

Add the route:

```python
@router.post("/admin/reset-password")
async def reset_password_op(body: ResetPasswordBody, user=Depends(require_admin)):
    """Reset the PeerTube admin (root) password. Lockout-safe: runs the PeerTube
    CLI in the LXC via the root spool, then rewrites the admin secret. If no
    password is given, a strong one is generated and returned in the op result."""
    pw = body.password or secrets.token_urlsafe(18)
    op_id = _spool_op("reset-password", password=pw)
    return {"success": True, "id": op_id}
```

- [ ] **Step 4: Replace the `cmd_reset_admin_password` stub in `peertubectl`**

```bash
cmd_reset_admin_password() {
    # args: <request-file> <id>  (called by process-ops)
    local reqf="${1:-}" id="${2:-}"
    [ -n "$reqf" ] && [ -n "$id" ] || { err "usage: reset-admin-password <request-file> <id>"; return 1; }
    local pw; pw="$(_jq "$reqf" '.password')"
    [ -n "$pw" ] || { _write_result "$id" '{"status":"error","detail":"no password in request"}'; return; }
    lxc_running || { _write_result "$id" '{"status":"error","detail":"LXC not running"}'; return; }
    # PeerTube reset-password CLI is interactive (prompts once for the new
    # password). Feed it on stdin as the peertube user with the service's env.
    if printf '%s\n' "$pw" | lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- \
        sudo -u peertube env NODE_ENV=production NODE_CONFIG_DIR=/var/www/peertube/config \
        bash -lc 'cd /var/www/peertube/peertube-latest && npm run reset-password -- -u root' >/dev/null 2>&1
    then
        # Keep the dashboard's stored admin secret in sync (get_admin_token()).
        printf '%s' "$pw" > "$ADMIN_SECRET" && chmod 0600 "$ADMIN_SECRET"
        chown secubox-peertube:secubox-peertube "$ADMIN_SECRET" 2>/dev/null || true
        _write_result "$id" "{\"status\":\"done\",\"detail\":\"password reset\",\"password\":$(printf '%s' "$pw" | jq -Rs .)}"
    else
        _write_result "$id" '{"status":"error","detail":"peertube reset-password CLI failed"}'
    fi
}
```

- [ ] **Step 5: Add the WebUI button (Users tab)**

In `www/peertube/index.html`, in the Users tab (near the per-user actions / `createUser` area ~line 461), add a maintenance-style reset control (admin action), plus a JS handler + polling helper. Add near the other JS functions:

```javascript
async function pollOp(id, onDone) {
    for (let i = 0; i < 60; i++) {
        const r = await api('/admin/op/' + id);
        if (r.status && r.status !== 'pending' && r.status !== 'running') { onDone(r); return; }
        await new Promise(res => setTimeout(res, 2000));
    }
    onDone({ status: 'error', detail: 'timed out waiting for op' });
}

async function resetAdminPassword() {
    const pw = prompt('New admin password (leave empty to generate a strong one):', '');
    if (pw === null) return;
    const r = await api('/admin/reset-password', { method: 'POST', body: JSON.stringify({ password: pw || null }) });
    if (!r || !r.id) { toast('Reset failed: ' + ((r && r.error) || 'no id'), 'error'); return; }
    toast('Resetting admin password…');
    pollOp(r.id, (res) => {
        if (res.status === 'done') toast('Password reset. ' + (res.password ? 'New password: ' + res.password : ''), 'success');
        else toast('Reset failed: ' + (res.detail || 'unknown'), 'error');
    });
}
```

And a button in the Users tab header:
```html
<button class="btn btn-danger" onclick="resetAdminPassword()">🔑 Reset admin password</button>
```

- [ ] **Step 6: Run tests + shellcheck**

Run: `cd packages/secubox-peertube && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/798-peertube-webui-admin-reset-password-vers/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_ops_api.py -q && shellcheck packages/secubox-peertube/sbin/peertubectl`
Expected: PASS; shellcheck clean.

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-peertube/sbin/peertubectl packages/secubox-peertube/api/main.py packages/secubox-peertube/www/peertube/index.html packages/secubox-peertube/tests/test_ops_api.py
git commit -m "feat(peertube): reset admin password button (lockout-safe, spool→root) (ref #798)"
```

---

## Task 4: Version check (`GET /version` + WebUI badge)

**Files:**
- Modify: `packages/secubox-peertube/api/main.py`
- Modify: `packages/secubox-peertube/www/peertube/index.html`
- Test: `packages/secubox-peertube/tests/test_version.py`

**Interfaces:**
- Consumes: `pt_api`, `require_jwt`.
- Produces: `_semver_lt(a, b) -> bool`; `GET /version` → `{"installed", "latest", "upgrade_available"}`.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-peertube/tests/test_version.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""PeerTube version check (#798)."""
from api import main as m


def test_semver_lt():
    assert m._semver_lt("8.2.0", "8.2.1") is True
    assert m._semver_lt("8.2.0", "8.10.0") is True   # numeric, not lexical
    assert m._semver_lt("8.2.0", "8.2.0") is False
    assert m._semver_lt("9.0.0", "8.9.9") is False


def test_version_upgrade_available(monkeypatch):
    import asyncio
    monkeypatch.setattr(m, "_installed_version", lambda: "8.2.0")
    monkeypatch.setattr(m, "_latest_version", lambda: "8.3.0")
    out = asyncio.run(m.version_info(user={"role": "user"}))
    assert out == {"installed": "8.2.0", "latest": "8.3.0", "upgrade_available": True}


def test_version_up_to_date(monkeypatch):
    import asyncio
    monkeypatch.setattr(m, "_installed_version", lambda: "8.3.0")
    monkeypatch.setattr(m, "_latest_version", lambda: "8.3.0")
    out = asyncio.run(m.version_info(user={"role": "user"}))
    assert out["upgrade_available"] is False


def test_version_offline_latest_none(monkeypatch):
    import asyncio
    monkeypatch.setattr(m, "_installed_version", lambda: "8.2.0")
    monkeypatch.setattr(m, "_latest_version", lambda: None)
    out = asyncio.run(m.version_info(user={"role": "user"}))
    assert out["latest"] is None and out["upgrade_available"] is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-peertube && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/798-peertube-webui-admin-reset-password-vers/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_version.py -v`
Expected: FAIL — `_semver_lt` / `version_info` undefined.

- [ ] **Step 3: Implement in `api/main.py`**

```python
def _semver_lt(a: str, b: str) -> bool:
    """True if version a < b (numeric field compare; tolerates a leading 'v')."""
    def parts(v):
        v = (v or "").lstrip("vV").split("-")[0]
        return [int(x) for x in re.findall(r"\d+", v)] or [0]
    pa, pb = parts(a), parts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa)); pb += [0] * (n - len(pb))
    return pa < pb


def _installed_version() -> Optional[str]:
    r = pt_api("/config")
    if r.get("success") and isinstance(r.get("data"), dict):
        return r["data"].get("serverVersion")
    return None


def _latest_version() -> Optional[str]:
    """Latest PeerTube release tag from GitHub, cached ~1h in /run. Best-effort:
    returns None offline / on rate-limit (never blocks the dashboard)."""
    cache = OPS_DIR.parent / "latest-version.json"
    try:
        if cache.exists() and (time.time() - cache.stat().st_mtime) < 3600:
            return json.loads(cache.read_text()).get("latest")
    except Exception:
        pass
    try:
        out = subprocess.run(
            ["curl", "-s", "--max-time", "8",
             "https://api.github.com/repos/Chocobozzz/PeerTube/releases/latest"],
            capture_output=True, text=True, timeout=12)
        tag = json.loads(out.stdout).get("tag_name")
        if tag:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps({"latest": tag}))
        return tag
    except Exception:
        return None


@router.get("/version")
async def version_info(user=Depends(require_jwt)):
    installed = _installed_version()
    latest = _latest_version()
    up = bool(installed and latest and _semver_lt(installed, latest))
    return {"installed": installed, "latest": latest, "upgrade_available": up}
```

Ensure `time` is imported at the top of the file (add `import time` if absent).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-peertube && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/798-peertube-webui-admin-reset-password-vers/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_version.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Add the WebUI version badge (Maintenance card)**

In `www/peertube/index.html`, in the Maintenance card (near `restartPeerTube`, ~line 623), add a version line + loader:

```html
<div id="ptVersion" style="margin:0.5rem 0;color:var(--text-muted);">version…</div>
<button class="btn" id="btnUpgrade" style="display:none;" onclick="upgradePeerTube()">⬆️ Upgrade</button>
```
```javascript
async function loadVersion() {
    const v = await api('/version');
    const el = document.getElementById('ptVersion');
    if (!v || !v.installed) { el.textContent = 'version: unknown'; return; }
    if (v.upgrade_available) {
        el.innerHTML = 'PeerTube <b>v' + v.installed + '</b> · ⬆️ <b>' + v.latest + '</b> available';
        const b = document.getElementById('btnUpgrade'); b.style.display = ''; b.textContent = '⬆️ Upgrade to ' + v.latest;
    } else {
        el.innerHTML = 'PeerTube <b>v' + v.installed + '</b> · ✅ up to date';
    }
}
```
Call `loadVersion()` from the page's existing init/`refresh()` function.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-peertube/api/main.py packages/secubox-peertube/www/peertube/index.html packages/secubox-peertube/tests/test_version.py
git commit -m "feat(peertube): version check (installed vs latest GitHub release) (ref #798)"
```

---

## Task 5: Upgrade (verb + API + WebUI)

**Files:**
- Modify: `packages/secubox-peertube/sbin/peertubectl` (replace `cmd_upgrade` stub)
- Modify: `packages/secubox-peertube/api/main.py` (endpoint)
- Modify: `packages/secubox-peertube/www/peertube/index.html` (button handler)
- Test: `packages/secubox-peertube/tests/test_ops_api.py` (extend)

**Interfaces:**
- Consumes: `_spool_op`, `require_admin`, `_write_result`, `_jq`, LXC helpers.
- Produces: `POST /upgrade` (body `{"target"?: str}` → `{"id"}`); `peertubectl upgrade <request-file> <id>`.

- [ ] **Step 1: Write the failing API test**

Append to `tests/test_ops_api.py`:

```python
def test_upgrade_spools_op(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "OPS_DIR", tmp_path)
    import asyncio, json
    out = asyncio.run(m.upgrade_op(m.UpgradeBody(target="latest"), user={"role": "admin"}))
    assert out["success"] and "id" in out
    req = json.loads((tmp_path / f"{out['id']}.request.json").read_text())
    assert req["op"] == "upgrade" and req["target"] == "latest"


def test_upgrade_requires_admin(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "OPS_DIR", tmp_path)
    import asyncio
    from fastapi import HTTPException
    try:
        asyncio.run(m.require_admin(user={"role": "user"}))
        assert False, "require_admin should reject non-admin"
    except HTTPException as e:
        assert e.status_code == 403
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-peertube && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/798-peertube-webui-admin-reset-password-vers/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_ops_api.py -k upgrade -v`
Expected: FAIL — `upgrade_op` / `UpgradeBody` undefined.

- [ ] **Step 3: Add the API endpoint**

```python
class UpgradeBody(BaseModel):
    target: Optional[str] = "latest"


@router.post("/upgrade")
async def upgrade_op(body: UpgradeBody, user=Depends(require_admin)):
    """Upgrade PeerTube in the LXC (backup → download → migrate → restart) via the
    root spool. Poll GET /admin/op/{id}; the op reports running/done/error."""
    op_id = _spool_op("upgrade", target=body.target or "latest")
    return {"success": True, "id": op_id}
```

- [ ] **Step 4: Replace the `cmd_upgrade` stub in `peertubectl`**

```bash
cmd_upgrade() {
    # args: <request-file> <id>  (called by process-ops)
    local reqf="${1:-}" id="${2:-}"
    [ -n "$id" ] || { err "usage: upgrade <request-file> <id>"; return 1; }
    lxc_running || { _write_result "$id" '{"status":"error","detail":"LXC not running"}'; return; }
    _write_result "$id" '{"status":"running","detail":"backup + download"}'
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    local backup="/var/lib/secubox/peertube/backups/pre-upgrade-$ts.sql.gz"

    # 1. Mandatory DB backup (abort on failure).
    if ! lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- bash -lc \
        "sudo -u postgres pg_dump peertube_prod | gzip > '$backup'" 2>/dev/null; then
        _write_result "$id" "{\"status\":\"error\",\"detail\":\"DB backup failed — upgrade aborted\"}"
        return
    fi

    # 2-5. Run PeerTube's official upgrade inside the LXC. PeerTube ships an
    #      upgrade script that downloads the latest release, installs deps, and
    #      runs migrations; the service is restarted after. It keeps the previous
    #      versions/ dir, so a failed run leaves peertube-latest on the old build.
    if lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- \
        sudo -u peertube env NODE_ENV=production NODE_CONFIG_DIR=/var/www/peertube/config \
        bash -lc 'cd /var/www/peertube && ./peertube-latest/scripts/upgrade.sh' >/dev/null 2>&1
    then
        # 6. Health-check: PeerTube answers /api/v1/config once back up.
        svc restart
        local ok=0 i
        for i in $(seq 1 30); do
            if lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- \
                curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HTTP_PORT}/api/v1/config" 2>/dev/null | grep -q 200
            then ok=1; break; fi
            sleep 2
        done
        if [ "$ok" = 1 ]; then
            _write_result "$id" "{\"status\":\"done\",\"detail\":\"upgraded\",\"backup\":$(printf '%s' "$backup" | jq -Rs .)}"
        else
            _write_result "$id" "{\"status\":\"error\",\"detail\":\"upgraded but health-check failed — restore from backup if needed\",\"backup\":$(printf '%s' "$backup" | jq -Rs .)}"
        fi
    else
        # Upgrade script failed — the old peertube-latest is untouched; restart it.
        svc restart
        _write_result "$id" "{\"status\":\"error\",\"detail\":\"upgrade script failed — running version unchanged\",\"backup\":$(printf '%s' "$backup" | jq -Rs .)}"
    fi
}
```

> Note for the implementer: verify the exact PeerTube v8.2.0 upgrade entrypoint at live-test time (`./peertube-latest/scripts/upgrade.sh` is the documented path; some releases use `npm run upgrade-peertube`). If the path differs, adjust this single command — the surrounding backup/health/rollback logic is unchanged. Live-testing the upgrade requires accepting PeerTube downtime + a verified backup.

- [ ] **Step 5: Wire the WebUI upgrade handler**

In `www/peertube/index.html`, add (reusing `pollOp` from Task 3):

```javascript
async function upgradePeerTube() {
    if (!confirm('Upgrade PeerTube now?\n\nThis stops PeerTube, backs up the DB, downloads the new release and runs migrations (several minutes of downtime). A pre-upgrade DB backup is taken automatically.')) return;
    const r = await api('/upgrade', { method: 'POST', body: JSON.stringify({ target: 'latest' }) });
    if (!r || !r.id) { toast('Upgrade failed to start: ' + ((r && r.error) || 'no id'), 'error'); return; }
    toast('Upgrade started — this takes several minutes…');
    document.getElementById('btnUpgrade').disabled = true;
    pollOp(r.id, (res) => {
        document.getElementById('btnUpgrade').disabled = false;
        if (res.status === 'done') { toast('Upgrade complete. Backup: ' + (res.backup || ''), 'success'); loadVersion(); }
        else toast('Upgrade failed: ' + (res.detail || 'unknown') + (res.backup ? ' (backup: ' + res.backup + ')' : ''), 'error');
    });
}
```
(`pollOp` in Task 3 caps at 60×2s = 2 min; for the upgrade, raise its cap or make `upgradePeerTube` poll with its own longer loop — use a 300-iteration/2s loop here so a multi-minute upgrade isn't cut off.)

- [ ] **Step 6: Run tests + shellcheck**

Run: `cd packages/secubox-peertube && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/798-peertube-webui-admin-reset-password-vers/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/ -q && shellcheck packages/secubox-peertube/sbin/peertubectl && bash packages/secubox-peertube/tests/test_process_ops.sh`
Expected: all PASS; shellcheck clean.

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-peertube/sbin/peertubectl packages/secubox-peertube/api/main.py packages/secubox-peertube/www/peertube/index.html packages/secubox-peertube/tests/test_ops_api.py
git commit -m "feat(peertube): one-click upgrade with pre-backup + rollback (spool→root) (ref #798)"
```

---

## Final verification

- [ ] **All tests + lint:**

```bash
cd packages/secubox-peertube && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/798-peertube-webui-admin-reset-password-vers/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/ -q
shellcheck packages/secubox-peertube/sbin/peertubectl
bash packages/secubox-peertube/tests/test_process_ops.sh
```
Expected: all green.

- [ ] **Deploy note (not a code step):** rebuild + install `secubox-peertube.deb` on gk2 (peertubectl → /usr/sbin, units → /usr/lib/systemd/system, `systemctl daemon-reload`, enable `peertube-ops.path`). Live-validate in order: reset-password (verify login + that the CLI took one stdin line — if it re-prompts for confirmation, feed the password twice in `cmd_reset_admin_password`), version badge, then upgrade **only when downtime is acceptable** (confirm the `upgrade.sh` entrypoint first, and that a backup lands in `/var/lib/secubox/peertube/backups/`).

---

## Self-Review

**Spec coverage:** spool→root mechanism (Task 2) ✅; reset-password lockout-safe + secret rewrite (Task 3) ✅; version check semver + GitHub + cache (Task 4) ✅; upgrade backup/migrate/restart/rollback (Task 5) ✅; `require_admin` gate (Task 1, applied Tasks 3/5) ✅; unprivileged API / NoNewPrivileges preserved (spool only, Tasks 1-2) ✅; packaging units+postinst+tmpfiles (Task 2) ✅; tests peertubectl+API+semver ✅.

**Placeholder scan:** none — every step has concrete code/commands. The upgrade entrypoint carries an explicit live-verify note (not a placeholder — a documented single-command adjustment point).

**Type consistency:** `OPS_DIR`, `_spool_op`, `_read_op_result`, `require_admin` defined in Task 1 and reused verbatim in 3/4/5; `_write_result`/`_jq`/`OPS_DIR`/`ADMIN_SECRET` defined in Task 2 and reused in 3/5; result JSON contract `{status, detail, [password|backup]}` consistent between `peertubectl` writers and `_read_op_result`/WebUI readers; `ResetPasswordBody`/`UpgradeBody`/`version_info`/`reset_password_op`/`upgrade_op` names match between tests and endpoints.
