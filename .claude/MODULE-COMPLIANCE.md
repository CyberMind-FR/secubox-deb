# MODULE-COMPLIANCE.md — SecuBox-DEB Module Compliance Requirements

*Formal design rules for all SecuBox-DEB modules*

---

## Overview

Every SecuBox-DEB module MUST comply with the following requirements before being marked as complete. These rules ensure consistent quality, testability, and documentation across all packages.

---

## Compliance Checklist

### 1. README.md (Required)

Each module MUST have a `packages/secubox-<module>/README.md` containing:

- [ ] Module name and description
- [ ] Feature list
- [ ] API endpoint documentation (all routes)
- [ ] Configuration file location and format
- [ ] Dependencies (Debian packages, Python modules)
- [ ] Port/socket information
- [ ] Installation instructions
- [ ] Usage examples

**Template location**: `.claude/TEMPLATES/README-template.md`

### 2. Wiki Documentation (Required)

Each module MUST have wiki documentation in:

- [ ] `wiki/MODULES-EN.md` — English module entry
- [ ] `wiki/MODULES-FR.md` — French module entry

Wiki entry MUST include:
- Screenshot (if applicable)
- Brief description
- Key features (bullet points)
- Related modules

### 3. VirtualBox Testing (Required)

Each module MUST be tested in VirtualBox before release:

- [ ] Service starts successfully (`systemctl status secubox-<module>`)
- [ ] API health endpoint responds (`/api/v1/<module>/health`)
- [ ] Web UI loads correctly (if applicable)
- [ ] Sidebar navigation works
- [ ] No critical errors in logs (`journalctl -u secubox-<module>`)

**Test VM**: SecuBox-Test (VirtualBox)
**Access**: SSH port 2223, HTTPS port 8444

### 4. VirtualBox Snapshots (Required)

After successful testing, create a VirtualBox snapshot:

```bash
VBoxManage snapshot "SecuBox-Test" take "<Phase>-<Module>-$(date +%Y%m%d)" \
  --description "SecuBox-DEB <Module> test - <summary>"
```

Snapshot naming convention:
- `Phase9-Complete-20260408` — Phase completion
- `Module-<name>-<date>` — Individual module test

---

## Module Structure Requirements

### Directory Structure

```
packages/secubox-<module>/
├── api/
│   ├── __init__.py
│   └── main.py              # FastAPI app
├── www/
│   └── <module>/
│       └── index.html       # Web UI with sidebar
├── debian/
│   ├── control              # Package metadata
│   ├── rules                # Build rules
│   ├── postinst             # Post-install script
│   ├── prerm                # Pre-remove script
│   └── secubox-<module>.service  # systemd unit
├── menu.d/
│   └── <order>-<module>.json    # Sidebar menu entry
└── README.md                # Module documentation
```

### Lifecycle Policy — scale-to-zero (ref #896)

Every module known to `secubox-profiles` (its manifest under
`/etc/secubox/modules.d/<id>.toml`) declares a `lifecycle`: `always-on`
(never stopped — forced for any `protected` module regardless of what it
declares), `eager` (starts at boot, may be idled), `on-demand` (off by
default, woken on first access), or `manual` (operator-only, via the
`/profiles/` panel). An optional `wake_class` (`normal`/`urgent`) tunes the
idle threshold and the wake-splash budget. This is a **module-wide**
guideline, not a `secubox-profiles`-internal detail: a module choosing
`on-demand`/`eager` is opting into being stopped by `secubox-sleeper.service`
and woken via `secubox-waker.service` (fronted by `sbxwaf`, which proxies a
request for a routeless on-demand vhost to the waker instead of returning
421). See `packages/secubox-profiles/README.md` (§ Scale-to-zero) and
`wiki/Architecture.md` (§ Scale-to-zero) for the full policy table, the
wake/sleep mechanism, and the pilot procedure for switching a module to
`on-demand`.

### Web UI Requirements (Pattern 12)

All module frontends MUST include:

```html
<head>
    <link rel="stylesheet" href="/shared/crt-light.css">
    <link rel="stylesheet" href="/shared/sidebar-light.css">
</head>
<body class="crt-light">
    <nav class="sidebar" id="sidebar"></nav>
    <main class="main-content">
        <!-- Module content -->
    </main>
    <script src="/shared/sidebar.js"></script>
</body>
```

### Menu Integration

Module MUST provide `menu.d/<order>-<module>.json`:

```json
{
  "id": "module-name",
  "name": "Display Name",
  "icon": "🔧",
  "path": "/module/",
  "category": "apps",
  "order": 800,
  "description": "Short description"
}
```

---

## API Requirements

### Mandatory Endpoints

Every module API MUST implement:

- `GET /health` — Returns `{"status": "ok", "module": "<name>"}`
- `GET /status` — Returns module-specific status

### Authentication

All endpoints (except /health) MUST use JWT authentication:

```python
from secubox_core.auth import require_jwt

@router.get("/status")
async def status(user=Depends(require_jwt)):
    ...
```

### Socket Path

API MUST listen on Unix socket: `/run/secubox/<module>.sock`

---

## Privileged Operations — webui delegates to a confined, audited `ctl` (Required)

**Principle.** The webui/API runs **unprivileged** — `User=secubox`, and when
aggregator-served it shares the aggregator's `secubox` context. It therefore
**cannot** read/write root-owned config (e.g. `/etc/secubox/waf` is `0750
root:root`), and **must not** drive systemd / LXC / applications in-process.

Every operation that (a) touches root-owned files, or (b) pilots the system or
another app (start/stop/reload a unit, edit a live config, run a privileged
CLI) **MUST be delegated to the module's root helper** `secubox-<module>ctl`.
The webui becomes a thin JWT client; the **`ctl` is the single privileged
surface** — confined (scoped sudoers), auditable (it logs each action to
`/var/log/secubox/audit.log` for security-relevant changes), and it is what
actually causes the system/apps to change. Doing the privileged work in-process
raises `PermissionError` → HTTP 500 ("request error" / empty panel) and
bypasses the audit trail.

**Sudoers grant (ship it — a missing grant is a compliance failure).**
Ship `sudoers.d/secubox-<module>` and install it `0440` to
`/etc/sudoers.d/secubox-<module>` from `debian/rules`. Every grant is an
**exact-command** match — no wildcards, no shell, no flag escapes — and each is
**documented** (which route uses it, why root):

```
# secubox ALL=(root) NOPASSWD: <absolute-path> <exact args...>
secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-cvectl waf-rules generate --json
secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-cvectl waf-rules generate --apply --json
```

Validate with `visudo -c -f sudoers.d/secubox-<module>` in CI/before deploy.

**Panel side.** Call the helper over `sudo -n` from a **plain `def`** handler
(so the blocking subprocess runs in FastAPI's threadpool, off the shared
aggregator loop), and map the `ctl` exit code to an HTTP status:

```python
def _run_ctl(*args):
    import subprocess
    return subprocess.run(["sudo", "-n", "/usr/sbin/secubox-<module>ctl", *args],
                          capture_output=True, text=True, timeout=120)

@app.post("/<action>", dependencies=[Depends(require_jwt)])
def do_action():
    import json
    p = _run_ctl("<verb>", "--apply", "--json")
    if p.returncode == 3:            # module-defined fail-safe refusal
        raise HTTPException(status_code=409, detail="…")
    if p.returncode != 0:
        raise HTTPException(status_code=500, detail=(p.stderr or p.stdout).strip()[:500])
    return json.loads(p.stdout)      # ctl emits a --json payload the panel renders
```

**The `ctl` contract.** Runs as root; validates its own inputs; performs the
privileged action; supports a **dry-run default** and an explicit `--apply` for
any state change; offers a machine-readable `--json` output for the panel;
appends an audit line for each security-relevant decision. Reference
implementations: `secubox-cvectl` (WAF rule generation), `secubox-profilectl`
(module on/off actuation).

**Aggregator note.** An aggregator-served module's route code is imported at
aggregator startup — after deploying new/changed routes you MUST
`systemctl restart secubox-aggregator` for them to appear (a stale aggregator
returns 404 on new routes). Modules on their own socket restart independently.

**System-driving ops from a `ProtectSystem=strict` service → `systemd-run`, not
plain `sudo`.** A `sudo` child INHERITS the caller service's mount namespace: if
the service runs `ProtectSystem=strict` with a reduced `ReadWritePaths`, the root
`ctl` sees every path outside `ReadWritePaths` as READ-ONLY (`EROFS`) and cannot
drive systemd/LXC — even as root. When the `ctl` writes state (snapshots, audit,
config) or actuates the system, wrap it in `systemd-run` so it runs in PID 1's
context, OUTSIDE the sandbox:

```python
argv = ["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe", "--collect",
        "--quiet", "/usr/sbin/secubox-<module>ctl", verb, "--apply", "--json"]
```

`--wait` = synchronous, `--pipe` = the `ctl`'s `--json` stdout comes back to the
route, `--collect --quiet` = auto-cleanup, no `systemd-run` noise. The sudoers
grant matches this FULL fixed argv (exact-command). Only needed for a hardened
service; a lightly-sandboxed one (e.g. the aggregator) can `sudo` the `ctl`
directly. Reference: `secubox-profiles` (0.6.1) — plain `sudo profilectl apply`
EROFS'd on its 4R snapshot dir; `systemd-run` fixed it.

---

## Debian Package Requirements

### debian/control

```
Source: secubox-<module>
Section: net
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://cybermind.fr/secubox
Rules-Requires-Root: no

Package: secubox-<module>
Architecture: all
Depends: ${misc:Depends}, secubox-core (>= 1.0), <dependencies>
Description: SecuBox <Module> — <short description>
 <Long description spanning multiple lines.>
 .
 Port Debian bookworm de luci-app-<module> (SecuBox OpenWrt / CyberMind.fr).
```

### debian/postinst

```bash
#!/bin/bash
set -e
case "$1" in
  configure)
    systemctl daemon-reload
    systemctl enable secubox-<module>.service
    systemctl start  secubox-<module>.service || true
    systemctl reload nginx 2>/dev/null || true
    ;;
esac
#DEBHELPER#
```

---

## Compliance Verification

### Automated Checks

```bash
# Check README exists
test -f packages/secubox-<module>/README.md

# Check API health
curl -sk https://localhost:8444/api/v1/<module>/health

# Check web UI
curl -sk https://localhost:8444/<module>/ | grep -q 'sidebar'

# Check service status
systemctl is-active secubox-<module>
```

### Manual Verification

1. Browse to `https://<vm-ip>/<module>/`
2. Verify sidebar loads with all menu entries
3. Test primary module functionality
4. Check browser console for JS errors

---

## Phase Completion Criteria

A phase is considered complete when:

1. All modules in the phase have README.md
2. All modules are documented in wiki (EN + FR)
3. All modules tested in VirtualBox
4. VirtualBox snapshot created for the phase
5. `.claude/TODO.md` updated with completion status

---

## Current Compliance Status

| Phase | Modules | READMEs | Wiki | VBox Test | Snapshot |
|-------|---------|---------|------|-----------|----------|
| Phase 1 | 6 | ✅ | ✅ | ✅ | ✅ |
| Phase 2 | 5 | ✅ | ✅ | ✅ | ✅ |
| Phase 3 | 33 | ✅ | ✅ | ✅ | ✅ |
| Phase 4 | 5 | ✅ | ✅ | ✅ | ✅ |
| Phase 5 | 7 | ✅ | ✅ | ✅ | ✅ |
| Phase 6 | 3 | ✅ | ✅ | ✅ | ✅ |
| Phase 7 | — | ✅ | ✅ | ✅ | ✅ |
| Phase 8 | 21 | ✅ | ⬜ | ✅ | ✅ |
| Phase 9 | 22 | ✅ | ⬜ | ✅ | ✅ |
| Phase 10 | 10 | ✅ | ⬜ | ✅ | ✅ |

---

*Last updated: 2026-04-08*
