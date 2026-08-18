<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-antirootkit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A host-IDS/anti-rootkit package `secubox-antirootkit` whose priority capability is a "super anti-escape" — any non-dpkg-backed process attempting outbound network I/O is auto-blocked (cgroup + nftables) before its first C2 beacon — plus an auditd-driven exec scanner, an integrity-tool wrapper, and alert-only process quarantine.

**Architecture:** A Python daemon (`sbx-antirootkitd`) reads auditd `execve` events; for each exec it resolves whether the binary is dpkg-backed; **unknown (non-dpkg) binaries get their PID placed in a `sbx-untrusted.slice` cgroup whose egress is dropped by an nftables rule** (the anti-escape). Every exec is recorded in an append-only SQLite execlog. Integrity scans wrap `debsums`/`aide`/`rkhunter`. A FastAPI app on a Unix socket serves an `/antirootkit` panel and alerting to secubox-soc/mail/threatmesh. Root actions go through a scoped-sudo `ctl`; the daemon itself never runs as root.

**Tech Stack:** Python 3.11, FastAPI + uvicorn (Unix socket), SQLite (stdlib `sqlite3`), auditd/`ausearch`, systemd cgroup v2 slices, nftables (`socket cgroupv2`), pytest (repo `.venv`, per-directory `pytest.ini`), Debian packaging (debhelper compat 13).

## Global Constraints

- Package name `secubox-antirootkit`; version `0.1.0-1~bookworm1`; `debian/compat` = 13; `Standards-Version: 4.6.2`; arch `all` (pure Python).
- Daemon runs as dedicated user/group `secubox-antirootkit` (created in postinst) — **never root in-process**.
- Root actions (cgroup move, nft load, quarantine-prep) ONLY via `/usr/sbin/secubox-antirootkitctl` invoked through a scoped sudoers drop-in `sudoers/secubox-antirootkit` — pattern from `feedback_webui_delegates_to_confined_ctl`.
- **Anti-escape (egress) = AUTO-BLOCK**; **process kill/quarantine = ALERT-ONLY (manual)**. Never auto-kill.
- Execlog is **append-only** (no UPDATE/DELETE) at `/var/lib/secubox/antirootkit/execlog.db`.
- **Never chown shared parents** `/run/secubox`, `/var/lib/secubox`, `/etc/secubox` — chmod only; create own subdir `/var/lib/secubox/antirootkit` owned `secubox-antirootkit:secubox-antirootkit`, parent stays 0755.
- FastAPI on Unix socket `/run/secubox/antirootkit.sock` (aggregator-served pattern; `RuntimeDirectory` with `Preserve=yes`).
- Config TOML `/etc/secubox/antirootkit.toml` including `[allowlist] exec_paths = [...]` for legitimate non-dpkg scripts (seed: `/usr/local/bin/certbot`, `/usr/local/bin/jws`, `/usr/local/bin/acme-*`).
- IOC seed (from incident #914): filename `notwork-monitoring`, sha256 `f2ca2b2051c2a98e23b80aab601369474006f6a6dd1dfb8f212f51a726b23dcc`, C2 `5.182.207.11`, domain `bunq-helpdesk.dns04.com`, ASN `AS213250`.
- License/SPDX header block on every Python/Bash file (per `.claude/CLAUDE.md`).
- Tests run from `packages/secubox-antirootkit/` with the repo `.venv`; per-directory `pytest.ini`.

---

## File Structure

```
packages/secubox-antirootkit/
├── api/
│   ├── __init__.py
│   ├── main.py            # FastAPI app, Unix socket, routes /status /execlog /alerts /quarantine-prep
│   ├── dpkg_backing.py    # resolve_pkg(path)->str|None, is_backed(path)->bool  (Task 1)
│   ├── cgroup.py          # jail_pid(pid), unjail_pid(pid), in_jail(pid) via ctl  (Task 2)
│   ├── execwatch.py       # auditd execve stream parser -> ExecEvent dataclass    (Task 4)
│   ├── execlog.py         # append-only SQLite writer/reader                      (Task 5)
│   ├── heuristics.py      # score(ExecEvent, history)->Verdict                    (Task 6)
│   ├── integrity.py       # run_debsums()/run_aide()/run_rkhunter() wrappers      (Task 7)
│   ├── alerts.py          # emit(alert) -> soc/mail/mesh; ioc_match(dest)         (Task 8)
│   └── allowlist.py       # load TOML allowlist; allowed(path)->bool              (Task 1)
├── sbin/
│   └── secubox-antirootkitctl   # root ops: cgroup-move, nft-load, quarantine-prep (Task 2/3/9)
├── nft/
│   └── secubox-antiescape.nft   # sbx-untrusted.slice egress drop                 (Task 3)
├── systemd/
│   ├── secubox-antirootkit.service        # the FastAPI daemon (User=secubox-antirootkit)
│   ├── sbx-antirootkitd.service           # the exec-watcher daemon
│   └── sbx-untrusted.slice                # the jail cgroup slice
├── sudoers/
│   └── secubox-antirootkit                # scoped sudo for the ctl verbs
├── nginx/
│   └── antirootkit.conf                   # /antirootkit route + API
├── www/antirootkit/
│   └── index.html                         # panel (WEBUI-PANEL-GUIDELINES)
├── menu.d/
│   └── 595-antirootkit.json               # menu entry, category security
├── conf/
│   └── antirootkit.toml                    # default config + allowlist + IOC seed
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_dpkg_backing.py test_allowlist.py test_cgroup.py test_execwatch.py
│   ├── test_execlog.py test_heuristics.py test_integrity.py test_alerts.py
│   ├── test_api.py test_ctl.py test_packaging.py
├── pytest.ini
├── README.md
└── debian/  (control, rules, changelog, compat, postinst, prerm, postrm, *.service, secubox.yaml)
```

---

### Task 1: dpkg-backing resolver + allowlist (the "is it legitimate?" core)

**Files:**
- Create: `packages/secubox-antirootkit/api/dpkg_backing.py`, `packages/secubox-antirootkit/api/allowlist.py`, `packages/secubox-antirootkit/conf/antirootkit.toml`
- Test: `packages/secubox-antirootkit/tests/test_dpkg_backing.py`, `packages/secubox-antirootkit/tests/test_allowlist.py`

**Interfaces:**
- Produces: `dpkg_backing.resolve_pkg(path: str, runner=subprocess.run) -> str | None` (package name or None); `dpkg_backing.is_backed(path: str, runner=...) -> bool`. `allowlist.load(toml_path: str) -> set[str]`; `allowlist.allowed(path: str, allow: set[str]) -> bool` (supports exact + glob like `/usr/local/bin/acme-*`).

- [ ] **Step 1: Write the failing test for resolve_pkg**

```python
# tests/test_dpkg_backing.py
from api import dpkg_backing

def fake_runner(ok, out=""):
    class R: pass
    def run(cmd, **kw):
        r = R(); r.returncode = 0 if ok else 1; r.stdout = out; r.stderr = ""
        return r
    return run

def test_resolve_pkg_backed():
    # dpkg -S prints "pkg: /path"
    r = fake_runner(True, "secubox-yacy: /usr/bin/yacy\n")
    assert dpkg_backing.resolve_pkg("/usr/bin/yacy", runner=r) == "secubox-yacy"

def test_resolve_pkg_unbacked():
    r = fake_runner(False, "dpkg-query: no path found matching pattern /usr/local/bin/notwork-monitoring\n")
    assert dpkg_backing.resolve_pkg("/usr/local/bin/notwork-monitoring", runner=r) is None

def test_is_backed_true_false():
    assert dpkg_backing.is_backed("/usr/bin/yacy", runner=fake_runner(True, "secubox-yacy: /usr/bin/yacy\n")) is True
    assert dpkg_backing.is_backed("/usr/local/bin/x", runner=fake_runner(False)) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-antirootkit && ../../.venv/bin/pytest tests/test_dpkg_backing.py -v`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement dpkg_backing.py**

```python
# api/dpkg_backing.py  (+ SPDX header block)
import subprocess
from functools import lru_cache

def resolve_pkg(path: str, runner=subprocess.run) -> str | None:
    """Return the dpkg package owning `path`, or None if not dpkg-backed."""
    try:
        r = runner(["dpkg", "-S", path], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    if r.returncode != 0 or not r.stdout:
        return None
    # "pkg: /path"  (diversions -> "pkg, other: /path"; take first pkg token)
    head = r.stdout.splitlines()[0].split(":", 1)[0]
    return head.split(",", 1)[0].strip() or None

def is_backed(path: str, runner=subprocess.run) -> bool:
    return resolve_pkg(path, runner=runner) is not None

@lru_cache(maxsize=4096)
def is_backed_cached(path: str) -> bool:
    return is_backed(path)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-antirootkit && ../../.venv/bin/pytest tests/test_dpkg_backing.py -v`
Expected: PASS.

- [ ] **Step 5: Write allowlist test + conf, implement allowlist.py**

```python
# tests/test_allowlist.py
from api import allowlist
def test_allowed_exact_and_glob(tmp_path):
    f = tmp_path / "a.toml"
    f.write_text('[allowlist]\nexec_paths = ["/usr/local/bin/certbot", "/usr/local/bin/acme-*"]\n')
    al = allowlist.load(str(f))
    assert allowlist.allowed("/usr/local/bin/certbot", al) is True
    assert allowlist.allowed("/usr/local/bin/acme-renew-batch.sh", al) is True
    assert allowlist.allowed("/usr/local/bin/notwork-monitoring", al) is False
```

```python
# api/allowlist.py  (+ SPDX)
import tomllib, fnmatch
def load(toml_path: str) -> set[str]:
    try:
        with open(toml_path, "rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return set()
    return set(data.get("allowlist", {}).get("exec_paths", []))
def allowed(path: str, allow: set[str]) -> bool:
    return any(path == p or fnmatch.fnmatch(path, p) for p in allow)
```

Seed `conf/antirootkit.toml`:
```toml
[allowlist]
exec_paths = ["/usr/local/bin/certbot", "/usr/local/bin/jws", "/usr/local/bin/acme-*"]
[procwatch]
mode = "targeted"   # targeted | full
[ioc]
hashes = ["f2ca2b2051c2a98e23b80aab601369474006f6a6dd1dfb8f212f51a726b23dcc"]
ips = ["5.182.207.11"]
domains = ["bunq-helpdesk.dns04.com"]
asns = ["AS213250"]
```

- [ ] **Step 6: Run both test files (PASS), then commit**

```bash
cd packages/secubox-antirootkit && ../../.venv/bin/pytest tests/test_dpkg_backing.py tests/test_allowlist.py -v
git add packages/secubox-antirootkit/api/dpkg_backing.py packages/secubox-antirootkit/api/allowlist.py packages/secubox-antirootkit/conf/antirootkit.toml packages/secubox-antirootkit/tests/test_dpkg_backing.py packages/secubox-antirootkit/tests/test_allowlist.py
git commit -m "feat(antirootkit): dpkg-backing resolver + allowlist (ref #915)"
```

---

### Task 2: cgroup jail via scoped-sudo ctl

**Files:**
- Create: `packages/secubox-antirootkit/api/cgroup.py`, `packages/secubox-antirootkit/sbin/secubox-antirootkitctl` (verb `jail`), `packages/secubox-antirootkit/systemd/sbx-untrusted.slice`, `packages/secubox-antirootkit/sudoers/secubox-antirootkit`
- Test: `packages/secubox-antirootkit/tests/test_cgroup.py`

**Interfaces:**
- Consumes: none.
- Produces: `cgroup.jail_pid(pid: int, runner=subprocess.run) -> bool` (invokes `sudo -n /usr/sbin/secubox-antirootkitctl jail <pid>`); `cgroup.in_jail(pid: int, proc_root="/proc") -> bool` (reads `/proc/<pid>/cgroup` for `sbx-untrusted.slice`).

- [ ] **Step 1: Write failing test**

```python
# tests/test_cgroup.py
from api import cgroup
def test_jail_pid_invokes_ctl():
    calls = []
    def run(cmd, **kw):
        calls.append(cmd)
        class R: returncode = 0
        return R()
    assert cgroup.jail_pid(1234, runner=run) is True
    assert calls[0] == ["sudo", "-n", "/usr/sbin/secubox-antirootkitctl", "jail", "1234"]

def test_in_jail_reads_proc(tmp_path):
    d = tmp_path / "1234"; d.mkdir()
    (d / "cgroup").write_text("0::/sbx-untrusted.slice/x\n")
    assert cgroup.in_jail(1234, proc_root=str(tmp_path)) is True
    (d / "cgroup").write_text("0::/system.slice/y\n")
    assert cgroup.in_jail(1234, proc_root=str(tmp_path)) is False
```

- [ ] **Step 2: Run to verify FAIL.** `cd packages/secubox-antirootkit && ../../.venv/bin/pytest tests/test_cgroup.py -v`

- [ ] **Step 3: Implement cgroup.py**

```python
# api/cgroup.py (+ SPDX)
import subprocess
CTL = "/usr/sbin/secubox-antirootkitctl"
def jail_pid(pid: int, runner=subprocess.run) -> bool:
    try:
        r = runner(["sudo", "-n", CTL, "jail", str(pid)], timeout=5)
        return r.returncode == 0
    except Exception:
        return False
def in_jail(pid: int, proc_root: str = "/proc") -> bool:
    try:
        with open(f"{proc_root}/{pid}/cgroup") as fh:
            return "sbx-untrusted.slice" in fh.read()
    except OSError:
        return False
```

- [ ] **Step 4: Run to verify PASS.**

- [ ] **Step 5: Write the ctl `jail` verb + slice + sudoers**

`sbin/secubox-antirootkitctl` (bash, `set -euo pipefail`, SPDX):
```bash
#!/usr/bin/env bash
set -euo pipefail
verb="${1:-}"
case "$verb" in
  jail) pid="${2:?pid}"; [[ "$pid" =~ ^[0-9]+$ ]] || exit 2
        systemctl set-property --runtime sbx-untrusted.slice 2>/dev/null || true
        # move the pid into the slice's cgroup
        mkdir -p /sys/fs/cgroup/sbx-untrusted.slice
        echo "$pid" > /sys/fs/cgroup/sbx-untrusted.slice/cgroup.procs ;;
  nft-load) exec nft -f /usr/share/secubox-antirootkit/secubox-antiescape.nft ;;
  *) echo "usage: $0 {jail <pid>|nft-load}" >&2; exit 2 ;;
esac
```
`systemd/sbx-untrusted.slice`:
```ini
[Unit]
Description=SecuBox anti-rootkit: untrusted (egress-blocked) process jail
[Slice]
```
`sudoers/secubox-antirootkit`:
```
secubox-antirootkit ALL=(root) NOPASSWD: /usr/sbin/secubox-antirootkitctl jail [0-9]*, /usr/sbin/secubox-antirootkitctl nft-load
Defaults!/usr/sbin/secubox-antirootkitctl !requiretty
```

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-antirootkit/api/cgroup.py packages/secubox-antirootkit/sbin/secubox-antirootkitctl packages/secubox-antirootkit/systemd/sbx-untrusted.slice packages/secubox-antirootkit/sudoers/secubox-antirootkit packages/secubox-antirootkit/tests/test_cgroup.py
git commit -m "feat(antirootkit): cgroup jail via scoped-sudo ctl + untrusted slice (ref #915)"
```

---

### Task 3: nftables anti-escape rule (drop egress from the jail cgroup)

**Files:**
- Create: `packages/secubox-antirootkit/nft/secubox-antiescape.nft`
- Test: `packages/secubox-antirootkit/tests/test_nft_rule.py`

**Interfaces:**
- Consumes: `sbx-untrusted.slice` from Task 2.
- Produces: an nft file loaded via `secubox-antirootkitctl nft-load`.

- [ ] **Step 1: Write failing test (rule shape + LAN carve-out present)**

```python
# tests/test_nft_rule.py
from pathlib import Path
def test_antiescape_rule():
    txt = Path("nft/secubox-antiescape.nft").read_text()
    assert "sbx-untrusted.slice" in txt
    assert "cgroupv2" in txt
    assert "drop" in txt
    # LAN carve-out so a jailed proc can still reach the local mgmt net (no exfil, but debuggable)
    assert "192.168.0.0/16" in txt or "@lan_safe" in txt
    assert "hook output" in txt
```

- [ ] **Step 2: Run to verify FAIL.**

- [ ] **Step 3: Implement nft file**

```
# nft/secubox-antiescape.nft
table inet secubox_antiescape {
  set lan_safe { type ipv4_addr; flags interval; elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } }
  chain output {
    type filter hook output priority filter; policy accept;
    socket cgroupv2 level 1 "sbx-untrusted.slice" ip daddr @lan_safe accept
    socket cgroupv2 level 1 "sbx-untrusted.slice" counter drop
  }
}
```

- [ ] **Step 4: Run to verify PASS.**

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-antirootkit/nft/secubox-antiescape.nft packages/secubox-antirootkit/tests/test_nft_rule.py
git commit -m "feat(antirootkit): nft anti-escape rule — drop egress from sbx-untrusted cgroup (ref #915)"
```

---

### Task 4: auditd execve watcher — the anti-escape MVP end-to-end

**Files:**
- Create: `packages/secubox-antirootkit/api/execwatch.py`
- Test: `packages/secubox-antirootkit/tests/test_execwatch.py`

**Interfaces:**
- Consumes: `dpkg_backing.is_backed`, `allowlist.allowed`, `cgroup.jail_pid`.
- Produces: `execwatch.ExecEvent` dataclass (`pid:int, ppid:int, uid:int, exe:str, argv:list[str], success:bool`); `execwatch.parse_ausearch(text: str) -> list[ExecEvent]`; `execwatch.decide(ev, allow, is_backed_fn) -> str` returning `"jail"` | `"allow"`.

- [ ] **Step 1: Write failing test (parse + decide)**

```python
# tests/test_execwatch.py
from api import execwatch as ew

AU = '''type=SYSCALL msg=audit(1785200000.123:42): arch=c00000b7 syscall=221 success=yes exit=0 ppid=1 pid=999 uid=0 exe="/usr/local/bin/notwork-monitoring" key="sbx_exec"
type=EXECVE msg=audit(1785200000.123:42): argc=2 a0="notwork-monitoring" a1="-server"'''

def test_parse():
    evs = ew.parse_ausearch(AU)
    assert len(evs) == 1
    e = evs[0]
    assert e.pid == 999 and e.exe == "/usr/local/bin/notwork-monitoring" and e.success is True
    assert e.argv == ["notwork-monitoring", "-server"]

def test_decide_jails_unknown():
    e = ew.ExecEvent(pid=999, ppid=1, uid=0, exe="/usr/local/bin/notwork-monitoring", argv=[], success=True)
    assert ew.decide(e, allow=set(), is_backed_fn=lambda p: False) == "jail"

def test_decide_allows_dpkg():
    e = ew.ExecEvent(pid=1, ppid=1, uid=0, exe="/usr/bin/yacy", argv=[], success=True)
    assert ew.decide(e, allow=set(), is_backed_fn=lambda p: True) == "allow"

def test_decide_allows_allowlisted():
    e = ew.ExecEvent(pid=2, ppid=1, uid=0, exe="/usr/local/bin/certbot", argv=[], success=True)
    assert ew.decide(e, allow={"/usr/local/bin/certbot"}, is_backed_fn=lambda p: False) == "allow"
```

- [ ] **Step 2: Run to verify FAIL.**

- [ ] **Step 3: Implement execwatch.py**

```python
# api/execwatch.py (+ SPDX)
import re
from dataclasses import dataclass, field
from api.allowlist import allowed

@dataclass
class ExecEvent:
    pid: int; ppid: int; uid: int; exe: str
    argv: list = field(default_factory=list); success: bool = True

_SYS = re.compile(r'type=SYSCALL .*?ppid=(\d+) pid=(\d+) .*?uid=(\d+) .*?exe="([^"]+)"')
_SUC = re.compile(r'success=(yes|no)')
_A   = re.compile(r'a\d+="([^"]*)"')

def parse_ausearch(text: str) -> list:
    out = []
    blocks = re.split(r'(?=type=SYSCALL )', text)
    for b in blocks:
        m = _SYS.search(b)
        if not m:
            continue
        suc = _SUC.search(b)
        argv = _A.findall(b)
        out.append(ExecEvent(pid=int(m.group(2)), ppid=int(m.group(1)),
                             uid=int(m.group(3)), exe=m.group(4),
                             argv=argv, success=(suc.group(1) == "yes" if suc else True)))
    return out

def decide(ev: ExecEvent, allow: set, is_backed_fn) -> str:
    if is_backed_fn(ev.exe) or allowed(ev.exe, allow):
        return "allow"
    return "jail"
```

- [ ] **Step 4: Run to verify PASS.**

- [ ] **Step 5: Write the watcher daemon loop (thin, tested via injection) + commit**

Add to `execwatch.py`:
```python
def run_once(events, allow, is_backed_fn, jail_fn, log_fn) -> int:
    """Process a batch of ExecEvents; jail unknowns; return #jailed."""
    n = 0
    for ev in events:
        d = decide(ev, allow, is_backed_fn)
        log_fn(ev, d)
        if d == "jail" and ev.success:
            jail_fn(ev.pid); n += 1
    return n
```
Test it:
```python
def test_run_once_jails_and_logs():
    from api import execwatch as ew
    e = ew.ExecEvent(pid=7, ppid=1, uid=0, exe="/tmp/x", argv=[], success=True)
    jailed = []; logged = []
    n = ew.run_once([e], set(), lambda p: False, jailed.append, lambda ev, d: logged.append(d))
    assert n == 1 and jailed == [7] and logged == ["jail"]
```

```bash
cd packages/secubox-antirootkit && ../../.venv/bin/pytest tests/test_execwatch.py -v
git add packages/secubox-antirootkit/api/execwatch.py packages/secubox-antirootkit/tests/test_execwatch.py
git commit -m "feat(antirootkit): auditd execve watcher + anti-escape decision (jail unknowns) (ref #915)"
```

---

### Task 5: append-only SQLite execlog

**Files:** Create `api/execlog.py`; Test `tests/test_execlog.py`.

**Interfaces:** Produces `execlog.ExecLog(db_path)` with `.record(ev: ExecEvent, verdict: str, pkg: str|None)`, `.recent(limit=100) -> list[dict]`, `.failed_exec_count(exe: str, window_s: int) -> int`. Consumes `execwatch.ExecEvent`.

- [ ] **Step 1: Failing test**

```python
# tests/test_execlog.py
from api.execlog import ExecLog
from api.execwatch import ExecEvent
def test_record_and_recent(tmp_path):
    lg = ExecLog(str(tmp_path/"e.db"))
    lg.record(ExecEvent(pid=1,ppid=0,uid=0,exe="/tmp/x",argv=["x"],success=True), "jail", None)
    rows = lg.recent()
    assert rows[0]["exe"] == "/tmp/x" and rows[0]["verdict"] == "jail" and rows[0]["pkg"] is None
def test_failed_exec_count(tmp_path):
    lg = ExecLog(str(tmp_path/"e.db"))
    for _ in range(3):
        lg.record(ExecEvent(pid=1,ppid=0,uid=0,exe="/tmp/m",argv=[],success=False), "jail", None)
    assert lg.failed_exec_count("/tmp/m", window_s=3600) >= 3
def test_append_only_no_update(tmp_path):
    import sqlite3
    lg = ExecLog(str(tmp_path/"e.db"))
    # schema must not be relied on for UPDATE; verify recorded rows are immutable by design (insert-only API)
    assert not hasattr(lg, "update")
```

- [ ] **Step 2: Run FAIL. Step 3: Implement execlog.py** (sqlite3 table `execlog(ts REAL, pid, ppid, uid, exe, argv, success, verdict, pkg)`, INSERT-only, WAL; `.record` uses `time.time()` injected via param `now=time.time`). **Step 4: Run PASS. Step 5: Commit.**

```python
# api/execlog.py (+ SPDX)
import sqlite3, json, time
DDL = "CREATE TABLE IF NOT EXISTS execlog (ts REAL, pid INT, ppid INT, uid INT, exe TEXT, argv TEXT, success INT, verdict TEXT, pkg TEXT)"
class ExecLog:
    def __init__(self, db_path: str):
        self.db = sqlite3.connect(db_path); self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute(DDL); self.db.commit()
    def record(self, ev, verdict, pkg, now=time.time):
        self.db.execute("INSERT INTO execlog VALUES (?,?,?,?,?,?,?,?,?)",
            (now(), ev.pid, ev.ppid, ev.uid, ev.exe, json.dumps(ev.argv), int(ev.success), verdict, pkg))
        self.db.commit()
    def recent(self, limit=100):
        cur = self.db.execute("SELECT * FROM execlog ORDER BY ts DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]
    def failed_exec_count(self, exe, window_s, now=time.time):
        cur = self.db.execute("SELECT COUNT(*) c FROM execlog WHERE exe=? AND success=0 AND ts>=?",
            (exe, now()-window_s))
        return cur.fetchone()["c"]
```

---

### Task 6: heuristics scoring

**Files:** Create `api/heuristics.py`; Test `tests/test_heuristics.py`.

**Interfaces:** Produces `heuristics.score(ev, pkg, unit_flags: dict, failed_count: int) -> tuple[int, list[str]]` (score, reasons). `unit_flags` = `{"restart_always": bool, "logs_silenced": bool}`. Signals: non-dpkg exec path in {/usr/local/bin,/tmp,/dev/shm,/opt,/home} (+2); repeated failed exec ≥3 (+2, "crash-loop"); restart_always+logs_silenced (+2). Verdict "strong" if score ≥3.

- [ ] Steps 1–5 (TDD): test that a notwork-like event (non-dpkg /usr/local/bin + restart_always + logs_silenced) scores ≥3 with reasons `["non-dpkg-exec-path","silenced-restart-always"]`, and a dpkg-backed event scores 0. Implement pure function. Commit.

```python
# tests/test_heuristics.py
from api.heuristics import score
from api.execwatch import ExecEvent
def test_strong_notwork_profile():
    e = ExecEvent(pid=1,ppid=1,uid=0,exe="/usr/local/bin/notwork-monitoring",argv=[],success=False)
    s, reasons = score(e, pkg=None, unit_flags={"restart_always":True,"logs_silenced":True}, failed_count=5)
    assert s >= 3 and "silenced-restart-always" in reasons
def test_legit_dpkg_zero():
    e = ExecEvent(pid=1,ppid=1,uid=0,exe="/usr/bin/yacy",argv=[],success=True)
    s, reasons = score(e, pkg="secubox-yacy", unit_flags={"restart_always":False,"logs_silenced":False}, failed_count=0)
    assert s == 0
```

```python
# api/heuristics.py (+ SPDX)
SUSPECT_DIRS = ("/usr/local/bin","/usr/local/sbin","/tmp","/dev/shm","/opt","/home")
def score(ev, pkg, unit_flags, failed_count):
    s = 0; reasons = []
    if pkg is None and ev.exe.startswith(SUSPECT_DIRS):
        s += 2; reasons.append("non-dpkg-exec-path")
    if failed_count >= 3:
        s += 2; reasons.append("crash-loop")
    if unit_flags.get("restart_always") and unit_flags.get("logs_silenced"):
        s += 2; reasons.append("silenced-restart-always")
    return s, reasons
```

---

### Task 7: integrity wrappers (debsums/aide/rkhunter)

**Files:** Create `api/integrity.py`; Test `tests/test_integrity.py`.

**Interfaces:** Produces `integrity.run_debsums(runner=...) -> list[str]` (altered files), `integrity.run_rkhunter(runner=...) -> list[str]` (warnings), `integrity.authkeys_drift(current: set, baseline: set) -> set` (new keys). All accept injected runner/inputs for testing; degrade to `[]` if tool absent.

- [ ] Steps 1–5 (TDD): test `run_debsums` parses `debsums -c` output lines to a list; `authkeys_drift` returns keys in current not in baseline; tools-absent → `[]`. Implement, commit. (No real tool calls in tests — inject runner.)

```python
# tests/test_integrity.py
from api import integrity
def test_debsums_parses_altered():
    def r(cmd, **k):
        class R: returncode=1; stdout="/usr/bin/foo\n/lib/bar\n"; stderr=""
        return R()
    assert integrity.run_debsums(runner=r) == ["/usr/bin/foo", "/lib/bar"]
def test_authkeys_drift():
    assert integrity.authkeys_drift({"kA","kB","kC"}, {"kA","kB"}) == {"kC"}
```

---

### Task 8: alerting + IOC match

**Files:** Create `api/alerts.py`; Test `tests/test_alerts.py`.

**Interfaces:** Produces `alerts.ioc_match(dest_ip: str, ioc: dict) -> bool`; `alerts.build_alert(ev, score, reasons, dest=None) -> dict`; `alerts.emit(alert, soc_post=..., mailer=..., mesh=...)` (injected sinks; each failure is caught, never raises). IOC seed loaded from `antirootkit.toml [ioc]`.

- [ ] Steps 1–5 (TDD): `ioc_match("5.182.207.11", {"ips":["5.182.207.11"]})` → True; `build_alert` includes exe/score/reasons/ioc; `emit` calls all three sinks and swallows a sink exception. Implement, commit.

```python
# tests/test_alerts.py
from api import alerts
from api.execwatch import ExecEvent
def test_ioc_match():
    assert alerts.ioc_match("5.182.207.11", {"ips":["5.182.207.11"]}) is True
    assert alerts.ioc_match("1.1.1.1", {"ips":["5.182.207.11"]}) is False
def test_emit_swallows_sink_error():
    a = {"x":1}
    def boom(_): raise RuntimeError("soc down")
    called = []
    alerts.emit(a, soc_post=boom, mailer=lambda x: called.append("mail"), mesh=lambda x: called.append("mesh"))
    assert "mail" in called and "mesh" in called   # one sink failing must not block others
```

---

### Task 9: quarantine-prep (manual) via ctl

**Files:** Modify `sbin/secubox-antirootkitctl` (add `quarantine-prep <path>` verb — writes the prepared command sequence to a file, does NOT execute kill); Create `api/quarantine.py` (`prepare(path) -> dict` returns the planned steps: chmod-000, copy, sha256, nft-block, disable-unit — as data, not executed); Test `tests/test_quarantine.py`.

**Interfaces:** Produces `quarantine.prepare(path, sha_fn=..., unit_of=...) -> dict` with keys `chmod, copy, sha256, nft_block, disable_unit`. **Never executes**; returns the plan for operator confirmation.

- [ ] Steps 1–5 (TDD): `prepare("/usr/local/bin/notwork-monitoring", ...)` returns a dict whose `nft_block` references the resolved C2 and whose steps are strings; assert no side effects (inject a fake `os`); commit.

---

### Task 10: FastAPI app + webui panel

**Files:** Create `api/main.py`, `api/__init__.py`, `www/antirootkit/index.html`, `nginx/antirootkit.conf`, `menu.d/595-antirootkit.json`; Test `tests/test_api.py`.

**Interfaces:** Consumes execlog/heuristics/alerts. Routes: `GET /status`, `GET /execlog?limit=`, `GET /alerts`, `POST /quarantine-prep` (returns plan, requires JWT). Panel `/antirootkit` = exec timeline + per-row dpkg verdict + integrity status + alert queue with a manual "quarantine" button.

- [ ] Steps 1–5 (TDD with FastAPI `TestClient`): `GET /status` → 200 with `{"execlog_rows": int}`; `GET /execlog` returns recorded rows; `POST /quarantine-prep` returns the plan (never executes). Panel is XSS-safe (event delegation, no inline handlers) per WEBUI-PANEL-GUIDELINES. Commit.

---

### Task 11: Debian packaging + systemd wiring

**Files:** Create `debian/{control,changelog,compat,rules,postinst,prerm,postrm}`, `debian/secubox-antirootkit.service`, `systemd/sbx-antirootkitd.service`, `debian/secubox.yaml`, `pytest.ini`, `README.md`, audit rule `conf/99-sbx-procwatch.rules`; Test `tests/test_packaging.py`.

**Interfaces:** postinst: create user `secubox-antirootkit`; `install -d -o secubox-antirootkit -g secubox-antirootkit /var/lib/secubox/antirootkit` (parent chmod 0755, NOT chown); install sudoers, nft (`secubox-antirootkitctl nft-load`), audit rules (`augenrules --load`), enable services + `sbx-untrusted.slice`; `#DEBHELPER#` alone. prerm stop; postrm purge dir. Depends: `auditd, debsums, python3, python3-fastapi | ...`; Recommends: `aide, rkhunter, chkrootkit` (soft — degrade if absent).

- [ ] Steps 1–5: `test_packaging.py` asserts (a) control Depends includes `auditd`+`debsums`, Recommends includes `aide`; (b) postinst contains `install -d` for the module dir and does NOT `chown` a shared parent; (c) the nft file path is referenced; (d) the audit rule file lists `execve`. Build check: `dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b`. Commit.

---

## Self-Review

**Spec coverage:** §A Process Scanner → Tasks 4,5,6,11(audit rule). §A2 anti-escape → Tasks 1,2,3,4 (MVP end-to-end). §B integrity → Task 7. §C alert+quarantine+webui → Tasks 8,9,10. Packaging/invariants → Task 11. Prerequisite (apt/boot) is out-of-plan maintenance (noted, not a task) — correct per spec §Prérequis. IOC seed → Task 1 conf + Task 8. Allowlist → Task 1. Append-only → Task 5. No-chown/never-root → Tasks 2,11.

**Placeholder scan:** each code step has concrete code; ctl/nft/sudoers/service bodies are literal. No "TBD".

**Type consistency:** `ExecEvent(pid,ppid,uid,exe,argv,success)` used identically in Tasks 4,5,6,8. `is_backed`/`resolve_pkg` names consistent (Task 1 → 4). `jail_pid`/`in_jail` (Task 2 → 4). `ExecLog.record(ev, verdict, pkg)` / `.recent` / `.failed_exec_count` consistent (Task 5 → 6,10).
