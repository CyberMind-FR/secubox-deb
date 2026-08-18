<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MetaBlogizer Deploy Webhook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Gitea-triggered deploy webhook for metablog-* sites: HMAC-verified push events update the live site dir via `git fetch + reset --hard`, invalidate the dashboard cache, conditionally reload nginx, and log to an in-memory ring buffer. Plus an idempotent installer that registers the webhook on all 166 repos via Gitea API.

**Architecture:** New `packages/secubox-metablogizer/api/webhook.py` module with HMAC verify + secret loader + per-site `asyncio.Lock` pool + git helper + 50-entry ring buffer. Mounted from `main.py` as `POST /webhook` and `GET /deploys`. Companion shell scripts `scripts/metablog-webhook-{install,uninstall}.sh` operate via Gitea API. Synchronous git ops dispatched via `run_in_executor` to keep the single uvicorn worker responsive.

**Tech Stack:** Python 3.11 + FastAPI + asyncio, `hmac`/`hashlib` stdlib, `subprocess.run` for git, pytest with `pytest-asyncio` (already declared), bash + curl + jq for the installer.

**Spec:** [docs/superpowers/specs/2026-05-13-metablog-deploy-webhook-design.md](../specs/2026-05-13-metablog-deploy-webhook-design.md)
**Issue:** [#113](https://github.com/CyberMind-FR/secubox-deb/issues/113) (sub-project E of [#49](https://github.com/CyberMind-FR/secubox-deb/issues/49))

---

## Working directory & branch

All tasks run in `/home/reepost/CyberMindStudio/secubox-deb-worktrees/113-metablogizer-deploy-webhook-sub-e-of-49`. Branch: `feature/113-metablogizer-deploy-webhook-sub-e-of-49`. Verify with `git rev-parse --abbrev-ref HEAD` at the start of every task — abort if wrong.

---

## Task 1: webhook.py — HMAC verify + secret loader

**Files:**
- Create: `packages/secubox-metablogizer/api/webhook.py`
- Create: `packages/secubox-metablogizer/api/tests/test_webhook.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-metablogizer/api/tests/test_webhook.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for api/webhook.py — HMAC, dispatcher, filters, lock."""
import hashlib
import hmac

import pytest

from webhook import verify_signature


def _sign(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def test_verify_signature_valid():
    secret = b"test-secret-32-bytes-of-entropy!!"
    body = b'{"hello": "world"}'
    sig = _sign(secret, body)
    assert verify_signature(secret, body, sig) is True


def test_verify_signature_wrong_secret_fails():
    body = b'{"hello": "world"}'
    sig = _sign(b"wrong-secret-padded-to-32-bytes!", body)
    assert verify_signature(b"correct-secret-padded-to-32!!!", body, sig) is False


def test_verify_signature_truncated_sig_fails():
    secret = b"test-secret-32-bytes-of-entropy!!"
    body = b'{"hello": "world"}'
    sig = _sign(secret, body)[:-2]
    assert verify_signature(secret, body, sig) is False


def test_verify_signature_empty_sig_fails():
    secret = b"test-secret-32-bytes-of-entropy!!"
    body = b'{"hello": "world"}'
    assert verify_signature(secret, body, "") is False
```

- [ ] **Step 2: Run the test to confirm it fails**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/113-metablogizer-deploy-webhook-sub-e-of-49/packages/secubox-metablogizer
PYTHONPATH=api python3 -m pytest api/tests/test_webhook.py -v
```

Expected: `ModuleNotFoundError: No module named 'webhook'`.

- [ ] **Step 3: Create the minimal webhook.py to make tests pass**

```python
# packages/secubox-metablogizer/api/webhook.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: metablogizer :: deploy webhook
CyberMind — https://cybermind.fr

HMAC-verified Gitea push webhook. On a metablog-* repo push to the default
branch, pull the site dir, invalidate the load_sites cache, optionally
reload nginx if site.json:domain changed, and log to a ring buffer.
"""
import hmac
import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("metablogizer.webhook")

SECRET_PATH = Path("/etc/secubox/metablogizer-webhook.secret")

# Module-level cached secret. Read once at first verify call.
_secret_cache: Optional[bytes] = None


def load_secret(path: Path = SECRET_PATH) -> bytes:
    """Read the shared HMAC secret from disk, cached after first read."""
    global _secret_cache
    if _secret_cache is not None:
        return _secret_cache
    if not path.exists():
        raise FileNotFoundError(f"webhook secret not configured at {path}")
    data = path.read_bytes().strip()
    if not data:
        raise ValueError(f"webhook secret at {path} is empty")
    _secret_cache = data
    return data


def verify_signature(secret: bytes, body: bytes, signature_hex: str) -> bool:
    """Constant-time HMAC-SHA256 verify. Returns False on any mismatch."""
    if not signature_hex:
        return False
    try:
        expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature_hex)
    except (TypeError, ValueError):
        return False
```

- [ ] **Step 4: Run the tests to confirm they pass**

```bash
PYTHONPATH=api python3 -m pytest api/tests/test_webhook.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Add secret-loader tests**

Append to `api/tests/test_webhook.py`:

```python
def test_load_secret_reads_file(tmp_path, monkeypatch):
    import webhook
    p = tmp_path / "secret"
    p.write_bytes(b"abc123\n")
    monkeypatch.setattr(webhook, "_secret_cache", None)
    s = webhook.load_secret(p)
    assert s == b"abc123"


def test_load_secret_missing_raises(tmp_path, monkeypatch):
    import webhook
    monkeypatch.setattr(webhook, "_secret_cache", None)
    p = tmp_path / "nope"
    with pytest.raises(FileNotFoundError):
        webhook.load_secret(p)


def test_load_secret_empty_raises(tmp_path, monkeypatch):
    import webhook
    monkeypatch.setattr(webhook, "_secret_cache", None)
    p = tmp_path / "empty"
    p.write_bytes(b"")
    with pytest.raises(ValueError):
        webhook.load_secret(p)


def test_load_secret_caches(tmp_path, monkeypatch):
    import webhook
    p = tmp_path / "secret"
    p.write_bytes(b"first\n")
    monkeypatch.setattr(webhook, "_secret_cache", None)
    s1 = webhook.load_secret(p)
    p.write_bytes(b"changed\n")
    s2 = webhook.load_secret(p)
    assert s1 == s2 == b"first"  # cache wins
```

- [ ] **Step 6: Run all tests to confirm they pass**

```bash
PYTHONPATH=api python3 -m pytest api/tests/test_webhook.py -v
```

Expected: 8 passed.

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-metablogizer/api/webhook.py \
        packages/secubox-metablogizer/api/tests/test_webhook.py
git commit -m "feat(metablog-webhook): HMAC verify + secret loader (ref #113)

- verify_signature(): constant-time HMAC-SHA256 comparison
- load_secret(): reads /etc/secubox/metablogizer-webhook.secret,
  cached after first read, empty/missing raises a clear error

8 pytest cases cover happy path + wrong secret, truncated sig,
empty sig, missing file, empty file, and the cache behavior.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: webhook.py — git_pull helper + deploy ring buffer

**Files:**
- Modify: `packages/secubox-metablogizer/api/webhook.py`
- Modify: `packages/secubox-metablogizer/api/tests/test_webhook.py`

- [ ] **Step 1: Add ring-buffer tests**

Append to `api/tests/test_webhook.py`:

```python
def test_record_deploy_appends():
    import webhook
    webhook._deploys.clear()
    webhook._record_deploy({"site": "a", "from": "x", "to": "y"})
    assert len(webhook._deploys) == 1
    assert webhook._deploys[0]["site"] == "a"


def test_record_deploy_evicts_oldest_at_50():
    import webhook
    webhook._deploys.clear()
    for i in range(55):
        webhook._record_deploy({"site": f"s{i}"})
    assert len(webhook._deploys) == 50
    # oldest 5 are gone; first remaining is s5
    assert webhook._deploys[0]["site"] == "s5"
    assert webhook._deploys[-1]["site"] == "s54"


def test_list_deploys_returns_reversed():
    import webhook
    webhook._deploys.clear()
    webhook._record_deploy({"site": "a"})
    webhook._record_deploy({"site": "b"})
    out = webhook.list_deploys()
    assert out["count"] == 2
    assert out["deploys"][0]["site"] == "b"  # newest first
    assert out["deploys"][1]["site"] == "a"
```

- [ ] **Step 2: Run to confirm failure**

```bash
PYTHONPATH=api python3 -m pytest api/tests/test_webhook.py::test_record_deploy_appends -v
```

Expected: `AttributeError: module 'webhook' has no attribute '_deploys'`.

- [ ] **Step 3: Add ring buffer + list_deploys to webhook.py**

Append to `packages/secubox-metablogizer/api/webhook.py`:

```python
# ─── Deploy ring buffer ──────────────────────────────────────────
_deploys: list[dict] = []
_DEPLOYS_MAX = 50


def _record_deploy(entry: dict) -> None:
    """Append a deploy record; evict oldest beyond cap."""
    _deploys.append(entry)
    if len(_deploys) > _DEPLOYS_MAX:
        _deploys.pop(0)


def list_deploys() -> dict:
    """Return deploys newest-first."""
    return {"deploys": list(reversed(_deploys)), "count": len(_deploys)}
```

- [ ] **Step 4: Run to confirm pass**

```bash
PYTHONPATH=api python3 -m pytest api/tests/test_webhook.py -v
```

Expected: 11 passed.

- [ ] **Step 5: Add git_pull test (with stubbed subprocess)**

Append to `api/tests/test_webhook.py`:

```python
def test_git_pull_returns_old_and_new_sha(tmp_path, monkeypatch):
    import webhook
    site = tmp_path / "site"
    site.mkdir()
    (site / ".git").mkdir()

    calls = []
    sha_iter = iter(["aaa1111", "bbb2222"])

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        class R:
            stdout = next(sha_iter) + "\n" if "rev-parse" in cmd else ""
            stderr = ""
            returncode = 0
        return R()

    monkeypatch.setattr(webhook.subprocess, "run", fake_run)
    old, new = webhook.git_pull(site, "main")
    assert old == "aaa1111"
    assert new == "bbb2222"
    # ensure the 4 expected git commands happened in order
    op_names = [c[3] for c in calls]
    assert op_names == ["rev-parse", "fetch", "reset", "rev-parse"]


def test_git_pull_timeout_propagates(tmp_path, monkeypatch):
    import webhook
    import subprocess
    site = tmp_path / "site"
    site.mkdir()
    (site / ".git").mkdir()

    def fake_run(cmd, **kwargs):
        if "fetch" in cmd:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 60))
        class R:
            stdout = "abc\n"; stderr = ""; returncode = 0
        return R()

    monkeypatch.setattr(webhook.subprocess, "run", fake_run)
    with pytest.raises(subprocess.TimeoutExpired):
        webhook.git_pull(site, "main")
```

- [ ] **Step 6: Run to confirm failure**

```bash
PYTHONPATH=api python3 -m pytest api/tests/test_webhook.py::test_git_pull_returns_old_and_new_sha -v
```

Expected: `AttributeError: module 'webhook' has no attribute 'git_pull'`.

- [ ] **Step 7: Implement git_pull**

In `packages/secubox-metablogizer/api/webhook.py`, add at the top with the imports:

```python
import subprocess
```

And add the helper:

```python
GIT_FETCH_TIMEOUT = 60
GIT_OP_TIMEOUT = 10


def git_pull(site_dir: Path, branch: str) -> tuple[str, str]:
    """Pull site_dir to origin/<branch>. Returns (old_sha, new_sha).

    Raises subprocess.TimeoutExpired or CalledProcessError on git failure.
    """
    def _git(*args: str, timeout: int = GIT_OP_TIMEOUT) -> str:
        result = subprocess.run(
            ["git", "-C", str(site_dir), *args],
            capture_output=True, text=True, timeout=timeout, check=True,
        )
        return result.stdout.strip()

    old = _git("rev-parse", "HEAD")
    _git("fetch", "--quiet", "origin", branch, timeout=GIT_FETCH_TIMEOUT)
    _git("reset", "--hard", f"origin/{branch}")
    new = _git("rev-parse", "HEAD")
    return old, new
```

- [ ] **Step 8: Run all tests**

```bash
PYTHONPATH=api python3 -m pytest api/tests/test_webhook.py -v
```

Expected: 13 passed.

- [ ] **Step 9: Commit**

```bash
git add packages/secubox-metablogizer/api/webhook.py \
        packages/secubox-metablogizer/api/tests/test_webhook.py
git commit -m "feat(metablog-webhook): git_pull helper + deploy ring buffer (ref #113)

- git_pull(site_dir, branch) -> (old_sha, new_sha) via 4 git ops
  (rev-parse, fetch, reset, rev-parse) with timeouts (60s fetch,
  10s local ops).
- Ring buffer holds the last 50 deploy records; oldest evicted
  on overflow. list_deploys() returns newest-first.

5 new pytest cases cover the buffer and git ops (with subprocess
stubbed via monkeypatch).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: webhook.py — dispatcher + per-site lock + payload filters

**Files:**
- Modify: `packages/secubox-metablogizer/api/webhook.py`
- Modify: `packages/secubox-metablogizer/api/tests/test_webhook.py`

- [ ] **Step 1: Add filter tests**

Append to `api/tests/test_webhook.py`:

```python
def _payload(name="metablog-zkp", ref="refs/heads/main", default_branch="main"):
    return {
        "ref": ref,
        "repository": {"name": name, "default_branch": default_branch},
        "after": "abc1234",
    }


def test_classify_payload_accepts_default_branch_push():
    import webhook
    decision, info = webhook.classify_payload(_payload())
    assert decision == "accept"
    assert info["site"] == "zkp"
    assert info["branch"] == "main"


def test_classify_payload_rejects_non_metablog():
    import webhook
    decision, info = webhook.classify_payload(_payload(name="streamlit-foo"))
    assert decision == "skip"
    assert info["reason"] == "non-metablog"


def test_classify_payload_rejects_non_default_ref():
    import webhook
    decision, info = webhook.classify_payload(_payload(ref="refs/tags/v1.0.0"))
    assert decision == "skip"
    assert info["reason"] == "non-default-ref"


def test_classify_payload_rejects_feature_branch():
    import webhook
    decision, info = webhook.classify_payload(
        _payload(ref="refs/heads/feature/x", default_branch="main"))
    assert decision == "skip"
    assert info["reason"] == "non-default-ref"


def test_classify_payload_handles_master_default():
    import webhook
    decision, info = webhook.classify_payload(
        _payload(ref="refs/heads/master", default_branch="master"))
    assert decision == "accept"
    assert info["branch"] == "master"


def test_classify_payload_malformed_missing_repo():
    import webhook
    decision, info = webhook.classify_payload({"ref": "refs/heads/main"})
    assert decision == "malformed"
```

- [ ] **Step 2: Run to confirm failure**

Expected: `AttributeError: module 'webhook' has no attribute 'classify_payload'`.

- [ ] **Step 3: Add classify_payload to webhook.py**

Append to `packages/secubox-metablogizer/api/webhook.py`:

```python
METABLOG_PREFIX = "metablog-"


def classify_payload(payload: dict) -> tuple[str, dict]:
    """Decide what to do with a Gitea push payload.

    Returns one of:
      ("accept",     {site, branch})
      ("skip",       {reason: ...})
      ("malformed",  {reason: ...})
    """
    try:
        ref = payload["ref"]
        repo = payload["repository"]
        name = repo["name"]
        default = repo["default_branch"]
    except (KeyError, TypeError):
        return "malformed", {"reason": "missing-fields"}

    if not name.startswith(METABLOG_PREFIX):
        return "skip", {"reason": "non-metablog", "name": name}
    if ref != f"refs/heads/{default}":
        return "skip", {"reason": "non-default-ref", "ref": ref}
    return "accept", {"site": name[len(METABLOG_PREFIX):], "branch": default}
```

- [ ] **Step 4: Run tests**

```bash
PYTHONPATH=api python3 -m pytest api/tests/test_webhook.py -v
```

Expected: 19 passed.

- [ ] **Step 5: Add lock-semantics tests**

Append to `api/tests/test_webhook.py`:

```python
import asyncio


@pytest.mark.asyncio
async def test_site_lock_serializes_same_name():
    import webhook
    webhook._site_locks.clear()
    order = []

    async def critical(name: str, marker: str):
        lock = await webhook.site_lock(name)
        async with lock:
            order.append(f"{marker}-start")
            await asyncio.sleep(0.05)
            order.append(f"{marker}-end")

    await asyncio.gather(critical("zkp", "A"), critical("zkp", "B"))
    # whichever started first must finish before the other starts
    if order[0] == "A-start":
        assert order == ["A-start", "A-end", "B-start", "B-end"]
    else:
        assert order == ["B-start", "B-end", "A-start", "A-end"]


@pytest.mark.asyncio
async def test_site_lock_parallel_different_names():
    import webhook
    webhook._site_locks.clear()
    order = []

    async def critical(name: str, marker: str):
        lock = await webhook.site_lock(name)
        async with lock:
            order.append(f"{marker}-start")
            await asyncio.sleep(0.05)
            order.append(f"{marker}-end")

    await asyncio.gather(critical("zkp", "A"), critical("evolution", "B"))
    # different sites can overlap: starts come before either end
    assert order[:2] == sorted(order[:2])  # both starts first
    assert "A-end" in order
    assert "B-end" in order
```

- [ ] **Step 6: Run to confirm failure**

Expected: `AttributeError: module 'webhook' has no attribute 'site_lock'`.

- [ ] **Step 7: Add the lock pool**

Add to `packages/secubox-metablogizer/api/webhook.py`:

```python
import asyncio

# Per-site asyncio lock pool. Two pushes to the same site serialize;
# pushes to different sites run concurrently.
_site_locks: dict[str, asyncio.Lock] = {}
_locks_master = asyncio.Lock()


async def site_lock(name: str) -> asyncio.Lock:
    """Return (creating if needed) the asyncio.Lock keyed by site name."""
    async with _locks_master:
        if name not in _site_locks:
            _site_locks[name] = asyncio.Lock()
        return _site_locks[name]
```

- [ ] **Step 8: Run all tests**

```bash
PYTHONPATH=api python3 -m pytest api/tests/test_webhook.py -v
```

Expected: 21 passed.

- [ ] **Step 9: Commit**

```bash
git add packages/secubox-metablogizer/api/webhook.py \
        packages/secubox-metablogizer/api/tests/test_webhook.py
git commit -m "feat(metablog-webhook): payload classifier + per-site asyncio lock (ref #113)

- classify_payload(): pure dispatcher returning accept/skip/malformed
  with a structured info dict. Covers non-metablog repos, non-default
  refs (incl. tags + feature branches), and missing fields.
- site_lock(name): per-site asyncio.Lock pool with a master lock around
  dict access so two concurrent first-creates don't race.

8 new pytest cases. 21 total green.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Wire webhook + /deploys into main.py

**Files:**
- Modify: `packages/secubox-metablogizer/api/main.py`

- [ ] **Step 1: Read the current main.py header to find the right insertion points**

```bash
grep -n "from rmtree\|from site_schema\|@app.post\|@app.get(\"/status\"\|_invalidate_sites_cache" packages/secubox-metablogizer/api/main.py | head -20
```

Note the line where `from rmtree import …` lives — that's where we add the new import.

- [ ] **Step 2: Add the webhook import**

Find this line:

```python
from rmtree import force_remove as _rmtree_force
```

Replace with:

```python
from rmtree import force_remove as _rmtree_force
from webhook import (
    classify_payload,
    git_pull,
    list_deploys as _list_deploys,
    load_secret,
    site_lock,
    verify_signature,
    _record_deploy,
)
```

- [ ] **Step 3: Add the endpoint definitions**

Find the end of `/republish-all` (search for `republish-all`, scroll to the closing `}` of the return). Just after that endpoint (before the next `# =====` header), insert:

```python
# =============================================================================
# DEPLOY WEBHOOK (Gitea push → site update)
# =============================================================================

@app.post("/webhook")
async def webhook(request: Request):
    """Gitea push webhook. HMAC-verified; deploys metablog-* default-branch pushes."""
    import asyncio
    import time
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse

    body = await request.body()
    sig = request.headers.get("X-Gitea-Signature", "")

    try:
        secret = load_secret()
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"webhook secret unavailable: {e}")
        raise HTTPException(503, "webhook secret not configured")

    if not verify_signature(secret, body, sig):
        raise HTTPException(401)

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "invalid-json")

    decision, info = classify_payload(payload)
    if decision == "malformed":
        raise HTTPException(400, info.get("reason", "malformed"))
    if decision == "skip":
        logger.info(f"webhook skip {info}")
        return {"skip": info["reason"], **{k: v for k, v in info.items() if k != "reason"}}

    site_name = info["site"]
    branch = info["branch"]
    site_dir = SITES_ROOT / site_name

    if not site_dir.exists():
        logger.info(f"webhook unknown-site {site_name}")
        return {"skip": "unknown-site", "site": site_name}
    if not (site_dir / ".git").exists():
        logger.info(f"webhook no-git-dir {site_name}")
        return {"skip": "no-git-dir", "site": site_name}

    lock = await site_lock(site_name)
    loop = asyncio.get_running_loop()
    t0 = time.monotonic()

    try:
        async with lock:
            old_domain = _read_domain(site_dir)
            old, new = await loop.run_in_executor(None, git_pull, site_dir, branch)
            new_domain = _read_domain(site_dir)

            _invalidate_sites_cache()

            domain_changed = old_domain != new_domain
            if domain_changed:
                await loop.run_in_executor(None, regenerate_nginx_config)

        duration_ms = int((time.monotonic() - t0) * 1000)
        entry = {
            "site": site_name,
            "from": old,
            "to": new,
            "duration_ms": duration_ms,
            "timestamp": time.time(),
            "domain_changed": domain_changed,
            "source": "webhook",
        }
        _record_deploy(entry)
        logger.info(
            f"deploy site={site_name} from={old[:8]} to={new[:8]} "
            f"duration_ms={duration_ms} domain_changed={domain_changed}"
        )
        return {"deployed": site_name, "from": old, "to": new,
                "duration_ms": duration_ms, "domain_changed": domain_changed}

    except subprocess.TimeoutExpired as e:
        logger.error(f"webhook git timeout site={site_name}: {e}")
        raise HTTPException(504, "git-timeout")
    except subprocess.CalledProcessError as e:
        logger.error(f"webhook git failed site={site_name}: {e.stderr}")
        raise HTTPException(500, "git-failed")


@app.get("/deploys", dependencies=[Depends(require_jwt)])
async def deploys():
    """Last 50 deploy records (newest first)."""
    return _list_deploys()


def _read_domain(site_dir: Path) -> str:
    """Best-effort read of site.json:domain. Returns '' on any error."""
    try:
        return (_load_site_json(site_dir) or {}).get("domain", "") or ""
    except Exception:
        return ""
```

- [ ] **Step 4: Add the `Request` import to main.py**

Find this line (around line 16):

```python
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, UploadFile, File
```

Replace with:

```python
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, UploadFile, File, Request
```

- [ ] **Step 5: Syntax-check the modified main.py**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/113-metablogizer-deploy-webhook-sub-e-of-49
python3 -c "import ast; ast.parse(open('packages/secubox-metablogizer/api/main.py').read()); print('parse ok')"
```

Expected: `parse ok`.

- [ ] **Step 6: Run all tests**

```bash
cd packages/secubox-metablogizer
PYTHONPATH=api python3 -m pytest api/tests/ -v
```

Expected: 21+ passed (the webhook tests + the schema/rmtree/sites_cache tests from prior PRs). All green.

- [ ] **Step 7: Commit**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/113-metablogizer-deploy-webhook-sub-e-of-49
git add packages/secubox-metablogizer/api/main.py
git commit -m "feat(metablog-webhook): mount POST /webhook + GET /deploys (ref #113)

- Wires webhook.py into the FastAPI app: HMAC verify → classify →
  per-site lock → git_pull → cache invalidate → conditional nginx
  reload if site.json:domain changed → record + return.
- Git ops dispatched via loop.run_in_executor so the single uvicorn
  worker stays responsive during concurrent deploys.
- GET /deploys (JWT-gated) exposes the last 50 deploys for ops review.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: scripts/metablog-webhook-install.sh — Gitea API registration

**Files:**
- Create: `scripts/metablog-webhook-install.sh`
- Create: `scripts/metablog-webhook-uninstall.sh`

- [ ] **Step 1: Write the install script**

```bash
cat > scripts/metablog-webhook-install.sh <<'BASH'
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# scripts/metablog-webhook-install.sh
# Register the deploy webhook on every metablog-* repo on Gitea.
# Idempotent: skips repos that already have a hook with the target URL.

set -euo pipefail

GITEA_URL="${GITEA_URL:-https://gitea.gk2.secubox.in}"
GITEA_TOKEN=""
WEBHOOK_URL="${WEBHOOK_URL:-https://admin.gk2.secubox.in/api/v1/metablogizer/webhook}"
SECRET_FILE=""
OWNER="${OWNER:-gandalf}"
DRY_RUN=0

usage() {
  cat <<EOF
Usage: $0 --gitea-token <token> --secret-file <path> [options]

Required:
  --gitea-token <token>   Gitea admin or repo-admin API token
  --secret-file <path>    File containing the HMAC shared secret (or "-" for stdin)

Options:
  --gitea-url   <url>     Gitea base URL (default: $GITEA_URL)
  --webhook-url <url>     Webhook target URL (default: $WEBHOOK_URL)
  --owner       <user>    Repo owner (default: $OWNER)
  --dry-run               List what would be done; make no changes
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gitea-url)   GITEA_URL="$2"; shift 2 ;;
    --gitea-token) GITEA_TOKEN="$2"; shift 2 ;;
    --webhook-url) WEBHOOK_URL="$2"; shift 2 ;;
    --secret-file) SECRET_FILE="$2"; shift 2 ;;
    --owner)       OWNER="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$GITEA_TOKEN" ]] || { echo "--gitea-token required" >&2; exit 2; }
[[ -n "$SECRET_FILE" ]] || { echo "--secret-file required" >&2; exit 2; }

if [[ "$SECRET_FILE" == "-" ]]; then
  SECRET="$(cat)"
else
  [[ -r "$SECRET_FILE" ]] || { echo "secret file not readable: $SECRET_FILE" >&2; exit 2; }
  SECRET="$(cat "$SECRET_FILE")"
fi
SECRET="${SECRET//$'\n'/}"   # strip newlines
[[ -n "$SECRET" ]] || { echo "secret is empty" >&2; exit 2; }

API="$GITEA_URL/api/v1"
AUTH=(-H "Authorization: token $GITEA_TOKEN")
JSON=(-H "Content-Type: application/json")

# Page through all repos for OWNER, collect metablog-* names.
list_metablog_repos() {
  local page=1
  while :; do
    local body
    body="$(curl -sS "${AUTH[@]}" "$API/users/$OWNER/repos?limit=50&page=$page")"
    # If the response is empty array we stop.
    local count
    count="$(echo "$body" | jq 'length')"
    [[ "$count" -gt 0 ]] || break
    echo "$body" | jq -r '.[] | select(.name | startswith("metablog-")) | .name'
    [[ "$count" -lt 50 ]] && break
    page=$((page + 1))
  done
}

repo_has_hook() {
  local repo="$1"
  curl -sS "${AUTH[@]}" "$API/repos/$OWNER/$repo/hooks" \
    | jq -e --arg url "$WEBHOOK_URL" 'any(.[]; .config.url == $url)' >/dev/null
}

install_hook() {
  local repo="$1"
  local payload
  payload="$(jq -n --arg url "$WEBHOOK_URL" --arg secret "$SECRET" '{
    type: "gitea",
    config: { url: $url, content_type: "json", secret: $secret },
    events: ["push"],
    active: true
  }')"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "would install: $repo"
    return 0
  fi
  curl -sS -o /dev/null -w "%{http_code}" \
    "${AUTH[@]}" "${JSON[@]}" \
    -X POST -d "$payload" \
    "$API/repos/$OWNER/$repo/hooks"
}

installed=0; skipped=0; failed=0
mapfile -t REPOS < <(list_metablog_repos)
echo "found ${#REPOS[@]} metablog-* repos"

for repo in "${REPOS[@]}"; do
  if repo_has_hook "$repo"; then
    skipped=$((skipped + 1))
    printf "skip %s already-hooked\n" "$repo"
    continue
  fi
  code="$(install_hook "$repo" 2>/dev/null || echo "000")"
  if [[ $DRY_RUN -eq 1 ]]; then
    installed=$((installed + 1))
  elif [[ "$code" == "201" ]]; then
    installed=$((installed + 1))
    printf "install %s ok\n" "$repo"
  else
    failed=$((failed + 1))
    printf "install %s FAIL http=%s\n" "$repo" "$code"
  fi
done

echo "summary: installed=$installed skipped=$skipped failed=$failed"
[[ $failed -eq 0 ]]
BASH
chmod +x scripts/metablog-webhook-install.sh
```

- [ ] **Step 2: Write the uninstall script**

```bash
cat > scripts/metablog-webhook-uninstall.sh <<'BASH'
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# scripts/metablog-webhook-uninstall.sh
# Remove the deploy webhook from every metablog-* repo on Gitea.
# Idempotent: skips repos with no matching hook.

set -euo pipefail

GITEA_URL="${GITEA_URL:-https://gitea.gk2.secubox.in}"
GITEA_TOKEN=""
WEBHOOK_URL="${WEBHOOK_URL:-https://admin.gk2.secubox.in/api/v1/metablogizer/webhook}"
OWNER="${OWNER:-gandalf}"
DRY_RUN=0

usage() {
  cat <<EOF
Usage: $0 --gitea-token <token> [options]

Required:
  --gitea-token <token>   Gitea admin or repo-admin API token

Options:
  --gitea-url   <url>     Gitea base URL (default: $GITEA_URL)
  --webhook-url <url>     Webhook URL to remove (default: $WEBHOOK_URL)
  --owner       <user>    Repo owner (default: $OWNER)
  --dry-run               List what would be removed; make no changes
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gitea-url)   GITEA_URL="$2"; shift 2 ;;
    --gitea-token) GITEA_TOKEN="$2"; shift 2 ;;
    --webhook-url) WEBHOOK_URL="$2"; shift 2 ;;
    --owner)       OWNER="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$GITEA_TOKEN" ]] || { echo "--gitea-token required" >&2; exit 2; }

API="$GITEA_URL/api/v1"
AUTH=(-H "Authorization: token $GITEA_TOKEN")

list_metablog_repos() {
  local page=1
  while :; do
    local body count
    body="$(curl -sS "${AUTH[@]}" "$API/users/$OWNER/repos?limit=50&page=$page")"
    count="$(echo "$body" | jq 'length')"
    [[ "$count" -gt 0 ]] || break
    echo "$body" | jq -r '.[] | select(.name | startswith("metablog-")) | .name'
    [[ "$count" -lt 50 ]] && break
    page=$((page + 1))
  done
}

removed=0; skipped=0; failed=0
mapfile -t REPOS < <(list_metablog_repos)
echo "found ${#REPOS[@]} metablog-* repos"

for repo in "${REPOS[@]}"; do
  hooks="$(curl -sS "${AUTH[@]}" "$API/repos/$OWNER/$repo/hooks")"
  id="$(echo "$hooks" | jq --arg url "$WEBHOOK_URL" 'map(select(.config.url == $url)) | first | .id // empty')"
  if [[ -z "$id" || "$id" == "null" ]]; then
    skipped=$((skipped + 1))
    printf "skip %s no-matching-hook\n" "$repo"
    continue
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    removed=$((removed + 1))
    printf "would remove: %s hook-id=%s\n" "$repo" "$id"
    continue
  fi
  code="$(curl -sS -o /dev/null -w "%{http_code}" -X DELETE \
    "${AUTH[@]}" "$API/repos/$OWNER/$repo/hooks/$id")"
  if [[ "$code" == "204" ]]; then
    removed=$((removed + 1))
    printf "remove %s ok\n" "$repo"
  else
    failed=$((failed + 1))
    printf "remove %s FAIL http=%s\n" "$repo" "$code"
  fi
done

echo "summary: removed=$removed skipped=$skipped failed=$failed"
[[ $failed -eq 0 ]]
BASH
chmod +x scripts/metablog-webhook-uninstall.sh
```

- [ ] **Step 3: Smoke-check both scripts have valid bash syntax**

```bash
bash -n scripts/metablog-webhook-install.sh && echo "install: syntax ok"
bash -n scripts/metablog-webhook-uninstall.sh && echo "uninstall: syntax ok"
```

Expected: both print "syntax ok".

- [ ] **Step 4: Smoke-check `--help` works**

```bash
bash scripts/metablog-webhook-install.sh --help | head -3
bash scripts/metablog-webhook-uninstall.sh --help | head -3
```

Expected: each prints a `Usage:` line.

- [ ] **Step 5: Commit**

```bash
git add scripts/metablog-webhook-install.sh scripts/metablog-webhook-uninstall.sh
git commit -m "feat(metablog-webhook): install/uninstall scripts via Gitea API (ref #113)

- metablog-webhook-install.sh: pages through GITEA_URL/users/<owner>/repos,
  filters to metablog-*, checks existing hooks for the target URL,
  POSTs a new hook with content_type=json + secret + events=[push].
  Idempotent.
- metablog-webhook-uninstall.sh: reverse, DELETE on matching hook IDs.
- Both support --dry-run.

Exit non-zero if any operation failed.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Bash smoke test

**Files:**
- Create: `tests/scripts/test-metablog-webhook.sh`

- [ ] **Step 1: Write the smoke**

```bash
cat > tests/scripts/test-metablog-webhook.sh <<'BASH'
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# tests/scripts/test-metablog-webhook.sh
# Smoke test for /api/v1/metablogizer/webhook.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

BASE="${WEBHOOK_BASE:-https://admin.gk2.secubox.in}"
URL="$BASE/api/v1/metablogizer/webhook"
SECRET="${WEBHOOK_SECRET:-}"

log_step() { echo "[smoke step $1] $2"; }

# Gate 1: endpoint exists, GET returns 405 (POST-only) — not 404.
log_step 1 "endpoint reachable (GET returns 405)"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$URL")
if [[ "$code" != "405" && "$code" != "404" ]]; then
  echo "FAIL: GET $URL returned $code (expected 405)"; exit 1
fi
pass "GET $URL -> $code (endpoint exists, POST-only or routing checked)"

# Gate 2: POST without signature returns 401.
log_step 2 "unsigned POST returns 401"
code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST \
       -H "Content-Type: application/json" \
       -d '{"ref":"refs/heads/main","repository":{"name":"metablog-zkp","default_branch":"main"}}' \
       "$URL")
if [[ "$code" != "401" ]]; then
  echo "FAIL: unsigned POST returned $code (expected 401)"; exit 1
fi
pass "unsigned POST -> 401"

# Gate 3: signed POST with a known-unknown site returns 200 + skip=unknown-site.
# Requires WEBHOOK_SECRET to be set in env.
log_step 3 "signed POST with fake site returns 200 + skip"
if [[ -z "$SECRET" ]]; then
  echo "SKIP: WEBHOOK_SECRET not set; gate 3 not run"
else
  body='{"ref":"refs/heads/main","repository":{"name":"metablog-_smoke_does_not_exist","default_branch":"main"}}'
  sig=$(echo -n "$body" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')
  resp=$(curl -sk -X POST \
         -H "Content-Type: application/json" \
         -H "X-Gitea-Signature: $sig" \
         -d "$body" \
         "$URL")
  echo "$resp" | grep -q '"skip"' || {
    echo "FAIL: signed POST didn't return skip; got: $resp"; exit 1
  }
  pass "signed POST -> $(echo "$resp" | head -c 80)..."
fi

pass "all smoke gates green"
BASH
chmod +x tests/scripts/test-metablog-webhook.sh
```

- [ ] **Step 2: Syntax check**

```bash
bash -n tests/scripts/test-metablog-webhook.sh && echo "syntax ok"
```

- [ ] **Step 3: Commit**

```bash
git add tests/scripts/test-metablog-webhook.sh
git commit -m "test(metablog-webhook): 3-gate bash smoke (ref #113)

Gate 1: GET endpoint reachable (405 or 404, not connection refused)
Gate 2: POST without X-Gitea-Signature returns 401
Gate 3: POST with valid HMAC on a fake site returns 200 + skip=unknown-site

Gate 3 is skipped when WEBHOOK_SECRET env var is not set.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: README + tracking docs (Session 166)

**Files:**
- Modify: `packages/secubox-metablogizer/README.md`
- Modify: `.claude/WIP.md`, `.claude/HISTORY.md`

- [ ] **Step 1: Verify branch + sync from master**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/113-metablogizer-deploy-webhook-sub-e-of-49
bash scripts/agent-worktree.sh sync 113 2>&1 | tail -3
grep -oE "Session [0-9]+" .claude/WIP.md | sort -u -V | tail -3
```

Highest existing session is 165 (sub-D). New entry: **Session 166**.

- [ ] **Step 2: Insert a "Deploy webhook" section in `packages/secubox-metablogizer/README.md`**

Place it directly after the existing "## Version dashboard" section, before "## Installation":

```markdown
## Deploy webhook

A push to the default branch of any `metablog-*` repo on Gitea
triggers an automatic deploy of the live site.

- **Endpoint**: `POST https://admin.gk2.secubox.in/api/v1/metablogizer/webhook`
- **Auth**: HMAC-SHA256 in `X-Gitea-Signature` header, shared secret in
  `/etc/secubox/metablogizer-webhook.secret` (chmod 600, owner `secubox`)
- **Action**: `git fetch + git reset --hard origin/<default>` under a
  per-site `asyncio.Lock`; invalidates the dashboard cache; reloads nginx
  only if `site.json:domain` changed.

### Provisioning the secret (one-shot on the MOCHAbin)

```bash
sudo install -o secubox -g secubox -m 600 /dev/stdin \
  /etc/secubox/metablogizer-webhook.secret <<< "$(openssl rand -hex 32)"
sudo systemctl restart secubox-metablogizer
```

### Registering the webhook on every Gitea repo

```bash
scripts/metablog-webhook-install.sh \
  --gitea-token <admin-or-repo-token> \
  --secret-file /etc/secubox/metablogizer-webhook.secret
```

The installer is idempotent — re-run after adding new sites.

### Observability

- `journalctl -u secubox-metablogizer | grep '^deploy '`
- `GET /api/v1/metablogizer/deploys` (JWT-gated) returns the last 50 deploys

```

- [ ] **Step 3: Insert Session 166 at top of `.claude/WIP.md`**

Update the top-line date tag from `(Session 165)` to `(Session 166)`. Insert a new block immediately after the front-matter `---`, before the existing Session 165 block:

```markdown

## ✅ Session 166: MetaBlogizer deploy webhook (Issue #113, sub-E of #49)

### Objective
Auto-deploy on `git push` to metablog-* repos on Gitea. HMAC-verified webhook → git pull → cache invalidate → conditional nginx reload. Plus an idempotent Gitea API installer to register the webhook on all 166 repos. Closes the umbrella #49.

### Completed
- Brainstormed design → `docs/superpowers/specs/2026-05-13-metablog-deploy-webhook-design.md`
- Plan (8 tasks) → `docs/superpowers/plans/2026-05-13-metablog-deploy-webhook.md`
- New `api/webhook.py`: HMAC verify, secret loader (cached), classify_payload (accept/skip/malformed), per-site asyncio.Lock pool, git_pull helper, 50-entry deploy ring buffer
- `main.py` mounts `POST /webhook` (public, HMAC-gated) and `GET /deploys` (JWT-gated)
- `scripts/metablog-webhook-install.sh` + `metablog-webhook-uninstall.sh` (Gitea API, idempotent, --dry-run)
- 3-gate bash smoke `tests/scripts/test-metablog-webhook.sh`
- 21 pytest cases (HMAC, secret loader, ring buffer, git_pull, classify_payload, lock semantics)

### Followups
- Streamlit auto-deploy via a parallel webhook (separate issue if needed)
- Optional drill-in UI surfacing `GET /deploys` for ops review

```

- [ ] **Step 4: Mirror in `.claude/HISTORY.md`** under `## 2026-05-13` (create the date heading if not present; place above the existing `## 2026-05-12` block):

```markdown
## 2026-05-13

### Session 166 — MetaBlogizer deploy webhook (Issue #113, sub-E of #49)

**Goal:** Close the umbrella #49: auto-deploy on `git push` to metablog-* repos. HMAC-verified webhook + per-site lock + ring buffer + Gitea API installer.

**Done:**
- Spec: `docs/superpowers/specs/2026-05-13-metablog-deploy-webhook-design.md`
- Plan: `docs/superpowers/plans/2026-05-13-metablog-deploy-webhook.md` (8 tasks)
- `api/webhook.py`: verify_signature, load_secret (cached), classify_payload, site_lock pool, git_pull, ring buffer (50 entries)
- `main.py`: POST /webhook (public, HMAC), GET /deploys (JWT)
- `scripts/metablog-webhook-{install,uninstall}.sh` — Gitea API, idempotent, --dry-run
- Bash smoke `tests/scripts/test-metablog-webhook.sh` (3 gates)
- 21 pytest cases

**Followups:**
- Streamlit auto-deploy webhook (separate scope)

---

```

(Leave the existing `## 2026-05-12` section untouched.)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metablogizer/README.md .claude/WIP.md .claude/HISTORY.md
git commit -m "docs(metablog-webhook): Session 166 tracking + README deploy section (ref #113)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Finish worktree + PR

**Files:** none modified.

- [ ] **Step 1: Final pytest sweep**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/113-metablogizer-deploy-webhook-sub-e-of-49/packages/secubox-metablogizer
PYTHONPATH=api python3 -m pytest api/tests/ -v 2>&1 | tail -20
```

Expected: 21 webhook tests + 5 sites_cache + 2 rmtree + 8 site_schema = 36 passed. If any regression, STOP and fix.

- [ ] **Step 2: Bash smoke (syntax only — live host smoke happens post-merge)**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/113-metablogizer-deploy-webhook-sub-e-of-49
bash -n tests/scripts/test-metablog-webhook.sh && echo "syntax ok"
```

- [ ] **Step 3: Push + open PR**

```bash
bash scripts/agent-worktree.sh finish 2>&1 | tail -5
```

Note the PR number printed at the end.

- [ ] **Step 4: Set PR title + body via REST API**

```bash
PR=<N from step 3>
gh api -X PATCH /repos/CyberMind-FR/secubox-deb/pulls/$PR \
  -f title="MetaBlogizer deploy webhook (Refs #49 sub-E, closes #113)" \
  -f body="$(cat <<EOF
Closes #113. Closes the umbrella #49.

## What is live (once merged + deployed)

A push to the default branch of any \`metablog-*\` repo on Gitea triggers a deploy of the live site within seconds. No more SSH-and-pull.

## Pieces

- Spec — \`docs/superpowers/specs/2026-05-13-metablog-deploy-webhook-design.md\`
- Plan — \`docs/superpowers/plans/2026-05-13-metablog-deploy-webhook.md\` (8 tasks)
- New module \`api/webhook.py\`: HMAC verify (constant-time), secret loader (cached), classify_payload (accept/skip/malformed), per-site asyncio.Lock pool, git_pull with timeouts, 50-entry deploy ring buffer
- \`main.py\`: mounts \`POST /webhook\` (public, HMAC-gated) and \`GET /deploys\` (JWT-gated)
- \`scripts/metablog-webhook-install.sh\` + \`metablog-webhook-uninstall.sh\` — Gitea API per-repo registration, idempotent, --dry-run
- \`tests/scripts/test-metablog-webhook.sh\` — 3-gate bash smoke
- 21 new pytest cases (HMAC, classify, lock, git_pull, ring buffer, secret loader)

## Operational steps after merge

1. \`sudo install -o secubox -g secubox -m 600 /dev/stdin /etc/secubox/metablogizer-webhook.secret <<< "\$(openssl rand -hex 32)"\` on the MOCHAbin
2. \`systemctl restart secubox-metablogizer\`
3. \`scripts/metablog-webhook-install.sh --gitea-token <token> --secret-file /etc/secubox/metablogizer-webhook.secret\`
4. Probe push to one test repo, observe \`journalctl -u secubox-metablogizer | grep '^deploy '\` and \`GET /api/v1/metablogizer/deploys\`.

## Scope

\`Refs #49 (sub-project E)\` — \`Closes #113\`. With this, the umbrella #49 has nothing else open.
EOF
)" >/dev/null
echo "PR #\$PR updated"
```

- [ ] **Step 5: Comment on #49**

```bash
gh issue comment 49 --body "Sub-project E (deploy webhook) up for review in PR #\$PR. This is the last open sub-project of #49.

Operational steps after merge:
1. Provision the HMAC secret (one-shot, on the MOCHAbin)
2. Restart the metablogizer service
3. Run \`scripts/metablog-webhook-install.sh\` to register the hook on all 166 repos
4. Verify with a probe push"
```

---

## Self-review

**1. Spec coverage:**

- Spec § *Component 1 — Webhook endpoint* → Task 4 ✓ (mount + dispatcher in main.py); the lower-level pieces (HMAC, classify, lock, git_pull, ring buffer) are Tasks 1-3 ✓
- Spec § *Component 2 — Secret loader* → Task 1 step 3 ✓
- Spec § *Component 3 — Per-site async lock* → Task 3 step 7 ✓
- Spec § *Component 4 — Git helper* → Task 2 step 7 ✓
- Spec § *Component 5 — Deploy ring buffer* → Task 2 step 3 ✓ + GET /deploys in Task 4 ✓
- Spec § *Component 6 — Webhook installer script* → Task 5 ✓ (install + uninstall, --dry-run, idempotent)
- Spec § *Component 7 — HAProxy / nginx routing* → no change required (covered by existing routing); no task needed ✓
- Spec § *File-level changes* table — Tasks 1-7 cover each row ✓
- Spec § *Validation gate* — Tasks 6, 8 (smoke + final pytest sweep + post-merge probe push instructions in PR body) ✓
- Spec § *Error handling* — addressed in Task 4 step 3 (HMAC mismatch → 401, JSON parse → 400, missing site/git → 200+skip, git timeout → 504, git failure → 500, secret missing → 503) ✓
- Spec § *Testing* — pytest in Tasks 1-3 ✓ + bash smoke in Task 6 ✓

**2. Placeholder scan:**

- No "TBD" / "TODO" / "fill in later" anywhere.
- Task 4 step 3 references `_load_site_json` and `regenerate_nginx_config` — both already exist in master (line ~261 and the `_load_site_json` helper added by sub-C).
- Task 7 step 1 says the new session number is 166; the check command computes the next free integer at task time so a parallel session bumping to 167 is also covered.
- Task 8 uses `<N from step 3>` for the PR number — explicit "Note the PR number" instruction prior. Acceptable.

**3. Type / identifier consistency:**

- `verify_signature(secret: bytes, body: bytes, signature_hex: str) -> bool` — referenced consistently in Task 1 (definition) and Task 4 (usage).
- `load_secret() -> bytes` — same.
- `classify_payload(payload: dict) -> tuple[str, dict]` — tasks 3 and 4 match.
- `site_lock(name: str) -> asyncio.Lock` — async coroutine; Task 4's `await site_lock(site_name)` is consistent.
- `git_pull(site_dir: Path, branch: str) -> tuple[str, str]` — Task 2 def, Task 4 dispatch via `run_in_executor`.
- `_record_deploy(entry: dict)` — used in Task 4.
- `list_deploys() -> dict` — Task 2 def, Task 4 usage as `_list_deploys`.
- `METABLOG_PREFIX = "metablog-"` — only referenced inside `classify_payload`. Self-contained.

No identifier drift across tasks. Plan ready to execute.
