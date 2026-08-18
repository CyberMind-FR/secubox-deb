<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Sentinel Activation + ToolBoX Surfaces Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the `sbx-sentinel` compromise-detection daemon live (async, report-only) on gk2 and surface its detections on three ToolBoX surfaces — the admin WebUI fleet tab, the per-device kbin HTML report, and the per-device PDF report — then produce a GPT demo prompt.

**Architecture:** The already-merged (dark) `sbx-sentinel` daemon exposes a read-only localhost status HTTP (`/stats`, `/verdicts`). A one-line Go change adds a per-`mac` filter to `/verdicts`. A new Python module `sentinel_link.py` in the `secubox-toolbox` portal does fail-safe stdlib fetches of that HTTP and computes a compromise/evaluation summary (`assess`). Three surfaces consume it: admin proxy routes + a WebUI tab (fleet), and `build_report_data`'s new `sentinel` key feeding both the kbin HTML template and the PDF renderer (per-device). Activation is the final deploy+verify task.

**Tech Stack:** Go (bbolt store, net/http), Python 3.11 (FastAPI portal, fpdf2, Jinja2), vanilla JS (P31 light-skin portal), systemd on Debian arm64 (gk2).

## Global Constraints

- **Report-only, defensive.** Do NOT enable the inline hot-path blocking gate. Heuristic and zero-click detections NEVER escalate to a "compromised" verdict and are never auto-blocked. `FinalizeAction` threshold stays 85.
- **PII floor:** every surface shows `mac_hash` ONLY — no IP, no other identifier.
- **No `waf_bypass`; no new external surface.** Daemon status HTTP binds `127.0.0.1:8790` only — no nft rule, never proxied to the outside.
- **Fail-safe everywhere:** a dark/wedged daemon must NEVER raise out to a portal client or break a report/PDF build. Absent daemon → an "inactive" state, HTTP 200, valid PDF.
- **No new Debian dependency** for the daemon fetch — use the Python stdlib (`urllib.request`) with a bounded timeout (1.5s).
- **gk2 ops rules:** never touch the shared `/run/secubox` (1777) or `/var/lib/secubox` parents; restart the 4 sbxmitm ng-workers sequentially with socket-wait (no mass restart); respect `RuntimeDirectoryPreserve=yes`.
- **Honest disposition:** `action=block` → "Bloquée"; `action=report` → "Détectée — observée" (never claim "blocked before any data left" for an observed/async detection).
- **Commit trailer:** every commit ends with `(ref #823)`. No Claude Code references in commits/PRs.
- **Verdict JSON keys are lowercase:** `class, severity, confidence, action, evidence, mac_hash, ts, report`.
- **Python tests run:** `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/<file> -q`.
- **Go tests run:** `cd packages/secubox-toolbox-ng && go test ./cmd/sbx-sentinel/...`.

---

### Task 1: Go — per-`mac` filter on `/verdicts`

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbx-sentinel/http.go` (the `/verdicts` handler, ~line 102-134)
- Test: `packages/secubox-toolbox-ng/cmd/sbx-sentinel/http_test.go`

**Interfaces:**
- Consumes: `store.Recent(limit int) ([]Verdict, error)` and `store.ByMac(macHash string, limit int) ([]Verdict, error)` (both exist in `internal/sentinel/store.go`); `verdictView` struct (http.go:47); `statusRecentLimit = 500`.
- Produces: `GET /verdicts?mac=<hash>&limit=N` → JSON array of `verdictView`, filtered to `macHash` via `ByMac`. `mac` absent → unchanged `Recent` behavior.

- [ ] **Step 1: Write the failing test**

Add to `packages/secubox-toolbox-ng/cmd/sbx-sentinel/http_test.go`:

```go
func TestVerdictsFilterByMac(t *testing.T) {
	store := openTestStore(t)
	store.Record(&sentinel.Verdict{
		Class: sentinel.ClassSpywarePegasus, Action: sentinel.ActionBlock,
		Evidence: map[string]string{"ioc_value": "a.example"},
		MacHash:  "aaaa", TS: time.Now().Unix(),
	})
	store.Record(&sentinel.Verdict{
		Class: sentinel.ClassSpywarePredator, Action: sentinel.ActionReport,
		Evidence: map[string]string{"ioc_value": "b.example"},
		MacHash:  "bbbb", TS: time.Now().Unix(),
	})
	mux := newStatusMux(store)

	req := httptest.NewRequest(http.MethodGet, "/verdicts?mac=aaaa", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var got []verdictView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].MacHash != "aaaa" {
		t.Fatalf("want 1 verdict for aaaa, got %d: %+v", len(got), got)
	}

	// Unknown mac → empty list, still 200.
	req = httptest.NewRequest(http.MethodGet, "/verdicts?mac=zzzz", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown-mac status %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode2: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 for unknown mac, got %d", len(got))
	}
}
```

> Note: `store.Record` takes `*Verdict` (see the existing `/verdicts` test which builds the store the same way). If the existing test uses a helper to seed, mirror it — keep this test self-contained otherwise.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox-ng && go test ./cmd/sbx-sentinel/ -run TestVerdictsFilterByMac -v`
Expected: FAIL — the `mac` param is ignored, so `mac=aaaa` returns both verdicts (len 2, not 1).

- [ ] **Step 3: Implement the filter in the `/verdicts` handler**

In `http.go`, inside the `mux.HandleFunc("/verdicts", …)` handler, after the `limit` is parsed and BEFORE `recent, err := store.Recent(limit)`, branch on `mac`:

```go
		limit := statusRecentLimit
		if q := r.URL.Query().Get("limit"); q != "" {
			if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= statusRecentLimit {
				limit = n
			}
		}
		var (
			recent []sentinel.Verdict
			err    error
		)
		if mac := r.URL.Query().Get("mac"); mac != "" {
			recent, err = store.ByMac(mac, limit)
		} else {
			recent, err = store.Recent(limit)
		}
		if err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
```

Replace the existing `recent, err := store.Recent(limit)` line (and its `if err != nil` block) with the block above. Leave the `verdictView` marshalling loop below it unchanged. Confirm the `sentinel` package is already imported in http.go (it is — `verdictView` uses `v.Class` etc.).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/secubox-toolbox-ng && go test ./cmd/sbx-sentinel/...`
Expected: PASS — `TestVerdictsFilterByMac` plus the existing `/verdicts`, `/stats`, non-GET tests all green.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbx-sentinel/http.go packages/secubox-toolbox-ng/cmd/sbx-sentinel/http_test.go
git commit -m "feat(sentinel): add mac filter to /verdicts status endpoint (ref #823)"
```

---

### Task 2: Python — `sentinel_link.py` (fail-safe fetch + assess)

**Files:**
- Create: `packages/secubox-toolbox/secubox_toolbox/sentinel_link.py`
- Test: `packages/secubox-toolbox/tests/test_sentinel_link.py`

**Interfaces:**
- Consumes: the daemon HTTP `GET /stats` → `{"detections":N,"blocked":N,"spyware":N}` and `GET /verdicts[?mac=&limit=]` → list of `{class,severity,confidence,action,evidence,mac_hash,ts,report}`.
- Produces (imported by Tasks 3, 5, 6):
  - `daemon_base() -> str | None`
  - `fetch_stats() -> dict`
  - `fetch_verdicts(limit: int = 50) -> list[dict]`
  - `fetch_detections(mac_hash: str, limit: int = 50) -> list[dict]`
  - `assess(detections: list[dict]) -> dict` with keys `tier` (`"clean"|"suspicious"|"compromised"`), `worst_severity: int`, `worst_confidence: int`, `count: int`, `dominant_class: str`, `strongest: dict | None`
  - `disposition(action: str) -> str`

- [ ] **Step 1: Write the failing tests**

Create `packages/secubox-toolbox/tests/test_sentinel_link.py`:

```python
from secubox_toolbox import sentinel_link as sl


def test_assess_clean_when_no_detections():
    a = sl.assess([])
    assert a["tier"] == "clean"
    assert a["count"] == 0
    assert a["strongest"] is None


def test_assess_report_only_spyware_is_suspicious():
    dets = [{"class": "spyware_pegasus", "severity": 95, "confidence": 95,
             "action": "report", "evidence": {}, "mac_hash": "aa", "ts": 1}]
    a = sl.assess(dets)
    assert a["tier"] == "suspicious"
    assert a["worst_severity"] == 95
    assert a["dominant_class"] == "spyware_pegasus"
    assert a["strongest"]["class"] == "spyware_pegasus"


def test_assess_high_conf_block_spyware_is_compromised():
    dets = [{"class": "spyware_pegasus", "severity": 95, "confidence": 95,
             "action": "block", "evidence": {}, "mac_hash": "aa", "ts": 1}]
    assert sl.assess(dets)["tier"] == "compromised"


def test_assess_zero_click_never_compromised_even_if_block():
    # zero-click is heuristic — must stay suspicious regardless of action.
    dets = [{"class": "zero_click", "severity": 90, "confidence": 90,
             "action": "block", "evidence": {}, "mac_hash": "aa", "ts": 1}]
    assert sl.assess(dets)["tier"] == "suspicious"


def test_assess_low_confidence_block_is_not_compromised():
    dets = [{"class": "malware_generic", "severity": 90, "confidence": 60,
             "action": "block", "evidence": {}, "mac_hash": "aa", "ts": 1}]
    assert sl.assess(dets)["tier"] == "suspicious"


def test_disposition_labels():
    assert sl.disposition("block") == "Bloquée"
    assert sl.disposition("report") == "Détectée — observée"
    assert sl.disposition("") == "Détectée — observée"


def test_fetch_stats_failsafe_when_daemon_down(monkeypatch):
    # Point at a base but make the HTTP call raise → {} (never raises out).
    monkeypatch.setattr(sl, "daemon_base", lambda: "http://127.0.0.1:9")
    assert sl.fetch_stats() == {}
    assert sl.fetch_verdicts() == []
    assert sl.fetch_detections("aa") == []


def test_fetch_stats_none_base_returns_empty(monkeypatch):
    monkeypatch.setattr(sl, "daemon_base", lambda: None)
    assert sl.fetch_stats() == {}
    assert sl.fetch_verdicts() == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/test_sentinel_link.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'secubox_toolbox.sentinel_link'`.

- [ ] **Step 3: Implement `sentinel_link.py`**

Create `packages/secubox-toolbox/secubox_toolbox/sentinel_link.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ToolBoX Sentinel link
CyberMind — https://cybermind.fr

Fail-safe bridge from the ToolBoX portal to the sbx-sentinel daemon's
read-only localhost status HTTP, plus the compromise/evaluation summary.

Everything here is defensive and MUST NOT raise out to a caller: a dark or
wedged daemon degrades to empty results, never an exception. Detections
carry mac_hash only — no other PII passes through this module.
"""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from collections import Counter

log = logging.getLogger("secubox.toolbox.sentinel")

_TIMEOUT = 1.5  # seconds — a wedged daemon must not stall a portal request
_DEFAULT_ADDR = "127.0.0.1:8790"
_SENTINEL_ENV = "/etc/secubox/sentinel.env"

# Heuristic classes never escalate to "compromised" — they are behavioral
# guesses, not confirmed known-infrastructure hits. Keep in sync with the Go
# scorer's heuristicClasses (currently zero-click).
_HEURISTIC_CLASSES = {"zero_click"}
_HIGH_CONFIDENCE = 85  # mirrors Go HighConfidenceThreshold


def daemon_base() -> str | None:
    """Resolve the daemon status-HTTP base URL, or None if unconfigured.

    Order: SENTINEL_HTTP_ADDR from the process env, then from
    /etc/secubox/sentinel.env, then the 127.0.0.1:8790 default. An explicitly
    empty value (the dark default) yields None so callers show 'inactive'.
    """
    addr = os.environ.get("SENTINEL_HTTP_ADDR")
    if addr is None:
        addr = _read_env_addr()
    if addr is None:
        addr = _DEFAULT_ADDR
    addr = addr.strip()
    if not addr:
        return None
    if not addr.startswith("http"):
        addr = "http://" + addr
    return addr.rstrip("/")


def _read_env_addr() -> str | None:
    """Best-effort read of SENTINEL_HTTP_ADDR from sentinel.env; None on any issue."""
    try:
        with open(_SENTINEL_ENV, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("SENTINEL_HTTP_ADDR="):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return None


def _get_json(path: str):
    """GET base+path and parse JSON. Returns None on ANY failure (never raises)."""
    base = daemon_base()
    if not base:
        return None
    try:
        req = urllib.request.Request(base + path, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # connection refused, timeout, bad JSON, HTTP error
        log.debug("sentinel fetch %s failed: %s", path, exc)
        return None


def fetch_stats() -> dict:
    data = _get_json("/stats")
    return data if isinstance(data, dict) else {}


def fetch_verdicts(limit: int = 50) -> list[dict]:
    limit = max(1, min(int(limit), 500))
    data = _get_json(f"/verdicts?limit={limit}")
    return data if isinstance(data, list) else []


def fetch_detections(mac_hash: str, limit: int = 50) -> list[dict]:
    if not mac_hash or not re.fullmatch(r"[0-9a-fA-F]{1,64}", mac_hash):
        return []
    limit = max(1, min(int(limit), 500))
    data = _get_json(f"/verdicts?mac={mac_hash}&limit={limit}")
    return data if isinstance(data, list) else []


def disposition(action: str) -> str:
    """Honest disposition label — an observed/async detection is not a block."""
    return "Bloquée" if action == "block" else "Détectée — observée"


def _is_confirmed_compromise(d: dict) -> bool:
    cls = str(d.get("class", ""))
    if cls in _HEURISTIC_CLASSES:
        return False
    return (
        d.get("action") == "block"
        and int(d.get("confidence", 0)) >= _HIGH_CONFIDENCE
    )


def assess(detections: list[dict]) -> dict:
    """Compromise/evaluation summary over one device's (or the fleet's) detections.

    tier: clean (none) · suspicious (report-only/heuristic) · compromised
    (a high-confidence, non-heuristic, block-action detection).
    """
    dets = detections or []
    if not dets:
        return {"tier": "clean", "worst_severity": 0, "worst_confidence": 0,
                "count": 0, "dominant_class": "", "strongest": None}
    strongest = max(dets, key=lambda d: (int(d.get("severity", 0)),
                                          int(d.get("confidence", 0))))
    tier = "compromised" if any(_is_confirmed_compromise(d) for d in dets) else "suspicious"
    classes = Counter(str(d.get("class", "")) for d in dets if d.get("class"))
    dominant = classes.most_common(1)[0][0] if classes else ""
    return {
        "tier": tier,
        "worst_severity": max(int(d.get("severity", 0)) for d in dets),
        "worst_confidence": max(int(d.get("confidence", 0)) for d in dets),
        "count": len(dets),
        "dominant_class": dominant,
        "strongest": strongest,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/test_sentinel_link.py -q`
Expected: PASS — all 8 tests green.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/sentinel_link.py packages/secubox-toolbox/tests/test_sentinel_link.py
git commit -m "feat(toolbox): sentinel_link — fail-safe daemon fetch + compromise assess (ref #823)"
```

---

### Task 3: Portal admin proxy routes (fleet)

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` (add two routes on the existing `router`)
- Test: `packages/secubox-toolbox/tests/test_sentinel_api.py`

**Interfaces:**
- Consumes: `sentinel_link.fetch_stats()`, `sentinel_link.fetch_verdicts(limit)`, `sentinel_link.assess(...)`.
- Produces: `GET /admin/sentinel/stats` → `{"active":bool,"detections":int,"blocked":int,"spyware":int}`; `GET /admin/sentinel/verdicts?limit=N` → `{"active":bool,"assess":{…},"detections":[…]}`. Both HTTP 200 even when the daemon is dark. Placed under `/admin/` so they inherit the portal's existing admin gating (like the other `/admin/*` routes, which carry no per-route `Depends`).

- [ ] **Step 1: Write the failing tests**

Create `packages/secubox-toolbox/tests/test_sentinel_api.py`:

```python
from fastapi.testclient import TestClient
from secubox_toolbox.app import app
from secubox_toolbox import sentinel_link as sl

client = TestClient(app)


def test_stats_active_when_daemon_up(monkeypatch):
    monkeypatch.setattr(sl, "fetch_stats",
                        lambda: {"detections": 3, "blocked": 1, "spyware": 2})
    r = client.get("/admin/sentinel/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["detections"] == 3 and body["spyware"] == 2


def test_stats_inactive_when_daemon_down(monkeypatch):
    monkeypatch.setattr(sl, "fetch_stats", lambda: {})
    r = client.get("/admin/sentinel/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is False
    assert body["detections"] == 0 and body["blocked"] == 0 and body["spyware"] == 0


def test_verdicts_shape_and_failsafe(monkeypatch):
    monkeypatch.setattr(sl, "fetch_verdicts", lambda limit=50: [
        {"class": "spyware_pegasus", "severity": 95, "confidence": 95,
         "action": "report", "evidence": {}, "mac_hash": "aa", "ts": 1, "report": "R"},
    ])
    r = client.get("/admin/sentinel/verdicts")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["assess"]["tier"] == "suspicious"
    assert len(body["detections"]) == 1

    monkeypatch.setattr(sl, "fetch_verdicts", lambda limit=50: [])
    r = client.get("/admin/sentinel/verdicts")
    assert r.status_code == 200
    assert r.json()["active"] is False
    assert r.json()["assess"]["tier"] == "clean"
```

> If `TestClient(app)` requires auth and returns 401 for `/admin/*` in tests, check how the existing `tests/test_admin_*.py` construct the client (they may use a fixture or a test app without the gate). Mirror that exact setup — do not weaken the gate to make the test pass.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/test_sentinel_api.py -q`
Expected: FAIL — routes return 404 (not yet defined).

- [ ] **Step 3: Implement the two routes**

In `packages/secubox-toolbox/secubox_toolbox/api.py`, add near the other `/admin/*` GET routes (e.g. after the `/admin/tor/*` block). First ensure the import exists at the top of the file with the other `from secubox_toolbox import …`:

```python
from secubox_toolbox import sentinel_link
```

Then add:

```python
@router.get("/admin/sentinel/stats")
async def admin_sentinel_stats() -> dict:
    """Fleet Sentinel counters for the WebUI tab. Fail-safe: a dark daemon
    yields active=false with zeroed counters (HTTP 200), never a 5xx."""
    stats = sentinel_link.fetch_stats()
    if not stats:
        return {"active": False, "detections": 0, "blocked": 0, "spyware": 0}
    return {
        "active": True,
        "detections": int(stats.get("detections", 0)),
        "blocked": int(stats.get("blocked", 0)),
        "spyware": int(stats.get("spyware", 0)),
    }


@router.get("/admin/sentinel/verdicts")
async def admin_sentinel_verdicts(limit: int = 50) -> dict:
    """Recent fleet detections + the compromise assessment for the WebUI tab."""
    dets = sentinel_link.fetch_verdicts(limit)
    return {
        "active": bool(dets),
        "assess": sentinel_link.assess(dets),
        "detections": dets,
    }
```

> `limit` is a plain query int — FastAPI parses `?limit=`. `fetch_verdicts` already clamps it.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/test_sentinel_api.py -q`
Expected: PASS — 3 tests green.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/tests/test_sentinel_api.py
git commit -m "feat(toolbox): /admin/sentinel/{stats,verdicts} fleet proxy routes (ref #823)"
```

---

### Task 4: WebUI ToolBoX Sentinel tab (fleet)

**Files:**
- Modify: `packages/secubox-toolbox/www/toolbox/index.html` (nav button, panel section, `switchTab` hook, `loadSentinel()` JS)

**Interfaces:**
- Consumes: `GET /admin/sentinel/stats` and `GET /admin/sentinel/verdicts` (Task 3); the existing `J(path)` fetch helper (returns parsed JSON or `{__error}`); the existing `switchTab(name)` function; `.tabs`/`.panel` CSS classes.
- Produces: a `data-tab="sentinel"` tab.

- [ ] **Step 1: Add the nav button**

In `www/toolbox/index.html`, in `<nav class="tabs" id="tabs">`, insert between the `tor` and `config` buttons:

```html
        <button class="tab" data-tab="sentinel" onclick="switchTab('sentinel')">🛡️ Sentinelle</button>
```

- [ ] **Step 2: Add the panel section**

After the `tor` panel `</section>` (and before the `config` panel), insert:

```html
    <section class="panel" id="panel-sentinel">
        <div class="row" style="margin-bottom:.6rem">
            <button onclick="loadSentinel()">🔁 Refresh</button>
            <span id="sentinel-state" class="v" style="margin-left:.5rem">…</span>
        </div>
        <div id="sentinel-verdict" class="card" style="margin-bottom:.8rem"></div>
        <div id="sentinel-detections"></div>
    </section>
```

> Use whatever the file's existing panels use for a wrapper (`class="card"`/`class="row"`); match the surrounding markup exactly. If those classes differ, copy the tor panel's structure and swap the ids.

- [ ] **Step 3: Hook lazy-load into `switchTab`**

In the `switchTab(name)` function, add alongside the other lazy-loads:

```javascript
    if (name === 'sentinel') loadSentinel();
```

- [ ] **Step 4: Add `loadSentinel()`**

Near the other `load*()` functions, add:

```javascript
const SENTINEL_TIER = {
    clean:        { emoji: '🟢', label: 'Aucune compromission détectée', color: 'var(--green,#2a9d3a)' },
    suspicious:   { emoji: '🟠', label: 'Activité suspecte',              color: 'var(--amber,#c77d00)' },
    compromised:  { emoji: '🔴', label: 'Compromission confirmée',        color: 'var(--red,#e63946)' },
};

function sentinelDisposition(action) {
    return action === 'block' ? 'Bloquée' : 'Détectée — observée';
}

function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

async function loadSentinel() {
    const stateEl = document.getElementById('sentinel-state');
    const vEl = document.getElementById('sentinel-verdict');
    const dEl = document.getElementById('sentinel-detections');
    const stats = await J('/admin/sentinel/stats');
    const data = await J('/admin/sentinel/verdicts');

    if (stats.__error || data.__error || !data.active) {
        stateEl.textContent = '⚪ Sentinelle inactive';
        vEl.innerHTML = '<span class="v">Sentinelle inactive — aucune donnée de détection réseau.</span>';
        dEl.innerHTML = '';
        return;
    }

    stateEl.textContent = `🟢 active · ${stats.detections || 0} détections · ${stats.blocked || 0} bloquées · ${stats.spyware || 0} spyware`;

    const a = data.assess || { tier: 'clean' };
    const t = SENTINEL_TIER[a.tier] || SENTINEL_TIER.clean;
    vEl.innerHTML =
        `<div style="font-size:1.1rem;color:${t.color}">${t.emoji} ${esc(t.label)}</div>` +
        `<div class="v" style="margin-top:.4rem">Sévérité max ${a.worst_severity || 0}/100 · ` +
        `Confiance ${a.worst_confidence || 0}/100 · ${a.count || 0} détections · ` +
        `${esc(a.dominant_class || '—')}</div>`;

    const rows = (data.detections || []).map(d => {
        const when = d.ts ? new Date(d.ts * 1000).toISOString().replace('T', ' ').slice(0, 19) : '?';
        return `<tr>
            <td>${esc(d.class)}</td>
            <td>${d.severity || 0}/${d.confidence || 0}</td>
            <td>${esc(sentinelDisposition(d.action))}</td>
            <td>${when}</td>
            <td><details><summary>rapport</summary><pre style="white-space:pre-wrap;font-size:.75rem">${esc(d.report)}</pre></details></td>
        </tr>`;
    }).join('');
    dEl.innerHTML = rows
        ? `<table><thead><tr><th>Menace</th><th>Sév/Conf</th><th>Disposition</th><th>Vu</th><th>Détail</th></tr></thead><tbody>${rows}</tbody></table>`
        : '<span class="v">Aucune détection récente.</span>';
}
```

- [ ] **Step 5: Verify the inline JS parses**

Extract the inline `<script>` block and syntax-check:

Run:
```bash
cd packages/secubox-toolbox && python3 - <<'PY'
import re, subprocess, tempfile, os
html = open("www/toolbox/index.html", encoding="utf-8").read()
scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
src = "\n".join(scripts)
p = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False)
p.write(src); p.close()
print(subprocess.run(["node", "--check", p.name]).returncode)
os.unlink(p.name)
PY
```
Expected: prints `0` (no syntax errors). If `node` is unavailable, load the page in a browser against a running portal and confirm the Sentinelle tab renders without console errors.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-toolbox/www/toolbox/index.html
git commit -m "feat(toolbox): WebUI Sentinelle fleet tab (evaluation + detections) (ref #823)"
```

---

### Task 5: Fold Sentinel into `build_report_data` (per-device data path)

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/reports.py` (`build_report_data`, ~line 60)
- Test: `packages/secubox-toolbox/tests/test_report_sentinel.py`

**Interfaces:**
- Consumes: `sentinel_link.fetch_detections(mac_hash)`, `sentinel_link.assess(...)`.
- Produces: `report["sentinel"] = {"active": bool, "assess": {…}, "detections": [ … ]}` — consumed by Task 6 (HTML) and Task 7 (PDF).

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-toolbox/tests/test_report_sentinel.py`:

```python
from secubox_toolbox import reports
from secubox_toolbox import sentinel_link as sl


def test_build_report_data_folds_sentinel_active(monkeypatch):
    monkeypatch.setattr(sl, "fetch_detections", lambda mh, limit=50: [
        {"class": "spyware_pegasus", "severity": 95, "confidence": 95,
         "action": "report", "evidence": {}, "mac_hash": "aa", "ts": 1, "report": "R"},
    ])
    rep = reports.build_report_data("aa", {"device_type": "phone"})
    assert rep["sentinel"]["active"] is True
    assert rep["sentinel"]["assess"]["tier"] == "suspicious"
    assert len(rep["sentinel"]["detections"]) == 1


def test_build_report_data_sentinel_inactive_when_daemon_down(monkeypatch):
    monkeypatch.setattr(sl, "fetch_detections", lambda mh, limit=50: [])
    rep = reports.build_report_data("aa", {})
    assert rep["sentinel"]["active"] is False
    assert rep["sentinel"]["assess"]["tier"] == "clean"
    assert rep["sentinel"]["detections"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/test_report_sentinel.py -q`
Expected: FAIL — `KeyError: 'sentinel'`.

- [ ] **Step 3: Fold the `sentinel` key into `build_report_data`**

At the top of `reports.py`, add with the other imports:

```python
from secubox_toolbox import sentinel_link
```

Rewrite `build_report_data` to build the base dict then attach `sentinel`:

```python
def build_report_data(mac_hash: str, session_data: dict) -> dict:
    """Aggregate session data into the structure consumed by render_pdf().
    session_data is expected to be the dict produced by api._aggregate_session()."""
    report = {
        "mac_hash": mac_hash,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **session_data,
    }
    detections = sentinel_link.fetch_detections(mac_hash)
    report["sentinel"] = {
        "active": bool(detections),
        "assess": sentinel_link.assess(detections),
        "detections": detections,
    }
    return report
```

> `fetch_detections` is fully fail-safe (dark daemon → `[]`), so `active` is `False` and the report still builds. This means "no detections" and "daemon dark" both render as the calm inactive/clean state — acceptable and safe (the surfaces don't over-claim either way).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/test_report_sentinel.py -q`
Expected: PASS — 2 tests green.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/reports.py packages/secubox-toolbox/tests/test_report_sentinel.py
git commit -m "feat(toolbox): fold per-device Sentinel detections into build_report_data (ref #823)"
```

---

### Task 6: kbin HTML report — Sentinel tab (per-device)

**Files:**
- Modify: `packages/secubox-toolbox/conf/report-live.html.j2` (add a tab in the existing `.tabs`/`.tab-pane` shell)

**Interfaces:**
- Consumes: the Jinja `report` context, specifically `report.sentinel = {active, assess:{tier,worst_severity,worst_confidence,count,dominant_class}, detections:[{class,severity,confidence,action,ts,report}]}` (Task 5).
- Produces: a per-device Compromission tab in the report.

- [ ] **Step 1: Locate the tab shell**

Read `conf/report-live.html.j2` around the `<div class="tabs">` (~line 208) and the sibling `.tab-pane` blocks. Note the exact button markup and how a pane is shown/hidden (the file's own `.tabs button` / `.tab-pane.active` convention from #699), and the tab-switch JS already in the file.

- [ ] **Step 2: Add the tab button + pane**

Following the file's existing tab pattern, add a new tab button (label `🛡️ Compromission`) and a matching `.tab-pane`. Use the file's own show/hide mechanism (match how the neighboring panes wire their button → pane). The pane body:

```html
{# 🛡️ Sentinel — per-device compromise, evaluation, detections (#823) #}
<div class="tab-pane" id="tab-sentinel">
  {% set s = report.sentinel or {} %}
  {% set a = s.assess or {} %}
  {% if not s.active %}
    <div class="card"><span style="color:var(--dim)">🛡️ Sentinelle inactive — aucune donnée de détection réseau.</span></div>
  {% else %}
    <div class="card">
      {% set tier = a.tier or 'clean' %}
      <h3>
        {% if tier == 'compromised' %}🔴 Compromission confirmée
        {% elif tier == 'suspicious' %}🟠 Activité suspecte
        {% else %}🟢 Aucune compromission détectée{% endif %}
      </h3>
      <div style="color:var(--dim);font-size:.85rem;margin-top:.3rem">
        Sévérité max {{ a.worst_severity or 0 }}/100 · Confiance {{ a.worst_confidence or 0 }}/100 ·
        {{ a.count or 0 }} détection(s) · {{ a.dominant_class or '—' }}
      </div>
    </div>
    <div class="card">
      <h3>Détections</h3>
      {% if s.detections %}
      <table>
        <thead><tr><th>Menace</th><th>Sév/Conf</th><th>Disposition</th><th>Vu</th></tr></thead>
        <tbody>
        {% for d in s.detections %}
          <tr>
            <td>{{ d.class }}</td>
            <td>{{ d.severity or 0 }}/{{ d.confidence or 0 }}</td>
            <td>{% if d.action == 'block' %}Bloquée{% else %}Détectée — observée{% endif %}</td>
            <td>{{ d.ts }}</td>
          </tr>
          {% if d.report %}
          <tr><td colspan="4"><details><summary style="cursor:pointer;color:var(--dim)">rapport</summary><pre style="white-space:pre-wrap;font-size:.72rem">{{ d.report }}</pre></details></td></tr>
          {% endif %}
        {% endfor %}
        </tbody>
      </table>
      {% else %}
      <span style="color:var(--dim)">Aucune détection récente sur cet appareil.</span>
      {% endif %}
    </div>
  {% endif %}
</div>
```

> Jinja `{{ d.report }}` and `{{ d.class }}` are auto-escaped by the template environment (the file already renders untrusted-ish fields elsewhere the same way — confirm the env has autoescape on for `.html.j2`; if not, wrap with `| e`). Match the file's card/heading classes exactly.

- [ ] **Step 3: Render-smoke the template**

Run:
```bash
cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 - <<'PY'
from jinja2 import Environment, FileSystemLoader, select_autoescape
env = Environment(loader=FileSystemLoader("conf"), autoescape=select_autoescape(["html", "j2"]))
tpl = env.get_template("report-live.html.j2")
# inactive
print("inactive ok:", bool(tpl.render(report={"mac_hash": "aa", "sentinel": {"active": False, "assess": {}, "detections": []}})))
# with a detection
print("active ok:", bool(tpl.render(report={"mac_hash": "aa", "sentinel": {
    "active": True,
    "assess": {"tier": "suspicious", "worst_severity": 95, "worst_confidence": 95, "count": 1, "dominant_class": "spyware_pegasus"},
    "detections": [{"class": "spyware_pegasus", "severity": 95, "confidence": 95, "action": "report", "ts": 1, "report": "R"}],
}})))
PY
```
Expected: prints `inactive ok: True` and `active ok: True` with no Jinja exception.

> If the template requires many other context keys to render (it aggregates a full report), pass a minimal stub for those it references, OR render only by loading and checking `env.get_template(...).render(...)` doesn't raise on the `report.sentinel` access path. If full render needs too much scaffolding, at minimum assert the template *compiles* with `env.get_template("report-live.html.j2")` and visually confirm the added block against the file's tab pattern.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-toolbox/conf/report-live.html.j2
git commit -m "feat(toolbox): kbin report per-device Compromission tab (ref #823)"
```

---

### Task 7: PDF report — Sentinel section (per-device)

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/reports.py` (`render_pdf`, add a section near the "🚨 ANALYSE COMPROMISSION" block ~line 170; `_render_text_fallback` ~line 1095)
- Test: `packages/secubox-toolbox/tests/test_report_sentinel_pdf.py`

**Interfaces:**
- Consumes: `report["sentinel"]` (Task 5); the existing `_section(pdf, title)` and `_kv(pdf, key, value)` helpers.
- Produces: a "🛡️ SENTINELLE" section in the rendered PDF bytes.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-toolbox/tests/test_report_sentinel_pdf.py`:

```python
from secubox_toolbox import reports


def _report(sentinel):
    return {"mac_hash": "aa", "generated_at": "2026-07-06T00:00:00Z",
            "device_type": "phone", "sentinel": sentinel}


def test_pdf_renders_with_sentinel_detection():
    rep = _report({
        "active": True,
        "assess": {"tier": "compromised", "worst_severity": 95, "worst_confidence": 95,
                   "count": 1, "dominant_class": "spyware_pegasus",
                   "strongest": {"class": "spyware_pegasus"}},
        "detections": [{"class": "spyware_pegasus", "severity": 95, "confidence": 95,
                        "action": "block", "evidence": {"source": "amnesty-mvt"},
                        "mac_hash": "aa", "ts": 1, "report": "R"}],
    })
    out = reports.render_pdf(rep)
    assert isinstance(out, (bytes, bytearray)) and len(out) > 500


def test_pdf_renders_with_sentinel_inactive():
    rep = _report({"active": False, "assess": {"tier": "clean"}, "detections": []})
    out = reports.render_pdf(rep)
    assert isinstance(out, (bytes, bytearray)) and len(out) > 500


def test_pdf_renders_when_sentinel_key_absent():
    rep = {"mac_hash": "aa", "generated_at": "2026-07-06T00:00:00Z", "device_type": "phone"}
    out = reports.render_pdf(rep)  # must not KeyError
    assert isinstance(out, (bytes, bytearray)) and len(out) > 500
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/test_report_sentinel_pdf.py -q`
Expected: The two "renders with sentinel" tests may pass structurally (no section yet) but assert nothing about the section; the goal is they stay green after adding the section AND the section actually appears. To make this a true failing test first, add a content assertion using the text fallback path (Step 3 also touches `_render_text_fallback`):

Append to the test file:

```python
def test_text_fallback_includes_sentinel_line():
    rep = _report({
        "active": True,
        "assess": {"tier": "compromised", "worst_severity": 95, "worst_confidence": 95,
                   "count": 1, "dominant_class": "spyware_pegasus", "strongest": None},
        "detections": [{"class": "spyware_pegasus", "severity": 95, "confidence": 95,
                        "action": "block", "evidence": {}, "mac_hash": "aa", "ts": 1, "report": "R"}],
    })
    txt = reports._render_text_fallback(rep)
    assert "SENTINELLE" in txt.upper()
    assert "spyware_pegasus" in txt
```

Run the same pytest command. Expected: FAIL — `test_text_fallback_includes_sentinel_line` fails (no Sentinel line in the fallback yet).

- [ ] **Step 3: Add the PDF section + text-fallback line**

In `render_pdf`, immediately after the "🚨 ANALYSE COMPROMISSION" block (the section starting ~line 170), add a helper call. First add a module-level helper (near the other `_section`-using code):

```python
def _sentinel_section(pdf, report: dict) -> None:
    """🛡️ Sentinel per-device compromise + detections (#823). Safe when the
    key is absent or the daemon was dark — renders an 'inactive' line, never
    raises."""
    sen = report.get("sentinel") or {}
    _section(pdf, "🛡️ SENTINELLE - DETECTION DE COMPROMISSION")
    if not sen.get("active"):
        _kv(pdf, "Etat", "Sentinelle inactive - aucune detection reseau")
        return
    a = sen.get("assess") or {}
    tier = a.get("tier", "clean")
    verdict = {"compromised": "COMPROMISSION CONFIRMEE",
               "suspicious": "ACTIVITE SUSPECTE",
               "clean": "Aucune compromission detectee"}.get(tier, "?")
    _kv(pdf, "Verdict", verdict)
    _kv(pdf, "Severite max", f"{a.get('worst_severity', 0)}/100")
    _kv(pdf, "Confiance", f"{a.get('worst_confidence', 0)}/100")
    _kv(pdf, "Detections", str(a.get("count", 0)))
    _kv(pdf, "Classe dominante", a.get("dominant_class") or "-")
    dets = sen.get("detections") or []
    if dets:
        _section(pdf, "SENTINELLE - DETECTIONS")
        for d in dets[:20]:
            disp = "Bloquee" if d.get("action") == "block" else "Detectee - observee"
            _kv(pdf, d.get("class", "?"),
                f"sev {d.get('severity', 0)}/conf {d.get('confidence', 0)} - {disp}")
```

Then call it in `render_pdf` right after the ANALYSE COMPROMISSION section renders:

```python
    _sentinel_section(pdf, report)
```

In `_render_text_fallback`, add near its compromise output:

```python
    sen = report.get("sentinel") or {}
    lines.append("")
    lines.append("SENTINELLE - DETECTION DE COMPROMISSION")
    if not sen.get("active"):
        lines.append("  Sentinelle inactive - aucune detection reseau")
    else:
        a = sen.get("assess") or {}
        lines.append(f"  Verdict: {a.get('tier', 'clean')} "
                     f"(sev {a.get('worst_severity', 0)}/conf {a.get('worst_confidence', 0)}, "
                     f"{a.get('count', 0)} detection(s))")
        for d in (sen.get("detections") or [])[:20]:
            disp = "Bloquee" if d.get("action") == "block" else "Detectee"
            lines.append(f"  - {d.get('class', '?')}: sev {d.get('severity', 0)} [{disp}]")
```

> Match the fallback's actual accumulator variable name (it may be `lines`, `out`, or built via `"\n".join(...)`) — read `_render_text_fallback` first and append using its own idiom. The ASCII-only wording (no accents) mirrors the fallback's Helvetica/latin-1 safety.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/test_report_sentinel_pdf.py -q`
Expected: PASS — all four tests green (PDF renders in all three sentinel states; text fallback carries the line).

- [ ] **Step 5: Run the full report test module to confirm no regression**

Run: `cd packages/secubox-toolbox && PYTHONPATH=../../common:. python3 -m pytest tests/ -q -k "report or sentinel"`
Expected: PASS — existing report tests still green.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/reports.py packages/secubox-toolbox/tests/test_report_sentinel_pdf.py
git commit -m "feat(toolbox): PDF + text-fallback Sentinel compromise section (ref #823)"
```

---

### Task 8: GPT demo prompt doc

**Files:**
- Create: `docs/demos/2026-07-06-kbin-sentinel-augmentation-prompt.md`

**Interfaces:** none (documentation artifact).

- [ ] **Step 1: Write the demo prompt**

Create `docs/demos/2026-07-06-kbin-sentinel-augmentation-prompt.md` describing the kbin's new capability group and a ready-to-paste GPT prompt. Content:

```markdown
# Demo Prompt — kbin ToolBoX × Sentinel Augmentation (#823)

## What changed
The SecuBox kbin (ToolBoX) gained an on-network **compromise-detection**
capability group ("Sentinelle"): the `sbx-sentinel` daemon inspects mirrored
tunnel traffic against commercial-spyware / exploit / botnet IOC packs (Pegasus,
Predator/Intellexa, plus live abuse.ch + MVT/Citizen-Lab feeds) and records
per-device verdicts. Findings now surface in three places:
- **Admin WebUI** — a fleet "🛡️ Sentinelle" tab (all recent detections +
  compromise evaluation).
- **kbin "mon rapport"** — a per-device Compromission tab.
- **PDF report** — a per-device Sentinelle section.

All findings are report-only and carry an anonymous `mac_hash` only. Heuristic
and zero-click signals are shown as "suspect", never as a confirmed compromise.

## GPT prompt (paste into a model)

> You are presenting SecuBox, a Debian-based home/SMB security gateway. It just
> shipped a new capability group called **Sentinelle**: while a device browses
> through the SecuBox tunnel, the box inspects the traffic against threat-intel
> indicators for commercial spyware (Pegasus, Predator/Intellexa), exploits, and
> botnets, and produces a per-device **compromise assessment** (clean / suspect /
> compromised) plus a detection list. It surfaces this to the admin as a fleet
> dashboard tab, to each user in their personal "mon rapport", and in a printable
> PDF — all keyed on an anonymous session hash, no personal data.
>
> Write a short, punchy narrative (max 250 words) for a security-savvy audience
> that (a) explains why on-network compromise detection at the gateway is a
> meaningful augmentation over endpoint-only tools, (b) walks through what a user
> sees when their phone contacts a known Pegasus C2, and (c) is honest that the
> system is detection/reporting, not blocking, and that heuristic signals are
> flagged as suspicion rather than proof. Avoid hype; be technically credible.
```

- [ ] **Step 2: Commit**

```bash
git add docs/demos/2026-07-06-kbin-sentinel-augmentation-prompt.md
git commit -m "docs: GPT demo prompt for kbin Sentinel augmentation (ref #823)"
```

---

### Task 9: Deploy + activate + live-verify (gk2)

**Files:** none in-repo (ops task). Operates on gk2 (`ssh root@192.168.1.200`).

**Interfaces:** Consumes the branch build of `secubox-toolbox-ng` (`sbx-sentinel` binary, packs, units, `sentinel.env`) and the merged portal changes.

> This task is deployment + functional verification, not TDD. Do it last so the deployed daemon carries the Task 1 `mac` filter and all three surfaces exist to verify against. Follow every gk2 ops rule in Global Constraints.

- [ ] **Step 1: Build the toolbox-ng binaries from the branch**

Run (cgo-free default build):
```bash
cd packages/secubox-toolbox-ng && go build -trimpath -ldflags=-s -o /tmp/sbx-sentinel ./cmd/sbx-sentinel
```
Expected: builds clean; `/tmp/sbx-sentinel` exists.

- [ ] **Step 2: Stage the daemon + packs + units on gk2**

Copy the binary, `packs/base/*.json`, `debian/sbx-sentinel.service`, `debian/sentinel.env`, and `tmpfiles/zz-secubox-sentinel.conf` to their install paths on gk2 (`/usr/sbin/sbx-sentinel`, `/usr/share/secubox/sentinel/packs/base/`, `/etc/systemd/system/` or the unit path, `/etc/secubox/sentinel.env`, `/usr/lib/tmpfiles.d/`). Prefer building + installing the `.deb` if the branch's `debian/rules` builds cleanly; otherwise stage the files directly. Do NOT create/modify the shared `/run/secubox` or `/var/lib/secubox` parents — let `RuntimeDirectory`/tmpfiles handle them.

- [ ] **Step 3: Configure the status HTTP**

Set in `/etc/secubox/sentinel.env` on gk2:
```
SENTINEL_HTTP_ADDR=127.0.0.1:8790
```
Leave `SENTINEL_MIRROR_SOCK`, store, and pack dirs at their defaults. Do not open any nft port — this stays localhost.

- [ ] **Step 4: Verify the mirror emit path**

Confirm the running sbxmitm ng-workers emit to `/run/secubox/sentinel-mirror.sock`:
```bash
ssh root@192.168.1.200 'ls -la /run/secubox/sentinel-mirror.sock 2>/dev/null; systemctl cat secubox-toolbox-ng-worker@1 | grep -i mirror'
```
If the workers lack the mirror hook, rebuild `sbxmitm` from the branch, deploy it, and restart the 4 workers **sequentially with a socket-wait between each** (never all at once). If they already emit, leave the workers untouched.

- [ ] **Step 5: Enable + start the daemon**

```bash
ssh root@192.168.1.200 'systemctl daemon-reload && systemctl enable --now sbx-sentinel.service && sleep 2 && systemctl is-active sbx-sentinel'
```
Expected: `active`.

- [ ] **Step 6: Verify the status HTTP + a live detection**

```bash
ssh root@192.168.1.200 'curl -s 127.0.0.1:8790/stats; echo; curl -s "127.0.0.1:8790/verdicts?limit=5"'
```
Expected: `/stats` returns the counters JSON; `/verdicts` returns an array (possibly empty initially). Then drive a benign flow and a placeholder-IOC flow through the tunnel (reuse the #823 e2e technique — a request to a base-pack placeholder host such as `notif-alert-news.example` via the tunnel) and re-check `/verdicts` shows the recorded spyware verdict.

- [ ] **Step 7: Verify all three surfaces against the live daemon**

- WebUI: open the ToolBoX admin portal, click the 🛡️ Sentinelle tab — confirm the evaluation banner + detections table populate (and show "inactive" cleanly if the daemon is stopped).
- kbin report: open a device's "mon rapport", confirm the Compromission tab shows that device's detections.
- PDF: generate the PDF report for that device, confirm the Sentinelle section is present.
Confirm daemon RSS is bounded (`systemctl status sbx-sentinel`) and the portal + aggregator are unaffected (no board-wide latency).

- [ ] **Step 8: Record activation state**

Note the deployed daemon version, `SENTINEL_HTTP_ADDR`, and whether workers were redeployed in the PR description / issue comment on #823. No repo commit for this task (config lives on the board).

---

## Self-Review

**Spec coverage:**
- Part 1 (activation) → Task 9. ✓
- Part 2 (Go `/verdicts?mac=`) → Task 1. ✓
- Part 3 (`sentinel_link.py` fetch + assess) → Task 2. ✓
- Part 4 (WebUI fleet tab: proxy + tab) → Tasks 3 + 4. ✓
- Part 5 (kbin HTML per-device tab) → Tasks 5 (data) + 6 (template). ✓
- Part 6 (PDF section) → Tasks 5 (data) + 7 (render). ✓
- Part 7 (GPT demo prompt) → Task 8. ✓
- Global constraints (report-only, mac_hash-only, fail-safe, no waf_bypass, honest disposition, localhost HTTP, no new dep) → encoded in Global Constraints + enforced per task (assess never escalates heuristic/zero-click; fetch fail-safe; urllib stdlib; `/admin/` gating). ✓

**Placeholder scan:** No TBD/TODO; every code step carries full code. The two "match the file's existing pattern" notes (Task 4 panel markup, Task 6 tab shell, Task 7 fallback accumulator) are grounded reads of specific existing conventions, not vague hand-waves — each names the exact structure to mirror.

**Type consistency:** `assess()` return keys (`tier`, `worst_severity`, `worst_confidence`, `count`, `dominant_class`, `strongest`) are used identically in Tasks 4 (JS reads `worst_severity`/`worst_confidence`/`count`/`dominant_class`), 6 (Jinja reads same), 7 (PDF reads same). `report["sentinel"]` shape (`active`/`assess`/`detections`) consistent across Tasks 5→6→7. `disposition` logic (`block`→"Bloquée") duplicated as literals in JS (Task 4) and Jinja (Task 6) and PDF (Task 7) because they're separate runtimes — intentional, not a drift. Route paths `/admin/sentinel/{stats,verdicts}` consistent between Task 3 (define) and Task 4 (consume).
