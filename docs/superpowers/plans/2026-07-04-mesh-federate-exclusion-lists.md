<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Mesh-federate the toolbox exclusion lists (#806) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Federate the toolbox's 3 mutable MITM-exclusion lists (splice-learned, mitm-bypass-dynamic, mitm-filter-disabled) peer-to-peer across the gondwana mesh via the existing signed ConfigBlob directory, so every node applies the fleet-wide union.

**Architecture:** Each node publishes its local deltas as a signed ConfigBlob under a per-node scope `mitm-exclusion:<node_id>` (ConfigBlob is single-writer-per-scope). A sync task on each node pulls all `mitm-exclusion:*` blobs, verifies signatures, unions them, and writes 3 `mitm-exclusion-fed-*.txt` files that the Go `sbxmitm` engine reads as additional sources (hot-reloaded). The webui badges federated rows `🌐 mesh`.

**Tech Stack:** Go (sbxmitm policy, pure stdlib), Python 3.11 (FastAPI toolbox module + CLI scripts), annuaire ConfigBlob federation (Ed25519-signed, unix socket `/run/secubox/annuaire.sock`), systemd timers.

## Global Constraints

- ConfigBlob is **single-writer per scope** → each node uses scope `mitm-exclusion:<node_id>` (never a shared scope). Verbatim scope prefix: `mitm-exclusion:`.
- Federated payload lists are **deduped + capped at 2000** (`FED_MAX = 2000`) on both publish and union.
- Only blobs whose **BLAKE2b content_hash matches AND signature verifies** are applied; a bad blob is skipped, never applied (untrusted input must not poison the fleet).
- Best-effort I/O: a directory/socket error is logged and retried next tick; it must **never block** the engine (which reads whatever fed files exist).
- Fed files are written **atomically** (temp + `os.replace`) and **only when content changed** (mtime-stable → no needless engine reload).
- `disabled` federation is **union** (disabled-anywhere ⇒ disabled-everywhere); the engine's effective disabled set is `local ∪ federated`.
- Never touch the never-set / ad-block precedence in `Decide` — federation only adds inputs to the existing splice/bypass/disabled decision surface.
- Node identity: `annuaire_client.node_identity()` → `(did, priv_hex)` from the node ed25519 key file; `node_id` for the scope = the box hostname (`/etc/secubox/... node.id` — read via `socket.gethostname()` fallback).
- SPDX header on every new file: `# SPDX-License-Identifier: LicenseRef-CMSD-1.0`.

**Paths (verbatim):**
- Local: `/var/lib/secubox/toolbox/splice-learned.txt`, `…/mitm-bypass-dynamic.conf`, `…/mitm-filter-disabled.txt`
- Federated (new): `/var/lib/secubox/toolbox/mitm-exclusion-fed-splice.txt`, `…-fed-bypass.txt`, `…-fed-disabled.txt`
- Annuaire socket: `/run/secubox/annuaire.sock`

---

### Task 1: Go engine — federated exclusion sources + union disabled

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxmitm/policy.go`
- Test: `packages/secubox-toolbox-ng/cmd/sbxmitm/policy_test.go`

**Interfaces:**
- Consumes: existing `PolicyOpts`, `Policy`, `bypassEntry{pat,re}`, `loadBypassRegex`, `hostMatchesEnabled`, `shouldSplice`, `matchesBypass`, the `reload.Target` list.
- Produces: engine reads `SpliceFederatedPath` / `BypassFederatedPath` / `DisabledFederatedPath`; `shouldSplice` unions `spliceFed`; `matchesBypass` adds `bypassFedRe`; effective `p.disabled = disabledLocal ∪ disabledFed`.

- [ ] **Step 1: Write failing tests** (append to `policy_test.go`)

```go
// #806 — federated exclusion sources: fed-splice/fed-bypass splice; fed-disabled
// unions with local disabled to suppress a match.
func TestFederatedSources(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	empty := write("empty", "")
	fedSplice := write("fed-splice.txt", "api.anthropic.com\n")
	fedBypass := write("fed-bypass.txt", "(.+\\.)?whatsapp\\.net\n")
	fedDisabled := write("fed-disabled.txt", "api.anthropic.com\n") // will re-suppress below

	pol, err := LoadPolicy(PolicyOpts{
		AllowPath: empty, LearnedPath: empty, SpliceSeedPath: empty,
		SpliceLearnPath: empty, PureTrackersPath: empty,
		BypassSeedPath: empty, BypassStaticPath: empty, BypassDynamicPath: empty,
		SpliceFederatedPath: fedSplice, BypassFederatedPath: fedBypass,
		DisabledPath: empty, DisabledFederatedPath: empty,
		SelfDomains: []string{"secubox.in"},
	})
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	for _, c := range []struct{ host, want string }{
		{"api.anthropic.com", "splice"},   // fed-splice source
		{"chat.whatsapp.net", "splice"},   // fed-bypass regex
		{"example.com", "mitm"},
	} {
		if got := pol.Decide(c.host, c.host); got != c.want {
			t.Errorf("Decide(%q)=%q want %q", c.host, got, c.want)
		}
	}

	// fed-disabled unions with local disabled → fed-splice entry suppressed.
	pol2, _ := LoadPolicy(PolicyOpts{
		AllowPath: empty, LearnedPath: empty, SpliceSeedPath: empty,
		SpliceLearnPath: empty, PureTrackersPath: empty,
		BypassSeedPath: empty, BypassStaticPath: empty, BypassDynamicPath: empty,
		SpliceFederatedPath: fedSplice, BypassFederatedPath: empty,
		DisabledPath: empty, DisabledFederatedPath: fedDisabled,
		SelfDomains: []string{"secubox.in"},
	})
	if got := pol2.Decide("api.anthropic.com", "api.anthropic.com"); got != "mitm" {
		t.Errorf("fed-disabled: Decide(api.anthropic.com)=%q want mitm", got)
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (undefined fields)

Run: `cd packages/secubox-toolbox-ng && go test ./cmd/sbxmitm/ -run TestFederatedSources -count=1`
Expected: compile error `unknown field 'SpliceFederatedPath'`.

- [ ] **Step 3: Add opts + defaults** — in `policy.go`, in `PolicyOpts` after `BypassDynamicPath`:

```go
	SpliceFederatedPath   string // mitm-exclusion-fed-splice.txt   (#806 mesh union)
	BypassFederatedPath   string // mitm-exclusion-fed-bypass.txt   (#806)
	DisabledFederatedPath string // mitm-exclusion-fed-disabled.txt (#806)
```

In `defaultPolicyOpts()` after the `DisabledPath` default:

```go
		SpliceFederatedPath:   envOr("SECUBOX_FED_SPLICE", "/var/lib/secubox/toolbox/mitm-exclusion-fed-splice.txt"),
		BypassFederatedPath:   envOr("SECUBOX_FED_BYPASS", "/var/lib/secubox/toolbox/mitm-exclusion-fed-bypass.txt"),
		DisabledFederatedPath: envOr("SECUBOX_FED_DISABLED", "/var/lib/secubox/toolbox/mitm-exclusion-fed-disabled.txt"),
```

In `LoadPolicy`, after the `DisabledPath` empty-check:

```go
	if opts.SpliceFederatedPath == "" {
		opts.SpliceFederatedPath = def.SpliceFederatedPath
	}
	if opts.BypassFederatedPath == "" {
		opts.BypassFederatedPath = def.BypassFederatedPath
	}
	if opts.DisabledFederatedPath == "" {
		opts.DisabledFederatedPath = def.DisabledFederatedPath
	}
```

- [ ] **Step 4: Add Policy fields** — replace the `disabled` field decl in `Policy`:

```go
	// #809/#806 — effective disabled = local ∪ federated. Kept split so either
	// source hot-reloads independently; disabled is the recomputed union.
	disabledLocal map[string]bool
	disabledFed   map[string]bool
	disabled      map[string]bool
	// #806 — federated (mesh-union) sources, read as ADDITIONAL inputs.
	spliceFed  map[string]bool
	bypassFedRe []bypassEntry
```

Add a union helper (top-level func in `policy.go`):

```go
// mergeSets returns the union of two string-sets (nil-safe).
func mergeSets(a, b map[string]bool) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}
```

- [ ] **Step 5: Wire loads in the Policy literal** — in `LoadPolicy`'s `p := &Policy{…}`, replace the `disabled:` line and add fed loads:

```go
		disabledLocal:  reload.LoadLines(opts.DisabledPath, true),
		disabledFed:    reload.LoadLines(opts.DisabledFederatedPath, true),
		spliceFed:      reload.LoadLines(opts.SpliceFederatedPath, true),
		bypassFedRe:    loadBypassRegex(opts.BypassFederatedPath),
```

Immediately after the literal (before the reload targets), compute the union:

```go
	p.disabled = mergeSets(p.disabledLocal, p.disabledFed)
```

- [ ] **Step 6: Use fed sources in matching** — in `shouldSplice`, change the return:

```go
	return hostMatchesEnabled(s, p.spliceSeed, p.disabled) ||
		hostMatchesEnabled(s, p.spliceLearn, p.disabled) ||
		hostMatchesEnabled(s, p.spliceFed, p.disabled)
```

In `matchesBypass`, add `p.bypassFedRe` to the groups:

```go
	for _, group := range [][]bypassEntry{p.bypassSeedRe, p.bypassStaticRe, p.bypassDynRe, p.bypassFedRe} {
```

- [ ] **Step 7: Add reload targets** — in the `targets := []reload.Target{…}` slice, replace the existing single `DisabledPath` target with local+fed disabled targets that recompute the union, and add fed splice/bypass targets:

```go
		{
			Path: opts.DisabledPath, LastMtime: reload.StatMtime(opts.DisabledPath),
			Load: func(path string) any { return reload.LoadLines(path, true) },
			Apply: func(v any) {
				p.mu.Lock()
				p.disabledLocal = v.(map[string]bool)
				p.disabled = mergeSets(p.disabledLocal, p.disabledFed)
				p.mu.Unlock()
			},
		},
		{
			Path: opts.DisabledFederatedPath, LastMtime: reload.StatMtime(opts.DisabledFederatedPath),
			Load: func(path string) any { return reload.LoadLines(path, true) },
			Apply: func(v any) {
				p.mu.Lock()
				p.disabledFed = v.(map[string]bool)
				p.disabled = mergeSets(p.disabledLocal, p.disabledFed)
				p.mu.Unlock()
			},
		},
		{
			Path: opts.SpliceFederatedPath, LastMtime: reload.StatMtime(opts.SpliceFederatedPath),
			Load: func(path string) any { return reload.LoadLines(path, true) },
			Apply: func(v any) { p.mu.Lock(); p.spliceFed = v.(map[string]bool); p.mu.Unlock() },
		},
		{
			Path: opts.BypassFederatedPath, LastMtime: reload.StatMtime(opts.BypassFederatedPath),
			Load: func(path string) any { return loadBypassRegex(path) },
			Apply: func(v any) { p.mu.Lock(); p.bypassFedRe = v.([]bypassEntry); p.mu.Unlock() },
		},
```

(Remove the old single `opts.DisabledPath` target replaced above — there must be exactly one target per path.)

- [ ] **Step 8: Run tests — expect PASS**

Run: `cd packages/secubox-toolbox-ng && go vet ./cmd/sbxmitm/ && go test ./cmd/sbxmitm/ -count=1`
Expected: `ok` (TestFederatedSources + full suite green).

- [ ] **Step 9: Commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbxmitm/policy.go packages/secubox-toolbox-ng/cmd/sbxmitm/policy_test.go
git commit -m "feat(toolbox-ng): sbxmitm reads federated exclusion lists + union disabled (ref #806)"
```

---

### Task 2: Python — local-list reader + payload builder + publisher

**Files:**
- Create: `packages/secubox-toolbox/secubox_toolbox/mesh_exclusion.py`
- Create: `packages/secubox-toolbox/sbin/secubox-toolbox-mesh-exclusion-publish`
- Test: `packages/secubox-toolbox/tests/test_mesh_exclusion_publish.py`

**Interfaces:**
- Consumes: node identity via a thin local helper (below); annuaire over `/run/secubox/annuaire.sock`.
- Produces: `local_lists() -> dict`, `build_payload(node_id, lists) -> dict`, `content_hash(payload) -> str`, `publish(payload, priv_hex, did, node_id) -> bool`. Task 3 reuses `FED_MAX`, `_read_list`, `_atomic_write`, and the `_annuaire_get`/`_annuaire_post` socket helpers from this module.

- [ ] **Step 1: Write failing test** (`tests/test_mesh_exclusion_publish.py`)

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
from secubox_toolbox import mesh_exclusion as mx


def test_local_lists_dedups_and_caps(tmp_path, monkeypatch):
    sp = tmp_path / "splice-learned.txt"; sp.write_text("a.com\na.com\nb.com\n")
    by = tmp_path / "bypass.conf"; by.write_text("(.+\\.)?x\\.com   # c\n(.+\\.)?x\\.com\n")
    di = tmp_path / "disabled.txt"; di.write_text("d.com\n")
    monkeypatch.setattr(mx, "LOCAL_SPLICE", sp)
    monkeypatch.setattr(mx, "LOCAL_BYPASS", by)
    monkeypatch.setattr(mx, "LOCAL_DISABLED", di)
    monkeypatch.setattr(mx, "FED_MAX", 10)
    lists = mx.local_lists()
    assert lists["splice"] == ["a.com", "b.com"]        # deduped, sorted
    assert lists["bypass"] == ["(.+\\.)?x\\.com"]        # inline-comment stripped, deduped
    assert lists["disabled"] == ["d.com"]


def test_build_payload_and_content_hash_stable():
    lists = {"splice": ["a.com"], "bypass": [], "disabled": []}
    p1 = mx.build_payload("gk2", lists)
    p2 = mx.build_payload("gk2", lists)
    assert p1["node"] == "gk2" and p1["splice"] == ["a.com"]
    assert mx.content_hash(p1) == mx.content_hash(p2)    # deterministic
    assert len(mx.content_hash(p1)) == 64                # blake2b-256 hex
```

- [ ] **Step 2: Run — expect FAIL** (`ModuleNotFoundError`/attr).

Run: `cd packages/secubox-toolbox && PYTHONPATH=. python -m pytest tests/test_mesh_exclusion_publish.py -q`

- [ ] **Step 3: Implement `mesh_exclusion.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: toolbox :: mesh-federate the MITM-exclusion lists (#806).

Publishes this node's LOCAL mutable exclusion lists (splice-learned, bypass-
dynamic, disabled) as a signed ConfigBlob under scope mitm-exclusion:<node_id>,
and (sync side, see the sync CLI) pulls every node's blob → union → the 3
federated files the R3 engine reads. Best-effort; never blocks.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
from pathlib import Path

LOCAL_SPLICE = Path("/var/lib/secubox/toolbox/splice-learned.txt")
LOCAL_BYPASS = Path("/var/lib/secubox/toolbox/mitm-bypass-dynamic.conf")
LOCAL_DISABLED = Path("/var/lib/secubox/toolbox/mitm-filter-disabled.txt")
FED_SPLICE = Path("/var/lib/secubox/toolbox/mitm-exclusion-fed-splice.txt")
FED_BYPASS = Path("/var/lib/secubox/toolbox/mitm-exclusion-fed-bypass.txt")
FED_DISABLED = Path("/var/lib/secubox/toolbox/mitm-exclusion-fed-disabled.txt")
ANNUAIRE_SOCK = "/run/secubox/annuaire.sock"
SCOPE_PREFIX = "mitm-exclusion:"
FED_MAX = 2000


def _read_list(path: Path) -> list:
    """Non-comment, non-empty, inline-#-stripped, deduped, sorted, capped."""
    try:
        seen = []
        for ln in path.read_text(encoding="utf-8").splitlines():
            s = ln.split("#", 1)[0].strip()
            if s and s not in seen:
                seen.append(s)
        return sorted(seen)[:FED_MAX]
    except OSError:
        return []


def local_lists() -> dict:
    return {"splice": _read_list(LOCAL_SPLICE),
            "bypass": _read_list(LOCAL_BYPASS),
            "disabled": _read_list(LOCAL_DISABLED)}


def node_id() -> str:
    try:
        n = Path("/etc/secubox/node.id").read_text(encoding="utf-8").strip()
        if n:
            return n
    except OSError:
        pass
    return socket.gethostname()


def build_payload(nid: str, lists: dict) -> dict:
    return {"node": nid,
            "splice": lists.get("splice", [])[:FED_MAX],
            "bypass": lists.get("bypass", [])[:FED_MAX],
            "disabled": lists.get("disabled", [])[:FED_MAX]}


def content_hash(payload: dict) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.blake2b(text.encode("utf-8"), digest_size=32).hexdigest()


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, sock_path: str):
        super().__init__("localhost")
        self._sock_path = sock_path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect(self._sock_path)
        self.sock = s


def _annuaire(method: str, path: str, body: dict | None = None) -> dict | None:
    try:
        c = _UnixHTTP(ANNUAIRE_SOCK)
        hdr = {"Content-Type": "application/json"} if body else {}
        c.request(method, path, json.dumps(body) if body else None, hdr)
        r = c.getresponse()
        raw = r.read()
        c.close()
        if r.status >= 400:
            return None
        return json.loads(raw) if raw else {}
    except Exception:
        return None


def _version() -> int:
    # monotonic-ish: seconds since epoch (single-writer per node scope).
    return int(Path("/proc/uptime").read_text().split()[0].split(".")[0]) if False else int(__import__("time").time())


def publish(payload: dict, priv_hex: str, did: str, nid: str) -> bool:
    """POST /config/publish under scope mitm-exclusion:<node_id>. Best-effort."""
    body = {"publisher_did": did, "publisher_priv_hex": priv_hex,
            "scope": SCOPE_PREFIX + nid, "version": _version(),
            "content_hash": content_hash(payload), "payload": payload}
    return _annuaire("POST", "/config/publish", body) is not None


def _atomic_write(path: Path, lines: list) -> bool:
    """Write sorted lines atomically; return True if content changed."""
    new = "\n".join(sorted(set(lines))[:FED_MAX])
    new = (new + "\n") if new else ""
    try:
        if path.exists() and path.read_text(encoding="utf-8") == new:
            return False
    except OSError:
        pass
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(new, encoding="utf-8")
    os.replace(tmp, path)
    return True
```

- [ ] **Step 4: Run test — expect PASS**

Run: `cd packages/secubox-toolbox && PYTHONPATH=. python -m pytest tests/test_mesh_exclusion_publish.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Implement the publish CLI** (`sbin/secubox-toolbox-mesh-exclusion-publish`, `chmod 755`)

```python
#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""#806 — publish this node's local exclusion lists as a signed ConfigBlob."""
import sys
sys.path.insert(0, "/usr/lib/secubox/toolbox")
sys.path.insert(0, "/usr/lib/secubox/p2p")  # annuaire_client.node_identity
from secubox_toolbox import mesh_exclusion as mx

def main() -> int:
    try:
        from api.annuaire_client import node_identity  # secubox-p2p
        did, priv = node_identity()
    except Exception:
        did, priv = None, None
    if not did or not priv:
        sys.stderr.write("mesh-exclusion-publish: no node identity — skip\n")
        return 0
    nid = mx.node_id()
    ok = mx.publish(mx.build_payload(nid, mx.local_lists()), priv, did, nid)
    sys.stderr.write("mesh-exclusion-publish: %s scope=%s%s\n"
                     % ("ok" if ok else "FAILED (retry next tick)", mx.SCOPE_PREFIX, nid))
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/mesh_exclusion.py \
        packages/secubox-toolbox/sbin/secubox-toolbox-mesh-exclusion-publish \
        packages/secubox-toolbox/tests/test_mesh_exclusion_publish.py
git commit -m "feat(toolbox): mesh-exclusion payload builder + publisher (ref #806)"
```

---

### Task 3: Python — sync (pull + verify + union + write fed files)

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/mesh_exclusion.py`
- Create: `packages/secubox-toolbox/sbin/secubox-toolbox-mesh-exclusion-sync`
- Test: `packages/secubox-toolbox/tests/test_mesh_exclusion_sync.py`

**Interfaces:**
- Consumes: `_annuaire`, `_atomic_write`, `content_hash`, `FED_*`, `SCOPE_PREFIX`, `FED_MAX` from Task 2.
- Produces: `pull_blobs() -> list[dict]`, `union_blobs(blobs) -> dict`, `sync() -> dict` (writes fed files; returns counts).

- [ ] **Step 1: Write failing test** (`tests/test_mesh_exclusion_sync.py`)

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import mesh_exclusion as mx


def test_union_blobs_dedups_across_nodes():
    blobs = [
        {"node": "gk2", "splice": ["a.com", "b.com"], "bypass": ["(.+\\.)?x\\.com"], "disabled": ["d.com"]},
        {"node": "c3box", "splice": ["b.com", "c.com"], "bypass": [], "disabled": ["e.com"]},
    ]
    u = mx.union_blobs(blobs)
    assert u["splice"] == ["a.com", "b.com", "c.com"]
    assert u["bypass"] == ["(.+\\.)?x\\.com"]
    assert u["disabled"] == ["d.com", "e.com"]


def test_sync_writes_fed_files_only_on_change(tmp_path, monkeypatch):
    monkeypatch.setattr(mx, "FED_SPLICE", tmp_path / "s.txt")
    monkeypatch.setattr(mx, "FED_BYPASS", tmp_path / "b.txt")
    monkeypatch.setattr(mx, "FED_DISABLED", tmp_path / "d.txt")
    monkeypatch.setattr(mx, "pull_blobs", lambda: [
        {"node": "gk2", "splice": ["a.com"], "bypass": [], "disabled": []}])
    r1 = mx.sync()
    assert r1["splice"] == 1 and (tmp_path / "s.txt").read_text() == "a.com\n"
    assert r1["changed"] is True
    r2 = mx.sync()                # same content → no rewrite
    assert r2["changed"] is False
```

- [ ] **Step 2: Run — expect FAIL** (`union_blobs`/`sync` undefined).

Run: `cd packages/secubox-toolbox && PYTHONPATH=. python -m pytest tests/test_mesh_exclusion_sync.py -q`

- [ ] **Step 3: Append to `mesh_exclusion.py`**

```python
def _verify_blob(cfg: dict) -> dict | None:
    """Return the payload dict if the blob's content_hash matches its payload.
    Signature/author verification is done by the annuaire on ingest (only
    validly-signed blobs enter the journal that /config lists), so here we
    re-check the content_hash binds the payload we apply. Skip on mismatch."""
    payload = cfg.get("payload")
    if not isinstance(payload, dict):
        return None
    if cfg.get("content_hash") != content_hash(payload):
        return None
    return payload


def pull_blobs() -> list:
    """All current mitm-exclusion:* blob payloads (content-hash-verified)."""
    resp = _annuaire("GET", "/config")
    out = []
    for cfg in (resp or {}).get("configs", []):
        scope = cfg.get("scope") or ""
        if not scope.startswith(SCOPE_PREFIX):
            continue
        p = _verify_blob(cfg)
        if p is not None:
            out.append(p)
    return out


def union_blobs(blobs: list) -> dict:
    s, b, d = set(), set(), set()
    for p in blobs:
        s.update(x for x in (p.get("splice") or []) if isinstance(x, str))
        b.update(x for x in (p.get("bypass") or []) if isinstance(x, str))
        d.update(x for x in (p.get("disabled") or []) if isinstance(x, str))
    return {"splice": sorted(s)[:FED_MAX], "bypass": sorted(b)[:FED_MAX],
            "disabled": sorted(d)[:FED_MAX]}


def sync() -> dict:
    u = union_blobs(pull_blobs())
    c1 = _atomic_write(FED_SPLICE, u["splice"])
    c2 = _atomic_write(FED_BYPASS, u["bypass"])
    c3 = _atomic_write(FED_DISABLED, u["disabled"])
    return {"splice": len(u["splice"]), "bypass": len(u["bypass"]),
            "disabled": len(u["disabled"]), "changed": c1 or c2 or c3}
```

- [ ] **Step 4: Run test — expect PASS**

Run: `cd packages/secubox-toolbox && PYTHONPATH=. python -m pytest tests/test_mesh_exclusion_sync.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Implement the sync CLI** (`sbin/secubox-toolbox-mesh-exclusion-sync`, `chmod 755`)

```python
#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""#806 — pull all nodes' mitm-exclusion blobs → union → federated files."""
import sys
sys.path.insert(0, "/usr/lib/secubox/toolbox")
from secubox_toolbox import mesh_exclusion as mx

def main() -> int:
    r = mx.sync()
    sys.stderr.write("mesh-exclusion-sync: splice=%d bypass=%d disabled=%d changed=%s\n"
                     % (r["splice"], r["bypass"], r["disabled"], r["changed"]))
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/mesh_exclusion.py \
        packages/secubox-toolbox/sbin/secubox-toolbox-mesh-exclusion-sync \
        packages/secubox-toolbox/tests/test_mesh_exclusion_sync.py
git commit -m "feat(toolbox): mesh-exclusion sync (pull+union+write fed files) (ref #806)"
```

---

### Task 4: Webui — 🌐 mesh badge on federated rows

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` (`_load_bypass_tagged`)
- Modify: `packages/secubox-toolbox/www/toolbox/index.html` (`BADGE` map)
- Test: `packages/secubox-toolbox/tests/test_filter_list_mesh_tag.py`

**Interfaces:**
- Consumes: existing `_read_splice`, `_load_disabled`, `_load_bypass_tagged` (returns rows `{pattern, source, enabled, editable}`).
- Produces: rows from the 3 fed files tagged `source ∈ {mesh-splice, mesh-bypass, mesh-disabled}`, `editable=False`.

- [ ] **Step 1: Write failing test** (`tests/test_filter_list_mesh_tag.py`)

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import api as A


def test_fed_rows_tagged_mesh(tmp_path, monkeypatch):
    fs = tmp_path / "fs"; fs.write_text("fed.example\n")
    monkeypatch.setattr(A, "FED_SPLICE_FILE", fs)
    monkeypatch.setattr(A, "FED_BYPASS_FILE", tmp_path / "nope1")
    monkeypatch.setattr(A, "FED_DISABLED_FILE", tmp_path / "nope2")
    # isolate the other sources to empty
    for name in ("MITM_BYPASS_SEED_FILE", "MITM_BYPASS_FILE", "MITM_BYPASS_DYNAMIC_FILE",
                 "TLS_SPLICE_SEED_FILE", "SPLICE_LEARNED_FILE", "MITM_FILTER_DISABLED_FILE"):
        monkeypatch.setattr(A, name, tmp_path / ("empty_" + name))
    rows = A._load_bypass_tagged()
    fed = [r for r in rows if r["pattern"] == "fed.example"]
    assert fed and fed[0]["source"] == "mesh-splice" and fed[0]["editable"] is False
```

- [ ] **Step 2: Run — expect FAIL** (`FED_SPLICE_FILE` undefined).

Run: `cd packages/secubox-toolbox && PYTHONPATH=. python -m pytest tests/test_filter_list_mesh_tag.py -q`

- [ ] **Step 3: Add fed constants + tag in `api.py`** — after `SPLICE_LEARNED_FILE`:

```python
# #806 — federated (mesh-union) lists the R3 engine also reads; surfaced in the
# Filtres MITM list tagged mesh-* (edit on the origin node).
FED_SPLICE_FILE = Path(os.environ.get("SECUBOX_FED_SPLICE", "/var/lib/secubox/toolbox/mitm-exclusion-fed-splice.txt"))
FED_BYPASS_FILE = Path(os.environ.get("SECUBOX_FED_BYPASS", "/var/lib/secubox/toolbox/mitm-exclusion-fed-bypass.txt"))
FED_DISABLED_FILE = Path(os.environ.get("SECUBOX_FED_DISABLED", "/var/lib/secubox/toolbox/mitm-exclusion-fed-disabled.txt"))
```

In `_load_bypass_tagged`, after the splice sources loop and before the `disabled = _load_disabled()` line, add the fed sources:

```python
    for source, path in (("mesh-splice", FED_SPLICE_FILE),
                         ("mesh-bypass", FED_BYPASS_FILE),
                         ("mesh-disabled", FED_DISABLED_FILE)):
        for pat in _read_splice(path):
            if pat not in seen:
                seen[pat] = source
```

Then update the `editable` set to keep mesh rows non-editable (they already are — `editable = {"static","learned","splice-learned"}` excludes `mesh-*`, so no change needed; verify).

- [ ] **Step 4: Add the badge in the webui** — in `loadFilters`'s `BADGE` map:

```javascript
                   'mesh-splice': '🌐 mesh', 'mesh-bypass': '🌐 mesh', 'mesh-disabled': '🌐 mesh',
```

- [ ] **Step 5: Run test — expect PASS**

Run: `cd packages/secubox-toolbox && PYTHONPATH=. python -m pytest tests/test_filter_list_mesh_tag.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/www/toolbox/index.html \
        packages/secubox-toolbox/tests/test_filter_list_mesh_tag.py
git commit -m "feat(toolbox): 🌐 mesh badge for federated exclusion entries (ref #806)"
```

---

### Task 5: Packaging — systemd timers + install + enable

**Files:**
- Create: `packages/secubox-toolbox/systemd/secubox-toolbox-mesh-exclusion-publish.service` + `.timer`
- Create: `packages/secubox-toolbox/systemd/secubox-toolbox-mesh-exclusion-sync.service` + `.timer`
- Modify: `packages/secubox-toolbox/debian/rules`, `packages/secubox-toolbox/debian/postinst`

**Interfaces:**
- Consumes: the 2 CLI scripts from Tasks 2–3.
- Produces: enabled timers on install; no test (packaging), verified by `dpkg-deb` contents.

- [ ] **Step 1: Create the 4 unit files**

`secubox-toolbox-mesh-exclusion-publish.service`:
```ini
[Unit]
Description=SecuBox ToolBoX — publish local MITM-exclusion lists to the mesh (#806)
After=secubox-toolbox.service secubox-annuaire.service
[Service]
Type=oneshot
ExecStart=/usr/sbin/secubox-toolbox-mesh-exclusion-publish
Nice=10
TimeoutStartSec=60
```
`secubox-toolbox-mesh-exclusion-publish.timer`:
```ini
[Unit]
Description=SecuBox ToolBoX — periodic mesh-exclusion publish (#806)
[Timer]
OnBootSec=8min
OnUnitActiveSec=30min
Persistent=true
RandomizedDelaySec=3min
[Install]
WantedBy=timers.target
```
`secubox-toolbox-mesh-exclusion-sync.service`:
```ini
[Unit]
Description=SecuBox ToolBoX — sync federated MITM-exclusion lists from the mesh (#806)
After=secubox-toolbox.service secubox-annuaire.service
[Service]
Type=oneshot
ExecStart=/usr/sbin/secubox-toolbox-mesh-exclusion-sync
Nice=10
TimeoutStartSec=60
```
`secubox-toolbox-mesh-exclusion-sync.timer`:
```ini
[Unit]
Description=SecuBox ToolBoX — periodic mesh-exclusion sync (#806)
[Timer]
OnBootSec=12min
OnUnitActiveSec=30min
Persistent=true
RandomizedDelaySec=3min
[Install]
WantedBy=timers.target
```

- [ ] **Step 2: Install in `debian/rules`** — inside `override_dh_auto_install`, after the autolearn install lines:

```makefile
	# #806 : mesh-federate the exclusion lists (publish + sync + timers)
	install -m 0755 sbin/secubox-toolbox-mesh-exclusion-publish debian/secubox-toolbox/usr/sbin/
	install -m 0755 sbin/secubox-toolbox-mesh-exclusion-sync debian/secubox-toolbox/usr/sbin/
	install -m 0644 systemd/secubox-toolbox-mesh-exclusion-publish.service debian/secubox-toolbox/lib/systemd/system/
	install -m 0644 systemd/secubox-toolbox-mesh-exclusion-publish.timer debian/secubox-toolbox/lib/systemd/system/
	install -m 0644 systemd/secubox-toolbox-mesh-exclusion-sync.service debian/secubox-toolbox/lib/systemd/system/
	install -m 0644 systemd/secubox-toolbox-mesh-exclusion-sync.timer debian/secubox-toolbox/lib/systemd/system/
```

- [ ] **Step 3: Enable in `debian/postinst`** — after the existing timer enables:

```sh
      systemctl enable secubox-toolbox-mesh-exclusion-publish.timer 2>/dev/null || true
      systemctl start  secubox-toolbox-mesh-exclusion-publish.timer 2>/dev/null || true
      systemctl enable secubox-toolbox-mesh-exclusion-sync.timer 2>/dev/null || true
      systemctl start  secubox-toolbox-mesh-exclusion-sync.timer 2>/dev/null || true
```

- [ ] **Step 4: Verify units are staged** (build-free check)

Run: `ls packages/secubox-toolbox/systemd/secubox-toolbox-mesh-exclusion-*.{service,timer} && grep -c mesh-exclusion packages/secubox-toolbox/debian/rules packages/secubox-toolbox/debian/postinst`
Expected: 4 unit files listed; `rules` ≥ 6 matches, `postinst` ≥ 4 matches.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/systemd/secubox-toolbox-mesh-exclusion-*.{service,timer} \
        packages/secubox-toolbox/debian/rules packages/secubox-toolbox/debian/postinst
git commit -m "feat(toolbox): package mesh-exclusion publish+sync timers (ref #806)"
```

---

## Deploy (after all tasks, manual — not a task)

1. Cross-build sbxmitm arm64 (`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/sbxmitm/`), deploy to gk2/c3box/amd64 with the old binary backed up, restart `secubox-toolbox-ng-worker@1..4` (only gk2 runs the R3 tunnel today; the others get the binary for parity).
2. rsync the 2 CLI scripts + `mesh_exclusion.py` + `api.py` + `index.html`; install the 4 units; `systemctl daemon-reload`; enable+start both timers on all 3 nodes.
3. Verify: run `secubox-toolbox-mesh-exclusion-publish` on gk2 → `secubox-toolbox-mesh-exclusion-sync` on c3box → confirm gk2's local splice hosts appear in c3box's `mitm-exclusion-fed-splice.txt` and its engine splices them.

## Self-Review notes

- **Spec coverage:** scope=`mitm-exclusion:<node>` (Global Constraints + T2 publish) resolves the single-writer-per-scope constraint from the spec's transport section; T1 = engine fed sources + union disabled; T2 = publisher; T3 = sync/pull/union; T4 = webui badge; T5 = packaging. Error handling (best-effort, skip-untrusted via content_hash, fail-open missing file, FED_MAX cap, change-only write) is in T2/T3 code + Global Constraints.
- **Signature note:** the annuaire only lets validly-signed blobs into the journal that `/config` lists, so the sync re-checks the `content_hash` binds the applied payload (T3 `_verify_blob`); it does not re-verify Ed25519 itself (the directory already did on ingest). This matches how `config_apply.apply_blob` trusts the listed journal.
- **Type consistency:** `FED_MAX`, `_read_list`, `_atomic_write`, `_annuaire`, `content_hash`, `SCOPE_PREFIX` defined in T2, reused in T3; `FED_*` file constants consistent between `mesh_exclusion.py` (T2/3) and `api.py` (`FED_*_FILE`, T4) — same default paths, different module-local names by design.
