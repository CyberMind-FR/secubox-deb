# Rapport kbin fidèle + media types + WebUI DPI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rendre le PDF du rapport kbin fidèle à sa page web (donut-grids DPI-Exfil + Overall), ajouter une dimension « types de médias » (MIME captés) au rapport (PDF + web, me + overall), et enrichir le WebUI DPI de deux cards (types de services par bytes + types MIME).

**Architecture:** Un helper pur partagé `secubox_core.media_catch.aggregate()` lit le JSONL `/run/secubox/media-catch.jsonl` (produit par sbxmitm) et en tire des vues `me`/`all`. Le toolbox l'enrobe dans `_media_stats()` (donuts via `_dpi_donut`), consommé par le rendu PDF (fpdf2 + matplotlib PNG donut-grids) et le template Jinja. Le module DPI expose un endpoint `/media_types` fail-empty et deux cards frontend. Aucun changement du code Go.

**Tech Stack:** Python 3.11, FastAPI, fpdf2, matplotlib (Agg), Jinja2, pytest, HTML/JS vanilla (thème P31).

## Global Constraints

- Licence header `LicenseRef-CMSD-1.0` sur tout nouveau fichier (Python : bloc SPDX + copyright CyberMind — Gérald Kerma <devel@cybermind.fr>).
- Fail-empty partout : `media-catch.jsonl` n'existe qu'en R3/R4 analyst — aucune exception ne doit remonter à une route.
- Lecture seule de `/run/secubox/media-catch.jsonl` (0644). Ne JAMAIS toucher aux permissions de `/run/secubox` (1777 root:root) ni `/etc/secubox` (0755).
- Réutiliser les helpers existants : `_dpi_donut` (pct/start/end), `_pdf_donut_grid`/`_mpl_donut_grid_png` (donuts PNG #703), `_emoji_table`, `_section`, `_kv`, macro Jinja `donut()`, map JS `CATEGORY`/`catMeta`.
- Deux notions de « media » à titrer distinctement : **catégorie de service** (SNI, existant) vs **types de médias captés (MIME)** (nouveau).
- Emoji kinds : `video 📺`, `audio 🎵`, `manifest 🎞️`, `page ▶️` ; ctype générique `🏷️`.
- Commits fréquents, un par tâche, message suffixé `(ref #785)`.
- Les tests tournent depuis le worktree. Core : `cd common && python -m pytest secubox_core/tests/…`. Toolbox : `cd packages/secubox-toolbox && python -m pytest tests/…`. DPI : `cd packages/secubox-dpi && python -m pytest tests/…`.

---

## File Structure

- `common/secubox_core/media_catch.py` — **nouveau** : parseur/agrégateur pur du JSONL. Responsabilité unique : lire + résumer, aucune dépendance FastAPI.
- `common/secubox_core/tests/test_media_catch.py` — **nouveau** : tests unitaires du helper.
- `packages/secubox-toolbox/secubox_toolbox/api.py` — **modifié** : `_media_stats()` + injection dans les 2 routes rapport.
- `packages/secubox-toolbox/tests/test_media_stats.py` — **nouveau** : tests de `_media_stats`.
- `packages/secubox-toolbox/secubox_toolbox/reports.py` — **modifié** : DPI-Exfil/Overall en donut-grids + bloc médias.
- `packages/secubox-toolbox/tests/test_report_pdf_media.py` — **nouveau** : smoke render PDF.
- `packages/secubox-toolbox/conf/report-live.html.j2` — **modifié** : bloc médias dans `#pane-dpi` + `#pane-overall`.
- `packages/secubox-dpi/api/main.py` — **modifié** : endpoint `/media_types`.
- `packages/secubox-dpi/tests/test_media_types.py` — **nouveau** : test endpoint.
- `packages/secubox-dpi/www/dpi/index.html` — **modifié** : card « Types de services » (A) + card « Types de médias » (B) + `loadMediaTypes` dans `refreshAll`.

---

## Task 1: Helper partagé `secubox_core.media_catch`

**Files:**
- Create: `common/secubox_core/media_catch.py`
- Test: `common/secubox_core/tests/test_media_catch.py`

**Interfaces:**
- Produces: `aggregate(path: str = MEDIA_CATCH_PATH, mac_hash: str | None = None, max_lines: int = 50_000) -> dict` returning `{"all": view, "me": view}` where each `view = {"present": bool, "flows": int, "bytes": int, "kinds": list[{"label","emoji","count"}], "ctypes": list[{"label","emoji","count"}], "top_hosts": list[{"host","kind","bytes"}]}`. `me` view is empty (`present=False`) when `mac_hash` is None.
- Module constant `MEDIA_CATCH_PATH = "/run/secubox/media-catch.jsonl"`.

- [ ] **Step 1: Write the failing test**

Create `common/secubox_core/tests/test_media_catch.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for the shared media-catch JSONL aggregator (ref #785)."""
import json
from secubox_core import media_catch


def _write(tmp_path, records):
    p = tmp_path / "media-catch.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return str(p)


def test_absent_file_fail_empty(tmp_path):
    out = media_catch.aggregate(path=str(tmp_path / "nope.jsonl"), mac_hash="aa")
    assert out["all"]["present"] is False
    assert out["me"]["present"] is False
    assert out["all"]["kinds"] == [] and out["all"]["top_hosts"] == []


def test_aggregates_all_and_me(tmp_path):
    path = _write(tmp_path, [
        {"client": "aa", "host": "v.example", "kind": "video", "ctype": "video/mp4", "bytes": 1000},
        {"client": "aa", "host": "a.example", "kind": "audio", "ctype": "audio/mp4", "bytes": 500},
        {"client": "bb", "host": "m.example", "kind": "manifest", "ctype": "application/vnd.apple.mpegurl", "bytes": 100},
        {"client": "aa", "host": "v.example", "kind": "video", "ctype": "video/mp4", "bytes": 2000},
        "this-is-a-corrupt-line-not-json",
    ])
    out = media_catch.aggregate(path=path, mac_hash="aa")
    # all: 4 valid records (corrupt line skipped)
    assert out["all"]["present"] is True
    assert out["all"]["flows"] == 4
    assert out["all"]["bytes"] == 3600
    # me (client aa): 3 records
    me = out["me"]
    assert me["present"] is True
    assert me["flows"] == 3
    # kinds sorted by count desc — video (2) before audio (1)
    labels = [k["label"] for k in me["kinds"]]
    assert labels[0] == "video"
    assert {"video", "audio"} <= set(labels)
    # emoji mapped
    kmap = {k["label"]: k["emoji"] for k in me["kinds"]}
    assert kmap["video"] == "📺" and kmap["audio"] == "🎵"
    # ctypes carry counts + generic emoji
    assert any(c["label"] == "video/mp4" and c["count"] == 2 for c in me["ctypes"])
    # top_hosts sorted by bytes desc, carry kind
    assert me["top_hosts"][0]["host"] == "v.example"
    assert me["top_hosts"][0]["bytes"] == 3000
    assert me["top_hosts"][0]["kind"] == "video"


def test_no_mac_hash_me_empty(tmp_path):
    path = _write(tmp_path, [{"client": "aa", "host": "h", "kind": "video", "bytes": 1}])
    out = media_catch.aggregate(path=path)
    assert out["all"]["present"] is True
    assert out["me"]["present"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd common && python -m pytest secubox_core/tests/test_media_catch.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'secubox_core.media_catch'`

- [ ] **Step 3: Write the implementation**

Create `common/secubox_core/media_catch.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: media-catch aggregator

Shared reader for the sbxmitm media-catch discovery log
(/run/secubox/media-catch.jsonl). Each line is one mediaRecord written by the
toolbox-ng MITM workers in R4/analyst mode:

    {"ts":…, "client":"<mac_hash>", "host":…, "url":…,
     "kind":"manifest|video|audio|page", "ctype":"video/mp4", "bytes":123}

`client` is the same wg-persona mac_hash the report keys on, so aggregate() can
produce a per-device (`me`) view alongside the board-wide (`all`) view. Pure /
stdlib only — no FastAPI, no I/O beyond reading the file. Fail-empty: a missing
file, empty file, or corrupt lines never raise.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

MEDIA_CATCH_PATH = "/run/secubox/media-catch.jsonl"

_KIND_EMOJI = {"video": "📺", "audio": "🎵", "manifest": "🎞️", "page": "▶️"}


def _tail_lines(path: Path, max_lines: int) -> list[str]:
    """Return up to the last `max_lines` decoded lines, best-effort."""
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    parts = raw.splitlines()
    if len(parts) > max_lines:
        parts = parts[-max_lines:]
    out: list[str] = []
    for b in parts:
        try:
            out.append(b.decode("utf-8"))
        except UnicodeDecodeError:
            continue
    return out


def _empty_view() -> dict:
    return {"present": False, "flows": 0, "bytes": 0,
            "kinds": [], "ctypes": [], "top_hosts": []}


def _summarize(records: list[dict]) -> dict:
    if not records:
        return _empty_view()
    kinds: Counter = Counter()
    ctypes: Counter = Counter()
    host_bytes: dict = defaultdict(int)
    host_kind: dict = {}
    total_bytes = 0
    for r in records:
        kind = r.get("kind") or "?"
        kinds[kind] += 1
        ct = r.get("ctype") or ""
        if ct:
            ctypes[ct] += 1
        b = int(r.get("bytes") or 0)
        total_bytes += b
        host = r.get("host") or "?"
        host_bytes[host] += b
        host_kind.setdefault(host, kind)
    kinds_out = [{"label": k, "emoji": _KIND_EMOJI.get(k, "🎬"), "count": c}
                 for k, c in kinds.most_common()]
    ctypes_out = [{"label": k, "emoji": "🏷️", "count": c}
                  for k, c in ctypes.most_common(8)]
    top_hosts = sorted(
        ({"host": h, "kind": host_kind.get(h, "?"), "bytes": b}
         for h, b in host_bytes.items()),
        key=lambda x: x["bytes"], reverse=True)[:10]
    return {"present": True, "flows": len(records), "bytes": total_bytes,
            "kinds": kinds_out, "ctypes": ctypes_out, "top_hosts": top_hosts}


def aggregate(path: str = MEDIA_CATCH_PATH, mac_hash: str | None = None,
              max_lines: int = 50_000) -> dict:
    """Aggregate the media-catch log into {all, me} views. Fail-empty."""
    p = Path(path)
    all_records: list[dict] = []
    me_records: list[dict] = []
    for line in _tail_lines(p, max_lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(rec, dict):
            continue
        all_records.append(rec)
        if mac_hash and rec.get("client") == mac_hash:
            me_records.append(rec)
    return {
        "all": _summarize(all_records),
        "me": _summarize(me_records) if mac_hash else _empty_view(),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd common && python -m pytest secubox_core/tests/test_media_catch.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add common/secubox_core/media_catch.py common/secubox_core/tests/test_media_catch.py
git commit -m "feat(core): shared media-catch JSONL aggregator (ref #785)"
```

---

## Task 2: `_media_stats()` dans le toolbox + injection dans les routes rapport

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` (add `_media_stats` near `_dpi_stats` ~line 2571; wire into `report_me_html` ~2767 and `report_me` ~2806)
- Test: `packages/secubox-toolbox/tests/test_media_stats.py`

**Interfaces:**
- Consumes: `secubox_core.media_catch.aggregate` (Task 1); existing `_dpi_donut(items, n=6)` in the same module.
- Produces: `_media_stats(mac_hash: str | None) -> {"me": view, "all": view}` where each view = `{"present": bool, "flows": int, "bytes": int, "kinds": [donut segs], "ctypes": [donut segs], "top_hosts": [...]}`. Donut segments carry `pct`/`start`/`end` from `_dpi_donut`. Template var name: `media_exfil`. PDF report key: `data["media_exfil"]`.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-toolbox/tests/test_media_stats.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for _media_stats — media-type donut data for the report (ref #785)."""
import json
from secubox_toolbox import api


def _write(tmp_path, records):
    p = tmp_path / "media-catch.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return str(p)


def test_media_stats_shapes_donuts(tmp_path, monkeypatch):
    path = _write(tmp_path, [
        {"client": "aa", "host": "v", "kind": "video", "ctype": "video/mp4", "bytes": 10},
        {"client": "aa", "host": "a", "kind": "audio", "ctype": "audio/mp4", "bytes": 5},
        {"client": "bb", "host": "m", "kind": "manifest", "ctype": "x/y", "bytes": 1},
    ])
    from secubox_core import media_catch
    monkeypatch.setattr(media_catch, "MEDIA_CATCH_PATH", path)
    out = api._media_stats("aa")
    assert out["me"]["present"] is True
    assert out["all"]["present"] is True
    # donut segments carry pct + cumulative bounds
    seg = out["me"]["kinds"][0]
    assert "pct" in seg and "start" in seg and "end" in seg
    assert sum(s["pct"] for s in out["me"]["kinds"]) in (99, 100, 101)


def test_media_stats_fail_empty(tmp_path, monkeypatch):
    from secubox_core import media_catch
    monkeypatch.setattr(media_catch, "MEDIA_CATCH_PATH", str(tmp_path / "absent.jsonl"))
    out = api._media_stats("aa")
    assert out["me"]["present"] is False
    assert out["all"]["present"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_media_stats.py -v`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.api' has no attribute '_media_stats'`

- [ ] **Step 3: Add `_media_stats` implementation**

In `packages/secubox-toolbox/secubox_toolbox/api.py`, immediately AFTER the `_dpi_stats` function (ends ~line 2571, `return {"me": me_stats, "all": all_stats}`), add:

```python
def _media_stats(mac_hash: str | None) -> dict:
    """#785 — media-type donut data (MIME captured by sbxmitm R4) for THIS
    device (me) and board-wide (all). Reuses _dpi_donut for pct/start/end so the
    donuts render identically to the DPI-exfil ones. Fail-empty."""
    from secubox_core import media_catch
    try:
        agg = media_catch.aggregate(path=media_catch.MEDIA_CATCH_PATH, mac_hash=mac_hash)
    except Exception:  # pragma: no cover — helper is fail-empty, this is belt+braces
        agg = {"me": {}, "all": {}}

    def _shape(view: dict) -> dict:
        view = view or {}
        return {
            "present": bool(view.get("present")),
            "flows": view.get("flows", 0),
            "bytes": view.get("bytes", 0),
            "kinds": _dpi_donut(list(view.get("kinds") or [])),
            "ctypes": _dpi_donut(list(view.get("ctypes") or [])),
            "top_hosts": view.get("top_hosts") or [],
        }

    return {"me": _shape(agg.get("me")), "all": _shape(agg.get("all"))}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_media_stats.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Wire into the HTML report route**

In `report_me_html`, the `_env.get_template("report-live.html.j2").render(...)` call (~line 2767) already passes `dpi_exfil=_dpi_e`. Add the media var right after it:

Find:
```python
        dpi_exfil=_dpi_e,
        persona=_persona_sheet(mac_hash, _level, gs, exposure_score, _dpi_e,
```
Replace with:
```python
        dpi_exfil=_dpi_e,
        media_exfil=_media_stats(mac_hash),
        persona=_persona_sheet(mac_hash, _level, gs, exposure_score, _dpi_e,
```

- [ ] **Step 6: Wire into the PDF report route**

In `report_me`, find (~line 2806):
```python
    data["dpi_exfil"] = _dpi_stats(mac_hash)  # #701 — DPI parity with the HTML report
    data["pdf_donuts"] = _build_pdf_donuts(mac_hash, data)  # #703 — visual donuts
```
Replace with:
```python
    data["dpi_exfil"] = _dpi_stats(mac_hash)  # #701 — DPI parity with the HTML report
    data["media_exfil"] = _media_stats(mac_hash)  # #785 — media-type (MIME) donuts
    data["pdf_donuts"] = _build_pdf_donuts(mac_hash, data)  # #703 — visual donuts
```

- [ ] **Step 7: Verify nothing broke + commit**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_media_stats.py -v && python -c "import ast; ast.parse(open('secubox_toolbox/api.py').read()); print('api.py parses OK')"`
Expected: tests PASS + "api.py parses OK"

```bash
git add packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/tests/test_media_stats.py
git commit -m "feat(toolbox): _media_stats + wire media_exfil into report routes (ref #785)"
```

---

## Task 3: PDF fidèle — DPI-Exfil/Overall donut-grids + bloc médias (`reports.py`)

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/reports.py` (replace the DPI/EXFIL section at lines 255-289 in `render_pdf`; add a media block right after)
- Test: `packages/secubox-toolbox/tests/test_report_pdf_media.py`

**Interfaces:**
- Consumes: `data["dpi_exfil"] = {"me","all"}` and `data["media_exfil"] = {"me","all"}` (Task 2); existing `_pdf_donut_grid(pdf, donuts)`, `_emoji_table(pdf, family, title, cols, rows)`, `_section`, `_kv`, `_bullet`.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-toolbox/tests/test_report_pdf_media.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Smoke tests: PDF renders with media_exfil + dpi_exfil donut grids (ref #785)."""
from secubox_toolbox import reports


def _donut(label="video", pct=100):
    return [{"label": label, "emoji": "📺", "count": 1, "pct": pct, "start": 0, "end": pct}]


def _base(**extra):
    d = {"mac_hash": "deadbeef", "device_type": "phone", "generated_at": "2026-07-03",
         "indicators": [], "recommendations": [], "pinned_apps": []}
    d.update(extra)
    return d


def test_pdf_renders_with_media_and_dpi():
    data = _base(
        dpi_exfil={
            "me": {"present": True, "flows": 3, "up": 2048, "down": 4096, "alert_count": 1,
                   "categories": _donut("cloud"), "protocols": _donut("tls"),
                   "alerts": _donut("exfil"), "destinations": _donut("aws")},
            "all": {"devices": 2, "flows": 9, "alert_count": 1,
                    "categories": _donut("media"), "protocols": _donut("quic"),
                    "alerts": _donut("beacon"), "destinations": _donut("yt")},
        },
        media_exfil={
            "me": {"present": True, "flows": 4, "bytes": 5_000_000,
                   "kinds": _donut("video", 60) + _donut("audio", 40),
                   "ctypes": _donut("video/mp4", 100),
                   "top_hosts": [{"host": "v.example", "kind": "video", "bytes": 3_000_000}]},
            "all": {"present": True, "flows": 8, "bytes": 9_000_000,
                    "kinds": _donut("manifest", 100), "ctypes": _donut("x/y", 100),
                    "top_hosts": []},
        },
    )
    blob = reports.render_pdf(data)
    assert isinstance(blob, (bytes, bytearray))
    assert len(blob) > 1000  # a real PDF, not the text stub


def test_pdf_renders_empty_media_no_raise():
    data = _base(dpi_exfil={"me": {"present": False}, "all": {}},
                 media_exfil={"me": {"present": False}, "all": {"present": False}})
    blob = reports.render_pdf(data)
    assert isinstance(blob, (bytes, bytearray)) and len(blob) > 500
```

- [ ] **Step 2: Run test to verify it fails (or reveals the old text rendering)**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_report_pdf_media.py -v`
Expected: `test_pdf_renders_with_media_and_dpi` FAILS or renders WITHOUT the media block (the media section does not exist yet). If fpdf2/matplotlib are installed both tests should run; the first asserts a real PDF which passes only once the media block is added and doesn't raise.

Note: if fpdf2 is absent in the dev env, `render_pdf` returns the text stub (<1000 bytes) and the first test fails on the length assert — install with `pip install fpdf2 matplotlib` before running.

- [ ] **Step 3: Replace the DPI/EXFIL text section with donut grids**

In `packages/secubox-toolbox/secubox_toolbox/reports.py`, find the block starting at line 255 (`# ── DPI / EXFILTRATION (R3 per-device + overall) — #701 (parity with HTML) ──`) through the `pdf.ln(2)` at line 289 (the whole `if dme.get("present") or dall.get("categories"):` block including the nested `_donut_lines` helper). Replace ALL of it with:

```python
    # ── DPI / EXFILTRATION (R3 per-device + overall) — donut grids (#785 parité HTML) ──
    dexf = report.get("dpi_exfil") or {}
    dme = dexf.get("me") or {}
    dall = dexf.get("all") or {}
    if dme.get("present") or dall.get("categories"):
        _section(pdf, "DPI / EXFILTRATION (TUNNEL R3)")
        if dme.get("present"):
            up_mo = round((dme.get("up", 0) or 0) / 1048576, 1)
            dn_mo = round((dme.get("down", 0) or 0) / 1048576, 1)
            _kv(pdf, "Cet appareil",
                f"{dme.get('flows', 0)} flux | {up_mo} Mo envoyes | {dn_mo} Mo recus | {dme.get('alert_count', 0)} alertes")
            _pdf_donut_grid(pdf, [
                {"title": "🏷️ Catégories de service", "hole": "flux", "segments": dme.get("categories") or []},
                {"title": "📡 Protocoles", "hole": "octets", "segments": dme.get("protocols") or []},
                {"title": "🛰️ Alertes exfil", "hole": "alertes", "segments": dme.get("alerts") or []},
                {"title": "🎯 Top destinations", "hole": "envoi", "segments": dme.get("destinations") or []},
            ])
        else:
            _bullet(pdf, "Aucune donnee DPI pour cet appareil (surfer via le tunnel R3).", font_size=8)
        if dall.get("categories") or dall.get("protocols") or dall.get("destinations"):
            _kv(pdf, "Reseau (tous appareils)",
                f"{dall.get('devices', 0)} appareils | {dall.get('flows', 0)} flux | {dall.get('alert_count', 0)} alertes")
            _pdf_donut_grid(pdf, [
                {"title": "🏷️ Catégories (global)", "hole": "flux", "segments": dall.get("categories") or []},
                {"title": "📡 Protocoles (global)", "hole": "octets", "segments": dall.get("protocols") or []},
                {"title": "🛰️ Alertes (global)", "hole": "alertes", "segments": dall.get("alerts") or []},
                {"title": "🎯 Top destinations (global)", "hole": "octets", "segments": dall.get("destinations") or []},
            ])
        pdf.ln(2)

    # ── TYPES DE MÉDIAS CAPTÉS (MIME — MITM R4) — #785 ──
    mexf = report.get("media_exfil") or {}
    mme = mexf.get("me") or {}
    mall = mexf.get("all") or {}
    if mme.get("present") or mall.get("present"):
        _section(pdf, "TYPES DE MEDIAS CAPTES (MIME - MITM R4)")
        if mme.get("present"):
            _kv(pdf, "Cet appareil",
                f"{mme.get('flows', 0)} flux media | {round((mme.get('bytes', 0) or 0) / 1048576, 1)} Mo")
        if mall.get("present"):
            _kv(pdf, "Reseau",
                f"{mall.get('flows', 0)} flux media | {round((mall.get('bytes', 0) or 0) / 1048576, 1)} Mo")
        _pdf_donut_grid(pdf, [
            {"title": "📺 Types (cet appareil)", "hole": "média", "segments": mme.get("kinds") or []},
            {"title": "🏷️ Content-Type (appareil)", "hole": "MIME", "segments": mme.get("ctypes") or []},
            {"title": "📺 Types (réseau)", "hole": "média", "segments": mall.get("kinds") or []},
            {"title": "🏷️ Content-Type (réseau)", "hole": "MIME", "segments": mall.get("ctypes") or []},
        ])
        hosts = mme.get("top_hosts") or mall.get("top_hosts") or []
        if hosts:
            _emoji_table(pdf, family, "🎬 TOP HÔTES MÉDIA",
                         [("Type", 0.16), ("Hôte", 0.56), ("Mo", 0.28)],
                         [[h.get("kind", "?"), h.get("host", "?"),
                           round((h.get("bytes", 0) or 0) / 1048576, 2)]
                          for h in hosts[:10]])
```

Note: `family` and the helpers are all in scope inside `render_pdf`. `_pdf_donut_grid` renders "Pas de données" per empty axis, so partial data (me-only or all-only) renders cleanly.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_report_pdf_media.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Guard against regressions in the existing report test**

Run: `cd packages/secubox-toolbox && python -m pytest tests/ -k "report or pdf or bundle" -v`
Expected: PASS (no regression in existing report/bundle tests)

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/reports.py packages/secubox-toolbox/tests/test_report_pdf_media.py
git commit -m "feat(toolbox): PDF DPI-exfil/overall donut-grids + media-type block (ref #785)"
```

---

## Task 4: Parité web — bloc médias dans `report-live.html.j2`

**Files:**
- Modify: `packages/secubox-toolbox/conf/report-live.html.j2` (add a media card in `#pane-dpi` before its closing `</div>{# /pane-dpi #}` at line 449, and in `#pane-overall` before `</div>{# /pane-overall #}` at line 473)
- Test: `packages/secubox-toolbox/tests/test_report_template_media.py`

**Interfaces:**
- Consumes: template var `media_exfil = {"me","all"}` (Task 2 wired it into `report_me_html`); existing macro `donut(title, hole, items)`.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-toolbox/tests/test_report_template_media.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""The report template renders the media-type block (me + overall) (ref #785)."""
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

CONF = Path(__file__).resolve().parents[1] / "conf"


def _render(media_exfil):
    env = Environment(loader=FileSystemLoader(str(CONF)))
    tpl = env.get_template("report-live.html.j2")
    return tpl.render(
        metrics={}, graph_stats={}, exposure_score=0, charts={}, graph={"edges": []},
        persona={}, dpi_exfil={"me": {}, "all": {}}, media_exfil=media_exfil,
        mac_hash="deadbeef", ip="10.99.0.2", device_type="phone",
        current_level="r3", indicators=[], recommendations=[], avatar_analysis={},
        cookies_providers=[], geo_top_hosts=[], pinned_apps=[], transparency={},
        request_args={},
    )


def test_media_block_present_when_data():
    html = _render({
        "me": {"present": True, "kinds": [{"label": "video", "emoji": "📺", "pct": 100, "start": 0, "end": 100}],
               "ctypes": [{"label": "video/mp4", "emoji": "🏷️", "pct": 100, "start": 0, "end": 100}],
               "top_hosts": [{"host": "v.example", "kind": "video", "bytes": 3000000}]},
        "all": {"present": True, "kinds": [{"label": "manifest", "emoji": "🎞️", "pct": 100, "start": 0, "end": 100}],
                "ctypes": [], "top_hosts": []},
    })
    assert "Types de médias captés" in html
    assert "video/mp4" in html
    assert "v.example" in html


def test_media_block_fail_empty_no_error():
    html = _render({"me": {"present": False}, "all": {"present": False}})
    assert "Types de médias captés" in html  # card title still there
    assert "Aucun média" in html             # fail-empty message
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_report_template_media.py -v`
Expected: FAIL — `assert "Types de médias captés" in html` fails (block not added yet)

- [ ] **Step 3: Add the media card to `#pane-dpi`**

In `packages/secubox-toolbox/conf/report-live.html.j2`, find (line ~448-449):
```jinja
    {% endif %}
  </div>
</div>{# /pane-dpi #}
```
Replace with (inserts the media card inside the pane, after the existing DPI card):
```jinja
    {% endif %}
  </div>
  {% set mme = (media_exfil or {}).me or {} %}
  <div class="card">
    <h2>🎬 Types de médias captés (MITM R4)</h2>
    {% if mme.present %}
    <div class="graphs">
      {{ donut('📺 Types de médias', 'média', mme.kinds) }}
      {{ donut('🏷️ Content-Type', 'MIME', mme.ctypes) }}
    </div>
    {% if mme.top_hosts %}
    <table style="margin-top:.6rem"><thead><tr><th>Type</th><th>Hôte</th><th style="text-align:right">Mo</th></tr></thead><tbody>
      {% for h in mme.top_hosts[:8] %}
      <tr><td>{{ h.kind }}</td><td><code>{{ h.host[:36] }}</code></td><td style="text-align:right;color:var(--phos)">{{ (h.bytes/1048576)|round(1) }}</td></tr>
      {% endfor %}
    </tbody></table>
    {% endif %}
    <p class="help">Types de contenu réellement captés par le MITM (vidéo/audio/manifests HLS·DASH/pages). Distinct de la catégorie de service « media » (SNI streaming).</p>
    {% else %}
    <div class="empty">Aucun média capté — surfer via le tunnel R3 (🧅) et lire une vidéo/audio pour alimenter cette vue.</div>
    {% endif %}
</div>{# /pane-dpi #}
```

- [ ] **Step 4: Add the media card to `#pane-overall`**

Find (line ~471-473):
```jinja
    {% endif %}
  </div>
</div>{# /pane-overall #}
```
Replace with:
```jinja
    {% endif %}
  </div>
  {% set mall = (media_exfil or {}).all or {} %}
  <div class="card">
    <h2>🎬 Types de médias captés — réseau</h2>
    {% if mall.present %}
    <div class="graphs">
      {{ donut('📺 Types de médias', 'média', mall.kinds) }}
      {{ donut('🏷️ Content-Type', 'MIME', mall.ctypes) }}
    </div>
    {% if mall.top_hosts %}
    <table style="margin-top:.6rem"><thead><tr><th>Type</th><th>Hôte</th><th style="text-align:right">Mo</th></tr></thead><tbody>
      {% for h in mall.top_hosts[:8] %}
      <tr><td>{{ h.kind }}</td><td><code>{{ h.host[:36] }}</code></td><td style="text-align:right;color:var(--phos)">{{ (h.bytes/1048576)|round(1) }}</td></tr>
      {% endfor %}
    </tbody></table>
    {% endif %}
    <p class="help">Contenus média captés à l'échelle du réseau (tous appareils R3/R4).</p>
    {% else %}
    <div class="empty">Aucun média capté à l'échelle réseau (tunnel R3/R4 inactif ou première capture en cours).</div>
    {% endif %}
</div>{# /pane-overall #}
```

Note: `test_media_block_fail_empty` asserts on the `#pane-dpi` card (`mme`). The overall fail-empty message differs ("à l'échelle réseau") which is fine.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_report_template_media.py -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-toolbox/conf/report-live.html.j2 packages/secubox-toolbox/tests/test_report_template_media.py
git commit -m "feat(toolbox): media-type cards in report web page (me + overall) (ref #785)"
```

---

## Task 5: WebUI DPI — Card A « Types de services captés » (frontend only)

**Files:**
- Modify: `packages/secubox-dpi/www/dpi/index.html` (add card markup after the exfil-card ~line 361; add aggregation+render inside `loadExfil` after the per-device block ~line 615)

**Interfaces:**
- Consumes: `/exfil` response already fetched by `loadExfil` (`devices[].services[]` carry `category`, `up_bytes`, `down_bytes`, `flows`); existing `catMeta()`, `formatBytes()`.

- [ ] **Step 1: Add the card markup**

In `packages/secubox-dpi/www/dpi/index.html`, find the timeline card (line ~363-369) and insert a new card BEFORE it. Find:
```html
            <!-- #720 — per-day timeline (board-wide) -->
            <div class="card">
                <div class="card-header"><h2>📈 Timeline — flux/jour (14 j)</h2></div>
```
Replace with:
```html
            <!-- #785 — services aggregated by category (up/down bytes board-wide) -->
            <div class="card">
                <div class="card-header"><h2>🏷️ Types de services captés <span style="color: var(--text-dim); text-transform:none; letter-spacing:0; font-size:0.7rem;">— octets par catégorie (SNI)</span></h2></div>
                <div class="app-list" id="svc-categories"><p class="empty">Loading…</p></div>
            </div>

            <!-- #720 — per-day timeline (board-wide) -->
            <div class="card">
                <div class="card-header"><h2>📈 Timeline — flux/jour (14 j)</h2></div>
```

- [ ] **Step 2: Add the aggregation + render in `loadExfil`**

In the same file, find the end of the per-device rollup in `loadExfil`, the line (~617-619):
```javascript
            foot.textContent = data.generated_at
                ? `Last capture: ${agoStr(data.generated_at)} · ${devices.length} device(s) · ${alerts.length} alert(s)`
                : (data.note || 'no capture window completed yet');
```
Insert AFTER that statement (before the `// #695 fill the list cards` comment):
```javascript

            // #785 Card A — services aggregated by category (bytes, board-wide)
            const byCat = {};
            devices.forEach(d => (d.services || d.clouds || []).forEach(c => {
                const cat = c.category || 'other';
                const e = byCat[cat] || (byCat[cat] = { up: 0, down: 0, flows: 0 });
                e.up += c.up_bytes || 0; e.down += c.down_bytes || 0; e.flows += (c.flows || 1);
            }));
            const svcBox = document.getElementById('svc-categories');
            if (svcBox) {
                const catRows = Object.keys(byCat).sort((a, b) => (byCat[b].up + byCat[b].down) - (byCat[a].up + byCat[a].down));
                svcBox.innerHTML = catRows.length ? catRows.map(cat => {
                    const m = catMeta(cat); const e = byCat[cat];
                    return `<div class="app-item"${m.exfil ? ' style="border-left:2px solid #ff4466; padding-left:0.5rem;"' : ''}>
                        <span><span class="badge ${m.cls}" style="margin-right:0.4rem;">${m.icon} ${cat}</span>
                            <span style="color:var(--text-dim);">${e.flows}f</span></span>
                        <span class="bytes">↑${formatBytes(e.up)} ↓${formatBytes(e.down)}</span>
                    </div>`;
                }).join('') : '<p class="empty">no classified egress yet</p>';
            }
```

- [ ] **Step 3: Verify the file still parses as HTML (balanced) + no JS syntax error**

Run: `cd packages/secubox-dpi && node --check <(sed -n '/<script>/,/<\/script>/p' www/dpi/index.html | grep -v -E '</?script') 2>&1 | head` — if `node` is unavailable, instead grep-verify the insert landed once:
Run: `grep -c "svc-categories" www/dpi/index.html`
Expected: `2` (the card div id + the getElementById)

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-dpi/www/dpi/index.html
git commit -m "feat(dpi): WebUI card — services by category (bytes) (ref #785)"
```

---

## Task 6: WebUI DPI — endpoint `GET /media_types`

**Files:**
- Modify: `packages/secubox-dpi/api/main.py` (add endpoint after `/history` ~line 111)
- Test: `packages/secubox-dpi/tests/test_media_types.py`

**Interfaces:**
- Consumes: `secubox_core.media_catch.aggregate` (Task 1).
- Produces: `GET /media_types` → the board-wide `all` view: `{"present","flows","bytes","kinds","ctypes","top_hosts"}`. No JWT (registered on `app`, like `/exfil`).

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-dpi/tests/test_media_types.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Test the DPI /media_types endpoint — fail-empty + populated (ref #785)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # make api importable
from fastapi.testclient import TestClient  # noqa: E402
from api.main import app  # noqa: E402


def test_media_types_fail_empty(tmp_path, monkeypatch):
    from secubox_core import media_catch
    monkeypatch.setattr(media_catch, "MEDIA_CATCH_PATH", str(tmp_path / "absent.jsonl"))
    r = TestClient(app).get("/media_types")
    assert r.status_code == 200
    assert r.json()["present"] is False


def test_media_types_populated(tmp_path, monkeypatch):
    p = tmp_path / "media-catch.jsonl"
    p.write_text(json.dumps({"client": "aa", "host": "v", "kind": "video",
                             "ctype": "video/mp4", "bytes": 10}) + "\n")
    from secubox_core import media_catch
    monkeypatch.setattr(media_catch, "MEDIA_CATCH_PATH", str(p))
    r = TestClient(app).get("/media_types")
    body = r.json()
    assert body["present"] is True
    assert any(k["label"] == "video" for k in body["kinds"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-dpi && python -m pytest tests/test_media_types.py -v`
Expected: FAIL — 404 on `/media_types` (endpoint not defined). (If `api.main` import needs deps, install FastAPI + secubox_core first: `pip install fastapi httpx` and ensure `common/` is on PYTHONPATH.)

- [ ] **Step 3: Add the endpoint**

In `packages/secubox-dpi/api/main.py`, after the `/history` endpoint (ends ~line 111 with `return {"device": "", "days": days_sorted[-days:]}`), add:

```python
@app.get("/media_types")
async def media_types():
    """#785 — board-wide MIME media-type breakdown captured by the sbxmitm R4
    media-catcher (/run/secubox/media-catch.jsonl). Distinct from the DPI service
    category 'media' (SNI). Read-only, no auth (like /exfil), fail-empty."""
    try:
        from secubox_core import media_catch
        agg = media_catch.aggregate(path=media_catch.MEDIA_CATCH_PATH)
        view = agg.get("all") or {}
        return {"present": bool(view.get("present")),
                "flows": view.get("flows", 0), "bytes": view.get("bytes", 0),
                "kinds": view.get("kinds", []), "ctypes": view.get("ctypes", []),
                "top_hosts": view.get("top_hosts", [])}
    except Exception as e:  # pragma: no cover
        return {"present": False, "flows": 0, "bytes": 0,
                "kinds": [], "ctypes": [], "top_hosts": [], "error": str(e)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-dpi && python -m pytest tests/test_media_types.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-dpi/api/main.py packages/secubox-dpi/tests/test_media_types.py
git commit -m "feat(dpi): /media_types endpoint (MIME media-catch, fail-empty) (ref #785)"
```

---

## Task 7: WebUI DPI — Card B « Types de médias captés » (MIME) + refreshAll

**Files:**
- Modify: `packages/secubox-dpi/www/dpi/index.html` (add card markup after the svc-categories card from Task 5; add `loadMediaTypes()` function; call it in `refreshAll`)

**Interfaces:**
- Consumes: `GET /api/v1/dpi/media_types` (Task 6); existing `api()`, `formatBytes()`.

- [ ] **Step 1: Add the card markup**

In `packages/secubox-dpi/www/dpi/index.html`, find the svc-categories card added in Task 5:
```html
                <div class="app-list" id="svc-categories"><p class="empty">Loading…</p></div>
            </div>

            <!-- #720 — per-day timeline (board-wide) -->
```
Replace with (adds the MIME card right after):
```html
                <div class="app-list" id="svc-categories"><p class="empty">Loading…</p></div>
            </div>

            <!-- #785 — MIME media types captured by sbxmitm R4 -->
            <div class="card">
                <div class="card-header"><h2>🎬 Types de médias captés <span style="color: var(--text-dim); text-transform:none; letter-spacing:0; font-size:0.7rem;">— Content-Type réels (MITM R4)</span></h2></div>
                <div class="app-list" id="media-types"><p class="empty">Loading…</p></div>
            </div>

            <!-- #720 — per-day timeline (board-wide) -->
```

- [ ] **Step 2: Add the `loadMediaTypes` function**

Find the `loadTimeline` function (starts ~line 665 `async function loadTimeline()`). Insert BEFORE it:
```javascript
        async function loadMediaTypes() {
            const data = await api('/media_types');
            const box = document.getElementById('media-types');
            if (!box) return;
            const KIND_ICON = { video: '📺', audio: '🎵', manifest: '🎞️', page: '▶️' };
            const kinds = (data && data.kinds) || [];
            const ctypes = (data && data.ctypes) || [];
            const hosts = (data && data.top_hosts) || [];
            if (!kinds.length && !ctypes.length) {
                box.innerHTML = '<p class="empty">Aucun média capté (tunnel R3/R4 requis + lecture vidéo/audio).</p>';
                return;
            }
            const kindRows = kinds.map(k =>
                `<div class="app-item"><span>${KIND_ICON[k.label] || '🎬'} ${k.label}</span><span class="bytes">${k.count}</span></div>`).join('');
            const ctypeRows = ctypes.slice(0, 6).map(c =>
                `<div class="app-item"><span style="font-family:monospace; font-size:0.78rem;">${c.label}</span><span class="bytes">${c.count}</span></div>`).join('');
            const hostRows = hosts.slice(0, 6).map(h =>
                `<div class="app-item"><span>${KIND_ICON[h.kind] || '🎬'} <span style="font-family:monospace; font-size:0.78rem;">${(h.host || '').slice(0, 32)}</span></span><span class="bytes">${formatBytes(h.bytes)}</span></div>`).join('');
            box.innerHTML =
                `<div style="color:var(--text-dim); font-size:0.7rem; margin-bottom:0.3rem;">Types</div>${kindRows}` +
                `<div style="color:var(--text-dim); font-size:0.7rem; margin:0.5rem 0 0.3rem;">Content-Type (MIME)</div>${ctypeRows}` +
                (hostRows ? `<div style="color:var(--text-dim); font-size:0.7rem; margin:0.5rem 0 0.3rem;">Top hôtes</div>${hostRows}` : '');
        }

```

- [ ] **Step 3: Call it in `refreshAll`**

Find (~line 682-687):
```javascript
        function refreshAll() {
            loadStatus();
            loadExfil();   // #695: also fills Top Apps/Protocols/Bandwidth/Active-Flows from the exfil engine
            loadTimeline();
            loadBlockRules();
        }
```
Replace with:
```javascript
        function refreshAll() {
            loadStatus();
            loadExfil();   // #695: also fills Top Apps/Protocols/Bandwidth/Active-Flows from the exfil engine
            loadMediaTypes();  // #785: MIME media types captured by sbxmitm R4
            loadTimeline();
            loadBlockRules();
        }
```

- [ ] **Step 4: Verify the inserts landed**

Run: `cd packages/secubox-dpi && grep -c "media-types" www/dpi/index.html && grep -c "loadMediaTypes" www/dpi/index.html`
Expected: `2` (card id + getElementById) then `2` (definition + refreshAll call)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-dpi/www/dpi/index.html
git commit -m "feat(dpi): WebUI card — MIME media types + refreshAll wiring (ref #785)"
```

---

## Final verification

- [ ] **Run all touched test suites:**

```bash
cd common && python -m pytest secubox_core/tests/test_media_catch.py -q
cd ../packages/secubox-toolbox && python -m pytest tests/test_media_stats.py tests/test_report_pdf_media.py tests/test_report_template_media.py -q
cd ../secubox-dpi && python -m pytest tests/test_media_types.py -q
```
Expected: all green.

- [ ] **No-regression sweep on toolbox report/bundle tests:**

```bash
cd packages/secubox-toolbox && python -m pytest tests/ -q
```
Expected: no new failures vs. baseline (`git stash` + run on master to compare if unsure).

- [ ] **Deploy note (not a code step):** 3 paquets touchés — `secubox-core`, `secubox-toolbox`, `secubox-dpi`. Rebuild + redeploy des 3 ; invalider le cache nginx des statics (`/dpi/`, page report). `media-catch.jsonl` n'est peuplé qu'avec sbxmitm en R3/R4 — pour valider en live, surfer via wg-toolbox et lire une vidéo, puis vérifier `/report/me/html` (onglets DPI-Exfil + Overall) et `/dpi/` (2 nouvelles cards).

---

## Self-Review

**Spec coverage:**
- Core helper `media_catch` → Task 1 ✅
- `_media_stats(me,all)` + wiring → Task 2 ✅
- PDF DPI-Exfil + Overall donut-grids + media block → Task 3 ✅
- Web parity media block (me + overall) → Task 4 ✅
- DPI Card A (services by category, bytes) → Task 5 ✅
- DPI `/media_types` endpoint → Task 6 ✅
- DPI Card B (MIME) + refreshAll → Task 7 ✅
- Fail-empty everywhere → covered in Tasks 1/2/3/4/6 tests ✅
- Two "media" notions titled distinctly → Task 3 (`TYPES DE MEDIAS CAPTES` vs `Catégories de service`), Task 4 help text, Task 5 vs Task 7 card titles ✅

**Type consistency:** `aggregate()` returns `{all, me}` with view keys `present/flows/bytes/kinds/ctypes/top_hosts`; `_media_stats` preserves those keys and adds donut pct via `_dpi_donut`; `reports.py` reads `.kinds/.ctypes/.top_hosts`; template reads `.me.kinds/.ctypes/.top_hosts` and `.all.*`; DPI endpoint returns the `all` view keys; frontend reads `.kinds/.ctypes/.top_hosts`. Consistent throughout. Kind emoji map identical in core (`_KIND_EMOJI`) and frontend (`KIND_ICON`).

**Placeholder scan:** none — all steps carry concrete code/commands.
