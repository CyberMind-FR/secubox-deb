# Rich PDF Character Sheet + Route Parity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the PDF report's Netrunner character sheet as rich as the HTML `.nr` card (pip attributes + notes, on/off inventory, bestiary, active-threats section), and make all three PDF routes emit the same enriched content.

**Architecture:** Part A enriches the existing `reports._persona_block` (full-fpdf, no matplotlib) plus a small `_attr_row` helper. Part B extracts `report_me`'s inline data-enrichment into `api._enrich_report_data(mac_hash, data, ua="")` and calls it from `report_me`, `report` (token), and `admin_client_report`.

**Tech Stack:** Python 3.11, fpdf2 (no matplotlib added), FastAPI, pytest.

## Global Constraints

- New test file(s) MUST carry the full 4-line SPDX header block: `# SPDX-License-Identifier: LicenseRef-CMSD-1.0` + `# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>` + `# Source-Disclosed License — All rights reserved except as expressly granted.` + `# See LICENCE-CMSD-1.0.md for terms.`
- The character sheet is **full-fpdf** — do NOT add any matplotlib render (keeps `render_pdf` light; the #785 incident was matplotlib-driven).
- Every text string drawn in the PDF goes through the existing `_safe(...)` helper (emoji-safe).
- The Quêtes/menaces section MUST fail-safe on missing keys: `alerts = ((report.get("dpi_exfil") or {}).get("me") or {}).get("alerts") or []`.
- Pip count clamped to 0..6 before string multiplication.
- Reuse existing helpers (`_safe`, `_persona_bar`, `_bullet`, `_page_w`) and the existing palette. No new drawing engine.
- Only `packages/secubox-toolbox/secubox_toolbox/reports.py`, `.../api.py`, and test files may change.
- Tests run from the package dir: `cd packages/secubox-toolbox && PYTHONPATH=<worktree>/common <venv>/bin/python3 -m pytest tests/<f> -q`. Venv: `/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3` (has fpdf2 + matplotlib).

---

## File Structure

- `packages/secubox-toolbox/secubox_toolbox/reports.py` — **modify**: add `_attr_row`; rewrite `_persona_block` body (lines 568-603) to the rich layout.
- `packages/secubox-toolbox/tests/test_persona_pdf.py` — **new**: tests for the enriched persona block.
- `packages/secubox-toolbox/secubox_toolbox/api.py` — **modify**: add `_enrich_report_data`; replace `report_me`'s inline block (2882-2904); add the call to `report` and `admin_client_report`.
- `packages/secubox-toolbox/tests/test_enrich_report_data.py` — **new**: hermetic test of the enrichment helper.

---

## Task 1: Enrich `_persona_block` (Part A)

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/reports.py` (add `_attr_row` before `_persona_block` at line 568; replace `_persona_block` body 568-603)
- Test: `packages/secubox-toolbox/tests/test_persona_pdf.py`

**Interfaces:**
- Consumes: `report["persona"]` = `{emoji, tag, klass, level, align, hp, exposure, xp, attrs:[{icon,name,v,pips,note}], inventory:[{icon,name,on}]}`; `report["bestiary"]` = `[{label,count,emoji?}]`; `report["dpi_exfil"]["me"]["alerts"]` = `[{kind,label?,service?,dst?,detail?}]`. Existing module helpers `_safe`, `_persona_bar`, `_bullet`, `_page_w`.
- Produces: `_attr_row(pdf, family, a)` (renders one attribute line); the enriched `_persona_block(pdf, family, report)` (same signature).

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-toolbox/tests/test_persona_pdf.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Rich PDF character sheet (#790): pips, on/off inventory, quests section."""
from secubox_toolbox import reports


def _base(**extra):
    d = {"mac_hash": "deadbeef", "device_type": "phone", "generated_at": "2026-07-04",
         "indicators": [], "recommendations": [], "pinned_apps": []}
    d.update(extra)
    return d


_PERSONA = {
    "emoji": "🧑‍💻", "tag": "VILLAGE3B·#A1B2", "klass": "Runner", "level": "R3",
    "align": "🛡️ Protégé", "hp": 85, "exposure": 15, "xp": 12480,
    "attrs": [
        {"icon": "🛡️", "name": "DÉFENSE", "v": 14, "pips": 5, "note": ""},
        {"icon": "⚔️", "name": "RIPOSTE", "v": 6, "pips": 2, "note": "312 pubs tuées"},
    ],
    "inventory": [
        {"icon": "🧅", "name": "Tunnel Tor", "on": True},
        {"icon": "🚫", "name": "Ad-blocker", "on": False},
    ],
}


def _spy_safe(monkeypatch):
    """Capture every string drawn (everything is wrapped in reports._safe)."""
    seen = []
    orig = reports._safe
    monkeypatch.setattr(reports, "_safe", lambda t: (seen.append(str(t)), orig(t))[1])
    return seen


def test_persona_rich_sections_and_pips(monkeypatch):
    seen = _spy_safe(monkeypatch)
    data = _base(persona=_PERSONA,
                 bestiary=[{"label": "doubleclick.net", "count": 42, "emoji": "👹"}],
                 dpi_exfil={"me": {"alerts": [
                     {"kind": "exfil_volume", "label": "exfil", "service": "drive.google", "detail": "up 4.2Mo"}]}})
    blob = reports.render_pdf(data)
    assert isinstance(blob, (bytes, bytearray)) and len(blob) > 1000
    joined = " ".join(seen)
    assert "CARACTERISTIQUES" in joined           # attributes section header
    assert "QUETES EN COURS" in joined            # quests section header
    assert "●" in joined and "○" in joined         # pip glyphs rendered
    assert any("✓" in s for s in seen) and any("✗" in s for s in seen)  # on/off inventory
    assert any("EXFIL" in s for s in seen)         # the alert surfaced in Quêtes
    assert any("doubleclick" in s for s in seen)   # bestiary


def test_persona_no_alerts_shows_safe_zone(monkeypatch):
    seen = _spy_safe(monkeypatch)
    data = _base(persona=_PERSONA, dpi_exfil={"me": {"alerts": []}})
    reports.render_pdf(data)
    assert any("zone sure" in s for s in seen)     # empty-threats message


def test_persona_missing_dpi_exfil_no_raise(monkeypatch):
    # dpi_exfil absent entirely (legacy/token path before enrichment) must not raise
    data = _base(persona=_PERSONA)
    blob = reports.render_pdf(data)
    assert isinstance(blob, (bytes, bytearray)) and len(blob) > 500
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/790-pdf-report-rich-netrunner-character-shee/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_persona_pdf.py -v`
Expected: `test_persona_rich_sections_and_pips` FAILS (`"CARACTERISTIQUES" in joined` is false — current block draws widgets, not this header; no pips; no Quêtes section). The other two may pass or fail; all three must pass after Step 3.

- [ ] **Step 3: Add `_attr_row` and rewrite `_persona_block`**

In `packages/secubox-toolbox/secubox_toolbox/reports.py`, insert `_attr_row` immediately BEFORE `def _persona_block` (line 568):

```python
def _attr_row(pdf, family: str, a: dict) -> None:
    """#790 — one character-sheet attribute line: icon+name · pips · value · note."""
    pips = max(0, min(6, int(a.get("pips", 0) or 0)))
    pdf.set_x(pdf.l_margin)
    pdf.set_font(family, "", 9)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(42, 5, _safe(f"{a.get('icon', '')} {a.get('name', '')[:12]}"), ln=False)
    pdf.set_text_color(0, 200, 80)
    pdf.cell(26, 5, _safe("●" * pips + "○" * (6 - pips)), ln=False)
    pdf.set_font(family, "B", 9)
    pdf.set_text_color(0, 120, 255)
    pdf.cell(12, 5, _safe(str(a.get("v", 0))), ln=False)
    note = a.get("note") or ""
    if note:
        pdf.set_font(family, "I", 7)
        pdf.set_text_color(140, 140, 140)
        pdf.cell(0, 5, _safe(str(note)[:48]), ln=True)
    else:
        pdf.ln()
    pdf.set_text_color(0)
```

Then REPLACE the entire body of `_persona_block` (currently lines 568-603, from `def _persona_block` through its final `pdf.ln(2)`) with:

```python
def _persona_block(pdf, family: str, report: dict) -> None:
    """#707/#790 — Cyberpunk-Netrunner character sheet for the PDF, faithful to
    the HTML .nr card: pip attributes + notes, on/off inventory, bestiary, and
    the active-threats (Quêtes) section from dpi_exfil alerts."""
    p = report.get("persona") or {}
    pdf.set_font(family, "B", 12)
    pdf.set_text_color(0, 212, 255)
    pdf.cell(0, 6, _safe("🎮 FICHE NETRUNNER"), ln=True)
    pdf.set_font(family, "B", 11)
    pdf.set_text_color(0, 212, 255)
    pdf.cell(0, 6, _safe(f"{p.get('emoji','')} {p.get('tag','?')}"), ln=True)
    pdf.set_font(family, "", 9)
    pdf.set_text_color(150, 120, 230)
    pdf.cell(0, 5, _safe(f"Classe {p.get('klass','?')}  ·  Niveau {p.get('level','?')}  ·  {p.get('align','')}"), ln=True)
    pdf.ln(1)
    _persona_bar(pdf, family, "ICE / integrite", p.get("hp", 0), (0, 255, 65))
    _persona_bar(pdf, family, "Exposition", p.get("exposure", 0), (255, 179, 71))
    pdf.set_font(family, "", 8)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 4, _safe(f"XP {p.get('xp',0):,} Ko echanges (7j)"), ln=True)
    pdf.ln(1)

    # ⚡ Caracteristiques — pip rows (mirror of the HTML .nr attributes)
    pdf.set_x(pdf.l_margin)
    pdf.set_font(family, "B", 9)
    pdf.set_text_color(0, 212, 255)
    pdf.cell(0, 5, _safe("⚡ CARACTERISTIQUES"), ln=True)
    for a in (p.get("attrs") or [])[:4]:
        _attr_row(pdf, family, a)

    # 🎒 Inventaire · protections — on/off checks
    inv = p.get("inventory") or []
    if inv:
        pdf.set_x(pdf.l_margin)
        pdf.set_font(family, "B", 9)
        pdf.set_text_color(0, 212, 255)
        pdf.cell(0, 5, _safe("🎒 INVENTAIRE · PROTECTIONS"), ln=True)
        pdf.set_x(pdf.l_margin)
        pdf.set_font(family, "", 8)
        for it in inv:
            seg = _safe(f"{it.get('icon','')} {it.get('name','')}  ")
            pdf.set_text_color(40, 40, 40)
            pdf.cell(pdf.get_string_width(seg) + 1, 5, seg, ln=False)
            if it.get("on"):
                pdf.set_text_color(0, 180, 70)
                mark = _safe("✓   ")
            else:
                pdf.set_text_color(170, 170, 170)
                mark = _safe("✗   ")
            pdf.cell(pdf.get_string_width(mark) + 2, 5, mark, ln=False)
        pdf.ln(6)

    # 🐉 Bestiaire · qui te traque — top trackers
    best = report.get("bestiary") or []
    if best:
        pdf.set_x(pdf.l_margin)
        pdf.set_font(family, "B", 9)
        pdf.set_text_color(0, 212, 255)
        pdf.cell(0, 5, _safe("🐉 BESTIAIRE · QUI TE TRAQUE"), ln=True)
        for b in best[:5]:
            _bullet(pdf, f"{b.get('emoji', '👾')} {b.get('label', '?')[:24]}  x{b.get('count', 0)}", font_size=8)

    # ⚔️ Quetes en cours · menaces — from dpi_exfil alerts (#790)
    alerts = ((report.get("dpi_exfil") or {}).get("me") or {}).get("alerts") or []
    pdf.set_x(pdf.l_margin)
    pdf.set_font(family, "B", 9)
    pdf.set_text_color(0, 212, 255)
    pdf.cell(0, 5, _safe("⚔️ QUETES EN COURS · MENACES"), ln=True)
    if alerts:
        for q in alerts[:5]:
            label = q.get("label") or q.get("kind") or "?"
            dest = q.get("service") or q.get("dst") or ""
            detail = q.get("detail") or ""
            _bullet(pdf, f"🗡️ {str(label).upper()} — {dest} {detail}".strip(), font_size=8)
    else:
        pdf.set_x(pdf.l_margin)
        pdf.set_font(family, "", 8)
        pdf.set_text_color(0, 150, 60)
        pdf.cell(0, 5, _safe("✓ Aucune menace active — zone sure, runner."), ln=True)
    pdf.set_text_color(0)
    pdf.ln(2)
```

Note: the old `_persona_block` used the `_widget` helper for 4 attribute boxes; that call is removed. `_widget` stays in the file (still used by `_dashboard_hero`), so do not delete it.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/790-pdf-report-rich-netrunner-character-shee/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_persona_pdf.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: No-regression on existing report tests**

Run: `cd packages/secubox-toolbox && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/790-pdf-report-rich-netrunner-character-shee/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/ -k "report or pdf or bundle or persona" -q`
Expected: PASS (no regression)

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/reports.py packages/secubox-toolbox/tests/test_persona_pdf.py
git commit -m "feat(toolbox): rich PDF character sheet — pips, on/off inventory, quests (ref #790)"
```

---

## Task 2: Extract `_enrich_report_data` + wire all PDF routes (Part B)

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` (add `_enrich_report_data` near the report routes; replace `report_me` inline block 2882-2904; add call in `report` ~2923 and `admin_client_report` ~3989)
- Test: `packages/secubox-toolbox/tests/test_enrich_report_data.py`

**Interfaces:**
- Consumes (all already in `api.py`): `_dpi_stats`, `_media_stats`, `_build_pdf_donuts`, `_persona_sheet`, `_build_report_charts`, `store.get_client_level`, `social.fetch_graph`.
- Produces: `_enrich_report_data(mac_hash: str, data: dict, ua: str = "") -> dict` — mutates+returns `data` with keys `dpi_exfil, media_exfil, pdf_donuts, persona, charts, graph_stats, bestiary, carto_nodes, carto_country`.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-toolbox/tests/test_enrich_report_data.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""_enrich_report_data populates every report enrichment key (#790 parity)."""
from secubox_toolbox import api, store


def test_enrich_populates_all_keys(monkeypatch):
    monkeypatch.setattr(api, "_dpi_stats", lambda mh: {"me": {"present": False}, "all": {}})
    monkeypatch.setattr(api, "_media_stats", lambda mh: {"me": {"present": False}, "all": {"present": False}})
    monkeypatch.setattr(api, "_build_pdf_donuts", lambda mh, d: [])
    monkeypatch.setattr(api, "_build_report_charts", lambda g: {"trackers": [{"label": "x", "count": 3}]})
    monkeypatch.setattr(api, "_persona_sheet", lambda *a, **k: {"tag": "T", "ua_seen": a[-1]})
    monkeypatch.setattr(store, "get_client_level", lambda mh: "r1")
    # social.fetch_graph is imported inside the helper via `from . import social`
    import secubox_toolbox.social as social
    monkeypatch.setattr(social, "fetch_graph",
                        lambda mh, since_seconds=0: {"stats": {"total_trackers": 4}, "nodes": [{"n": 1}], "by_country": [{"c": "FR"}]})

    data = {"device_type": "phone"}
    out = api._enrich_report_data("aabbccdd", data, ua="Mozilla/5.0")

    assert out is data  # mutates in place
    for k in ("dpi_exfil", "media_exfil", "pdf_donuts", "persona", "charts",
              "graph_stats", "bestiary", "carto_nodes", "carto_country"):
        assert k in out, f"missing {k}"
    assert out["persona"]["tag"] == "T"
    assert out["persona"]["ua_seen"] == "Mozilla/5.0"   # ua threaded through
    assert out["bestiary"] == [{"label": "x", "count": 3}]
    assert out["graph_stats"] == {"total_trackers": 4}
    assert out["carto_nodes"] == [{"n": 1}]


def test_enrich_survives_graph_failure(monkeypatch):
    monkeypatch.setattr(api, "_dpi_stats", lambda mh: {"me": {}, "all": {}})
    monkeypatch.setattr(api, "_media_stats", lambda mh: {"me": {}, "all": {}})
    monkeypatch.setattr(api, "_build_pdf_donuts", lambda mh, d: [])
    monkeypatch.setattr(api, "_build_report_charts", lambda g: {"trackers": []})
    monkeypatch.setattr(api, "_persona_sheet", lambda *a, **k: {"tag": "T"})
    monkeypatch.setattr(store, "get_client_level", lambda mh: "r1")
    import secubox_toolbox.social as social

    def _boom(*a, **k):
        raise RuntimeError("graph down")
    monkeypatch.setattr(social, "fetch_graph", _boom)

    out = api._enrich_report_data("aabbccdd", {"device_type": "pc"})
    assert out["graph_stats"] == {}          # fell back to empty graph
    assert out["bestiary"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/790-pdf-report-rich-netrunner-character-shee/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_enrich_report_data.py -v`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.api' has no attribute '_enrich_report_data'`

- [ ] **Step 3: Add `_enrich_report_data`**

In `packages/secubox-toolbox/secubox_toolbox/api.py`, add this function immediately BEFORE `@router.get("/report/me")` (line 2863):

```python
def _enrich_report_data(mac_hash: str, data: dict, ua: str = "") -> dict:
    """#790 — attach the live enrichment (DPI, media, persona, charts, carto) to
    a report `data` dict. Factored out of report_me so /report/{token} and the
    admin route produce the SAME rich PDF. `ua` drives the persona device class;
    "" is fine for non-HTTP callers (falls back to a generic Runner class)."""
    data["dpi_exfil"] = _dpi_stats(mac_hash)          # #701 DPI parity
    data["media_exfil"] = _media_stats(mac_hash)      # #785 media-type donuts
    data["pdf_donuts"] = _build_pdf_donuts(mac_hash, data)  # #703 visual donuts
    try:
        from . import social as _social
        _graph = _social.fetch_graph(mac_hash, since_seconds=7 * 86400)
    except Exception:
        _graph = {"stats": {}, "nodes": [], "by_country": []}
    _gs = _graph.get("stats") or {}
    _exp = min(100, int((_gs.get("total_trackers", 0) or 0) * 1.5
                        + (_gs.get("opgrade_sites", 0) or 0) * 12
                        + (_gs.get("antibot_sites", 0) or 0) * 8))
    _lvl = store.get_client_level(mac_hash) if mac_hash else "r1"
    data["persona"] = _persona_sheet(mac_hash, _lvl, _gs, _exp, data["dpi_exfil"],
                                     data.get("device_type", ""), ua)
    _charts = _build_report_charts(_graph)
    data["charts"] = _charts                          # #711 "En un coup d'œil"
    data["graph_stats"] = _gs
    data["bestiary"] = (_charts.get("trackers") or [])[:5]
    data["carto_nodes"] = _graph.get("nodes") or []   # #709 carto + tables
    data["carto_country"] = _graph.get("by_country") or []
    return data
```

- [ ] **Step 4: Replace the inline block in `report_me`**

In `report_me`, DELETE the inline enrichment (lines 2882-2904 — from `data["dpi_exfil"] = _dpi_stats(mac_hash)` through `data["carto_country"] = _graph.get("by_country") or []`) and replace with a single call. The surrounding lines stay:

Find:
```python
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    data["dpi_exfil"] = _dpi_stats(mac_hash)  # #701 — DPI parity with the HTML report
    data["media_exfil"] = _media_stats(mac_hash)  # #785 — media-type (MIME) donuts
    data["pdf_donuts"] = _build_pdf_donuts(mac_hash, data)  # #703 — visual donuts
    # #707 — Netrunner persona sheet (live graph + DPI + ads + request UA)
    try:
        from . import social as _social
        _graph = _social.fetch_graph(mac_hash, since_seconds=7 * 86400)
    except Exception:
        _graph = {"stats": {}, "nodes": [], "by_country": []}
    _gs = _graph.get("stats") or {}
    _exp = min(100, int((_gs.get("total_trackers", 0) or 0) * 1.5
                        + (_gs.get("opgrade_sites", 0) or 0) * 12
                        + (_gs.get("antibot_sites", 0) or 0) * 8))
    _lvl = store.get_client_level(mac_hash) if mac_hash else "r1"
    data["persona"] = _persona_sheet(mac_hash, _lvl, _gs, _exp, data["dpi_exfil"],
                                     data.get("device_type", ""),
                                     request.headers.get("user-agent", ""))
    _charts = _build_report_charts(_graph)
    data["charts"] = _charts                              # #711 "En un coup d'œil"
    data["graph_stats"] = _gs
    data["bestiary"] = (_charts.get("trackers") or [])[:5]
    data["carto_nodes"] = _graph.get("nodes") or []      # #709 carto + tables
    data["carto_country"] = _graph.get("by_country") or []
    pdf_bytes = await _render_pdf_offloaded(reports.render_pdf, data, cache_key=f"me:{mac_hash}")
```
Replace with:
```python
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    _enrich_report_data(mac_hash, data, ua=request.headers.get("user-agent", ""))
    pdf_bytes = await _render_pdf_offloaded(reports.render_pdf, data, cache_key=f"me:{mac_hash}")
```

- [ ] **Step 5: Wire `report` (token) and `admin_client_report`**

In `report` (the `/report/{token}` handler), find:
```python
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    pdf_bytes = await _render_pdf_offloaded(reports.render_pdf, data, cache_key=f"tok:{mac_hash}")
```
Replace with:
```python
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    _enrich_report_data(mac_hash, data)  # #790 — same rich content as /report/me
    pdf_bytes = await _render_pdf_offloaded(reports.render_pdf, data, cache_key=f"tok:{mac_hash}")
```

In `admin_client_report`, find:
```python
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    pdf_bytes = await _render_pdf_offloaded(reports.render_pdf, data, cache_key=f"adm:{mac_hash}")
```
Replace with:
```python
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    _enrich_report_data(mac_hash, data)  # #790 — same rich content as /report/me
    pdf_bytes = await _render_pdf_offloaded(reports.render_pdf, data, cache_key=f"adm:{mac_hash}")
```

- [ ] **Step 6: Run test + syntax check**

Run: `cd packages/secubox-toolbox && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/790-pdf-report-rich-netrunner-character-shee/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_enrich_report_data.py -v && /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -c "import ast; ast.parse(open('secubox_toolbox/api.py').read()); print('api.py parses OK')"`
Expected: PASS (2 tests) + "api.py parses OK"

- [ ] **Step 7: Confirm all three routes call the helper**

Run: `grep -n "_enrich_report_data(mac_hash, data" secubox_toolbox/api.py`
Expected: 3 lines (report_me with `ua=`, report token, admin) — plus the `def _enrich_report_data` definition line.

- [ ] **Step 8: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/tests/test_enrich_report_data.py
git commit -m "feat(toolbox): factor _enrich_report_data + apply to token/admin PDF routes (ref #790)"
```

---

## Final verification

- [ ] **Full toolbox suite (no regression):**

```bash
cd packages/secubox-toolbox && PYTHONPATH=/home/reepost/CyberMindStudio/secubox-deb-worktrees/790-pdf-report-rich-netrunner-character-shee/common /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/ -q
```
Expected: all green (the two new files add 5 tests).

- [ ] **Deploy note (not a code step):** only `secubox-toolbox` changed (pure Python). To validate live: deploy `reports.py` + `api.py` to `/usr/lib/secubox/toolbox/secubox_toolbox/` on gk2, restart `secubox-toolbox`, then render `/report/me?mh=<real-hash>` and confirm the character sheet shows pips/inventory/quests, and that `/report/{token}` now carries persona too. Watch for pip/check glyph rendering (`●○✓✗`) — DejaVu should cover them.

---

## Self-Review

**Spec coverage:**
- Part A pips + notes → Task 1 `_attr_row` ✅
- Part A inventory ✓/✗ → Task 1 ✅
- Part A bestiary → Task 1 ✅
- Part A Quêtes/menaces + empty-safe message → Task 1 (+ test) ✅
- Part A fail-safe on missing `dpi_exfil` → Task 1 `test_persona_missing_dpi_exfil_no_raise` ✅
- Part B `_enrich_report_data` helper → Task 2 ✅
- Part B wire 3 routes → Task 2 Steps 4-5 + Step 7 check ✅
- full-fpdf / no matplotlib → no matplotlib call added in Task 1 ✅
- pip clamp 0..6 → `_attr_row` `max(0, min(6, ...))` ✅

**Placeholder scan:** none — every step has concrete code/commands.

**Type consistency:** `_enrich_report_data(mac_hash, data, ua="")` signature identical across definition, tests, and all 3 call sites; `_attr_row(pdf, family, a)` consistent between definition and `_persona_block` usage; persona/bestiary/alerts key names match the shapes read from `api._persona_sheet` and `_dpi_stats`.
