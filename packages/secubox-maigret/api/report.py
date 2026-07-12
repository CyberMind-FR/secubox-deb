# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: metalogue / maigret PDF report
CyberMind — https://cybermind.fr

Turns a raw maigret `--json simple` report (stored on the lookup record as a
JSON string in results.raw) into a FORMAL, SecuBox-branded PDF dossier: a
titled masthead, a document metadata block, a numbered Summary, and the claimed
accounts laid out as a single coherent results table (platform / category /
profile / details), grouped by category and paginated with a repeating header.

Pure fpdf2 core fonts (Helvetica/Courier) — no embedded TTFs, no network. CPU
work: callers on the event loop MUST run build_pdf via asyncio.to_thread.
"""
from __future__ import annotations

import json
from typing import Any

from fpdf import FPDF

# ── SecuBox cyber palette ────────────────────────────────────────────────────
BG = (13, 17, 23)          # cosmos dark ground
BAND = (18, 24, 33)        # header / footer / table-head band
CARD = (23, 30, 41)        # zebra row A
ROWB = (16, 21, 29)        # zebra row B
LINE = (40, 52, 66)        # hairline rules
CYAN = (0, 212, 255)       # primary accent
GOLD = (201, 168, 76)
GREEN = (0, 221, 68)
TEXT = (232, 230, 217)
MUTED = (120, 140, 155)
RED = (255, 68, 102)

_CAT_COLOR = {
    "coding": CYAN, "social": (68, 136, 255), "blog": GOLD, "photo": (163, 113, 247),
    "gaming": GREEN, "video": RED, "music": (255, 153, 68), "finance": GREEN,
    "shopping": (255, 204, 0), "news": (150, 165, 180), "forum": (68, 136, 255),
    "tech": CYAN, "sport": GREEN, "hobby": (255, 153, 68),
}

# table geometry (A4 usable width = 210 - 2*14 = 182 mm)
COLS = [("#", 9), ("PLATFORM", 40), ("CATEGORY", 24), ("PROFILE URL", 72), ("DETAILS", 37)]
ROW_H = 7.0
MARGIN = 14.0


def _cat_color(cat: str):
    return _CAT_COLOR.get((cat or "").lower(), (150, 165, 180))


def _parse(results: Any) -> dict:
    if isinstance(results, dict) and "raw" in results:
        results = results["raw"]
    if isinstance(results, str):
        results = results.strip()
        if not results:
            return {}
        try:
            results = json.loads(results)
        except json.JSONDecodeError:
            return {}
    return results if isinstance(results, dict) else {}


def _claimed(data: dict) -> list[dict]:
    out = []
    for name, site in (data or {}).items():
        if not isinstance(site, dict):
            continue
        st = site.get("status") or {}
        if str(st.get("status", "")).lower() != "claimed":
            continue
        tags = st.get("tags") or (site.get("site") or {}).get("tags") or []
        ids = st.get("ids") or {}
        extra = {k: v for k, v in ids.items()
                 if k.lower() in ("name", "fullname", "company", "location", "id")
                 and isinstance(v, str) and v.strip()}
        out.append({
            "site": name,
            "url": site.get("url_user") or st.get("url") or "",
            "category": (tags[0] if tags else "other"),
            "rank": site.get("rank") or 10_000_000,
            "details": "  ".join(f"{k}: {v}" for k, v in extra.items()),
        })
    out.sort(key=lambda a: (a["category"], a["rank"], a["site"].lower()))
    return out


class _Report(FPDF):
    def __init__(self, username: str, generated: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.username = username
        self.generated = generated
        self.set_auto_page_break(True, margin=16)
        self.set_margins(MARGIN, 32, MARGIN)
        self.set_title(f"SecuBox OSINT report - {username}")
        self._in_table = False

    # dark ground + masthead on every page
    def header(self):
        self.set_fill_color(*BG); self.rect(-1, -1, self.w + 2, self.h + 2, "F")
        self.set_fill_color(*BAND); self.rect(0, 0, self.w, 24, "F")
        self.set_xy(MARGIN, 5.5)
        self.set_font("Helvetica", "B", 14); self.set_text_color(*CYAN)
        self.cell(0, 7, "SECUBOX  //  OSINT IDENTITY REPORT")
        self.set_xy(MARGIN, 13)
        self.set_font("Courier", "", 8); self.set_text_color(*MUTED)
        self.cell(0, 5, f"metalogue - maigret - generated {self.generated} UTC")
        self.set_draw_color(*CYAN); self.set_line_width(0.5); self.line(0, 24, self.w, 24)
        # a continued table repeats its head at the top of each new page
        if self._in_table:
            self.set_y(30)
            self._table_head()

    def footer(self):
        self.set_draw_color(*LINE); self.set_line_width(0.3)
        self.line(MARGIN, self.h - 13, self.w - MARGIN, self.h - 13)
        self.set_font("Courier", "", 8); self.set_text_color(*MUTED)
        self.set_y(-11)
        self.cell((self.w - 2 * MARGIN) / 2, 6, "CONFIDENTIAL - SecuBox metalogue")
        self.cell((self.w - 2 * MARGIN) / 2, 6, f"page {self.page_no()}", align="R")

    # ── helpers ──────────────────────────────────────────────────────────────
    def _fit(self, text: str, width: float) -> str:
        # core fonts are latin-1 only → replace unencodable chars (unicode names,
        # emoji in profile data) so a render never crashes.
        text = str(text or "").encode("latin-1", "replace").decode("latin-1")
        if self.get_string_width(text) <= width:
            return text
        while text and self.get_string_width(text + "...") > width:
            text = text[:-1]
        return (text + "...") if text else ""

    def _label(self, text, color=MUTED, size=8.5):
        self.set_font("Courier", "", size); self.set_text_color(*color)

    # ── sections ─────────────────────────────────────────────────────────────
    def metadata(self, ref, checked):
        self.set_y(30)
        rows = [
            ("REFERENCE", ref or "-"),
            ("SUBJECT", f"@{self.username}"),
            ("GENERATED", f"{self.generated} UTC"),
            ("SOURCE", "maigret - SecuBox metalogue"),
            ("SCOPE", f"{checked} platforms checked"),
            ("CLASSIFICATION", "CONFIDENTIAL"),
        ]
        x, y = MARGIN, self.get_y()
        w = self.w - 2 * MARGIN
        self.set_fill_color(*CARD); self.rect(x, y, w, len(rows) * 6 + 4, "F")
        self.set_fill_color(*CYAN); self.rect(x, y, 1.4, len(rows) * 6 + 4, "F")
        yy = y + 2
        for k, v in rows:
            self.set_xy(x + 6, yy)
            self.set_font("Courier", "", 8); self.set_text_color(*MUTED)
            self.cell(38, 6, k)
            self.set_font("Courier", "B", 9)
            self.set_text_color(*(GOLD if k == "CLASSIFICATION" else TEXT))
            self.cell(w - 46, 6, self._fit(v, w - 52))
            yy += 6
        self.set_y(y + len(rows) * 6 + 4)

    def h2(self, text):
        self.ln(5)
        self.set_font("Helvetica", "B", 11); self.set_text_color(*CYAN)
        y = self.get_y(); self.cell(0, 7, text, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*CYAN); self.set_line_width(0.3)
        self.line(MARGIN, y + 7.3, self.w - MARGIN, y + 7.3)
        self.ln(2)

    def summary(self, found, checked, cats):
        self.h2("1.  SUMMARY")
        self.set_font("Helvetica", "", 10.5); self.set_text_color(*TEXT)
        self.set_x(MARGIN)
        self.multi_cell(0, 5.6,
            f"maigret identified {found} claimed account(s) for the identity "
            f"@{self.username} across {checked} platforms checked, spanning "
            f"{cats} category(ies). Findings are enumerated in section 2.")
        self.ln(2)
        cards = [("ACCOUNTS FOUND", str(found), GREEN),
                 ("PLATFORMS CHECKED", str(checked), CYAN),
                 ("CATEGORIES", str(cats), GOLD)]
        gap = 4; w = (self.w - 2 * MARGIN - gap * 2) / 3
        x0, y0 = MARGIN, self.get_y()
        for i, (label, value, color) in enumerate(cards):
            x = x0 + i * (w + gap)
            self.set_fill_color(*CARD); self.rect(x, y0, w, 18, "F")
            self.set_fill_color(*color); self.rect(x, y0, 1.4, 18, "F")
            self.set_xy(x + 5, y0 + 2.5)
            self.set_font("Helvetica", "B", 18); self.set_text_color(*color)
            self.cell(w - 6, 8, value)
            self.set_xy(x + 5, y0 + 12)
            self.set_font("Courier", "", 7); self.set_text_color(*MUTED)
            self.cell(w - 6, 4, label)
        self.set_y(y0 + 18)

    def _table_head(self):
        x, y = MARGIN, self.get_y()
        self.set_fill_color(*BAND); self.rect(x, y, self.w - 2 * MARGIN, ROW_H, "F")
        self.set_font("Helvetica", "B", 8); self.set_text_color(*CYAN)
        cx = x
        for title, w in COLS:
            self.set_xy(cx + 2, y + 1.6)
            self.cell(w - 3, 4, title)
            cx += w
        self.set_draw_color(*CYAN); self.set_line_width(0.3)
        self.line(x, y + ROW_H, self.w - MARGIN, y + ROW_H)
        self.set_y(y + ROW_H)

    def _row(self, n, acc, zebra):
        x, y = MARGIN, self.get_y()
        color = _cat_color(acc["category"])
        self.set_fill_color(*(CARD if zebra else ROWB))
        self.rect(x, y, self.w - 2 * MARGIN, ROW_H, "F")
        self.set_fill_color(*color); self.rect(x, y, 1.2, ROW_H, "F")
        cx = x
        vals = [
            (str(n), MUTED, "Courier", "", 8),
            (acc["site"], TEXT, "Helvetica", "B", 9),
            (acc["category"], color, "Courier", "", 8),
            (acc["url"], CYAN, "Courier", "", 7.5),
            (acc["details"] or "-", MUTED, "Courier", "", 7.5),
        ]
        for (val, col, fam, style, size), (_, w) in zip(vals, COLS):
            self.set_font(fam, style, size); self.set_text_color(*col)
            self.set_xy(cx + 2, y + 2.0)
            link = acc["url"] if val == acc["url"] and acc["url"] else ""
            self.cell(w - 3, 3.4, self._fit(val, w - 4), link=link)
            cx += w
        self.set_draw_color(*LINE); self.set_line_width(0.15)
        self.line(x, y + ROW_H, self.w - MARGIN, y + ROW_H)
        self.set_y(y + ROW_H)

    def findings(self, accounts):
        self.h2("2.  FINDINGS")
        if not accounts:
            self.set_font("Helvetica", "", 11); self.set_text_color(*MUTED)
            self.cell(0, 8, "No claimed accounts were found for this identity.", new_x="LMARGIN", new_y="NEXT")
            return
        self._table_head()
        self._in_table = True
        for i, acc in enumerate(accounts, 1):
            if self.get_y() > self.h - (ROW_H + 16):
                self.add_page()          # header() repaints the table head
            self._row(i, acc, zebra=(i % 2 == 0))
        self._in_table = False


def build_pdf(record: dict) -> bytes:
    username = str(record.get("username", "unknown"))
    generated = str(record.get("finished_at") or record.get("started_at") or "")[:19].replace("T", " ")
    ref = str(record.get("id", ""))
    data = _parse(record.get("results"))
    accounts = _claimed(data)
    cats = len({a["category"] for a in accounts})

    pdf = _Report(username, generated)
    pdf.add_page()
    pdf.metadata(ref=ref, checked=len(data))
    pdf.summary(found=len(accounts), checked=len(data), cats=cats)
    pdf.findings(accounts)
    return bytes(pdf.output())
