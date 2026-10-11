# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: metrics :: primitives Aurora communes aux rapports PDF (#2390)

Le langage visuel des vues Aurora : fond sombre, tuiles, panneaux, graphiques matplotlib aux jetons Aurora, carte du monde en points. Extrait du rapport de sécurité (#2299) pour que le
rapport de fréquentation parle la même langue.

Ce module est autonome : il n'importe ni `rapport` ni `rapport_securite` (pas de cycle). fpdf2 et matplotlib ne sont chargés qu'à l'usage ; seules les fonctions de dessin les exigent.
"""
from __future__ import annotations

import io
import sys
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

_ici = str(Path(__file__).resolve().parent)
if _ici not in sys.path:
    sys.path.insert(0, _ici)

# Jetons Aurora (thème sombre).
FOND, PANNEAU, TRAIT = (6, 13, 27), (13, 26, 51), (45, 80, 150)
TEXTE, DOUX, FAIBLE = (234, 241, 255), (159, 179, 214), (111, 132, 168)
CYAN, BLEU, VERT, ROUGE, ORANGE, VIOLET, JAUNE = ((41, 182, 246), (59, 130, 246), (46, 204, 113), (255, 77, 94), (255, 159, 28), (167, 139, 250), (255, 210, 63))
PALETTE = [BLEU, ROUGE, ORANGE, VIOLET, CYAN, VERT, JAUNE, DOUX]
RAIL = (40, 58, 96)                  # fond des barres
TERRE_PT = "#33507f"                 # points de terre de la carte

# Les polices de base de fpdf ne connaissent que latin-1.
_SUBST = {"—": "-", "–": "-", "’": "'", "‘": "'", "“": '"', "”": '"', "…": "...", " ": " ", "→": "->", "·": "-"}


def hexa(c) -> str:
    return "#%02x%02x%02x" % tuple(c)


def txt(v) -> str:
    """Une chaîne que la police de base sait écrire (latin-1)."""
    s = str(v)
    for k, r in _SUBST.items():
        s = s.replace(k, r)
    return s.encode("latin-1", "replace").decode("latin-1")


def num(x) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def n(v) -> str:
    """Entier groupé par milliers ; une mesure absente est « — », jamais 0."""
    if v is None:
        return "—"
    try:
        return f"{int(round(float(v))):,}".replace(",", " ")
    except (TypeError, ValueError):
        return "—"


def octets(b) -> str:
    if b is None:
        return "—"
    try:
        b = float(b)
    except (TypeError, ValueError):
        return "—"
    for u in ("o", "Ko", "Mo", "Go", "To"):
        if b < 1024 or u == "To":
            return f"{b:.0f} {u}" if u in ("o", "Ko") else f"{b:.1f} {u}"
        b /= 1024
    return "—"


# ── mise en page (fpdf2) ──────────────────────────────────────────────────
def classe_page(titre_doc: str, pied: str):
    """La page A4 sombre : fond plein, filet d'en-tête, pied centré. `pied` reçoit « {page} » et « {nb} »."""
    from fpdf import FPDF

    class Page(FPDF):
        def header(self):
            self.set_fill_color(*FOND)
            self.rect(0, 0, 210, 297, "F")
            self.set_xy(10, 7)
            self.set_font("Helvetica", "B", 8.5)
            self.set_text_color(*CYAN)
            self.cell(120, 5, txt(titre_doc))
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*FAIBLE)
            self.cell(70, 5, datetime.now().strftime("%d/%m/%Y %H:%M"), align="R")
            self.set_draw_color(*TRAIT)
            self.line(10, 14, 200, 14)
            self.set_y(18)

        def footer(self):
            self.set_y(-12)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*FAIBLE)
            self.cell(0, 5, txt(pied.replace("{page}", str(self.page_no()))), align="C")
    return Page


def panneau(pdf, x, y, w, h, titre="", sous=""):
    pdf.set_fill_color(*PANNEAU)
    pdf.set_draw_color(*TRAIT)
    pdf.rect(x, y, w, h, "DF")
    if titre:
        pdf.set_xy(x + 3, y + 2)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*TEXTE)
        pdf.cell(w - 6, 5, txt(titre))
        if sous:
            pdf.set_xy(x + 3, y + 2)
            pdf.set_font("Helvetica", "", 6.5)
            pdf.set_text_color(*FAIBLE)
            pdf.cell(w - 6, 5, txt(sous), align="R")


def tuile(pdf, x, y, w, libelle, valeur, sous="", accent=CYAN, h=19):
    pdf.set_fill_color(*PANNEAU)
    pdf.set_draw_color(*accent)
    pdf.rect(x, y, w, h, "DF")
    pdf.set_fill_color(*accent)
    pdf.rect(x, y, 1.2, h, "F")
    pdf.set_xy(x + 3.5, y + 2)
    pdf.set_font("Helvetica", "", 6.8)
    pdf.set_text_color(*DOUX)
    pdf.cell(w - 5, 4, txt(libelle.upper()))
    pdf.set_xy(x + 3.5, y + 6.2)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*TEXTE)
    pdf.cell(w - 5, 7, txt(valeur))
    if sous:
        pdf.set_xy(x + 3.5, y + 13.6)
        pdf.set_font("Helvetica", "", 6.3)
        pdf.set_text_color(*FAIBLE)
        pdf.cell(w - 5, 4, txt(sous))


def rangee_tuiles(pdf, y, cases):
    w = (190 - 3 * (len(cases) - 1)) / len(cases)
    for i, c in enumerate(cases):
        tuile(pdf, 10 + i * (w + 3), y, w, *c)
    return y + 22


def titre_volet(pdf, y, texte, sous=""):
    pdf.set_xy(10, y)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*TEXTE)
    pdf.cell(0, 7, txt(texte), new_x="LMARGIN", new_y="NEXT")
    if sous:
        pdf.set_x(10)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*FAIBLE)
        pdf.multi_cell(190, 3.8, txt(sous), new_x="LMARGIN", new_y="NEXT")
    return pdf.get_y() + 2


def tronque(libelle, largeur_mm: float) -> str:
    """Un libellé qui tient dans sa colonne (coupé avec un point)."""
    t = str(libelle if libelle is not None else "?")
    m = max(6, int(largeur_mm / 1.7))
    return t if len(t) <= m else t[:m - 1] + "."


def barres(pdf, x, y, w, lignes, fmt=n, couleur=None, pas=6.2, max_l=8, court: Optional[Callable] = None, part_libelle=0.40):
    """Barres horizontales : (libellé, valeur[, couleur]). Rend le y suivant. `court(libellé, largeur)` met les libellés à la taille de leur colonne."""
    court = court or tronque
    lignes = [lg for lg in lignes if lg[1] is not None][:max_l]
    if not lignes:
        pdf.set_xy(x, y)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*FAIBLE)
        pdf.cell(w, 5, txt("— aucune donnée —"))
        return y + 7
    fort = max(num(lg[1]) for lg in lignes) or 1
    lw, vw = w * part_libelle, w * 0.22
    bw = w - lw - vw - 2
    for i, lg in enumerate(lignes):
        c = lg[2] if len(lg) > 2 else (couleur or PALETTE[i % len(PALETTE)])
        pdf.set_xy(x, y)
        pdf.set_font("Helvetica", "", 7.3)
        pdf.set_text_color(*TEXTE)
        pdf.cell(lw, 4.4, txt(court(lg[0], lw)))
        pdf.set_fill_color(*RAIL)
        pdf.rect(x + lw, y + 0.9, bw, 2.6, "F")
        pdf.set_fill_color(*c)
        pdf.rect(x + lw, y + 0.9, max(0.6, bw * num(lg[1]) / fort), 2.6, "F")
        pdf.set_xy(x + lw + bw + 1, y)
        pdf.set_text_color(*DOUX)
        pdf.cell(vw, 4.4, txt(fmt(lg[1])), align="R")
        y += pas
    return y


def image(pdf, png: bytes, x, y, w):
    pdf.image(io.BytesIO(png), x=x, y=y, w=w)


def hauteur_png(png: bytes, w: float) -> float:
    """Hauteur (mm) qu'occupe ce PNG posé à la largeur `w`."""
    import struct
    lg, ht = struct.unpack(">II", png[16:24])
    return w * ht / lg if lg else 0.0


def garde(pdf, besoin: float) -> bool:
    """Saute à la page suivante si `besoin` mm ne tiennent pas avant le pied. True si saut."""
    if pdf.get_y() + besoin > pdf.h - 15:
        pdf.add_page()
        return True
    return False


# ── graphiques matplotlib aux jetons Aurora ───────────────────────────────
def _plt():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    return plt


def fig_sombre(figsize):
    fig, ax = _plt().subplots(figsize=figsize)
    fig.patch.set_facecolor(hexa(PANNEAU))
    ax.set_facecolor(hexa(PANNEAU))
    ax.tick_params(labelsize=7, colors=hexa(DOUX))
    for bord in ax.spines.values():
        bord.set_visible(False)
    ax.grid(axis="y", color="#9fb3d6", alpha=.14)
    return fig, ax


def png(fig) -> bytes:
    t = io.BytesIO()
    fig.savefig(t, format="png", dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    _plt().close(fig)
    return t.getvalue()


def graphe_courbes(series: list, etiquettes: list) -> bytes:
    """Courbes pleines : [(nom, valeurs, couleur)]."""
    fig, ax = fig_sombre((8.6, 1.9))
    x = range(len(etiquettes))
    for nom, vals, c in series:
        ax.plot(x, vals, color=hexa(c), lw=1.8, label=nom)
        ax.fill_between(x, vals, color=hexa(c), alpha=.13)
    pas = max(1, -(-len(etiquettes) // 16))                  # au-delà de 16 points, étiquettes éclaircies (≤ 16 : inchangé)
    ax.set_xticks(list(x)[::pas])
    ax.set_xticklabels(etiquettes[::pas], rotation=0, color=hexa(DOUX), fontsize=6.5)
    ax.set_ylim(bottom=0)
    ax.legend(fontsize=6.5, frameon=False, labelcolor=hexa(DOUX), loc="upper left", ncol=len(series))
    return png(fig)


def graphe_heures(vals: list) -> bytes:
    fig, ax = fig_sombre((7.4, 2.2))
    ax.bar(range(len(vals)), vals, color=hexa(CYAN), width=.7)
    ax.set_xticks(range(0, len(vals), 3))
    ax.set_xticklabels([f"{h:02d}h" for h in range(0, len(vals), 3)], color=hexa(DOUX), fontsize=6.5)
    return png(fig)


def graphe_histogramme(vals: list, etiquettes: list, couleur=CYAN, nom: str = "") -> bytes:
    """Barres verticales par jour ; les étiquettes sont éclaircies au-delà de 16 barres."""
    fig, ax = fig_sombre((8.6, 1.9))
    x = list(range(len(vals)))
    ax.bar(x, vals, color=hexa(couleur), width=.62, label=nom)
    pas = max(1, -(-len(x) // 16))
    ax.set_xticks(x[::pas])
    ax.set_xticklabels(etiquettes[::pas], color=hexa(DOUX), fontsize=6.5)
    ax.set_ylim(bottom=0)
    if nom:
        ax.legend(fontsize=6.5, frameon=False, labelcolor=hexa(DOUX), loc="upper left")
    return png(fig)


def graphe_donut(parts: list, centre: str, couleurs: Optional[list] = None) -> bytes:
    """parts : [(nom, valeur)]. Anneau sans légende (la légende est en barres à côté)."""
    fig, ax = fig_sombre((2.6, 2.6))
    ax.grid(False)
    vals = [max(0.0, num(v)) for _, v in parts]
    if sum(vals) <= 0:
        ax.text(0.5, 0.5, "—", ha="center", va="center", color=hexa(DOUX), fontsize=16, transform=ax.transAxes)
    else:
        cols = couleurs or [PALETTE[i % len(PALETTE)] for i in range(len(vals))]
        ax.pie(vals, colors=[hexa(c) for c in cols], startangle=90, counterclock=False, wedgeprops={"width": .38, "edgecolor": hexa(PANNEAU), "linewidth": 1.2})
        ax.text(0, 0, centre, ha="center", va="center", color=hexa(TEXTE), fontsize=9, fontweight="bold")
    return png(fig)


def graphe_carte(pays: dict, couleur=ROUGE) -> bytes:
    import carte_monde as cm
    fig, ax = fig_sombre((7.6, 3.4))
    ax.grid(False)
    pts = cm.points_terre()
    ax.scatter([x for x, _ in pts], [y for _, y in pts], s=3.4, c=TERRE_PT, linewidths=0)
    b = cm.bulles(pays or {})
    if b:
        ax.scatter([e[1] for e in b], [e[2] for e in b], s=[(e[3] * 6.0) ** 2 for e in b], c=hexa(couleur), alpha=.5, edgecolors="none")
        for code, x, y, r in b[:6]:
            ax.annotate(code, (x, y), ha="center", va="center", fontsize=6, color="white", fontweight="bold")
    else:
        ax.text(60, 30, "aucun pays identifié", ha="center", va="center", fontsize=9, color=hexa(DOUX))
    ax.set_xlim(0, 120)
    ax.set_ylim(60, 0)
    ax.set_aspect("equal")
    ax.axis("off")
    return png(fig)
