# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Graphiques des dossiers et association des diapositives (#4058, Task 8).

Rendu serveur en SVG (aucune bibliothèque, aucun CDN) depuis le dossier de faits d'un sujet : bans par semaine, zoom
sur chaque vague (fenêtre de dates, barres mises en avant), phases, opérateurs. Aucune adresse IP ni nom interne :
toute étiquette qui en ressemble à une est remplacée par « — » avant d'entrer dans le dessin.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import unicodedata
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional

# Palette SecuBox (DESIGN-CHARTER.md) : MIND pour les barres, AUTH pour la mise en avant
FOND, TEXTE, GRILLE = "#0F1220", "#E8E6F5", "#2A2E45"
BARRE, AVANT, PALE = "#3D35A0", "#C04E24", "#5A5490"
L, H, MARGE_G, MARGE_B, MARGE_H = 1280, 720, 90, 110, 90

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b|::(?:[0-9A-Fa-f]{1,4}:?){1,7}")
INTERNE = re.compile(r"\bgk\d\b|\.(?:lan|local|internal|home|intra)\b|\bsecubox\.in\b", re.I)
NOMBRE = re.compile(r"\d{1,3}(?:[\s  ]\d{3})+(?![\d])|\d+")


def _sur(s: Any) -> str:
    s = str(s)
    return "—" if IPV4.search(s) or IPV6.search(s) or INTERNE.search(s) else s


def _txt(x: float, y: float, s: str, taille: int = 22, ancre: str = "middle", couleur: str = TEXTE,
         gras: bool = False) -> str:
    g = ' font-weight="700"' if gras else ""
    return (f'<text x="{x:.0f}" y="{y:.0f}" font-size="{taille}" text-anchor="{ancre}" fill="{couleur}"{g}>'
            f"{escape(_sur(s))}</text>")


def _barres(titre: str, etiquettes: List[str], valeurs: List[int], avant: Optional[set] = None,
            unite: str = "") -> str:
    """Un histogramme vertical ; `avant` = rangs mis en avant (les autres pâlissent)."""
    n = max(1, len(valeurs))
    haut = max(valeurs or [0]) or 1
    lb = (L - MARGE_G - 40) / n
    zone = H - MARGE_H - MARGE_B
    p = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{L}" height="{H}" viewBox="0 0 {L} {H}" '
         f'font-family="DejaVu Sans, sans-serif">', f'<rect width="{L}" height="{H}" fill="{FOND}"/>',
         _txt(L / 2, 52, titre, 34, gras=True)]
    for k in range(5):
        y = MARGE_H + zone * k / 4
        p.append(f'<line x1="{MARGE_G}" y1="{y:.0f}" x2="{L - 40}" y2="{y:.0f}" stroke="{GRILLE}"/>')
        p.append(_txt(MARGE_G - 10, y + 7, str(round(haut * (4 - k) / 4)), 18, "end"))
    pas = max(1, n // 12)   # au plus ~12 étiquettes lisibles
    for i, v in enumerate(valeurs):
        h = zone * v / haut
        x = MARGE_G + i * lb + lb * 0.12
        c = (AVANT if i in avant else PALE) if avant else BARRE
        p.append(f'<rect x="{x:.1f}" y="{MARGE_H + zone - h:.1f}" width="{lb * 0.76:.1f}" height="{h:.1f}" fill="{c}"/>')
        if n <= 12 or (avant and i in avant):
            p.append(_txt(x + lb * 0.38, MARGE_H + zone - h - 8, f"{v}{unite}", 18))
        if i % pas == 0 or (avant and i in avant):
            p.append(_txt(x + lb * 0.38, H - MARGE_B + 30, etiquettes[i], 16))
    p.append("</svg>")
    return "".join(p)


def _jm(iso: str) -> str:
    return f"{iso[8:10]}/{iso[5:7]}" if re.match(r"^\d{4}-\d{2}-\d{2}", iso or "") else str(iso)


def _ent(x: Any) -> int:
    return x if isinstance(x, int) and not isinstance(x, bool) else 0


def graphiques(dossier: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Les graphiques disponibles pour ce dossier : `[{"id", "svg", "chiffres", "termes"}]`."""
    sortie: List[Dict[str, Any]] = []
    nom = _sur((dossier.get("sujet") or {}).get("nom") or "")
    sem = [s for s in dossier.get("serie_semaine") or [] if isinstance(s, dict) and isinstance(s.get("debut"), str)]
    if sem:
        vals = [_ent(s.get("bans")) for s in sem]
        tot = _ent((dossier.get("chiffres") or {}).get("bans_90j")) or sum(vals)
        sortie.append({"id": "bans", "svg": _barres(f"{nom} — bans par semaine", [_jm(s["debut"]) for s in sem], vals),
                       "chiffres": sorted({str(v) for v in vals if v} | {str(tot)}),
                       "termes": ["bans", "semaine", "semaines", "90 jours"]})
        for k, v in enumerate(dossier.get("vagues") or [], 1):
            if not isinstance(v, dict) or not isinstance(v.get("debut"), str) or not isinstance(v.get("fin"), str):
                continue
            avant = {i for i, s in enumerate(sem) if v["debut"][:10] <= s["debut"][:10] <= v["fin"][:10]
                     or (i + 1 < len(sem) and s["debut"] <= v["debut"] < sem[i + 1]["debut"])}
            titre = f"Vague {k} — du {_jm(v['debut'])} au {_jm(v['fin'])}"
            sortie.append({"id": f"vague-{k}", "svg": _barres(titre, [_jm(s["debut"]) for s in sem], vals, avant),
                           "chiffres": sorted({str(_ent(v.get(c))) for c in ("bans", "adresses", "blocs24",
                                                                            "jours_actifs") if _ent(v.get(c))}),
                           "termes": [f"vague {k}", _jm(v["debut"]), _jm(v["fin"])]
                           + [_sur(o) for o in v.get("operateurs") or [] if isinstance(o, str)]})
    ph = [p for p in dossier.get("phases") or [] if isinstance(p, dict) and isinstance(p.get("phase"), str)]
    if ph:
        sortie.append({"id": "phases", "svg": _barres(f"{nom} — phases", [p["phase"] for p in ph],
                                                      [_ent(p.get("bans")) for p in ph]),
                       "chiffres": sorted({str(_ent(p.get("bans"))) for p in ph}),
                       "termes": ["phase", "phases"] + [_sur(p["phase"]) for p in ph]})
    op = [o for o in dossier.get("operateurs") or [] if isinstance(o, dict) and isinstance(o.get("nom"), str)]
    if op:
        sortie.append({"id": "operateurs", "svg": _barres(f"{nom} — opérateurs (part des adresses)",
                                                          [o["nom"] for o in op], [_ent(o.get("part")) for o in op], unite=" %"),
                       "chiffres": sorted({str(_ent(o.get("part"))) for o in op}),
                       "termes": ["opérateur", "opérateurs"] + [_sur(o["nom"]) for o in op]})
    for g in sortie:
        g["termes"] = [t for t in dict.fromkeys(g["termes"]) if t and t != "—"]
    return sortie


def png(svg: str, sortie: Path) -> Path:
    """SVG → PNG par `rsvg-convert`, puis compression sans perte facultative (oxipng, sinon optipng)."""
    sortie = Path(sortie)
    sortie.parent.mkdir(parents=True, exist_ok=True)
    rsvg = shutil.which("rsvg-convert")
    if not rsvg:
        raise RuntimeError("rsvg-convert absent (paquet librsvg2-bin)")
    subprocess.run([rsvg, "-f", "png", "-o", str(sortie)], input=svg.encode(), check=True, timeout=60,
                   capture_output=True)
    # Compression sans perte FACULTATIVE : oxipng s'il est là, sinon optipng -o2, sinon PNG non optimisé (pas d'erreur).
    oxi, opti = shutil.which("oxipng"), shutil.which("optipng")
    if oxi:
        subprocess.run([oxi, "-q", "-o", "2", "-z", "--strip", "safe", str(sortie)], check=False, timeout=120,
                       capture_output=True)
    elif opti:
        subprocess.run([opti, "-quiet", "-o2", str(sortie)], check=False, timeout=120, capture_output=True)
    return sortie


def _plat(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", s.lower()) if unicodedata.category(c) != "Mn")


def nombres(texte: str) -> List[str]:
    """Les nombres cités, milliers groupés réunis : « 1 204 » → « 1204 »."""
    return [re.sub(r"[\s  ]", "", m) for m in NOMBRE.findall(texte or "")]


def associer(repliques: List[Dict[str, Any]], graphs: List[Dict[str, Any]]) -> Dict[int, str]:
    """Rang de réplique → id de graphique : par chiffres cités, puis par termes, sinon la diapo précédente."""
    if not graphs:
        return {}
    sortie: Dict[int, str] = {}
    courant = graphs[0]["id"]
    for i, r in enumerate(repliques):
        rang = r.get("rang", i) if isinstance(r.get("rang"), int) else i
        texte = r.get("texte") or ""
        cites = set(nombres(texte))
        choix = next((g["id"] for g in graphs if cites & set(g.get("chiffres") or [])), None)
        if choix is None:
            plat = _plat(texte)
            # le graphique qui partage le plus de termes avec la réplique (à égalité : le premier)
            scores = [(sum(1 for t in g.get("termes") or []
                           if re.search(r"(?<!\w)" + re.escape(_plat(t)) + r"(?!\w)", plat)), -k, g["id"])
                      for k, g in enumerate(graphs)]
            meilleur = max(scores)
            choix = meilleur[2] if meilleur[0] else None
        courant = choix or courant
        sortie[rang] = courant
    return sortie
