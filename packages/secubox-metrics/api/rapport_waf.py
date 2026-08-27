# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: metrics :: rapport WAF dédié (#1063)
CyberMind — https://cybermind.fr

Un rapport WAF autonome, envoyé chaque jour par le relais mail interne : il lit
l'historique agrégé des menaces (waf-history.json, produit par secubox-waf #1062)
et en fait un PDF focalisé — tendance par jour, catégories, sévérités,
attaquants persistants. Séparé du rapport de fréquentation, pour qui veut le
bilan WAF seul dans sa boîte.

Réutilise les briques du module (rapport.py) : mise en page, matplotlib, envoi.
L'orchestrateur `executer_waf` reçoit ses collaborateurs par injection pour
rester testable sans matplotlib ni SMTP.
"""
from __future__ import annotations

import io
import sys
from collections import Counter
import tomllib
from pathlib import Path
from typing import Optional

# Rendre les modules voisins importables en « python3 -m api.rapport_waf ».
_ici = str(Path(__file__).resolve().parent)
if _ici not in sys.path:
    sys.path.insert(0, _ici)

CONF = Path("/etc/secubox/metrics.toml")

DEFAUTS = {
    "destinataire": "gk2@secubox.in",
    "jours": 7,
    "periode": "quotidien",
}


def config_waf() -> dict:
    """Config déclarative `[rapport.waf]` : à qui, sur combien de jours."""
    c = dict(DEFAUTS)
    try:
        with CONF.open("rb") as f:
            bloc = tomllib.load(f).get("rapport", {}).get("waf", {})
    except (OSError, ValueError):
        bloc = {}
    for k in DEFAUTS:
        if k in bloc:
            c[k] = bloc[k]
    return c


def executer_waf(lire_hist, construire_pdf, envoyer, cfg: Optional[dict] = None) -> dict:
    """Lit l'historique WAF, produit le PDF, l'expédie. Rien si pas de données."""
    c = cfg or config_waf()
    hist = lire_hist()
    if not hist or not hist.get("jours"):
        return {"envoye": False, "raison": "aucun historique WAF"}
    pdf = construire_pdf(hist, c["jours"])
    return envoyer(pdf, c["destinataire"], "Menaces WAF", c["periode"])


# ── PDF ────────────────────────────────────────────────────────────────────
# Palette catégorielle : couches distinctes et lisibles sur fond blanc.
# (rouge attaque en tête, puis cyan/ambre/violet/vert, gris pour « autres ».)
_PALETTE_CAT = ["#ff4466", "#00a8cc", "#f59e0b", "#8b5cf6",
                "#10b981", "#ec4899", "#6b7b8b"]


def _serie_categories(hist: dict, jours: int, top_n: int = 6):
    """Prépare l'empilement : les N derniers jours × les top catégories globales.

    Retourne (labels_jours, {categorie: [valeurs/jour]}, ordre_categories). Les
    catégories hors top_n sont fondues dans « autres » (dernière couche, grise)."""
    noms = sorted(hist.get("jours", {}).keys())[-jours:]
    globales: Counter = Counter()
    for j in noms:
        for c, n in (hist["jours"][j].get("categories") or {}).items():
            globales[c] += n
    top = [c for c, _ in globales.most_common(top_n)]
    series = {c: [] for c in top}
    autres = []
    for j in noms:
        cats = hist["jours"][j].get("categories") or {}
        for c in top:
            series[c].append(cats.get(c, 0))
        autres.append(sum(v for k, v in cats.items() if k not in top))
    ordre = list(top)
    if any(autres):
        series["autres"] = autres
        ordre.append("autres")
    return [j[5:] for j in noms], series, ordre


def _histo_menaces(hist: dict, jours: int) -> bytes:
    """Histogramme EMPILÉ des menaces par jour, une couche colorée par catégorie."""
    import rapport as R
    labels, series, ordre = _serie_categories(hist, jours)
    fig, ax = R.plt.subplots(figsize=(7.2, 2.8))
    bas = [0] * len(labels)
    for i, cat in enumerate(ordre):
        vals = series[cat]
        ax.bar(labels, vals, bottom=bas, width=.62, label=cat,
               color=_PALETTE_CAT[i % len(_PALETTE_CAT)])
        bas = [b + v for b, v in zip(bas, vals)]
    ax.set_ylabel("menaces", fontsize=8, color=R.GRIS)
    ax.tick_params(labelsize=7, colors=R.GRIS)
    if ordre:
        ax.legend(fontsize=6.5, frameon=False, ncol=3, loc="upper left")
    for bord in ("top", "right"):
        ax.spines[bord].set_visible(False)
    ax.grid(axis="y", alpha=.18)
    R.plt.xticks(rotation=45, ha="right")
    return R._png(fig)


def construire_pdf_waf(hist: dict, jours: int = 7) -> bytes:
    """Assemble le PDF WAF. Bloquant (matplotlib) : à lancer dans un thread."""
    import rapport as R
    resume = R._resume_waf(hist, jours) or {
        "total": 0, "jours": 0, "categories": [], "top_ips": []}

    pdf = R._Page()
    pdf.titre_doc = "SecuBox - Menaces WAF"
    pdf.set_auto_page_break(True, margin=18)
    pdf.alias_nb_pages()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, R._txt("Menaces WAF bloquees"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(110, 125, 140)
    pdf.cell(0, 5, R._txt(f"{resume['jours']} jour(s) - "
                          f"{resume['total']:,} menaces").replace(",", " "),
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    pdf.set_text_color(26, 36, 48)

    if hist.get("jours"):
        R._titre(pdf, "Menaces bloquees par jour (par categorie)")
        pdf.image(io.BytesIO(_histo_menaces(hist, jours)), w=190)
        pdf.ln(3)

    if resume["categories"]:
        R._titre(pdf, "Par categorie")
        pdf.set_font("Helvetica", "", 8)
        for c, n in resume["categories"]:
            R._garde(pdf, 5)
            pdf.cell(80, 5, R._txt(c))
            pdf.cell(30, 5, f"{n:,}".replace(",", " "), align="R",
                     new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    if resume["top_ips"]:
        R._titre(pdf, "Attaquants persistants")
        pdf.set_font("Helvetica", "", 8)
        for ip, n in resume["top_ips"]:
            R._garde(pdf, 5)
            pdf.cell(80, 5, R._txt(ip))
            pdf.cell(30, 5, f"{n:,}".replace(",", " "), align="R",
                     new_x="LMARGIN", new_y="NEXT")

    # ── DONNEES VENUES DU RAPPORT DE VISITE (#1367) ───────────────────────────
    # L'origine geographique vue par le WAF et les noms scannes que la box ne
    # sert pas sont des donnees d'ATTAQUE : elles etaient dans le rapport de
    # frequentation, leur place est ici. Lues depuis le cache de comptage WAF.
    _wstats = R._lire_waf_stats()
    _pays_waf = _wstats.get("top_countries") or {}
    if _pays_waf:
        _pays_waf = {k: v for k, v in _pays_waf.items() if k not in ("LAN", "??", "")}
    if _pays_waf:
        R._titre(pdf, "Origine des requetes vues par le WAF")
        pdf.image(io.BytesIO(R._camembert(_pays_waf, "Requetes par pays (WAF)")), w=92)
        pdf.ln(2)

    _noms, _distincts, _total = R._noms_non_servis(_wstats)
    if _noms:
        R._titre(pdf, R._txt(f"Noms demandes que la box ne sert pas - "
                             f"{_distincts} noms distincts, {_total:,} requetes"
                             ).replace(",", " "))
        pdf.set_font("Helvetica", "", 7)
        pdf.multi_cell(0, 4, R._txt(
            "Ces noms recoivent un 421 : aucun vhost ne leur repond. Entre le "
            "balayage, la liste designe les vhosts qui manquent - un nom encore "
            "reference ailleurs, un service jamais publie."),
            new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        pdf.set_font("Helvetica", "", 8)
        for nom, n in _noms:
            R._garde(pdf, 5)
            pdf.cell(120, 5, R._txt(nom))
            pdf.cell(30, 5, f"{n:,}".replace(",", " "), align="R",
                     new_x="LMARGIN", new_y="NEXT")

    return bytes(pdf.output())


def main(argv=None) -> int:
    """Point d'entrée de la tâche planifiée (service oneshot)."""
    import rapport
    try:
        res = executer_waf(rapport._lire_waf_historique, construire_pdf_waf,
                           rapport.envoyer)
    except Exception as e:  # noqa: BLE001 — une tâche planifiée journalise et sort
        print(f"rapport WAF : échec : {e}", file=sys.stderr)
        return 1
    if not res.get("envoye"):
        print(f"rapport WAF : non envoyé ({res.get('raison', '?')})",
              file=sys.stderr)
        return 0
    print(f"rapport WAF envoyé à {res.get('destinataire')} "
          f"({res.get('octets')} octets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
