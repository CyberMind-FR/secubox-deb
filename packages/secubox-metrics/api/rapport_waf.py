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
def _serie_menaces(hist: dict, jours: int) -> list:
    """Les N derniers jours en [{jour, total}] (du plus ancien au plus récent)."""
    noms = sorted(hist.get("jours", {}).keys())[-jours:]
    return [{"jour": j, "total": hist["jours"][j].get("total", 0)} for j in noms]


def _histo_menaces(serie: list) -> bytes:
    """Barres : menaces bloquées par jour."""
    import rapport as R
    fig, ax = R.plt.subplots(figsize=(7.2, 2.4))
    jours = [s["jour"][5:] for s in serie]
    vals = [s["total"] for s in serie]
    ax.bar(jours, vals, color=R.ROUGE, width=.62)
    ax.set_ylabel("menaces", fontsize=8, color=R.GRIS)
    ax.tick_params(labelsize=7, colors=R.GRIS)
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

    serie = _serie_menaces(hist, jours)
    if serie:
        R._titre(pdf, "Menaces bloquees par jour")
        pdf.image(io.BytesIO(_histo_menaces(serie)), w=190)
        pdf.ln(3)

    if resume["categories"]:
        R._titre(pdf, "Par categorie")
        pdf.set_font("Helvetica", "", 8)
        for c, n in resume["categories"]:
            pdf.cell(80, 5, R._txt(c))
            pdf.cell(30, 5, f"{n:,}".replace(",", " "), align="R",
                     new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    if resume["top_ips"]:
        R._titre(pdf, "Attaquants persistants")
        pdf.set_font("Helvetica", "", 8)
        for ip, n in resume["top_ips"]:
            pdf.cell(80, 5, R._txt(ip))
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
