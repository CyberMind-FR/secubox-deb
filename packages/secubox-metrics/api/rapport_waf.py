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


# ── HELPERS DE MISE EN PAGE (#1368) ─────────────────────────────────────────
# Le rapport WAF etait plus pauvre que le tableau du Hall : quelques categories
# et des IP, la ou le Hall montre efficacite, surfaces, origines, comptes vises,
# leurres touches, cibles internes. On lui donne les memes sections, depuis le
# meme cache de comptage (`_lire_waf_stats`).

def _tuiles_waf(pdf, R, cases) -> None:
    """Bandeau de chiffres cles, en teinte menace (rouge pale)."""
    largeur = 190 / max(1, len(cases))
    haut = pdf.get_y()
    for i, (k, v) in enumerate(cases):
        x = 10 + i * largeur
        pdf.set_xy(x, haut)
        pdf.set_fill_color(250, 241, 241)
        pdf.cell(largeur - 2, 17, "", fill=True, border=0)
        pdf.set_xy(x + 3, haut + 2.5)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(150, 92, 92)
        pdf.cell(largeur - 6, 4, R._txt(str(k).upper()), new_x="LEFT", new_y="NEXT")
        pdf.set_x(x + 3)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(26, 36, 48)
        pdf.cell(largeur - 6, 7, R._txt(str(v)))
    pdf.set_y(haut + 22)


def _table_kv(pdf, R, titre, donnees, entete=None, n=15,
              largeurs=(120, 30), suffixe="") -> None:
    """Tableau {libelle: nombre} trie decroissant, chaque ligne d'un bloc."""
    donnees = {k: v for k, v in (donnees or {}).items() if v}
    if not donnees:
        return
    R._titre(pdf, titre)
    if entete:
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_fill_color(244, 238, 238)
        pdf.cell(largeurs[0], 6, R._txt(entete[0]), fill=True)
        pdf.cell(largeurs[1], 6, R._txt(entete[1]), fill=True, align="R",
                 new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8)
    for k, v in sorted(donnees.items(), key=lambda kv: -kv[1])[:n]:
        R._garde(pdf, 5)
        pdf.cell(largeurs[0], 5, R._txt(str(k))[:82])
        pdf.cell(largeurs[1], 5, f"{v:,}".replace(",", " ") + suffixe, align="R",
                 new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)


def _table_efficacite(pdf, R, eff, n=18) -> None:
    """Bannis vs simplement avertis, par categorie de detection."""
    eff = {k: v for k, v in (eff or {}).items() if isinstance(v, dict)}
    if not eff:
        return
    R._titre(pdf, "Efficacite par categorie (bannis / avertis)")
    pdf.set_font("Helvetica", "B", 7.5)
    pdf.set_fill_color(244, 238, 238)
    for l, w in (("Categorie", 110), ("Bannis", 35), ("Avertis", 35)):
        pdf.cell(w, 6, R._txt(l), fill=True, align="L" if w == 110 else "R")
    pdf.ln()
    pdf.set_font("Helvetica", "", 8)
    for k, v in sorted(eff.items(),
                       key=lambda kv: -(kv[1].get("banned", 0)
                                        + kv[1].get("warning", 0)))[:n]:
        R._garde(pdf, 5)
        pdf.cell(110, 5, R._txt(str(k))[:72])
        pdf.cell(35, 5, f"{v.get('banned', 0):,}".replace(",", " "), align="R")
        pdf.cell(35, 5, f"{v.get('warning', 0):,}".replace(",", " "), align="R",
                 new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)


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

    # Le cache de comptage du WAF (les memes chiffres que le tableau du Hall).
    _wstats = R._lire_waf_stats()
    _eff = _wstats.get("efficacite", {}) or {}
    _bannis = sum(v.get("banned", 0) for v in _eff.values() if isinstance(v, dict))
    _avertis = sum(v.get("warning", 0) for v in _eff.values() if isinstance(v, dict))
    # CHIFFRES CLES, comme les tuiles du Hall : menaces vues au total, part
    # bannie vs simplement avertie, nombre de surfaces surveillees, comptes et
    # leurres vises. Un rapport doit se lire d'un coup d'oeil avant le detail.
    _tuiles_waf(pdf, R, [
        ("Menaces", f"{_wstats.get('total_threats', resume['total']):,}".replace(",", " ")),
        ("Bannies", f"{_bannis:,}".replace(",", " ")),
        ("Averties", f"{_avertis:,}".replace(",", " ")),
        ("Surfaces", str(len(_wstats.get("par_type", {}) or {}))),
        ("Leurres", str(len(_wstats.get("leurres_touches", {}) or {}))),
        ("Comptes vises", str(len(_wstats.get("comptes_vises", {}) or {}))),
    ])

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
        pdf.ln(2)

    # ── LES SECTIONS DU TABLEAU DU HALL (#1368) ───────────────────────────────
    # Efficacite, surfaces surveillees, origines des detections, comptes vises,
    # leurres touches et cibles internes : tout ce que le Hall montre, le
    # rapport le porte aussi, pour qui lit le PDF plutot que l'ecran.
    _table_efficacite(pdf, R, _eff)
    _table_kv(pdf, R, "Surfaces surveillees",
              _wstats.get("par_type"), ("Surface", "Requetes"),
              largeurs=(120, 30))
    _table_kv(pdf, R, "Origine des detections",
              _wstats.get("par_origine"), ("Origine", "Detections"),
              largeurs=(120, 30))
    _table_kv(pdf, R, "Comptes vises (SSH / SMTP / IMAP)",
              _wstats.get("comptes_vises"), ("Compte", "Tentatives"),
              largeurs=(150, 30), n=20)
    _table_kv(pdf, R, "Leurres touches",
              _wstats.get("leurres_touches"), ("Service leurre", "Contacts"),
              largeurs=(120, 30))
    _table_kv(pdf, R, "Cibles internes les plus visees",
              _wstats.get("top_vhosts"), ("Vhost", "Menaces"),
              largeurs=(120, 30))

    # ── DONNEES VENUES DU RAPPORT DE VISITE (#1367) ───────────────────────────
    # L'origine geographique vue par le WAF et les noms scannes que la box ne
    # sert pas sont des donnees d'ATTAQUE : elles etaient dans le rapport de
    # frequentation, leur place est ici. Lues depuis le meme cache de comptage.
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
