#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: Metrics — rapport de frequentation (PDF + envoi interne)

Fabrique un PDF a partir des compteurs par vhost et l'expedie par la
messagerie interne de la boite. Le courrier ne sort pas sur le WAN : il part
vers le relais local, qui est le conteneur `mail`.

Tout ce fichier est synchrone et bloquant — le rendu matplotlib comme
l'ouverture SMTP. Les appelants DOIVENT le lancer dans un thread
(`asyncio.to_thread`) : un rendu synchrone sur une boucle mono-worker fige le
module entier, ce qui a deja coute des 504 ailleurs sur cette boite.
"""

import io
import json
import smtplib
import ssl
import sys
import tomllib
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use("Agg")            # aucun serveur X ici : backend fichier
import matplotlib.pyplot as plt  # noqa: E402
from fpdf import FPDF            # noqa: E402

_ici = str(Path(__file__).resolve().parent)
if _ici not in sys.path:
    sys.path.insert(0, _ici)
import pdf_aurora as A  # noqa: E402  primitives Aurora communes (#2390)

CONF = Path("/etc/secubox/metrics.toml")

# Les polices de base de fpdf ne connaissent que latin-1. Les chemins et
# referents viennent des journaux : ils peuvent contenir n'importe quel
# caractere, et un seul suffit a faire echouer tout le rapport.
_SUBST = {
    "\u2014": "-", "\u2013": "-", "\u2019": "'", "\u2018": "'",
    "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00a0": " ",
    "\u2192": "->", "\u00b7": "-",
}


SMTP_DELAI_S = 200  # > réveil à froid du LXC clamav (~120 s) ; tâche de fond, personne n'attend


def _txt(v) -> str:
    """Rend une chaine que la police de base sait ecrire."""
    s = str(v)
    for k, r in _SUBST.items():
        s = s.replace(k, r)
    return s.encode("latin-1", "replace").decode("latin-1")


CYAN, ROUGE, GRIS, ENCRE = "#00a8cc", "#ff4466", "#6b7b8b", "#1a2430"

DEFAUTS = {
    "smtp_hote": "10.100.0.10",
    "smtp_port": 25,
    "expediteur": "secubox@localdomain",
    "destinataire": "admin@localdomain",
}


def config() -> dict:
    c = dict(DEFAUTS)
    try:
        with CONF.open("rb") as f:
            c.update(tomllib.load(f).get("rapport", {}))
    except (OSError, ValueError):
        pass
    return c


# ── graphiques ───────────────────────────────────────────────────────────
def _png(fig) -> bytes:
    tampon = io.BytesIO()
    fig.savefig(tampon, format="png", dpi=130, bbox_inches="tight",
                facecolor="white")
    plt.close(fig)
    return tampon.getvalue()


def _histogramme(serie: list[dict]) -> bytes:
    """Visites par jour. Les VISITES seulement (#1367).

    Les sondes (scans, tentatives) sont des ATTAQUES, pas de la frequentation :
    empilees ici, elles gonflaient un graphe de visites avec du trafic hostile
    et brouillaient la lecture. Elles ont leur place dans le rapport WAF dedie,
    pas dans le rapport de visite d'un vhost.
    """
    fig, ax = plt.subplots(figsize=(7.2, 2.4))
    jours = [s["jour"][5:] for s in serie]
    visites = [s["visites"] for s in serie]
    ax.bar(jours, visites, color=CYAN, label="Visites", width=.62)
    ax.set_ylabel("visites", fontsize=8, color=GRIS)
    ax.tick_params(labelsize=7, colors=GRIS)
    ax.legend(fontsize=7, frameon=False)
    for bord in ("top", "right"):
        ax.spines[bord].set_visible(False)
    ax.grid(axis="y", alpha=.18)
    plt.xticks(rotation=45, ha="right")
    return _png(fig)


def _camembert(pays: dict, titre: str = "Visites par pays") -> bytes:
    """Repartition geographique (#1190).

    Un camembert ne supporte pas la longue traine : au-dela de sept parts on ne
    lit plus rien. Les suivantes sont donc regroupees en « autres » — les
    montrer separement reviendrait a ne montrer personne.

    Les pays viennent du geoip, qui ne resout que les IP PUBLIQUES : la part
    affichee est donc celle des VRAIS visiteurs, cohérente avec le compteur de
    visiteurs uniques (cf. _publique dans vhost_stats).
    """
    items = sorted(pays.items(), key=lambda kv: -kv[1])
    if not items:
        fig, ax = plt.subplots(figsize=(3.4, 2.4))
        ax.text(.5, .5, "aucune origine connue", ha="center", va="center",
                fontsize=8, color=GRIS)
        ax.axis("off")
        return _png(fig)

    tete, reste = items[:7], items[7:]
    if reste:
        tete.append(("autres", sum(n for _, n in reste)))
    noms = [k for k, _ in tete]
    vals = [v for _, v in tete]
    total = sum(vals) or 1

    fig, ax = plt.subplots(figsize=(4.4, 2.6))
    parts, _ = ax.pie(vals, startangle=90, counterclock=False,
                      wedgeprops={"linewidth": .6, "edgecolor": "white"})
    # LEGENDE plutot qu'etiquettes posees sur le camembert : sur des parts
    # fines, les libelles se chevauchent au point de se superposer (« CH IT ES
    # autres » empiles au meme endroit). La legende porte aussi le compte, que
    # le pourcentage seul ne donne pas.
    ax.legend(parts, [f"{n}  {v}  ({100 * v / total:.0f} %)" for n, v in zip(noms, vals)],
              loc="center left", bbox_to_anchor=(.98, .5),
              fontsize=7, frameon=False, labelcolor=ENCRE)
    ax.set_title(titre, fontsize=8.5, color=ENCRE, loc="left")
    ax.axis("equal")
    return _png(fig)


def _cumul(serie: list[dict], base: int = 0, depuis: str = "") -> bytes:
    """Visites CUMULEES depuis la premiere visite (#1190).

    `base` est le total des jours deja sortis de la retention : sans lui, la
    courbe repartirait de zero tous les trente jours et ne dirait plus « depuis
    la premiere visite » mais « depuis un mois ».

    Courbe et non barres : ce qu'on lit ici est une PENTE — l'audience
    accelere, stagne ou retombe. Des barres cumulees ne montrent que des
    colonnes qui montent toujours, ce qui n'apprend rien.
    """
    fig, ax = plt.subplots(figsize=(7.2, 2.2))
    jours, total, cumule = [], base, []
    for s in serie:
        total += s.get("visites", 0)
        jours.append(s["jour"][5:])
        cumule.append(total)
    if not jours:
        jours, cumule = ["-"], [base]

    ax.plot(jours, cumule, color=CYAN, linewidth=1.8)
    ax.fill_between(range(len(jours)), cumule, color=CYAN, alpha=.14)
    if base:
        # Le trait dit ou commence la fenetre detaillee : au-dessous, c'est
        # l'acquis qu'on ne detaille plus.
        ax.axhline(base, color=GRIS, linewidth=.7, linestyle=":")
    titre = "Visites cumulees"
    if depuis:
        titre += f" depuis le {depuis}"
    ax.set_title(titre, fontsize=8.5, color=ENCRE, loc="left")
    ax.set_ylabel("cumul", fontsize=8, color=GRIS)
    ax.tick_params(labelsize=7, colors=GRIS)
    for bord in ("top", "right"):
        ax.spines[bord].set_visible(False)
    ax.grid(axis="y", alpha=.18)
    plt.xticks(rotation=45, ha="right")
    return _png(fig)


def _barres(donnees: dict, titre: str) -> bytes:
    """Repartition (navigateurs, plateformes) en barres horizontales."""
    items = list(donnees.items())[:7]
    if not items:
        items = [("aucune donnee", 1)]
    fig, ax = plt.subplots(figsize=(3.4, max(1.3, .34 * len(items))))
    noms = [k for k, _ in items][::-1]
    vals = [v for _, v in items][::-1]
    ax.barh(noms, vals, color=CYAN, height=.6)
    ax.set_title(titre, fontsize=8.5, color=ENCRE, loc="left")
    ax.tick_params(labelsize=7, colors=GRIS)
    for bord in ("top", "right", "left"):
        ax.spines[bord].set_visible(False)
    ax.grid(axis="x", alpha=.18)
    return _png(fig)


# ── mise en page ─────────────────────────────────────────────────────────
class _Page(FPDF):
    titre_doc = "SecuBox - rapport de frequentation"

    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(0, 120, 150)
        self.cell(0, 6, _txt(self.titre_doc), align="L")
        self.set_font("Helvetica", "", 8)
        self.set_text_color(120, 130, 140)
        self.cell(0, 6, datetime.now().strftime("%d/%m/%Y %H:%M"),
                  align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 215, 225)
        self.line(10, 18, 200, 18)
        self.ln(6)

    def footer(self):
        self.set_y(-13)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(140, 150, 160)
        self.cell(0, 6, f"page {self.page_no()}/{{nb}}", align="C")



def _tuiles(pdf: _Page, t: dict) -> None:
    # PAS DE « SONDES » ICI (#1367) : les sondes sont des attaques, elles vont
    # au rapport WAF. Le rapport de visite ne compte que la frequentation.
    cases = [
        ("Visites", f"{t['visites']:,}".replace(",", " ")),
        ("Visiteurs", f"{t['visiteurs']:,}".replace(",", " ")),
        ("Requetes", f"{t['requetes']:,}".replace(",", " ")),
        ("Erreurs", f"{t['erreurs']:,}".replace(",", " ")),
    ]
    largeur = 190 / len(cases)
    haut = pdf.get_y()
    for i, (k, v) in enumerate(cases):
        x = 10 + i * largeur
        pdf.set_xy(x, haut)
        pdf.set_fill_color(242, 248, 251)
        pdf.cell(largeur - 2, 17, "", fill=True, border=0)
        pdf.set_xy(x + 3, haut + 2.5)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(110, 125, 140)
        pdf.cell(largeur - 6, 4, _txt(k.upper()), new_x="LEFT", new_y="NEXT")
        pdf.set_x(x + 3)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(26, 36, 48)
        pdf.cell(largeur - 6, 7, _txt(v))
    pdf.set_y(haut + 22)


def _titre(pdf: _Page, texte: str) -> None:
    # UN TITRE NE RESTE PAS ORPHELIN EN BAS DE PAGE (#1367). Sans garde, un
    # titre de section s'imprimait au ras de la marge basse et sa table partait
    # a la page suivante, coupee de son intitule. On reserve de quoi poser le
    # titre + une premiere ligne, sinon on saute avant de l'ecrire.
    _garde(pdf, 16)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(0, 120, 150)
    pdf.cell(0, 7, _txt(texte), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(26, 36, 48)


def _garde(pdf: _Page, besoin: float = 5.0) -> bool:
    """Saute a la page suivante si `besoin` mm ne tiennent pas avant la marge.

    LE BUG (#1367) : le saut de page AUTOMATIQUE de fpdf2 ne deplace que la
    cellule qui deborde. Une LIGNE de tableau est faite de plusieurs cellules
    posees l'une apres l'autre ; quand le saut tombe au milieu, les premieres
    cellules restent en bas d'une page et les dernieres passent a la suivante,
    decalees — la ligne, coupee en deux, devient illisible voire invisible.

    On appelle donc `_garde` AVANT la premiere cellule de chaque ligne : la
    ligne entiere descend d'un bloc. Rend True si un saut a eu lieu — utile pour
    re-tracer l'entete d'un tableau qui continue sur la nouvelle page.
    """
    if pdf.get_y() + besoin > pdf.h - pdf.b_margin:
        pdf.add_page()
        return True
    return False


# ── bilan WAF (#1062) : menaces bloquées, depuis l'historique agrégé par sbxwaf ──
WAF_HISTORIQUE = Path("/var/lib/secubox/waf/waf-history.json")
# Cache de comptage du WAF : c'est lui qui porte les pays du journal de menaces
# et les noms demandes que la box ne sert pas (#1219).
WAF_STATS = Path("/var/lib/secubox/waf/stats-disk-cache.json")


def _lire_waf_historique(chemin: Path = WAF_HISTORIQUE) -> Optional[dict]:
    """Lit l'agrégat d'historique WAF (waf-history.json). None si absent."""
    try:
        return json.loads(chemin.read_text())
    except (OSError, ValueError):
        return None


def _resume_waf(hist: Optional[dict], jours: int = 7) -> Optional[dict]:
    """Résume les N derniers jours : total menaces, top catégories, top attaquants."""
    if not hist or not hist.get("jours"):
        return None
    noms = sorted(hist["jours"].keys())[-jours:]
    total = 0
    cats: dict = {}
    for j in noms:
        d = hist["jours"][j]
        total += d.get("total", 0)
        for c, n in (d.get("categories") or {}).items():
            cats[c] = cats.get(c, 0) + n
    if not total:
        return None
    return {
        "jours": len(noms),
        "total": total,
        "categories": sorted(cats.items(), key=lambda x: -x[1])[:6],
        "top_ips": list((hist.get("top_ips") or {}).items())[:5],
    }


def _lire_waf_stats(chemin: Path = WAF_STATS) -> dict:
    """Compteurs cumules du WAF. Lecture tolerante : le rapport doit partir
    meme sans WAF installe, avec une section en moins plutot qu'une erreur."""
    try:
        return json.loads(chemin.read_text()).get("counters", {}) or {}
    except (OSError, ValueError, AttributeError):
        return {}


def _noms_non_servis(counters: dict, limite: int = 20) -> tuple:
    """Noms demandes auxquels aucun vhost ne repond, du plus frequent au moins.

    Le WAF repond 421 et n'atteint aucun backend : ces requetes sont exclues des
    statistiques de visite, si bien que rien ne les totalisait. La liste vaut
    pourtant d'etre lue : entre le balayage, elle designe les vhosts qui
    MANQUENT. Rend (liste, nombre de noms distincts, total des requetes).
    """
    bruts = counters.get("noms_non_routes") or {}
    if not isinstance(bruts, dict):
        return [], 0, 0
    ordonnes = sorted(bruts.items(), key=lambda kv: -int(kv[1] or 0))
    return ordonnes[:limite], len(bruts), sum(int(v or 0) for v in bruts.values())


def _pays_de(source: dict) -> dict:
    """Normalise `pays`, que l'API rende un dict ou une liste d'entrees."""
    p = source.get("pays")
    if isinstance(p, dict):
        return p
    if isinstance(p, list):
        return {e.get("code", "?"): e.get("n", 0) for e in p if isinstance(e, dict)}
    return {}


# ── rapport de fréquentation, langage Aurora (#2390) ─────────────────────
_CLASSES = (("2", "2xx succes", A.VERT), ("3", "3xx redir.", A.CYAN),
            ("4", "4xx client", A.ORANGE), ("5", "5xx serveur", A.ROUGE))
BAS = 283.0     # ordonnée maximale d'un bloc (le pied est à 285)


def _date_fr(iso) -> str:
    try:
        return datetime.strptime(str(iso)[:10], "%Y-%m-%d").strftime("%d/%m/%Y")
    except ValueError:
        return str(iso) if iso else "—"


def _classes_statuts(statuts: Optional[dict]) -> dict:
    """Codes de retour regroupés par classe (« 2xx »..« 5xx »), que l'API rende « 2xx » ou « 404 »."""
    out: dict = {}
    for code, v in (statuts or {}).items():
        t = str(code)[:1]
        out[t] = out.get(t, 0) + A.num(v)
    return out


def _somme_dicts(dicts) -> dict:
    out: dict = {}
    for d in dicts:
        for k, v in (d or {}).items():
            out[k] = out.get(k, 0) + A.num(v)
    return out


def _place(pdf, y: float, h: float) -> float:
    """Ordonnée où poser un bloc de hauteur h : saute de page (retour en haut) s'il ne tient pas."""
    if y + h > BAS:
        pdf.add_page()
        return 18.0
    return y


def _tuiles_aurora(source: dict, vhosts: list) -> list:
    """Les cases de tête. Une mesure absente est « — », jamais 0."""
    cl = _classes_statuts(source.get("statuts")) if source.get("statuts") else {}
    n5 = cl.get("5") if cl else None
    octs = source.get("octets")
    if octs is None and vhosts and any("octets" in v for v in vhosts):
        octs = sum(A.num(v.get("octets")) for v in vhosts)
    req = source.get("requetes")
    rob = None
    if vhosts and req:
        rob = sum(A.num(v.get("robots")) for v in vhosts) if any("robots" in v for v in vhosts) else None
    elif source.get("robots") is not None and req:
        rob = source.get("robots")
    err = source.get("erreurs")
    return [("Visites", A.n(source.get("visites")), "pages, hors accessoires", A.CYAN),
            ("Visiteurs", A.n(source.get("visiteurs")), "adresses publiques", A.BLEU),
            ("Requetes", A.n(req), (f"dont {100 * rob / req:.0f} % de robots" if rob is not None and req else "toutes requetes"), A.VIOLET),
            ("Erreurs", A.n(err), ("4xx et 5xx" + (f", dont {A.n(n5)} 5xx" if n5 is not None else "")), A.ORANGE if not n5 else A.ROUGE),
            ("Bande passante", A.octets(octs), "octets servis", A.VERT)]


def _image_dans(pdf, png: bytes, x: float, y: float, w: float, hmax: float) -> None:
    """Pose le PNG à la largeur w, réduite (et recentrée) pour que sa hauteur tienne dans hmax."""
    h = A.hauteur_png(png, w)
    if h > hmax:
        w2 = w * hmax / h
        x, w = x + (w - w2) / 2, w2
    A.image(pdf, png, x, y, w)


def _bloc_jours(pdf, y: float, serie: list) -> float:
    y = _place(pdf, y, 56)
    A.panneau(pdf, 10, y, 190, 52, "Visites jour par jour", "pages vues · hors sondes et attaques")
    if len(serie or []) >= 2:
        _image_dans(pdf, A.graphe_histogramme([A.num(s.get("visites")) for s in serie], [str(s["jour"])[5:] for s in serie], A.CYAN), 14, y + 8, 182, 42)
    else:
        pdf.set_xy(13, y + 24)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*A.FAIBLE)
        pdf.cell(0, 5, A.txt("— historique insuffisant (moins de deux jours) —"))
    return y + 56


def _bloc_cumul(pdf, y: float, serie: list, cum: dict) -> float:
    y = _place(pdf, y, 56)
    base = int(A.num(cum.get("base")))
    depuis = cum.get("depuis")
    A.panneau(pdf, 10, y, 190, 52, "Visites cumulees depuis la premiere visite" + (f" ({_date_fr(depuis)})" if depuis else ""),
              (f"dont {A.n(base)} avant la fenetre detaillee" if base else "sur la fenetre detaillee"))
    if len(serie or []) >= 2:
        tot, vals = base, []
        for s in serie:
            tot += A.num(s.get("visites"))
            vals.append(tot)
        _image_dans(pdf, A.graphe_courbes([("Cumul", vals, A.VERT)], [str(s["jour"])[5:] for s in serie]), 14, y + 8, 182, 42)
    else:
        pdf.set_xy(13, y + 24)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*A.FAIBLE)
        pdf.cell(0, 5, A.txt("— historique insuffisant (moins de deux jours) —"))
    return y + 56


def _bloc_statuts_carte(pdf, y: float, statuts: dict, pays: dict, sous_carte: str) -> float:
    """Gauche : anneau et barres des classes de statut HTTP. Droite : carte du monde (la grille de la page WAF)."""
    y = _place(pdf, y, 64)
    cl = _classes_statuts(statuts)
    parts = [(lib, cl.get(t, 0), c) for t, lib, c in _CLASSES if cl.get(t)]
    autres = sum(v for t, v in cl.items() if t not in "2345")
    if autres:
        parts.append(("autres", autres, A.DOUX))
    tot = sum(p[1] for p in parts)
    A.panneau(pdf, 10, y, 92, 60, "Codes de retour HTTP", "part des requetes")
    if tot:
        A.image(pdf, A.graphe_donut([(p[0], p[1]) for p in parts], A.n(tot), [p[2] for p in parts]), 12, y + 9, 36)
        A.barres(pdf, 50, y + 14, 50, [(p[0], p[1], p[2]) for p in parts], fmt=lambda v: ("<1%" if 0 < 100 * A.num(v) / tot < 1 else f"{100 * A.num(v) / tot:.0f}%"), pas=7, max_l=5, part_libelle=0.50)
    else:
        pdf.set_xy(13, y + 26)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*A.FAIBLE)
        pdf.cell(80, 5, A.txt("— indisponible —"))
    A.panneau(pdf, 108, y, 92, 60, "Origine des visiteurs", sous_carte)
    _image_dans(pdf, A.graphe_carte(pays, A.CYAN), 110, y + 9, 88, 49)
    return y + 64


def _bloc_deux(pdf, y: float, gauche, droite, rangs: int = 7) -> float:
    """Deux panneaux de barres côte à côte : (titre, sous, lignes, couleur, fmt). Hauteur selon le plus long des deux (3 à `rangs` lignes)."""
    h = 14 + 6.2 * min(rangs, max(3, *(sum(1 for l_ in g[2] if l_[1] is not None) for g in (gauche, droite))))
    y = _place(pdf, y, h + 4)
    for x, (titre, sous, lignes, couleur, fmt) in ((10, gauche), (108, droite)):
        A.panneau(pdf, x, y, 92, h, titre, sous)
        A.barres(pdf, x + 3, y + 10, 86, lignes, fmt=fmt, couleur=couleur, max_l=rangs, part_libelle=0.46)
    return y + h + 4


def _bloc_large(pdf, y: float, titre: str, sous: str, lignes: list, couleur, fmt=A.n, max_l: int = 8) -> float:
    lignes = [l_ for l_ in lignes if l_[1] is not None][:max_l]
    h = 14 + 6.2 * max(1, len(lignes))
    y = _place(pdf, y, h + 4)
    A.panneau(pdf, 10, y, 190, h, titre, sous)
    A.barres(pdf, 13, y + 10, 184, lignes, fmt=fmt, couleur=couleur, max_l=max_l, part_libelle=0.46)
    return y + h + 4


def _tableau_vhosts(pdf, y: float, vhosts: list) -> float:
    cols = (("Domaine", 66, "L"), ("Visites", 24, "R"), ("Visiteurs", 24, "R"), ("Robots", 20, "R"), ("Erreurs", 24, "R"), ("Octets", 32, "R"))

    y = _place(pdf, y, 8 + 5 * 3 + 12)
    pdf.set_xy(10, y)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*A.TEXTE)
    pdf.cell(0, 7, A.txt("Detail par vhost"), new_x="LMARGIN", new_y="NEXT")
    y = pdf.get_y() + 1
    liste = vhosts[:40]

    def tete(yy):
        pdf.set_fill_color(*A.PANNEAU)
        pdf.set_draw_color(*A.TRAIT)
        pdf.rect(10, yy, 190, 6.5, "DF")
        pdf.set_xy(12, yy + 0.8)
        pdf.set_font("Helvetica", "B", 6.8)
        pdf.set_text_color(*A.DOUX)
        for lib, w, al in cols:
            pdf.cell(w - (3 if lib == "Octets" else 0), 4.8, A.txt(lib.upper()), align=al)
        return yy + 6.5

    y = tete(y)
    for i, v in enumerate(liste):
        if y + 5.2 > BAS:
            pdf.add_page()
            y = tete(18.0)
        pdf.set_fill_color(*((10, 21, 42) if i % 2 else A.FOND))
        pdf.rect(10, y, 190, 5.2, "F")
        nom = v["vhost"] + (f"  ({len(v['membres'])} domaines)" if v.get("membres") and len(v["membres"]) > 1 else "")
        pdf.set_xy(12, y + 0.4)
        pdf.set_font("Helvetica", "", 7.2)
        pdf.set_text_color(*A.TEXTE)
        pdf.cell(66, 4.4, A.txt(nom)[:44])
        pdf.set_text_color(*A.DOUX)
        rob = v.get("part_robots")
        for val, w in ((A.n(v.get("visites")), 24), (A.n(v.get("visiteurs")), 24), ("—" if rob is None else f"{rob} %", 20), (A.n(v.get("erreurs")), 24), (A.octets(v.get("octets")), 29)):
            pdf.cell(w, 4.4, A.txt(val), align="R")
        pdf.cell(3, 4.4, "")
        y += 5.2
    if len(vhosts) > len(liste):
        pdf.set_xy(12, y + 1)
        pdf.set_font("Helvetica", "", 6.8)
        pdf.set_text_color(*A.FAIBLE)
        pdf.cell(0, 4, A.txt(f"{len(vhosts) - len(liste)} vhost(s) de plus, non listes"))
        y += 5
    return y


def _bloc_texte(pdf, y: float, titre: str, sous: str, texte: str) -> float:
    pdf.set_font("Helvetica", "", 7.5)
    lignes = pdf.multi_cell(184, 4, A.txt(texte), dry_run=True, output="LINES")
    h = 12 + 4 * len(lignes)
    y = _place(pdf, y, h + 4)
    A.panneau(pdf, 10, y, 190, h, titre, sous)
    pdf.set_xy(13, y + 9)
    pdf.set_text_color(*A.DOUX)
    pdf.multi_cell(184, 4, A.txt(texte))
    return y + h + 4


def construire_pdf(vue: dict, detail: Optional[dict] = None) -> bytes:
    """Assemble le PDF (A4, thème Aurora comme le rapport de sécurité). Bloquant : a lancer dans un thread."""
    pdf = A.classe_page("SecuBox — rapport de fréquentation", "SecuBox — fréquentation · page {page}/{nb}")()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(False)
    pdf.add_page()

    portee = detail["vhost"] if detail else "Tous les vhosts"
    pdf.set_xy(10, 20)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*A.TEXTE)
    pdf.cell(0, 10, A.txt("Fréquentation"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(10)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*A.CYAN)
    pdf.cell(0, 6, A.txt(portee), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(10)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*A.FAIBLE)
    pdf.cell(0, 5, A.txt(f"Période : {vue.get('periode') or '—'} · du {_date_fr(vue.get('du'))} au {_date_fr(vue.get('au'))} · généré le "
                         f"{datetime.now().strftime('%d/%m/%Y à %H:%M')}"), new_x="LMARGIN", new_y="NEXT")

    source = detail or vue.get("total", {})
    vhosts = vue.get("vhosts") or []
    y = A.rangee_tuiles(pdf, 44, _tuiles_aurora(source, [] if detail else vhosts)) + 2

    if detail:
        y = _bloc_jours(pdf, y, detail.get("serie") or [])
        y = _bloc_cumul(pdf, y, detail.get("serie") or [], detail.get("cumul") or {})
        pays = detail.get("pays_cumul") or _pays_de(detail)
        y = _bloc_statuts_carte(pdf, y, detail.get("statuts") or {}, pays, "depuis la premiere visite" if detail.get("pays_cumul") else "visites par pays")
        y = _bloc_large(pdf, y, "Pages les plus vues", "visites sur la periode",
                        [(e.get("chemin"), e.get("n")) for e in (detail.get("top_chemins") or [])], A.CYAN, max_l=12)
        directs = detail.get("directs_pct") or 0.0
        y = _bloc_deux(pdf, y,
                       ("Referents", f"{directs:.1f} % d'acces direct", [(e.get("hote"), e.get("n")) for e in (detail.get("top_referents") or [])], A.VIOLET, A.n),
                       ("Pays des visiteurs", "geoip, adresses publiques", [(e.get("code") or "??", e.get("n")) for e in (detail.get("pays") or [])], A.VERT, A.n), rangs=8)
        y = _bloc_deux(pdf, y,
                       ("Navigateurs", "requetes", list((detail.get("navigateurs") or {}).items()), A.BLEU, A.n),
                       ("Plateformes", "requetes", list((detail.get("plateformes") or {}).items()), A.ORANGE, A.n))
        membres = detail.get("membres") or []
        if len(membres) > 1:
            y = _bloc_texte(pdf, y, "Domaines de la famille", f"{len(membres)} domaines", " · ".join(membres))
    else:
        y = _bloc_jours(pdf, y, vue.get("serie") or [])
        pays = _somme_dicts({e.get("code", "?"): e.get("n", 0) for e in (v.get("pays") or []) if isinstance(e, dict)} for v in vhosts) or _pays_de(source)
        statuts = _somme_dicts(v.get("statuts") for v in vhosts) or (source.get("statuts") or {})
        y = _bloc_statuts_carte(pdf, y, statuts, pays, "visites par pays, tous vhosts")
        y = _bloc_large(pdf, y, "Sites les plus visites", "visites sur la periode",
                        [(v["vhost"], v.get("visites")) for v in vhosts], A.CYAN, max_l=8)
        y = _bloc_deux(pdf, y,
                       ("Navigateurs", "requetes", list((source.get("navigateurs") or {}).items()), A.BLEU, A.n),
                       ("Plateformes", "requetes", list((source.get("plateformes") or {}).items()), A.ORANGE, A.n))
        refs = source.get("top_referents") or []
        if refs or source.get("directs_pct") is not None:
            y = _bloc_deux(pdf, y,
                           ("Referents", f"{A.num(source.get('directs_pct')):.1f} % d'acces direct", [(e.get("hote"), e.get("n")) for e in refs], A.VIOLET, A.n),
                           ("Pays des visiteurs", "geoip, adresses publiques",
                            sorted(pays.items(), key=lambda kv: -A.num(kv[1])), A.VERT, A.n))
        _tableau_vhosts(pdf, y, vhosts)

    # LES DONNEES D'ATTAQUE NE SONT PLUS ICI (#1367) : menaces WAF, attaquants, noms scannes -> rapport WAF / securite.
    return bytes(pdf.output())


# ── expedition ───────────────────────────────────────────────────────────
def _lire_secret(chemin: Optional[str]) -> Optional[str]:
    """Lit un mot de passe depuis un fichier hors-code (CSPN : secrets en
    /etc/secubox/secrets/, jamais versionnes). Absent/illisible -> None."""
    if not chemin:
        return None
    try:
        return Path(chemin).read_text(encoding="utf-8").strip("\r\n")
    except OSError:
        return None


def resume_statuts(statuts: Optional[dict]) -> str:
    """Résumé EMOJI des codes de retour pour le corps de l'e-mail (#1131an).

    Le PDF (Helvetica/latin-1) ne peut pas afficher d'emoji ; le corps du mail,
    lui, est en UTF-8 — c'est donc là qu'on met un résumé lisible d'un coup
    d'œil : groupé par classe 🟢2xx / 🔵3xx / 🟠4xx / 🔴5xx, avec les principaux
    codes d'erreur repérés par une émoticône qui dit LE TYPE d'erreur.
    """
    if not statuts:
        return ""
    classe = {"2": "🟢", "3": "🔵", "4": "🟠", "5": "🔴"}
    par_code = {"400": "❓", "401": "🔑", "403": "🚫", "404": "🔍", "405": "🙅",
                "408": "⏳", "429": "🐢", "500": "💥", "502": "🔌", "503": "😴",
                "504": "⏱️"}
    total = sum(statuts.values()) or 1
    groupes: dict = {}
    erreurs: list = []
    for code, n in statuts.items():
        tete = str(code)[:1]
        groupes[tete] = groupes.get(tete, 0) + n
        if tete in ("4", "5"):
            erreurs.append((str(code), n))
    lignes = ["— Codes de retour —"]
    for tete in ("2", "3", "4", "5"):
        n = groupes.get(tete)
        if not n:
            continue
        ligne = f"{classe.get(tete, '•')} {tete}xx : {n:,}".replace(",", " ")
        ligne += f" ({100 * n / total:.0f} %)"
        det = sorted((e for e in erreurs if e[0][:1] == tete),
                     key=lambda x: -x[1])[:4]
        if det:
            ligne += "  ·  " + " · ".join(
                f"{par_code.get(cd, '⚠️')} {cd}:{m:,}".replace(",", " ")
                for cd, m in det)
        lignes.append(ligne)
    return "\n".join(lignes) + "\n"


def envoyer(pdf: bytes, destinataire: Optional[str] = None,
            portee: str = "Tous les vhosts", periode: str = "semaine",
            resume: str = "", objet: Optional[str] = None,
            nom_fichier: Optional[str] = None, intro: Optional[str] = None) -> dict:
    """Expedie le PDF. Bloquant : thread/tache oneshot obligatoire.

    Deux modes selon la config `[rapport]` :
      - relais LOCAL (defaut #1059) : port 25, sans auth, destinataire INTERNE.
      - soumission AUTHENTIFIEE : des que `smtp_user` est configure, on passe en
        STARTTLS + login. Obligatoire pour un destinataire EXTERNE (ex. Gmail) :
        l'hote n'est pas dans le `mynetworks` du relais, le port 25 ne relaie
        que le courrier local — une adresse externe y serait refusee.

    `copie_cachee` : une adresse interne mise en Bcc pour laisser une TRACE du
    rapport dans le webmail quand il part vers un destinataire externe.
    """
    c = config()
    dest = destinataire or c["destinataire"]
    if "@" not in dest:
        raise ValueError("adresse destinataire invalide")

    msg = EmailMessage()
    msg["Subject"] = objet or f"SecuBox — frequentation {portee} ({periode})"
    msg["From"] = c["expediteur"]
    msg["To"] = dest
    bcc = c.get("copie_cachee")
    if bcc:
        # send_message honore Bcc dans l'enveloppe puis retire l'en-tete.
        msg["Bcc"] = bcc
    corps = (
        f"{intro or 'Rapport de frequentation SecuBox.'}\n\n"
        f"Portee  : {portee}\n"
        f"Periode : {periode}\n"
        f"Genere  : {datetime.now().strftime('%d/%m/%Y a %H:%M')}\n\n"
        "Le detail est dans la piece jointe.\n"
    )
    # Résumé emoji des codes de retour (#1131an) : 4xx/5xx d'un coup d'œil, avant
    # même d'ouvrir la pièce jointe.
    if resume:
        corps += "\n" + resume
    # NOTE facultative (`[rapport] note = "..."`) : un mot pour le destinataire,
    # joint au rapport. Sert à faire remonter un avis ponctuel (ex. corriger les
    # balises canoniques d'un site) sans ouvrir un autre canal. Vide = rien.
    note = (c.get("note") or "").strip()
    if note:
        corps += "\n— Note —\n" + note + "\n"
    msg.set_content(corps)
    horodatage = datetime.now().strftime("%Y%m%d")
    msg.add_attachment(pdf, maintype="application", subtype="pdf",
                       filename=(nom_fichier or "secubox-frequentation-{date}.pdf").format(date=horodatage))

    # Le scan antivirus du relais peut attendre le réveil du LXC clamav (jusqu'à ~120 s au premier message
    # après un long repos) : la transaction SMTP reste ouverte autant de temps. 20 s coupaient l'envoi
    # (« Connection unexpectedly closed: timed out »), alors que le courrier arrivait quand même.
    with smtplib.SMTP(c["smtp_hote"], int(c["smtp_port"]), timeout=SMTP_DELAI_S) as s:
        user = c.get("smtp_user")
        if user:
            # Le relais interne presente souvent un certificat auto-signe : on
            # chiffre (STARTTLS) sans exiger la chaine — le lien est LAN vers la
            # LXC mail, l'authentification protege deja l'usage du compte.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s.starttls(context=ctx)
            mdp = _lire_secret(c.get("smtp_pass_file"))
            if mdp:
                s.login(user, mdp)
        s.send_message(msg)
    return {"envoye": True, "destinataire": dest, "octets": len(pdf)}
