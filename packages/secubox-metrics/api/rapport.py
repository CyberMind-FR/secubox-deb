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
import smtplib
import tomllib
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use("Agg")            # aucun serveur X ici : backend fichier
import matplotlib.pyplot as plt  # noqa: E402
from fpdf import FPDF            # noqa: E402

CONF = Path("/etc/secubox/metrics.toml")

# Les polices de base de fpdf ne connaissent que latin-1. Les chemins et
# referents viennent des journaux : ils peuvent contenir n'importe quel
# caractere, et un seul suffit a faire echouer tout le rapport.
_SUBST = {
    "\u2014": "-", "\u2013": "-", "\u2019": "'", "\u2018": "'",
    "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00a0": " ",
    "\u2192": "->", "\u00b7": "-",
}


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
    """Visites par jour, sondes empilees dessous."""
    fig, ax = plt.subplots(figsize=(7.2, 2.4))
    jours = [s["jour"][5:] for s in serie]
    visites = [s["visites"] for s in serie]
    sondes = [s.get("sondes", 0) for s in serie]
    ax.bar(jours, visites, color=CYAN, label="Visites", width=.62)
    ax.bar(jours, sondes, bottom=visites, color=ROUGE, label="Sondes", width=.62)
    ax.set_ylabel("visites", fontsize=8, color=GRIS)
    ax.tick_params(labelsize=7, colors=GRIS)
    ax.legend(fontsize=7, frameon=False)
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
    cases = [
        ("Visites", f"{t['visites']:,}".replace(",", " ")),
        ("Visiteurs", f"{t['visiteurs']:,}".replace(",", " ")),
        ("Requetes", f"{t['requetes']:,}".replace(",", " ")),
        ("Sondes", f"{t['sondes']:,}".replace(",", " ")),
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
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(0, 120, 150)
    pdf.cell(0, 7, _txt(texte), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(26, 36, 48)


def construire_pdf(vue: dict, detail: Optional[dict] = None) -> bytes:
    """Assemble le PDF. Bloquant : a lancer dans un thread."""
    pdf = _Page()
    pdf.set_auto_page_break(True, margin=18)
    pdf.alias_nb_pages()
    pdf.add_page()

    portee = detail["vhost"] if detail else "Tous les vhosts"
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, _txt(portee), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(110, 125, 140)
    pdf.cell(0, 5, _txt(f"periode : {vue.get('periode')} - du {vue.get('du')} "
                        f"au {vue.get('au')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    pdf.set_text_color(26, 36, 48)

    source = detail or vue.get("total", {})
    _tuiles(pdf, {k: source.get(k, 0) for k in
                  ("visites", "visiteurs", "requetes", "sondes", "erreurs")})

    if detail and detail.get("serie"):
        _titre(pdf, "Frequentation jour par jour")
        pdf.image(io.BytesIO(_histogramme(detail["serie"])), w=190)
        pdf.ln(3)

    y = pdf.get_y()
    # Les deux graphiques sont poses cote a cote a la meme ordonnee, donc le
    # curseur ne descend pas tout seul. On le replace sous le plus haut des
    # deux — une valeur fixe laissait un grand vide quand ils etaient courts.
    hauteurs = []
    for donnees, titre, x in ((source.get("navigateurs", {}), "Navigateurs", 10),
                              (source.get("plateformes", {}), "Plateformes", 108)):
        info = pdf.image(io.BytesIO(_barres(donnees, titre)), x=x, y=y, w=92)
        hauteurs.append(getattr(info, "rendered_height", 0) or 0)
    pdf.set_y(y + (max(hauteurs) if any(hauteurs) else 55) + 6)

    if detail:
        # Le PDF d'un domaine doit porter TOUT ce que la page web montre.
        # Il lui manquait les codes de retour et les referents, alors que ce
        # sont eux qui disent si le trafic est sain et d'ou il vient.
        membres = detail.get("membres") or []
        if len(membres) > 1:
            _titre(pdf, "Domaines de la famille")
            pdf.set_font("Helvetica", "", 8)
            pdf.multi_cell(190, 5, _txt(" - ".join(membres)))
            pdf.ln(2)

        statuts = detail.get("statuts") or {}
        if statuts:
            _titre(pdf, "Codes de retour")
            pdf.set_font("Helvetica", "", 8)
            total = sum(statuts.values()) or 1
            for code, n in sorted(statuts.items()):
                pdf.cell(30, 5, _txt(code))
                pdf.cell(40, 5, f"{n:,}".replace(",", " "), align="R")
                pdf.cell(30, 5, f"{100 * n / total:.1f} %", align="R",
                         new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

        _titre(pdf, "Pages les plus vues")
        pdf.set_font("Helvetica", "", 8)
        chemins = detail.get("top_chemins") or []
        if not chemins:
            pdf.cell(0, 5, _txt("aucune page enregistree sur la periode"),
                     new_x="LMARGIN", new_y="NEXT")
        for e in chemins[:12]:
            pdf.cell(160, 5, _txt(e["chemin"])[:95])
            pdf.cell(30, 5, f"{e['n']:,}".replace(",", " "), align="R",
                     new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        _titre(pdf, "Referents")
        pdf.set_font("Helvetica", "", 8)
        referents = detail.get("top_referents") or []
        if not referents:
            pdf.cell(0, 5, _txt("aucun referent - trafic direct ou sans en-tete"),
                     new_x="LMARGIN", new_y="NEXT")
        for e in referents[:12]:
            pdf.cell(160, 5, _txt(e["hote"])[:95])
            pdf.cell(30, 5, f"{e['n']:,}".replace(",", " "), align="R",
                     new_x="LMARGIN", new_y="NEXT")
    else:
        _titre(pdf, "Detail par vhost")
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_fill_color(236, 244, 249)
        for l, w in (("Domaine", 66), ("Visites", 24), ("Visiteurs", 24),
                     ("Robots", 22), ("Sondes", 24), ("Erreurs", 30)):
            pdf.cell(w, 6, _txt(l), fill=True, align="L" if w == 66 else "R")
        pdf.ln()
        pdf.set_font("Helvetica", "", 7.5)
        for v in vue.get("vhosts", [])[:40]:
            nom = v["vhost"]
            if v.get("membres") and len(v["membres"]) > 1:
                nom += f"  ({len(v['membres'])} domaines)"
            pdf.cell(66, 5, _txt(nom)[:44])
            for val, w in ((v["visites"], 24), (v["visiteurs"], 24)):
                pdf.cell(w, 5, f"{val:,}".replace(",", " "), align="R")
            pdf.cell(22, 5, f"{v['part_robots']} %", align="R")
            pdf.cell(24, 5, f"{v['sondes']:,}".replace(",", " "), align="R")
            pdf.cell(30, 5, f"{v['erreurs']:,}".replace(",", " "), align="R",
                     new_x="LMARGIN", new_y="NEXT")

    sortie = pdf.output()
    return bytes(sortie)


# ── expedition ───────────────────────────────────────────────────────────
def envoyer(pdf: bytes, destinataire: Optional[str] = None,
            portee: str = "Tous les vhosts", periode: str = "semaine") -> dict:
    """Expedie le PDF par le relais interne. Bloquant : thread obligatoire."""
    c = config()
    dest = destinataire or c["destinataire"]
    if "@" not in dest:
        raise ValueError("adresse destinataire invalide")

    msg = EmailMessage()
    msg["Subject"] = f"SecuBox — frequentation {portee} ({periode})"
    msg["From"] = c["expediteur"]
    msg["To"] = dest
    msg.set_content(
        f"Rapport de frequentation SecuBox.\n\n"
        f"Portee  : {portee}\n"
        f"Periode : {periode}\n"
        f"Genere  : {datetime.now().strftime('%d/%m/%Y a %H:%M')}\n\n"
        "Le detail est dans la piece jointe.\n"
    )
    horodatage = datetime.now().strftime("%Y%m%d")
    msg.add_attachment(pdf, maintype="application", subtype="pdf",
                       filename=f"secubox-frequentation-{horodatage}.pdf")

    with smtplib.SMTP(c["smtp_hote"], int(c["smtp_port"]), timeout=20) as s:
        s.send_message(msg)
    return {"envoye": True, "destinataire": dest, "octets": len(pdf)}
