# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: metrics :: rapport quotidien de sécurité (#2299)

Un PDF à trois volets — WAF, Actor Intelligence, DPI — au style des vues du Hall : thème sombre, tuiles, courbes, donuts, carte en points, barres. Il remplace le PDF WAF
seul du service quotidien (mêmes destinataires, `[rapport.waf]`).

RÈGLE DU MODULE : des données RÉELLES seulement. Une source qu'on ne sait pas lire (actord arrêté, résumé DPI absent ou périmé, WAF muet) laisse un « — » et une ligne dans
« Mesures non disponibles » ; jamais un zéro rassurant, jamais un chiffre inventé. Les définitions des chiffres (unité, fenêtre, source) sont écrites sous chaque volet.

Les collecteurs et le constructeur sont séparés : `collecter()` lit, `construire_pdf_securite(data)` met en page (testable sans réseau, sans matplotlib côté données).
"""
from __future__ import annotations

import http.client
import io
import json
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

_ici = str(Path(__file__).resolve().parent)
if _ici not in sys.path:
    sys.path.insert(0, _ici)

ACTOR_SOCK = "/run/secubox/actor.sock"
DPI_RESUME = Path("/var/cache/secubox/dpi/resume-rapport.json")
DPI_PERIME_S = 3 * 3600            # un résumé plus vieux : annoncé périmé, ses chiffres restent lisibles mais datés
WAF_CAMPAGNES = Path("/var/cache/secubox/waf/campaigns.json")
ETATS_MODE = (Path("/var/lib/secubox/waf/campagne-ban-etat.json"), Path("/var/lib/secubox/waf/actor-ban-etat.json"))
FRAICHEUR_MODE_S = 15 * 60

# Palette des vues du Hall (thème sombre).
FOND, PANNEAU, TRAIT = (6, 13, 27), (13, 26, 51), (45, 80, 150)
TEXTE, DOUX, FAIBLE = (234, 241, 255), (159, 179, 214), (111, 132, 168)
CYAN, BLEU, VERT, ROUGE, ORANGE, VIOLET, JAUNE = ((41, 182, 246), (59, 130, 246), (46, 204, 113), (255, 77, 94), (255, 159, 28), (167, 139, 250), (255, 210, 63))
PALETTE = [BLEU, ROUGE, ORANGE, VIOLET, CYAN, VERT, JAUNE, DOUX]


def _hex(c) -> str:
    return "#%02x%02x%02x" % tuple(c)


# ── collecte ──────────────────────────────────────────────────────────────
def _json(chemin: Path) -> Any:
    try:
        return json.loads(Path(chemin).read_text())
    except (OSError, ValueError):
        return None


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, chemin: str, delai: float = 4.0):
        super().__init__("actord", timeout=delai)
        self._chemin = chemin

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._chemin)


def lire_actord(chemin_api: str, sock: str = ACTOR_SOCK) -> Any:
    """Lecture VUE RÉDUITE d'actord (jamais l'en-tête de la vue complète). None si actord ne répond pas."""
    try:
        c = _UnixHTTP(sock)
        c.request("GET", chemin_api, headers={"Accept": "application/json"})
        r = c.getresponse()
        corps = r.read(4 << 20)
        c.close()
        return json.loads(corps) if r.status == 200 else None
    except (OSError, ValueError, http.client.HTTPException):
        return None


def mode_application(etats=ETATS_MODE, now: Optional[float] = None) -> Optional[dict]:
    """Mode global d'application des décisions (même règle que le WAF : PASSIVE_ONLY < SIMULATION < ACTIVE ; un état trop vieux compte comme PASSIVE_ONLY)."""
    now = time.time() if now is None else now
    ordre = {"PASSIVE_ONLY": 0, "SIMULATION": 1, "ACTIVE": 2}
    table = {"propose": "SIMULATION", "auto": "ACTIVE"}
    detail = {}
    lus = 0
    for nom, ch in zip(("campagnes", "acteurs"), etats):
        d = _json(ch)
        if isinstance(d, dict):
            lus += 1
        frais = isinstance(d, dict) and now - float(d.get("genere_le") or 0) <= FRAICHEUR_MODE_S
        detail[nom] = table.get((d or {}).get("mode", ""), "PASSIVE_ONLY") if frais else "PASSIVE_ONLY"
    if not lus:
        return None
    return {"mode": max(detail.values(), key=ordre.get), "detail": detail}


def lire_dpi(chemin: Path = DPI_RESUME, now: Optional[float] = None) -> Optional[dict]:
    r = _json(chemin)
    if not isinstance(r, dict):
        return None
    now = time.time() if now is None else now
    r["age_s"] = max(0, int(now - float(r.get("genere_le") or 0)))
    r["perime"] = r["age_s"] > DPI_PERIME_S
    return r


def collecter() -> dict:
    import rapport as R
    return {
        "genere": datetime.now(),
        "waf": {"hist": R._lire_waf_historique(), "compteurs": R._lire_waf_stats(), "campagnes": _json(WAF_CAMPAGNES)},
        "actor": {"stats": lire_actord("/api/v1/actor/stats"), "overview": lire_actord("/api/v1/actor/overview"), "radar": lire_actord("/api/v1/actor/radar?limit=30"),
                  "mesures": lire_actord("/api/v1/actor/mesures"), "mode": mode_application()},
        "dpi": lire_dpi(),
    }


# ── formats ───────────────────────────────────────────────────────────────
def _txt(v) -> str:
    import rapport as R
    return R._txt(v)


def n(v) -> str:
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


def _num(x) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def gravite_menaces(sev: Optional[dict]) -> Optional[int]:
    """Menaces = gravité moyenne, haute ou critique ; les robots (gravité « info ») n'en sont pas."""
    if not isinstance(sev, dict):
        return None
    return int(_num(sev.get("critical")) + _num(sev.get("high")) + _num(sev.get("medium")))


def seuils_actors(radar: Optional[dict]) -> Optional[dict]:
    """Même barème que le Hall : critique = risque ≥ 70, suspect = 40 à 69, observé = moins de 40 ; sur les acteurs suivis du radar."""
    if not isinstance(radar, dict) or not isinstance(radar.get("acteurs"), list):
        return None
    r = [_num((a.get("risque") or {}).get("valeur")) for a in radar["acteurs"]]
    return {"suivis": len(r), "critiques": sum(v >= 70 for v in r), "suspects": sum(40 <= v < 70 for v in r), "observes": sum(v < 40 for v in r)}


def indisponibles(d: dict) -> list:
    """Les sources absentes, dites telles quelles."""
    m = []
    w, a, p = d.get("waf") or {}, d.get("actor") or {}, d.get("dpi")
    if not (w.get("hist") or {}).get("jours"):
        m.append("WAF : historique des menaces")
    if not w.get("compteurs"):
        m.append("WAF : compteurs du jour")
    for cle, lib in (("stats", "compteurs"), ("overview", "vue d'ensemble"), ("radar", "radar"), ("mesures", "mesures en cours")):
        if a.get(cle) is None:
            m.append(f"Actor Intelligence : {lib}")
    if a.get("mode") is None:
        m.append("Actor Intelligence : mode d'application des décisions")
    if p is None:
        m.append("DPI : résumé (secubox-dpi-resume.timer)")
    elif p.get("perime"):
        m.append(f"DPI : résumé périmé ({p.get('age_s', 0) // 3600} h)")
    return m


# ── mise en page (fpdf2) ──────────────────────────────────────────────────
def _classe_page():
    import rapport as R

    class Page(R.FPDF):
        titre_doc = "SecuBox — rapport quotidien de sécurité"

        def header(self):
            self.set_fill_color(*FOND)
            self.rect(0, 0, 210, 297, "F")
            self.set_xy(10, 7)
            self.set_font("Helvetica", "B", 8.5)
            self.set_text_color(*CYAN)
            self.cell(120, 5, R._txt(self.titre_doc))
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
            self.cell(0, 5, _txt(f"SecuBox — données réelles seulement · page {self.page_no()}/{{nb}}"), align="C")
    return Page


def _panneau(pdf, x, y, w, h, titre="", sous=""):
    pdf.set_fill_color(*PANNEAU)
    pdf.set_draw_color(*TRAIT)
    pdf.rect(x, y, w, h, "DF")
    if titre:
        pdf.set_xy(x + 3, y + 2)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*TEXTE)
        pdf.cell(w - 6, 5, _txt(titre))
        if sous:
            pdf.set_xy(x + 3, y + 2)
            pdf.set_font("Helvetica", "", 6.5)
            pdf.set_text_color(*FAIBLE)
            pdf.cell(w - 6, 5, _txt(sous), align="R")


def _tuile(pdf, x, y, w, libelle, valeur, sous="", accent=CYAN, h=19):
    pdf.set_fill_color(*PANNEAU)
    pdf.set_draw_color(*accent)
    pdf.rect(x, y, w, h, "DF")
    pdf.set_fill_color(*accent)
    pdf.rect(x, y, 1.2, h, "F")
    pdf.set_xy(x + 3.5, y + 2)
    pdf.set_font("Helvetica", "", 6.8)
    pdf.set_text_color(*DOUX)
    pdf.cell(w - 5, 4, _txt(libelle.upper()))
    pdf.set_xy(x + 3.5, y + 6.2)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*TEXTE)
    pdf.cell(w - 5, 7, _txt(valeur))
    if sous:
        pdf.set_xy(x + 3.5, y + 13.6)
        pdf.set_font("Helvetica", "", 6.3)
        pdf.set_text_color(*FAIBLE)
        pdf.cell(w - 5, 4, _txt(sous))


def _rangee_tuiles(pdf, y, cases):
    w = (190 - 3 * (len(cases) - 1)) / len(cases)
    for i, c in enumerate(cases):
        _tuile(pdf, 10 + i * (w + 3), y, w, *c)
    return y + 22


def _titre_volet(pdf, y, texte, sous=""):
    pdf.set_xy(10, y)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*TEXTE)
    pdf.cell(0, 7, _txt(texte), new_x="LMARGIN", new_y="NEXT")
    if sous:
        pdf.set_x(10)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*FAIBLE)
        pdf.multi_cell(190, 3.8, _txt(sous), new_x="LMARGIN", new_y="NEXT")
    return pdf.get_y() + 2


def _court(libelle, largeur_mm: float) -> str:
    """Un libellé de catégorie lisible et qui tient dans sa colonne (« host_anomaly:unrouted » -> « hote unrouted »)."""
    t = str(libelle if libelle is not None else "?").replace("host_anomaly:", "hote ").replace("auth_smtp:sasl_failed", "smtp echec").replace("auth_gitea:ssh_failed", "ssh echec").replace(":", " ").replace("_", " ")
    m = max(6, int(largeur_mm / 1.7))
    return t if len(t) <= m else t[:m - 1] + "."


def _barres(pdf, x, y, w, lignes, fmt=n, couleur=None, pas=6.2, max_l=8):
    """Barres horizontales : (libellé, valeur[, couleur]). Rend le y suivant."""
    lignes = [l for l in lignes if l[1] is not None][:max_l]
    if not lignes:
        pdf.set_xy(x, y)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*FAIBLE)
        pdf.cell(w, 5, _txt("— aucune donnée —"))
        return y + 7
    fort = max(_num(l[1]) for l in lignes) or 1
    lw, vw = w * 0.40, w * 0.22
    bw = w - lw - vw - 2
    for i, l in enumerate(lignes):
        c = l[2] if len(l) > 2 else (couleur or PALETTE[i % len(PALETTE)])
        pdf.set_xy(x, y)
        pdf.set_font("Helvetica", "", 7.3)
        pdf.set_text_color(*TEXTE)
        pdf.cell(lw, 4.4, _txt(_court(l[0], lw)))
        pdf.set_fill_color(40, 58, 96)
        pdf.rect(x + lw, y + 0.9, bw, 2.6, "F")
        pdf.set_fill_color(*c)
        pdf.rect(x + lw, y + 0.9, max(0.6, bw * _num(l[1]) / fort), 2.6, "F")
        pdf.set_xy(x + lw + bw + 1, y)
        pdf.set_text_color(*DOUX)
        pdf.cell(vw, 4.4, _txt(fmt(l[1])), align="R")
        y += pas
    return y


def _image(pdf, png: bytes, x, y, w):
    pdf.image(io.BytesIO(png), x=x, y=y, w=w)


def _fig_sombre(figsize):
    import rapport as R
    fig, ax = R.plt.subplots(figsize=figsize)
    fig.patch.set_facecolor(_hex(PANNEAU))
    ax.set_facecolor(_hex(PANNEAU))
    ax.tick_params(labelsize=7, colors=_hex(DOUX))
    for bord in ax.spines.values():
        bord.set_visible(False)
    ax.grid(axis="y", color="#9fb3d6", alpha=.14)
    return fig, ax


def _png(fig) -> bytes:
    import rapport as R
    t = io.BytesIO()
    fig.savefig(t, format="png", dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    R.plt.close(fig)
    return t.getvalue()


def graphe_courbes(series: list, etiquettes: list) -> bytes:
    """Courbes pleines : [(nom, valeurs, couleur)]."""
    fig, ax = _fig_sombre((8.6, 1.9))
    x = range(len(etiquettes))
    for nom, vals, c in series:
        ax.plot(x, vals, color=_hex(c), lw=1.8, label=nom)
        ax.fill_between(x, vals, color=_hex(c), alpha=.13)
    ax.set_xticks(list(x))
    ax.set_xticklabels(etiquettes, rotation=0, color=_hex(DOUX), fontsize=6.5)
    ax.set_ylim(bottom=0)
    ax.legend(fontsize=6.5, frameon=False, labelcolor=_hex(DOUX), loc="upper left", ncol=len(series))
    return _png(fig)


def graphe_heures(vals: list) -> bytes:
    fig, ax = _fig_sombre((7.4, 2.2))
    ax.bar(range(len(vals)), vals, color=_hex(CYAN), width=.7)
    ax.set_xticks(range(0, len(vals), 3))
    ax.set_xticklabels([f"{h:02d}h" for h in range(0, len(vals), 3)], color=_hex(DOUX), fontsize=6.5)
    return _png(fig)


def graphe_donut(parts: list, centre: str) -> bytes:
    """parts : [(nom, valeur)]. Anneau sans légende (la légende est en barres à côté)."""
    fig, ax = _fig_sombre((2.6, 2.6))
    ax.grid(False)
    vals = [max(0.0, _num(v)) for _, v in parts]
    if sum(vals) <= 0:
        ax.text(0.5, 0.5, "—", ha="center", va="center", color=_hex(DOUX), fontsize=16, transform=ax.transAxes)
    else:
        ax.pie(vals, colors=[_hex(PALETTE[i % len(PALETTE)]) for i in range(len(vals))], startangle=90, counterclock=False, wedgeprops={"width": .38, "edgecolor": _hex(PANNEAU), "linewidth": 1.2})
        ax.text(0, 0, centre, ha="center", va="center", color=_hex(TEXTE), fontsize=9, fontweight="bold")
    return _png(fig)


def graphe_carte(pays: dict) -> bytes:
    import carte_monde as cm
    fig, ax = _fig_sombre((7.6, 3.4))
    ax.grid(False)
    pts = cm.points_terre()
    ax.scatter([x for x, _ in pts], [y for _, y in pts], s=3.4, c="#33507f", linewidths=0)
    b = cm.bulles(pays or {})
    if b:
        ax.scatter([e[1] for e in b], [e[2] for e in b], s=[(e[3] * 6.0) ** 2 for e in b], c=_hex(ROUGE), alpha=.5, edgecolors="none")
        for code, x, y, r in b[:6]:
            ax.annotate(code, (x, y), ha="center", va="center", fontsize=6, color="white", fontweight="bold")
    else:
        ax.text(60, 30, "aucun pays identifié", ha="center", va="center", fontsize=9, color=_hex(DOUX))
    ax.set_xlim(0, 120)
    ax.set_ylim(60, 0)
    ax.set_aspect("equal")
    ax.axis("off")
    return _png(fig)


# ── volets ────────────────────────────────────────────────────────────────
def _synthese(pdf, d: dict) -> None:
    w, a, p = d.get("waf") or {}, d.get("actor") or {}, d.get("dpi")
    c = w.get("compteurs") or {}
    st, ov, rd = a.get("stats"), a.get("overview"), a.get("radar")
    sa = seuils_actors(rd)
    pdf.set_xy(10, 20)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*TEXTE)
    pdf.cell(0, 10, _txt("Rapport quotidien de sécurité"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(10)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*CYAN)
    pdf.cell(0, 6, _txt("WAF · Actor Intelligence · DPI"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(10)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*FAIBLE)
    pdf.cell(0, 5, _txt(f"Généré le {d['genere'].strftime('%d/%m/%Y à %H:%M')} · données lues sur la box, rien d'estimé"), new_x="LMARGIN", new_y="NEXT")
    y = 44
    y = _rangee_tuiles(pdf, y, [
        ("WAF · requêtes analysées", n((c.get("par_origine") or {}).get("waf")) if c.get("par_origine") else "—", "aujourd'hui", BLEU),
        ("WAF · bloquées", n(c.get("blocked_24h")) if "blocked_24h" in c else "—", "24 h", ROUGE),
        ("WAF · menaces", n(gravite_menaces(c.get("by_severity"))), "gravité moyenne et plus", VIOLET),
        ("WAF · robots connus", n((c.get("by_category") or {}).get("robots")) if c.get("by_category") else "—", "aujourd'hui", CYAN)])
    y = _rangee_tuiles(pdf, y, [
        ("Actor · acteurs", n((st or {}).get("actors")), "uniques, au total", BLEU),
        ("Actor · campagnes", n((st or {}).get("campaigns")), "actives", ORANGE),
        ("Actor · critiques", n((sa or {}).get("critiques")), "risque >= 70 (radar)", ROUGE),
        ("Actor · mode", (a.get("mode") or {}).get("mode", "—").replace("_ONLY", ""), "application des décisions", VERT)])
    ds = (p or {}).get("stats") or {}
    y = _rangee_tuiles(pdf, y, [
        ("DPI · trafic analysé", octets(ds.get("octets")), "cumul du moteur", CYAN),
        ("DPI · flux", n(ds.get("flux")), "cumul du moteur", BLEU),
        ("DPI · appareils", n((p or {}).get("appareils_total")), "vus par le moteur", VERT),
        ("DPI · pays contactés", n(len((p or {}).get("pays") or []) or None), "destinations", ORANGE)])
    y += 2
    lignes = []
    tv = (c.get("top_vhosts") or [])
    if tv:
        lignes.append(f"Site le plus visé par le WAF : {tv[0].get('vhost')} ({n(tv[0].get('count'))} événements).")
    if sa:
        lignes.append(f"Actor Intelligence suit {n(sa['suivis'])} acteurs au radar : {sa['critiques']} critiques, {sa['suspects']} suspects, {sa['observes']} observés.")
    ms = (a.get("mesures") or {}).get("par_niveau")
    if isinstance(ms, dict):
        lignes.append("Mesures en cours : " + ", ".join(f"{k} {n(v)}" for k, v in ms.items() if v) + "." if any(ms.values()) else "Aucune mesure d'atténuation en cours.")
    if (p or {}).get("suggestions"):
        lignes.append(f"DPI : {len(p['suggestions'])} domaines à classer (suggestions du moteur, pas des menaces).")
    lignes = lignes or ["Aucune ligne deductible : les sources sont muettes (voir ci-dessous)."]
    hauteur = 12 + 5.6 * len(lignes)
    _panneau(pdf, 10, y, 190, hauteur, "À regarder aujourd'hui", "lignes déduites des mesures ci-dessous")
    pdf.set_xy(13, y + 9)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*TEXTE)
    for l in (lignes or ["Aucune ligne déductible : les sources sont muettes (voir ci-dessous)."]):
        pdf.set_x(13)
        pdf.multi_cell(184, 5, _txt("-  " + l), new_x="LMARGIN", new_y="NEXT")
    manque = indisponibles(d)
    y2 = y + hauteur + 4
    _panneau(pdf, 10, y2, 190, 12 + 5 * max(1, len(manque)), "Mesures non disponibles", "dites telles quelles, jamais comblées")
    pdf.set_xy(13, y2 + 9)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*(ORANGE if manque else VERT))
    for l in (manque or ["Toutes les sources ont répondu."]):
        pdf.set_x(13)
        pdf.cell(184, 5, _txt("-  " + l), new_x="LMARGIN", new_y="NEXT")
    y3 = y2 + 12 + 5 * max(1, len(manque)) + 4
    defs = [("Requêtes analysées, robots", "compteurs du WAF depuis minuit ; un robot reconnu n'est pas une menace."),
            ("Menaces, bloquées", "gravité moyenne, haute ou critique ; bloquées = ban ou blocage sur 24 h, une requête comptée une fois."),
            ("Risque / confiance", "risque = gravité si l'hypothèse est vraie ; confiance = solidité des preuves. Deux mesures séparées."),
            ("Acteurs", "regroupent des adresses, une empreinte, des cibles : corrélation, pas attribution."),
            ("DPI", "cumul du moteur depuis son démarrage, métadonnées seulement ; ne mesure ni menaces ni blocages.")]
    _panneau(pdf, 10, y3, 190, 12 + 8.2 * len(defs), "Définitions", "unité, fenêtre, source")
    yy = y3 + 9
    for k, v in defs:
        pdf.set_xy(13, yy)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*CYAN)
        pdf.cell(40, 4, _txt(k))
        pdf.set_font("Helvetica", "", 7.3)
        pdf.set_text_color(*DOUX)
        pdf.multi_cell(144, 3.8, _txt(v), new_x="LMARGIN", new_y="NEXT")
        yy = max(yy + 7.6, pdf.get_y() + 1)


def _volet_waf(pdf, d: dict) -> None:
    pdf.add_page()
    w = d.get("waf") or {}
    c, hist, camps = w.get("compteurs") or {}, w.get("hist") or {}, w.get("campagnes") or {}
    y = _titre_volet(pdf, 18, "WAF — pare-feu applicatif", "Menaces vues par sbxwaf. Requêtes analysées et robots : compteurs du jour ; courbes : historique par jour des journaux (rétention) ; gravité « info » = robots.")
    jours = sorted((hist.get("jours") or {}).keys())[-14:]
    _panneau(pdf, 10, y, 190, 54, "Évolution par jour", "événements · menaces · bloquées (haute et critique)")
    if len(jours) >= 2:
        tot = [_num(hist["jours"][j].get("total")) for j in jours]
        sv = [hist["jours"][j].get("severites") or {} for j in jours]
        men = [_num(s.get("critical")) + _num(s.get("high")) + _num(s.get("medium")) for s in sv]
        blo = [_num(s.get("critical")) + _num(s.get("high")) for s in sv]
        _image(pdf, graphe_courbes([("Événements", tot, CYAN), ("Menaces", men, VIOLET), ("Bloquées", blo, ROUGE)], [j[5:] for j in jours]), 14, y + 9, 176)
    else:
        pdf.set_xy(13, y + 25)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*FAIBLE)
        pdf.cell(0, 5, _txt("— historique insuffisant (moins de deux jours) —"))
    y += 58
    bc = {k: v for k, v in (c.get("by_category") or {}).items() if k != "robots"}
    cats = sorted(bc.items(), key=lambda kv: -_num(kv[1]))
    top = cats[:6]
    reste = sum(_num(v) for _, v in cats[6:])
    if reste:
        top.append(("autres", reste))
    tot = sum(_num(v) for _, v in top)
    _panneau(pdf, 10, y, 92, 60, "Répartition par catégorie d'attaque", "aujourd'hui, hors robots")
    _image(pdf, graphe_donut(top, n(tot) if tot else "—"), 12, y + 9, 36)
    _barres(pdf, 50, y + 12, 50, [(k, v) for k, v in top], fmt=lambda v: f"{100 * _num(v) / tot:.0f}%" if tot else "—", pas=6.6, max_l=7)
    _panneau(pdf, 108, y, 92, 60, "Carte des attaques", "pays déduit de l'adresse")
    pays = c.get("pays") or {}
    _image(pdf, graphe_carte(pays), 110, y + 9, 88)
    y += 64
    _panneau(pdf, 10, y, 92, 52, "Sites les plus visés", "événements, aujourd'hui")
    _barres(pdf, 13, y + 10, 86, [(v.get("vhost"), v.get("count")) for v in (c.get("top_vhosts") or [])], couleur=CYAN)
    _panneau(pdf, 108, y, 92, 52, "Acteurs persistants", "adresses, sur la rétention des journaux")
    ti = {k: v for k, v in (hist.get("top_ips") or {}).items() if k != "local"}
    _barres(pdf, 111, y + 10, 86, sorted(ti.items(), key=lambda kv: -_num(kv[1])), couleur=ROUGE)
    y += 56
    _panneau(pdf, 10, y, 190, 38, "Empreintes de campagnes", "attaques au même mode opératoire")
    cl = (camps.get("campagnes") or [])[:5] if isinstance(camps, dict) else []
    _barres(pdf, 13, y + 10, 184, [(f"{str(x.get('signature'))[:8]}  {x.get('outil') or ''}", x.get("sondes")) for x in cl], fmt=lambda v: f"{n(v)} sondes", couleur=ORANGE, max_l=5)


def _volet_actor(pdf, d: dict) -> None:
    pdf.add_page()
    a = d.get("actor") or {}
    st, ov, rd, ms, mo = a.get("stats"), a.get("overview"), a.get("radar"), a.get("mesures"), a.get("mode")
    y = _titre_volet(pdf, 18, "Actor Intelligence — acteurs et décisions", "Le RISQUE (gravité si l'hypothèse est vraie) et la CONFIANCE (solidité des preuves) sont deux mesures séparées. Corrélation, pas attribution : un acteur peut regrouper plusieurs adresses.")
    sa = seuils_actors(rd)
    y = _rangee_tuiles(pdf, y, [
        ("Événements analysés", n((st or {}).get("events_24h")), "24 h", CYAN),
        ("Tentatives", n((st or {}).get("attempts_24h")), "hostiles non bloquées, 24 h", ORANGE),
        ("Bloquées", n((st or {}).get("blocked_24h")), "24 h", ROUGE),
        ("Posture", str((st or {}).get("posture") or "—"), f"analyse : {(st or {}).get('mode', '—')}", VERT)])
    _panneau(pdf, 10, y, 92, 58, "Activité des événements", "par heure, 24 h")
    act = (ov or {}).get("activite_24h")
    if isinstance(act, list) and len(act) >= 2:
        _image(pdf, graphe_heures([_num(v) for v in act]), 12, y + 9, 88)
    else:
        pdf.set_xy(13, y + 25)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*FAIBLE)
        pdf.cell(80, 5, _txt("— indisponible —"))
    _panneau(pdf, 108, y, 92, 58, "Pays d'origine", "événements bruts, robots exclus")
    _image(pdf, graphe_carte({p.get("code"): p.get("n") for p in ((ov or {}).get("top_pays") or [])}), 110, y + 9, 88)
    y += 62
    _panneau(pdf, 10, y, 190, 70, "Acteurs principaux", "risque et confiance, séparés")
    ac = (rd or {}).get("acteurs") or []
    pdf.set_xy(13, y + 9)
    pdf.set_font("Helvetica", "B", 6.8)
    pdf.set_text_color(*FAIBLE)
    for t, lw in (("ACTEUR", 30), ("NIVEAU", 24), ("RISQUE", 62), ("CONFIANCE", 62)):
        pdf.cell(lw, 4, t)
    yy = y + 14
    for x in ac[:8]:
        r, c = _num((x.get("risque") or {}).get("valeur")), _num((x.get("confiance") or {}).get("valeur"))
        pdf.set_xy(13, yy)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*CYAN)
        pdf.cell(30, 5, _txt(x.get("id")))
        pdf.set_font("Helvetica", "", 7.3)
        pdf.set_text_color(*TEXTE)
        pdf.cell(24, 5, _txt(x.get("niveau")))
        for val, col, xo in ((r, ROUGE if r >= 70 else ORANGE if r >= 40 else VERT, 67), (c, BLEU, 129)):
            pdf.set_fill_color(40, 58, 96)
            pdf.rect(xo, yy + 1.2, 48, 2.6, "F")
            pdf.set_fill_color(*col)
            pdf.rect(xo, yy + 1.2, max(.6, 48 * val / 100), 2.6, "F")
            pdf.set_xy(xo + 49, yy)
            pdf.set_text_color(*DOUX)
            pdf.cell(10, 5, _txt(n(val)))
        yy += 6.2
    if not ac:
        pdf.set_xy(13, yy)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*FAIBLE)
        pdf.cell(80, 5, _txt("— radar indisponible —"))
    y += 74
    T: dict = {}
    for liste in ((ov or {}).get("techniques") or {}).values():
        for t in liste:
            T[t.get("nom")] = T.get(t.get("nom"), 0) + _num(t.get("n"))
    _panneau(pdf, 10, y, 92, 50, "Techniques observées", "occurrences")
    _barres(pdf, 13, y + 10, 86, sorted(T.items(), key=lambda kv: -kv[1]), couleur=ORANGE, max_l=6)
    _panneau(pdf, 108, y, 92, 50, "Mesures en cours", "échelle de réponse, acteurs sous mesure")
    pn = (ms or {}).get("par_niveau")
    _barres(pdf, 111, y + 10, 86, [(k, pn.get(k)) for k in ("DELAY", "CHALLENGE", "TARPIT", "DENY", "QUARANTINE")] if isinstance(pn, dict) else [], couleur=VIOLET, max_l=5)
    pdf.set_xy(111, y + 43)
    pdf.set_font("Helvetica", "", 6.8)
    pdf.set_text_color(*DOUX)
    det = (mo or {}).get("detail") or {}
    pdf.multi_cell(86, 3.4, _txt(("Mode d'application : " + mo["mode"] + f" (campagnes : {det.get('campagnes')}, acteurs : {det.get('acteurs')}). ACTIVE = mesures graduées et bans temporaires réversibles.") if mo else "Mode d'application : indisponible."))
    y += 54
    rob = (ov or {}).get("robots") or []
    _panneau(pdf, 10, y, 190, 28, "Robots connus", "familles reconnues — du contexte, pas un verdict")
    _barres(pdf, 13, y + 9, 184, [(r.get("famille"), r.get("hits")) for r in rob], fmt=lambda v: f"{n(v)} requêtes", couleur=CYAN, max_l=3, pas=5.6)


def _volet_dpi(pdf, d: dict) -> None:
    pdf.add_page()
    p = d.get("dpi")
    age = "" if not p else f" Résumé du {datetime.fromtimestamp(p.get('genere_le') or 0).strftime('%d/%m/%Y %H:%M')}" + (" — PÉRIMÉ" if p.get("perime") else "") + "."
    y = _titre_volet(pdf, 18, "DPI — votre trafic réseau", "Analyse des métadonnées seulement, aucun contenu lu. Trafic et flux : cumul du moteur depuis son démarrage (pas une fenêtre de 24 h). Menaces et blocages : voir le WAF et Actor Intelligence." + age)
    if not p:
        _panneau(pdf, 10, y, 190, 24, "Résumé DPI indisponible")
        pdf.set_xy(13, y + 10)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*ORANGE)
        pdf.multi_cell(184, 5, _txt("Le résumé produit par secubox-dpi-resume.timer est absent : aucune mesure DPI n'est affichée, et aucune n'est estimée."))
        return
    s = p.get("stats") or {}
    y = _rangee_tuiles(pdf, y, [
        ("Trafic analysé", octets(s.get("octets")), "cumul du moteur", CYAN),
        ("Connexions (flux)", n(s.get("flux")), "cumul du moteur", BLEU),
        ("Protocoles", n(len(s.get("protocoles") or []) or None), "détectés", VIOLET),
        ("Appareils actifs", n(p.get("appareils_total")), "vus par le moteur", VERT)])
    _panneau(pdf, 10, y, 92, 60, "Types de trafic", "par volume")
    us = p.get("usages") or []
    tot = sum(_num(u.get("octets")) for u in us)
    _image(pdf, graphe_donut([(u.get("nom"), u.get("octets")) for u in us], octets(tot) if tot else "—"), 12, y + 9, 36)
    _barres(pdf, 50, y + 12, 50, [(u.get("nom"), u.get("octets")) for u in us], fmt=lambda v: f"{100 * _num(v) / tot:.0f}%" if tot else "—", pas=6.6, max_l=7)
    _panneau(pdf, 108, y, 92, 60, "Protocoles détectés", "part du volume")
    _barres(pdf, 111, y + 11, 86, [(x.get("nom"), x.get("pct")) for x in (s.get("protocoles") or [])], fmt=lambda v: f"{_num(v):.1f}%", pas=6.6, max_l=7)
    y += 64
    _panneau(pdf, 10, y, 92, 60, "Appareils les plus actifs", "par volume")
    _barres(pdf, 13, y + 11, 86, [(a.get("nom"), a.get("octets")) for a in (p.get("appareils") or [])], fmt=octets, couleur=BLEU, pas=6.6, max_l=7)
    _panneau(pdf, 108, y, 92, 60, "Destinations par pays", "par volume")
    _barres(pdf, 111, y + 11, 86, [(x.get("cc"), x.get("octets")) for x in (p.get("pays") or [])], fmt=octets, couleur=VERT, pas=6.6, max_l=7)
    y += 64
    D: dict = {}
    for a in (p.get("appareils") or []):
        for dd in a.get("destinations") or []:
            D[dd.get("hote")] = D.get(dd.get("hote"), 0) + _num(dd.get("octets"))
    _panneau(pdf, 10, y, 92, 52, "Destinations les plus contactées", "par volume")
    _barres(pdf, 13, y + 10, 86, sorted(D.items(), key=lambda kv: -kv[1]), fmt=octets, couleur=CYAN, max_l=6)
    _panneau(pdf, 108, y, 92, 52, "Domaines à classer", "pas des menaces")
    _barres(pdf, 111, y + 10, 86, [(x.get("domaine"), x.get("octets")) for x in (p.get("suggestions") or [])], fmt=octets, couleur=JAUNE, max_l=6)


def construire_pdf_securite(data: dict) -> bytes:
    """Le PDF complet (A4, 4 pages : synthèse, WAF, Actor Intelligence, DPI)."""
    pdf = _classe_page()()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(False)
    pdf.add_page()
    _synthese(pdf, data)
    _volet_waf(pdf, data)
    _volet_actor(pdf, data)
    _volet_dpi(pdf, data)
    return bytes(pdf.output())


def executer_securite(collecter_: Callable[[], dict], construire: Callable[[dict], bytes], envoyer: Callable[..., dict], cfg: dict) -> dict:
    """Collecte, met en page, expédie. Rien si aucun destinataire ; rien si AUCUNE source n'a répondu (un rapport vide n'a pas de sens)."""
    if not cfg.get("destinataire"):
        return {"envoye": False, "raison": "aucun destinataire configuré ([rapport.waf])"}
    d = collecter_()
    if len(indisponibles(d)) >= 8:
        return {"envoye": False, "raison": "aucune source n'a répondu"}
    pdf = construire(d)
    return envoyer(pdf, cfg["destinataire"], "Sécurité : WAF, Actor Intelligence, DPI", cfg.get("periode", "quotidien"),
                   objet="SecuBox — rapport quotidien de sécurité (WAF, Actor Intelligence, DPI)", nom_fichier="secubox-securite-{date}.pdf",
                   intro="Rapport quotidien de sécurité SecuBox : WAF, Actor Intelligence et DPI.")
