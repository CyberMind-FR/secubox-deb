#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/pages-erreur.py
"""Pages d'erreur SecuBox : UN modèle (la mire de télévision), UNE table (#3885).

Toutes les pages d'erreur — nginx (secubox-hub), HAProxy (secubox-haproxy),
sbxwaf (secubox-toolbox-ng, livré par secubox-waf-ng) — sortent d'ici. On ne
retouche jamais une page générée à la main : on modifie ce fichier, puis

    python3 scripts/pages-erreur.py            # réécrit les pages
    python3 scripts/pages-erreur.py --verifier # échoue si une page diffère

Bibliothèque standard seule. Aucune ressource externe, aucun JavaScript.
"""
from __future__ import annotations

import argparse
import html
import sys
from dataclasses import dataclass
from pathlib import Path
from string import Template

RACINE = Path(__file__).resolve().parents[1]

# Le dessin validé par le propriétaire (2026-11-23), repris tel quel. Seuls
# changent, d'une page à l'autre, les champs $... ci-dessous.
MODELE = Template("""<!DOCTYPE html>
<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
  Page générée par scripts/pages-erreur.py (#3885) : ne pas modifier à la main.
-->
$marqueur<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
$rafraichir<title>$titre</title>
<style>
:root{--fond:#dfe9f6;--carte:#c9daf0;--trait:#0f1b2d;--doux:#3b4a63}
*{box-sizing:border-box;margin:0}
html,body{height:100%}
body{background:var(--fond);color:var(--trait);font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;display:flex;align-items:center;justify-content:center;padding:16px}
main{width:min(100%,880px);text-align:center}
svg{width:100%;height:auto;display:block}
.titre{font:italic 700 112px Georgia,"Times New Roman",serif;letter-spacing:-2px}
.code{font:700 28px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:2px}
.ligne{font:800 40px "Arial Narrow","Helvetica Neue",Arial,sans-serif;letter-spacing:1px}
.tech{margin-top:14px;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--doux)}
.tech b{color:var(--trait)}
@media (prefers-color-scheme:dark){:root{--fond:#0b1220;--carte:#16233a;--trait:#cfe0f7;--doux:#8aa0bf}}
@media (prefers-reduced-motion:no-preference){.lueur{animation:clignote 2.4s ease-in-out infinite}@keyframes clignote{50%{opacity:.35}}}
</style>
</head>
<body>
<main role="main">
<svg viewBox="0 0 1200 800" role="img" aria-labelledby="t d">
  <title id="t">Désolé ! Nous rencontrons des difficultés techniques</title>
  <desc id="d">Mire de télévision SecuBox. Erreur $code : $phrase_desc.</desc>
  <defs>
    <g id="roue" fill="none" stroke="currentColor">
      <circle r="92" stroke-width="5"/>
      <circle r="20" stroke-width="5"/><circle r="9" fill="currentColor"/>
      <g stroke-width="3">
        <path d="M-88 -6H-24M-88 6H-24M24 -6H88M24 6H88M-6 -88V-24M6 -88V-24M-6 24V88M6 24V88"/>
        <path d="M-80 -14H-26M-80 14H-26M26 -14H80M26 14H80M-14 -80V-26M14 -80V-26M-14 26V80M14 26V80"/>
        <path d="M-58 -58L-40 -40M58 -58L40 -40M-58 58L-40 40M58 58L40 40"/>
      </g>
    </g>
  </defs>
  <g color="var(--trait)" style="color:var(--trait)">
    <rect x="10" y="10" width="1180" height="780" rx="44" fill="var(--carte)" stroke="currentColor" stroke-width="8"/>
    <rect x="34" y="34" width="1132" height="732" rx="24" fill="none" stroke="currentColor" stroke-width="3"/>
    <g stroke="currentColor" stroke-width="2.5" opacity=".75">
      <path d="M34 150H1166M34 300H1166M34 500H1166M34 650H1166"/>
      <path d="M190 34V766M340 34V766M860 34V766M1010 34V766"/>
    </g>
    <use href="#roue" x="190" y="170"/><use href="#roue" x="1010" y="170"/>
    <use href="#roue" x="190" y="630"/><use href="#roue" x="1010" y="630"/>
    <circle cx="600" cy="400" r="350" fill="var(--carte)" stroke="currentColor" stroke-width="5"/>
    <g stroke="currentColor" stroke-width="2.5" opacity=".55">
      <path d="M330 400H870M600 60V160M600 640V740"/>
      <path d="M380 250V330M820 250V330"/>
    </g>
    <!-- le dé SecuBox, à la place de l'ampoule -->
    <circle cx="600" cy="130" r="64" fill="var(--carte)" stroke="currentColor" stroke-width="4"/>
    <g class="lueur" stroke="currentColor" stroke-width="3">
      <path d="M600 52V40M600 220V208M522 130H510M690 130H678M545 75L537 67M655 75L663 67M545 185L537 193M655 185L663 193"/>
    </g>
    <rect x="566" y="96" width="68" height="68" rx="14" fill="var(--fond)" stroke="currentColor" stroke-width="4"/>
    <g fill="currentColor"><circle cx="584" cy="114" r="6"/><circle cx="600" cy="130" r="6"/><circle cx="616" cy="146" r="6"/></g>
    <text x="600" y="345" text-anchor="middle" class="titre" fill="currentColor">Désolé !</text>
    <text x="600" y="430" text-anchor="middle" class="ligne" fill="currentColor">NOUS RENCONTRONS DES</text>
    <text x="600" y="478" text-anchor="middle" class="ligne" fill="currentColor">DIFFICULTÉS TECHNIQUES</text>
    <text x="600" y="540" text-anchor="middle" class="code" fill="currentColor"$taille>$code · $phrase_maj</text>
    <g fill="currentColor">
      <rect x="430" y="570" width="340" height="8"/><rect x="470" y="598" width="260" height="8"/>
      <rect x="505" y="624" width="190" height="7"/><rect x="540" y="648" width="120" height="6"/>
      <rect x="565" y="670" width="70" height="5"/><rect x="585" y="690" width="30" height="4"/>
    </g>
  </g>
</svg>
<p class="tech"><b>$code</b> · $phrase_min. $constat<br>$geste · SecuBox</p>
</main>
</body>
</html>
""")

# Largeur de la ligne « code · phrase » dans la mire. Chasse fixe : une capitale
# vaut ~0,6 em, plus l'espacement de 2 unités. À cette hauteur (y = 540) la
# corde du cercle mesure ~640 unités : au-delà de 570 on réduit la police de
# CETTE ligne (jamais textLength, qui écrase les lettres). Le 502 validé
# (30 signes, ~564) garde ses 28 unités.
TAILLE_CODE = 28
LARGEUR_MAX = 570


def taille_police(texte: str) -> int:
    """Plus grande taille (≤ 28) pour laquelle `texte` tient dans LARGEUR_MAX."""
    n = len(texte)
    taille = TAILLE_CODE
    while taille > 12 and n * (0.6 * taille + 2) > LARGEUR_MAX:
        taille -= 1
    return taille


@dataclass(frozen=True)
class Erreur:
    """Texte d'une erreur. `constat` : ce qui se passe ; `geste` : quoi faire.
    Les deux sont du HTML déjà sûr (écrit ici, jamais une donnée reçue)."""
    code: int
    phrase: str
    constat: str
    geste: str


# Phrases validées par le propriétaire (#3885).
E = {
    "400": Erreur(400, "Requête mal formée",
                  "Le navigateur a envoyé une requête que la box ne sait pas lire.",
                  "Vérifiez l'adresse, puis réessayez."),
    "403": Erreur(403, "Accès refusé",
                  "Vous n'avez pas le droit d'ouvrir cette page.",
                  "Si c'est une erreur, contactez la personne qui gère cette box."),
    "404": Erreur(404, "Cette page n'existe pas",
                  "L'adresse demandée ne correspond à aucune page de cette box.",
                  "Vérifiez le lien, ou repartez de la page d'accueil."),
    "408": Erreur(408, "Requête trop lente",
                  "La requête a mis trop de temps à arriver jusqu'à la box.",
                  "Vérifiez votre connexion, puis réessayez."),
    "421": Erreur(421, "Service non routé",
                  "Ce nom n'est relié à aucun service sur cette box pour l'instant.",
                  "S'il vient d'être créé, attendez la fin de sa mise en place."),
    "500": Erreur(500, "Erreur interne",
                  "Un service de la box a rencontré une erreur en traitant votre demande. L'incident est noté.",
                  "Réessayez dans un instant."),
    "502": Erreur(502, "Le service ne répond pas",
                  "La box est en ligne, mais l'application demandée ne répond pas pour l'instant.",
                  "Réessayez dans un instant."),
    "503": Erreur(503, "Service en préparation",
                  "Le service démarre et n'est pas encore prêt à répondre.",
                  "Réessayez dans un instant."),
    "504": Erreur(504, "Délai dépassé",
                  "L'application demandée a mis trop de temps à répondre.",
                  "Réessayez dans un instant."),
    "waf-avertissement": Erreur(403, "Requête bloquée par le pare-feu",
                                "Votre requête ressemble à une attaque connue (catégorie : <b>{categorie}</b>)."
                                " Elle n'a pas été transmise et l'incident est noté.",
                                "Si cela se répète, votre adresse sera bloquée."
                                " En cas d'erreur, contactez la personne qui gère cette box."),
    "waf-banni": Erreur(403, "Adresse bloquée",
                        "Votre adresse a été bloquée par le pare-feu de cette box après des requêtes suspectes."
                        " L'incident est noté.",
                        "En cas d'erreur, contactez la personne qui gère cette box."),
}


def rafraichi(e: Erreur, secondes: int) -> Erreur:
    """Même erreur, la page se rechargeant seule toutes les `secondes`."""
    return Erreur(e.code, e.phrase, e.constat,
                  f"{e.geste.removesuffix('Réessayez dans un instant.')}"
                  f"Cette page se rafraîchit toute seule toutes les {secondes}&nbsp;secondes.".strip())


def avec_hote(e: Erreur) -> Erreur:
    """Variante sbxwaf : errpages.go remplace {host} (échappé) et {time}."""
    return Erreur(e.code, e.phrase, e.constat + " Hôte : <b>{host}</b>, à {time}.", e.geste)


@dataclass(frozen=True)
class Page:
    chemin: str                    # relatif à la racine du dépôt
    erreur: Erreur
    rafraichir: int = 0            # secondes ; 0 = jamais
    marqueur: str = ""             # commentaire lu par les tests et les journaux
    entetes: tuple[str, ...] = ()  # réponse HTTP brute (HAProxy errorfile)


HUB = "packages/secubox-hub/errorpages"
HAP = "packages/secubox-haproxy/errors"
WAF = "packages/secubox-toolbox-ng/cmd/sbxwaf/templates"

# En-têtes des errorfile HAProxy, repris des fichiers d'avant #3885 (fins de
# ligne LF, sans Content-Length, comme eux).
_NS = "Cache-Control: no-store"
_NC = "Cache-Control: no-store, no-cache, must-revalidate"


def _http(statut: str, cache: str) -> tuple[str, ...]:
    return (f"HTTP/1.1 {statut}", cache, "Connection: close", "Content-Type: text/html; charset=utf-8")


PAGES: tuple[Page, ...] = (
    # nginx (snippets/secubox-errorpages.conf, secubox-errorpages-404.conf)
    Page(f"{HUB}/404.html", E["404"]),
    # Accueil du nom de nœud (secubox-core, vhost généré par secubox-noeud) : tout chemin inconnu du nom public (#3885)
    Page("packages/secubox-core/www/noeud/404.html", E["404"]),
    Page(f"{HUB}/421.html", E["421"]),
    Page(f"{HUB}/500.html", E["500"]),
    Page(f"{HUB}/502.html", E["502"]),
    Page(f"{HUB}/503.html", rafraichi(E["503"], 15), rafraichir=15),
    Page(f"{HUB}/504.html", E["504"]),
    # HAProxy (haproxyctl : errorfile <code> /etc/haproxy/secubox-errors/<code>.http).
    # 502/503/504 se rechargeaient seuls (#626, par JavaScript) : même geste par
    # <meta http-equiv="refresh">.
    Page(f"{HAP}/400.http", E["400"], entetes=_http("400 Bad Request", _NS)),
    Page(f"{HAP}/403.http", E["403"], entetes=_http("403 Forbidden", _NS)),
    Page(f"{HAP}/408.http", E["408"], entetes=_http("408 Request Timeout", _NS)),
    Page(f"{HAP}/500.http", E["500"], entetes=_http("500 Internal Server Error", _NS)),
    Page(f"{HAP}/502.http", rafraichi(E["502"], 15), rafraichir=15, entetes=_http("502 Bad Gateway", _NC)),
    Page(f"{HAP}/503.http", rafraichi(E["503"], 15), rafraichir=15, entetes=_http("503 Service Unavailable", _NC)),
    Page(f"{HAP}/504.http", rafraichi(E["504"], 15), rafraichir=15, entetes=_http("504 Gateway Timeout", _NC)),
    # sbxwaf (errpages.go, go:embed). 502/504 se rechargeaient au bout de 10 s.
    Page(f"{WAF}/error-502.html", avec_hote(rafraichi(E["502"], 10)), rafraichir=10),
    Page(f"{WAF}/error-503.html", avec_hote(E["503"])),
    Page(f"{WAF}/error-504.html", avec_hote(rafraichi(E["504"], 10)), rafraichir=10),
    Page(f"{WAF}/waf-avertissement.html", E["waf-avertissement"], marqueur="<!-- sbxwaf-warning -->\n"),
    Page(f"{WAF}/waf-banni.html", E["waf-banni"], marqueur="<!-- sbxwaf-banned -->\n"),
)


def _texte(s: str) -> str:
    return html.escape(s, quote=False)


def rendre(p: Page) -> str:
    e = p.erreur
    phrase_maj = e.phrase.upper()
    taille = taille_police(f"{e.code} · {phrase_maj}")
    corps = MODELE.substitute(
        marqueur=p.marqueur,
        rafraichir=f'<meta http-equiv="refresh" content="{p.rafraichir}">\n' if p.rafraichir else "",
        titre=_texte(f"{e.code} — {e.phrase} · SecuBox"),
        code=e.code,
        phrase_min=_texte(e.phrase),
        phrase_desc=_texte(e.phrase[:1].lower() + e.phrase[1:]),
        phrase_maj=_texte(phrase_maj),
        taille="" if taille == TAILLE_CODE else f' style="font-size:{taille}px"',
        constat=e.constat,
        geste=e.geste,
    )
    if p.entetes:
        return "\n".join(p.entetes) + "\n\n" + corps
    return corps


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--verifier", action="store_true",
                    help="n'écrit rien ; code 1 si une page du dépôt diffère du modèle")
    ap.add_argument("--racine", type=Path, default=RACINE, help="racine du dépôt (tests)")
    args = ap.parse_args(argv)

    ecarts = []
    for p in PAGES:
        cible = args.racine / p.chemin
        attendu = rendre(p)
        try:
            actuel = cible.read_text(encoding="utf-8")
        except FileNotFoundError:
            actuel = None
        if actuel == attendu:
            continue
        if args.verifier:
            ecarts.append(p.chemin)
            continue
        cible.parent.mkdir(parents=True, exist_ok=True)
        cible.write_text(attendu, encoding="utf-8")
        print(f"écrit {p.chemin} ({len(attendu.encode())} o)")

    if ecarts:
        print("pages d'erreur à régénérer (python3 scripts/pages-erreur.py) :", file=sys.stderr)
        for c in ecarts:
            print(f"  {c}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
