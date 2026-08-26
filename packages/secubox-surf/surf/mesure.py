# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Surf — le harnais de mesure
CyberMind — https://cybermind.fr

CE N'EST PAS LE PROXY. C'est ce qui DÉCIDE s'il vaut la peine d'exister.

Le §0bis demande trois mesures : un site statique, un site applicatif, un SaaS
hostile. Ce harnais en réalise UNE, à la demande : il va chercher la page,
applique les transformations du relais, et rend un rapport de ce qui a été
réécrit et de ce qui a cassé — sans monter aucune origine publique, sans
toucher la production. On sait où est le mur avant de construire le mur.

    python3 -m surf.mesure https://www.facebook.com/
    python3 -m surf.mesure --egress tor https://check.torproject.org/
    python3 -m surf.mesure <adresse>.onion        # Tor implicite

Le verdict est volontairement sévère : un `fetch()` en dur suffit à classer
« MUR », parce qu'en pratique il suffit à rendre le site inutilisable relayé.
"""

from __future__ import annotations

import sys
import json
import argparse

from . import relais
from . import egress


def mesure(url: str, mode: str = "auto") -> relais.Rapport:
    p = relais.urlsplit(url if "://" in url else "https://" + url)
    hote = p.hostname or ""
    base = relais.urlunsplit((p.scheme or "https", p.netloc, p.path or "/", "", ""))
    rap = relais.Rapport(cible=hote, egress=("tor" if egress._onion(hote)
                                             or mode == "tor" else "direct"))

    # `sur_hote` : ce que la réécriture fait de chaque hôte tiers rencontré.
    # On note au passage tous les tiers — un site qui en tire de trente
    # domaines est un site qu'on relaie trente fois ou pas du tout.
    tiers: set[str] = set()
    pisteurs: set[str] = set()

    def sur_hote(h: str):
        if relais.est_pisteur(h):
            pisteurs.add(h)
            return None            # bloqué : pas d'origine, un filtre le coupe
        if h != hote:
            tiers.add(h)
        return relais.origine_de(h)

    try:
        with egress.client_pour(hote, mode) as cli:
            r = cli.get(base)
    except Exception as e:   # noqa: BLE001 — un POC rapporte tout, y compris l'échec réseau
        rap.note("reseau", "bloquant",
                 "la box n'a pas pu joindre la cible (%s: %s). En Tor, vérifier "
                 "que le service tourne." % (type(e).__name__, e))
        return rap

    rap.statut = r.status_code
    rap.type_contenu = r.headers.get("content-type", "")

    # Les en-têtes d'abord : c'est là que se lisent CSP, cookies, redirections.
    relais.reecris_entetes(dict(r.headers), base, rap, sur_hote)

    # Le corps, selon sa nature.
    ct = rap.type_contenu.lower()
    if "text/html" in ct:
        relais.reecris_html(r.text, base, rap, sur_hote)
    elif "css" in ct:
        relais.reecris_css(r.text, base, rap, sur_hote)
    elif "javascript" in ct or "json" in ct:
        relais._recense_js(r.text, rap, ou="ressource-js")

    # Les murs propres aux SaaS hostiles, lus dans la réponse.
    _mesure_hostilite(r, rap)

    if len(tiers) > 12:
        rap.note("tiers", "degrade",
                 "%d domaines tiers référencés : chacun exige sa propre origine "
                 "relayée. Au-delà d'une poignée, le coût de mise en place "
                 "dépasse le bénéfice." % len(tiers))
    if pisteurs:
        rap.note("pisteurs", "note",
                 "%d pisteurs connus coupés à la source : %s" %
                 (len(pisteurs), ", ".join(sorted(pisteurs)[:6])))
    rap._tiers = sorted(tiers)          # type: ignore[attr-defined]
    rap._pisteurs = sorted(pisteurs)    # type: ignore[attr-defined]
    return rap


def _mesure_hostilite(r, rap: relais.Rapport):
    """Ce qu'un gros SaaS oppose spécifiquement à un proxy."""
    corps = r.text if "text" in r.headers.get("content-type", "") else ""

    if r.status_code in (301, 302, 303, 307, 308):
        loc = r.headers.get("location", "")
        rap.note("redirection", "note",
                 "redirige d'emblée (%d → %s). Souvent une porte de login ou de "
                 "détection : la page utile est ailleurs." % (r.status_code, loc))

    marqueurs = {
        "checkpoint": "mur anti-robot / checkpoint de connexion",
        "captcha": "captcha",
        "not supported": "navigateur déclaré non supporté",
        "enable javascript": "exige JavaScript pour tout rendu",
        "__d(": "modules chiffrés façon Facebook (bootload __d)",
        "DTSGInitialData": "jeton anti-CSRF Facebook lié à l'origine",
        "LSD": "jeton de session lié à l'origine",
    }
    bas = corps.lower()
    for aiguille, sens in marqueurs.items():
        if aiguille.lower() in bas:
            rap.note("hostilite", "bloquant" if aiguille in ("__d(", "checkpoint")
                     else "degrade", sens)

    if "text/html" in r.headers.get("content-type", "") and len(corps) < 4000 \
            and "<script" in bas:
        rap.note("coquille-js", "bloquant",
                 "la page HTML est une coquille quasi vide qui monte tout en "
                 "JavaScript (%d octets). Rien à réécrire statiquement : tout se "
                 "joue à l'exécution, hors de portée du relais." % len(corps))


def imprime(rap: relais.Rapport):
    L = "─" * 66
    print(L)
    print(f"  MESURE SURF  ·  {rap.cible}  ·  égress {rap.egress}")
    print(L)
    print(f"  statut {rap.statut}   ·   {rap.type_contenu.split(';')[0]}")
    print(f"  URL réécrites avec succès : {rap.reecrit}")
    print(f"  domaines tiers : {len(getattr(rap, '_tiers', []))}   ·   "
          f"pisteurs coupés : {len(getattr(rap, '_pisteurs', []))}")
    print()
    ordre = {"bloquant": 0, "degrade": 1, "note": 2}
    icone = {"bloquant": "⛔", "degrade": "⚠ ", "note": "· "}
    for c in sorted(rap.casses, key=lambda x: ordre[x.gravite]):
        print(f"  {icone[c.gravite]} [{c.genre}] {c.detail}")
        if c.echantillon:
            print(f"       ↳ {c.echantillon}")
    print()
    print(f"  VERDICT : {rap.verdict}")
    print(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Mesure la relayabilité d'un site.")
    ap.add_argument("url")
    ap.add_argument("--egress", choices=["auto", "direct", "tor"], default="auto")
    ap.add_argument("--json", action="store_true", help="rapport machine")
    a = ap.parse_args(argv)

    if a.egress == "tor" and not egress.tor_vivant():
        print("Tor (127.0.0.1:9050) ne répond pas. `systemctl start tor` ?",
              file=sys.stderr)
        return 2

    rap = mesure(a.url, a.egress)
    if a.json:
        print(json.dumps({
            "cible": rap.cible, "egress": rap.egress, "statut": rap.statut,
            "type": rap.type_contenu, "reecrit": rap.reecrit,
            "verdict": rap.verdict,
            "tiers": getattr(rap, "_tiers", []),
            "pisteurs": getattr(rap, "_pisteurs", []),
            "casses": [vars(c) for c in rap.casses],
        }, ensure_ascii=False, indent=2))
    else:
        imprime(rap)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
