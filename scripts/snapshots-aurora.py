#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Régénère docs/aurora/*.webp : une capture « bureau » (1400 px) et une capture « mobile » (420 px, ?embed=1) de chaque page du
profil projet référence Aurora, EN MODE DÉMONSTRATION (?demo=1) — données fictives annoncées par un bandeau, jamais une mesure réelle :
une capture authentifiée de la box publierait des adresses, des noms d'appareils et des empreintes dans le dépôt.

    python3 scripts/snapshots-aurora.py            # toutes les pages
    python3 scripts/snapshots-aurora.py waf toolbox # celles dont le nom commence par…

Prérequis : playwright (chromium) et Pillow. Les appels réseau relatifs échouent sous file:// : c'est voulu (cas « sans session »),
la démonstration n'en émet aucun.
"""
import asyncio
import io
import sys
from pathlib import Path

from playwright.async_api import async_playwright
from PIL import Image

RACINE = Path(__file__).resolve().parents[1]
SORTIE = RACINE / "docs" / "aurora"
P = "packages"
PAGES = [  # (nom, chemin, titre)
    ('waf-vue', 'secubox-waf-ng/composants/waf/www/waf/vue.html', "WAF — Vue d'ensemble (le modèle)"),
    ('waf-menaces', 'secubox-waf-ng/composants/waf/www/waf/menaces.html', 'WAF — Menaces'),
    ('waf-attaquants', 'secubox-waf-ng/composants/waf/www/waf/attaquants.html', 'WAF — Attaquants suivis'),
    ('waf-campagnes', 'secubox-waf-ng/composants/waf/www/waf/campagnes.html', 'WAF — Campagnes'),
    ('waf-surfaces', 'secubox-waf-ng/composants/waf/www/waf/surfaces.html', 'WAF — Surfaces'),
    ('waf-visites', 'secubox-waf-ng/composants/waf/www/waf/visites.html', 'WAF — Visites'),
    ('waf-historique', 'secubox-waf-ng/composants/waf/www/waf/historique.html', 'WAF — Historique'),
    ('dpi-vue', 'secubox-dpi/www/dpi/vue.html', "DPI — Vue d'ensemble"),
    ('ndpid-flux', 'secubox-dpi/composants/ndpid/www/ndpid/flux.html', 'ndpid — Flux'),
    ('ndpid-protocoles', 'secubox-dpi/composants/ndpid/www/ndpid/protocoles.html', 'ndpid — Protocoles'),
    ('ndpid-empreintes', 'secubox-dpi/composants/ndpid/www/ndpid/empreintes.html', 'ndpid — Empreintes'),
    ('ndpid-risques', 'secubox-dpi/composants/ndpid/www/ndpid/risques.html', 'ndpid — Risques'),
    ('ndpid-reglages', 'secubox-dpi/composants/ndpid/www/ndpid/reglages.html', 'ndpid — Réglages'),
    ('soc-guardian', 'secubox-soc/www/soc/guardian.html', 'SOC — Guardian'),
    ('soc-reseau', 'secubox-soc/www/soc/reseau.html', 'SOC — Réseau en direct'),
    ('threats', 'secubox-threats/www/threats/index.html', 'Threats'),
    ('metrics-index', 'secubox-metrics/www/metrics/index.html', "Metrics — Vue d'ensemble"),
    ('metrics-vhosts', 'secubox-metrics/www/metrics/vhosts.html', 'Metrics — Sites'),
    ('toolbox-apercu', 'secubox-toolbox/www/toolbox/apercu.html', "Toolbox — Vue d'ensemble"),
    ('toolbox-clients', 'secubox-toolbox/www/toolbox/clients.html', 'Toolbox — Clients'),
    ('toolbox-filtres', 'secubox-toolbox/www/toolbox/filtres.html', 'Toolbox — Filtres MITM'),
    ('toolbox-social', 'secubox-toolbox/www/toolbox/social.html', 'Toolbox — Cartographie sociale'),
    ('toolbox-pubs', 'secubox-toolbox/www/toolbox/pubs.html', 'Toolbox — Pubs'),
    ('toolbox-tor', 'secubox-toolbox/www/toolbox/tor.html', 'Toolbox — Tor'),
    ('toolbox-sentinelle', 'secubox-toolbox/www/toolbox/sentinelle.html', 'Toolbox — Sentinelle'),
    ('toolbox-config', 'secubox-toolbox/www/toolbox/config.html', 'Toolbox — Config'),
    ('actor', 'secubox-webos/www/actor-intelligence/index.html', 'Actor Intelligence — Renseignement'),
    ('guardian', 'secubox-ad-guard/www/guardian/index.html', 'Guardian (filtrage DNS)'),
]
HAUTEUR_MAX = 3200


async def main(filtres):
    SORTIE.mkdir(parents=True, exist_ok=True)
    erreurs = {}
    async with async_playwright() as p:
        nav = await p.chromium.launch()
        for nom, chemin, _ in PAGES:
            if filtres and not any(nom.startswith(f) for f in filtres):
                continue
            for tag, largeur, requete in (("bureau", 1400, "?demo=1"), ("mobile", 420, "?demo=1&embed=1")):
                page = await nav.new_page(viewport={"width": largeur, "height": 900})
                page.on("pageerror", lambda e, n=nom: erreurs.setdefault(n, []).append(str(e)[:80]))

                async def vide(route):
                    if route.request.url.startswith("file:"):
                        return await route.continue_()
                    await route.fulfill(status=200, content_type="application/json", body="{}")

                await page.route("**/*", vide)
                await page.goto(f"file://{RACINE}/{P}/{chemin}{requete}")
                await page.wait_for_timeout(700)
                im = Image.open(io.BytesIO(await page.screenshot(full_page=True))).convert("RGB")
                if im.height > HAUTEUR_MAX:
                    im = im.crop((0, 0, im.width, HAUTEUR_MAX))
                im.save(SORTIE / f"{nom}-{tag}.webp", "WEBP", quality=78, method=6)
                await page.close()
        await nav.close()
    print("erreurs JS :", erreurs or "aucune")
    return 1 if erreurs else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
