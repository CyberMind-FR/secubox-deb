#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Captures des pages Aurora d'une box RÉELLE, avec les identifiants masqués (wiki).

    SBX_TOKEN=<jeton de session> SBX_BASE=https://admin.<domaine> python3 scripts/snapshots-live.py [sortie] [préfixe…]

Le jeton vient de l'environnement : il n'est JAMAIS dans le dépôt, ni écrit dans une capture. Pages en `?embed=1` (sans menu : le menu porte le nom de
l'utilisateur). Avant chaque capture, le navigateur masque dans le texte et les infobulles : adresses IPv4 et IPv6, adresses MAC, empreintes et clés
(hexadécimal long, base64 de 44 caractères), courriels, noms de domaine (le domaine de la box devient `exemple.test`, tout autre domaine garde sa seule
terminaison). Les noms d'appareils et de personnes ne se devinent pas : les pages qui en montrent sont FLOUTÉES par sélecteur (FLOU). Une capture se
RELIT toujours à l'œil avant publication — un masque est un filet, pas une garantie.
"""
import asyncio
import io
import os
import sys
from pathlib import Path

from playwright.async_api import async_playwright
from PIL import Image

PAGES = {  # nom : chemin sur la box
    "dashboard": "/", "apercu": "/apercu/", "nac": "/nac/", "webfilter": "/webfilter/", "ad-guard": "/ad-guard/", "dns-guard": "/dns-guard/",
    "network-anomaly": "/network-anomaly/", "wireguard": "/wireguard/", "interceptor": "/interceptor/", "netmodes": "/netmodes/", "cdn": "/cdn/",
    "threats": "/threats/", "metrics-index": "/metrics/", "waf-vue": "/waf/vue.html", "dpi-vue": "/dpi/vue.html", "ndpid-flux": "/ndpid/flux.html",
    "toolbox-apercu": "/toolbox/apercu.html", "soc-guardian": "/soc/guardian.html", "billets": "/billets/",
}
# noms d'appareils, de personnes, de comptes : flou (sélecteurs par page)
FLOU = {
    "nac": ".app-c b, .app-c .fab, .evt span, .ligne .n", "webfilter": "td:first-child, .appareil b, .ligne .n", "toolbox-apercu": ".ligne .n, td:first-child",
    "soc-guardian": ".ligne .n, td:first-child", "ad-guard": ".ligne .n, td:first-child", "metrics-index": ".ligne .n, td:first-child", "dpi-vue": ".ligne .n, td:first-child",
    "ndpid-flux": "td:first-child", "threats": "td:nth-child(5), td:nth-child(2)", "interceptor": ".hn", "billets": ".item .t",
}
MASQUE_JS = r"""
(function(){
  const RX = [
    [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '•••.•••.•••.•••'],
    [/\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b/gi, '••••:••••::••••'],
    [/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi, '••:••:••:••:••:••'],
    [/\b[A-Za-z0-9+\/]{43}=/g, '••••••••••••••••'],
    [/\b[0-9a-f]{24,}\b/gi, '••••••••••••'],
    [/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, '•••@•••'],
    [/\b(?:[a-z0-9-]+\.)*(?:gk[0-9]|secubox)\.(?:secubox\.)?(?:in|net)\b/gi, 'exemple.test'],
    [/\b(?:[a-z0-9-]+\.)+(com|net|org|fr|io|in|eu|de|uk|us|ru|cn|info|tv|me|co|app|dev|cloud|be|ch|nl|es|it|pl|jp|kr|br|au|ca|xyz|top|site|online)\b/gi, '••••.$1'],
  ];
  const mask = s => { for (const [r, t] of RX) s = s.replace(r, t); return s; };
  function passe(n){
    const w = document.createTreeWalker(n, NodeFilter.SHOW_TEXT);
    let t; while ((t = w.nextNode())) { const v = t.nodeValue; if (v && v.trim()) { const m = mask(v); if (m !== v) t.nodeValue = m; } }
    n.querySelectorAll && n.querySelectorAll('[title],[data-ban],[href],[placeholder]').forEach(e => { for (const a of ['title','placeholder']) { const v = e.getAttribute(a); if (v) { const m = mask(v); if (m !== v) e.setAttribute(a, m); } } });
  }
  window.__masque = () => passe(document.body);
  new MutationObserver(() => window.__masque()).observe(document, {childList: true, subtree: true, characterData: true});
})();
"""


async def main(sortie, filtres):
    base = os.environ.get("SBX_BASE", "").rstrip("/")
    jeton = os.environ.get("SBX_TOKEN", "")
    if not base or not jeton:
        sys.exit("SBX_BASE et SBX_TOKEN sont requis (le jeton ne s'écrit jamais dans le dépôt).")
    sortie.mkdir(parents=True, exist_ok=True)
    erreurs = {}
    async with async_playwright() as p:
        nav = await p.chromium.launch()
        for nom, chemin in PAGES.items():
            if filtres and not any(nom.startswith(f) for f in filtres):
                continue
            for tag, largeur in (("bureau", 1400), ("mobile", 420)):
                ctx = await nav.new_context(viewport={"width": largeur, "height": 900}, ignore_https_errors=False)
                await ctx.add_init_script("try{localStorage.setItem('sbx_token', %r)}catch(e){}" % jeton)
                await ctx.add_init_script(MASQUE_JS)
                page = await ctx.new_page()
                page.on("pageerror", lambda e, n=nom: erreurs.setdefault(n, []).append(str(e)[:80]))
                await page.goto(f"{base}{chemin}{'&' if '?' in chemin else '?'}embed=1", wait_until="load", timeout=60000)
                await page.wait_for_timeout(4500)
                if nom in FLOU:
                    await page.add_style_tag(content=f"{FLOU[nom]}{{filter:blur(6px)!important}}")
                await page.evaluate("window.__masque && window.__masque()")
                await page.wait_for_timeout(300)
                im = Image.open(io.BytesIO(await page.screenshot(full_page=True))).convert("RGB")
                if im.height > 3200:
                    im = im.crop((0, 0, im.width, 3200))
                im.save(sortie / f"{nom}-{tag}.webp", "WEBP", quality=78, method=6)
                await ctx.close()
        await nav.close()
    print("erreurs JS :", erreurs or "aucune")
    return 1 if erreurs else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    sortie = Path(args[0]) if args and "/" in args[0] else Path("docs/aurora-live")
    filtres = [a for a in (args[1:] if args and "/" in args[0] else args)]
    sys.exit(asyncio.run(main(sortie, filtres)))
