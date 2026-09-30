# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ToolBoX — garde des routes appelées par les pages (#1778)
CyberMind — https://cybermind.fr

Les fusions du 2026-08-17 ont retiré de l'API des routes que les pages
continuaient d'appeler (/rlevel/*, /exit_country, /vpn/*, /tor/bridge*,
/admin/sentinel/c2*, /admin/filter-control/{toggle,delete}) : 404 muets
pendant six semaines. Ce test lit les appels dans les pages et exige,
pour chacun, une route de l'application avec la MÊME méthode.

Pages couvertes : panneau toolbox, panneau /rlevel, et la page secubox-tor
qui pilote la sortie Tor/VPN de la toolbox (appels `toolboxApi`).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from starlette.routing import Route

from secubox_toolbox.app import app

PKG = Path(__file__).resolve().parents[1]
PAGES = {
    "toolbox": PKG / "www" / "toolbox" / "index.html",
    "rlevel": PKG / "www" / "rlevel" / "index.html",
    "tor": PKG.parent / "secubox-tor" / "www" / "tor" / "index.html",
}

# Fonctions d'appel qui visent l'API toolbox, par page. Les autres helpers
# (exposureApi, nacApi, Xj, Jhub…) visent d'autres modules : ignorés.
_CALLERS = {
    "toolbox": r"(?:\bJ|\bTj|\b_splicePost|\bfetch)\(\s*(?:API\s*\+\s*)?",
    "rlevel": r"\bapi\(\s*",
    "tor": r"(?:\btoolboxApi|\bfetch)\(\s*(?:TOOLBOX_API\s*\+\s*)?",
}
_API_VARS = {"toolbox": "API", "rlevel": "API", "tor": "TOOLBOX_API"}
_PREFIXES = ("/admin", "/rlevel", "/exit_country", "/vpn", "/tor", "/__toolbox")


def _call_args(src: str, start: int) -> str:
    """Texte entre la parenthèse ouvrante (déjà consommée) et sa fermante."""
    depth, i = 1, start
    while i < len(src) and depth:
        c = src[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        i += 1
    return src[start:i - 1]


def _expand(path_tpl: str) -> list[str]:
    """`/admin/tor/${on ? 'on' : 'off'}` → ['/admin/tor/on', '/admin/tor/off'] ;
    une expression sans littéral devient un segment témoin."""
    parts = re.split(r"\$\{([^}]*)\}", path_tpl)
    out = [""]
    for i, p in enumerate(parts):
        if i % 2 == 0:
            out = [o + p for o in out]
        else:
            lits = re.findall(r"'([^']*)'", p) or ["x1"]
            out = [o + lit for o in out for lit in lits]
    return out


def _calls(page: str) -> set[tuple[str, str]]:
    src = PAGES[page].read_text(encoding="utf-8")
    api_var = _API_VARS[page]
    found: set[tuple[str, str]] = set()
    for m in re.finditer(_CALLERS[page], src):
        args = _call_args(src, m.end())
        lit = re.match(r"""\s*(['"])(/[^'"]*)\1(\s*\+)?""", args)
        tpl = re.match(r"\s*`(?:\$\{" + api_var + r"\})?(/[^`]*)`", args)
        if lit:
            path = lit.group(2) + ("x1" if lit.group(3) else "")
        elif tpl:
            path = tpl.group(1)
        else:
            continue  # URL dynamique (paramètre) : couverte par l'appelant
        if not path.startswith(_PREFIXES):
            continue
        # `method: 'POST'` ou `method: turnOn ? 'POST' : 'DELETE'` : chaque
        # littéral de l'expression compte.
        meth = re.search(r"method\s*:\s*([^,}\n]+)", args)
        methods = [x.upper() for x in re.findall(r"['\"](\w+)['\"]", meth.group(1))] if meth else []
        if m.group(0).lstrip().startswith("_splicePost"):
            methods = ["POST"]  # helper qui POSTe toujours
        for p in _expand(path):
            p = p.split("?", 1)[0]  # après l'expansion : un `?` ternaire n'est pas une requête
            for method in methods or ["GET"]:
                found.add((method, p))
    return found


def _routes(routes):
    """Aplatit les routes : FastAPI récent enveloppe les routeurs inclus
    (`_IncludedRouter.original_router`), l'ancien les recopie à plat."""
    for r in routes:
        inner = getattr(r, "original_router", None)
        if inner is not None:
            yield from _routes(inner.routes)
        elif isinstance(r, Route):
            yield r


def _route_exists(method: str, path: str) -> bool:
    return any(r.path_regex.match(path) and method in (r.methods or ())
               for r in _routes(app.routes))


@pytest.mark.parametrize("page", sorted(PAGES))
def test_page_calls_resolve_to_routes(page):
    if not PAGES[page].exists():
        pytest.skip(f"page {PAGES[page]} absente de l'arbre")
    calls = _calls(page)
    assert calls, f"aucun appel API extrait de {page} — l'extracteur est cassé"
    missing = sorted(c for c in calls if not _route_exists(*c))
    assert not missing, f"{page} appelle des routes absentes de l'API : {missing}"


def test_extractor_sees_the_restored_routes():
    """L'extracteur doit voir les appels restaurés — sinon le test ci-dessus
    passerait à vide sur une page réécrite."""
    got = _calls("toolbox") | _calls("rlevel")
    for want in [("GET", "/rlevel/peers"), ("POST", "/rlevel/peer"),
                 ("GET", "/rlevel/me"), ("POST", "/rlevel/me"),
                 ("GET", "/exit_country"), ("POST", "/exit_country"),
                 ("GET", "/vpn/clients"), ("POST", "/vpn/client"), ("DELETE", "/vpn/client"),
                 ("GET", "/tor/bridges"), ("POST", "/tor/bridge"), ("DELETE", "/tor/bridge"),
                 ("GET", "/admin/sentinel/c2"), ("POST", "/admin/sentinel/c2/allow"),
                 ("POST", "/admin/filter-control/toggle"), ("POST", "/admin/filter-control/delete")]:
        assert want in got, f"appel {want} introuvable dans les pages"


def test_toolbox_page_uses_api_prefix_for_writes():
    """Les écritures du panneau passent par /api/v1/toolbox (nginx) : un
    fetch('/admin/…') nu part vers la racine du vhost d'administration."""
    src = PAGES["toolbox"].read_text(encoding="utf-8")
    assert not re.search(r"fetch\(\s*['\"]/admin/", src)
    assert not re.search(r"fetch\(\s*url\s*,", src)


def test_toolbox_page_has_no_duplicate_ids_or_functions():
    """La fusion #823 avait recopié le panneau Sentinelle une seconde fois
    (deux `id="panel-sentinel"`) : `getElementById` ne voit que le premier et
    une fonction déclarée deux fois masque silencieusement la première."""
    import collections
    src = PAGES["toolbox"].read_text(encoding="utf-8")
    ids = collections.Counter(re.findall(r'\bid="([^"$]+)"', src))
    fns = collections.Counter(re.findall(r"^(?:async\s+)?function\s+(\w+)", src, re.M))
    assert not [k for k, v in ids.items() if v > 1], "id HTML en double"
    assert not [k for k, v in fns.items() if v > 1], "fonction JS déclarée deux fois"
