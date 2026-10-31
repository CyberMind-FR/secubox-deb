# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Kiosque distant (#3330) : PWA installable, CSP stricte, cache sans API, lecture seule."""
import json
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
WWW = RACINE / "www" / "kiosque"


def lire(p):
    return (RACINE / p).read_text(encoding="utf-8")


def test_manifest_installable():
    m = json.loads((WWW / "manifest.webmanifest").read_text(encoding="utf-8"))
    assert m["start_url"] == "/kiosque/" and m["scope"] == "/kiosque/" and m["display"] == "standalone"
    assert m["lang"] == "fr" and any(i["src"] == "/kiosque/icone.svg" for i in m["icons"])


def test_aucun_script_ni_style_integre():
    html = (WWW / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "script intégré"
    assert "<style" not in html and ' style="' not in html and not re.search(r"\son[a-z]+=", html)
    assert 'href="/kiosque/manifest.webmanifest"' in html and 'src="/kiosque/kiosque.js"' in html


def test_js_sans_innerhtml_ni_ecriture():
    js = (WWW / "kiosque.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "eval(" not in js
    # MVP en lecture seule : aucune requête autre que GET (fetch sans method)
    assert "method:" not in js and "'POST'" not in js and '"POST"' not in js


def test_service_worker_ne_cache_jamais_l_api():
    sw = (WWW / "sw.js").read_text(encoding="utf-8")
    assert "/api/" not in re.search(r"STATIQUES = \[(.*?)\];", sw, re.S).group(1)
    assert "STATIQUES.includes(u.pathname)" in sw and "e.request.method !== 'GET'" in sw


def test_nginx_csp_stricte_et_en_tetes():
    c = lire("nginx/kiosque.conf")
    assert "location ^~ /kiosque/" in c
    csp = re.search(r'Content-Security-Policy "([^"]+)"', c).group(1)
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert "frame-ancestors 'none'" in csp and "worker-src 'self'" in csp
    for e in ("X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"):
        assert e in c


def test_paquet_debian():
    c = lire("debian/control")
    assert "Package: secubox-kiosque" in c and "Architecture: all" in c and "Standards-Version: 4.6.2" in c
    assert lire("debian/compat").strip() == "13"
    assert lire("debian/changelog").startswith("secubox-kiosque (0.1.0-1~trixie1) trixie;")
    r = lire("debian/rules")
    assert "/usr/share/secubox/www/kiosque" in r and "/etc/nginx/secubox-routes.d/kiosque.conf" in r


def test_spdx_partout():
    for p in [*WWW.iterdir(), RACINE / "nginx/kiosque.conf", RACINE / "debian/rules", RACINE / "debian/postinst"]:
        if p.suffix in (".json", ".webmanifest", ".svg"):
            continue
        assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in p.read_text(encoding="utf-8"), p


def test_js_syntaxe():
    for f in ("kiosque.js", "sw.js"):
        assert subprocess.run(["node", "--check", str(WWW / f)], capture_output=True).returncode == 0, f
