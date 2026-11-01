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


def test_js_sans_innerhtml_ni_ecriture_hors_deblocage():
    js = (WWW / "kiosque.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "eval(" not in js
    # Lecture seule, sauf UNE écriture (#3374) : le geste borné « Je débloque » vers la route d'usager dédiée
    assert js.count("method:") == 1 and js.count("'POST'") == 1 and '"POST"' not in js
    assert "const TV_API = '/api/v1/ad-guard/adblock-tv/protection/usager';" in js
    assert "fetch(TV_API + '/debloquer', { method: 'POST'" in js


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
    assert lire("debian/changelog").startswith("secubox-kiosque (0.3.0-1~trixie1) trixie;")
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


def _donnees_box(inv):
    """Exécute la fonction pure donneesBox de kiosque.js sous node (sans DOM)."""
    harnais = (
        "const vm=require('vm');const fs=require('fs');"
        "const ctx={document:{addEventListener(){}},localStorage:{getItem(){return ''}},console};vm.createContext(ctx);"
        f"vm.runInContext(fs.readFileSync({json.dumps(str(WWW / 'kiosque.js'))},'utf8'),ctx);"
        "process.stdout.write(JSON.stringify(vm.runInContext('donneesBox('+process.argv[1]+')',ctx)));"
    )
    r = subprocess.run(["node", "-e", harnais, json.dumps(inv)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_donnees_d_une_box_lues_dans_l_inventaire_du_pilotage():
    """0.2.0 : la pastille d'une box du maillage affiche SES données (inventaire du pilotage), jamais celles du maître."""
    d = _donnees_box({"en_ligne": True, "agent_version": "0.6.1", "inventaire": {
        "Device.DeviceInfo.MemoryStatus.Total": 3881000, "Device.DeviceInfo.MemoryStatus.Free": 2391000,
        "Device.DeviceInfo.UpTime": 90061, "Device.DeviceInfo.ProcessStatus.CPUUsage": 12,
        "Device.X_SECUBOX_Services.FailedNumberOfEntries": 0, "Device.X_SECUBOX_Pilotage.Interface": "distante",
        "Device.X_SECUBOX_Pilotage.MainsLiees": False}})
    assert d["etat"] == "en ligne" and d["etatDetail"] == "aucun service en échec"
    assert d["memoire"] == "38 %" and d["memoireDetail"] == "2335 Mo disponibles"
    assert d["charge"] == "12 %" and d["uptime"] == "1 j 1 h"
    assert d["interface"] == "distante" and d["mainsLiees"] == "non" and d["agent"] == "0.6.1"


def test_donnees_absentes_restent_des_tirets():
    d = _donnees_box({"en_ligne": False, "inventaire": {"Device.X_SECUBOX_Services.FailedNumberOfEntries": "3"}})
    assert d["etat"] == "hors ligne" and d["etatDetail"] == "3 service(s) en échec"
    for k in ("memoire", "charge", "uptime", "interface", "mainsLiees", "agent"):
        assert d[k] is None, k


# ── « Ça ne marche plus ? Je débloque » (#3374, lot 3 SBX TV Privacy) ─────────────────────────────────

def _corps(*args):
    harnais = (
        "const vm=require('vm');const fs=require('fs');"
        "const ctx={document:{addEventListener(){}},localStorage:{getItem(){return ''}},console};vm.createContext(ctx);"
        f"vm.runInContext(fs.readFileSync({json.dumps(str(WWW / 'kiosque.js'))},'utf8'),ctx);"
        "process.stdout.write(JSON.stringify(vm.runInContext('corpsDeblocage.apply(null,'+process.argv[1]+')',ctx)??null));"
    )
    r = subprocess.run(["node", "-e", harnais, json.dumps(list(args))], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_corps_de_deblocage_borne():
    assert _corps("tv-salon", "pause", 60) == {"tv": "tv-salon", "geste": "pause", "minutes": 60}
    assert _corps("toutes", "observe", None) == {"tv": "toutes", "geste": "observe"}
    for args in (("tv-salon", "pause", 30), ("tv-salon", "proteger", 60), ("", "observe", None), ("x" * 41, "observe", None),
                 ("TV salon", "observe", None)):
        assert _corps(*args) is None, args


def test_carte_debloque_dans_l_ecran_securite():
    html = (WWW / "index.html").read_text(encoding="utf-8")
    sec = html[html.index('id="ecran-securite"'):html.index('id="ecran-reseau"')]
    assert "Ça ne marche plus ? Je débloque" in sec and 'id="k-tv"' in sec and 'id="k-retour"' in sec
    for m in ("15", "60", "240"):
        assert f'data-minutes="{m}"' in sec
    assert "bloque les pubs que la TV va chercher, pas celles qu'un service insère dans sa propre vidéo" in sec
    js = (WWW / "kiosque.js").read_text(encoding="utf-8")
    assert "$('k-retour').textContent" in js and "TV_API + '/tv'" in js
