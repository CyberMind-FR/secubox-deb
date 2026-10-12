# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2483 — le masque des captures réelles : adresses, MAC, clés, courriels, domaines masqués AVANT la capture ; le jeton n'est jamais dans le script."""
import concurrent.futures
import importlib.util
import pathlib

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "snapshots-live.py"
spec = importlib.util.spec_from_file_location("snapshots_live", SCRIPT)
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

HTML = """<html><body>
<p id=a>Client 192.168.1.78 vu sur fe80::6018:d6ff:fe0b:290c et 2a01:e0a:dec:c4e0:f2ad:4eff:fe27:889b</p>
<p id=b>MAC d4:93:90:27:a7:dd et AA-BB-CC-00-11-22</p>
<p id=c>Clé 90n7uAFYCIOT1QRwWKdCypNGZCfFimQkqoTyULErpS4= empreinte 8a1f3c5e9b7d2a4c6e0f1b3d5a7c9e2f</p>
<p id=d>Contact utilisateur@exemple.org</p>
<p id=e>admin.gk2.secubox.in et hall.gk3.secubox.in et www.bfmtv.com et cl3.apple.com</p>
<p id=f title="IP 10.99.1.5">Protocoles TLS.YouTube, index.html, v3.0.0, 12d 4h 31m, 87 %, wg-toolbox</p>
</body></html>"""


def _masque():
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return None
            pg = nav.new_page()
            pg.add_init_script(S.MASQUE_JS)
            pg.route("http://t.test/**", lambda r: r.fulfill(status=200, content_type="text/html", body=HTML))
            pg.goto("http://t.test/page")
            pg.evaluate("window.__masque()")
            r = {i: pg.inner_text("#" + i) for i in "abcdef"}
            r["titre"] = pg.get_attribute("#f", "title")
            nav.close()
            return r
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        r = ex.submit(tache).result(timeout=60)
    if r is None:
        pytest.skip("chromium indisponible")
    return r


def test_adresses_mac_cles_empreintes_et_courriels_sont_masques():
    r = _masque()
    for brut in ("192.168.1.78", "fe80::6018", "2a01:e0a", "d4:93:90", "AA-BB-CC", "90n7uAFY", "8a1f3c5e", "utilisateur@", "10.99.1.5"):
        assert brut not in " ".join(r.values()), brut
    assert "•••.•••.•••.•••" in r["a"] and "••:••:••:••:••:••" in r["b"]


def test_domaines_de_la_box_deviennent_exemple_test_et_les_autres_gardent_leur_terminaison():
    r = _masque()["e"]
    assert "gk2" not in r and "gk3" not in r and "secubox.in" not in r and "bfmtv" not in r and "apple" not in r
    assert r.count("exemple.test") == 2 and ".com" in r


def test_ce_qui_n_est_pas_un_identifiant_reste_lisible():
    f = _masque()["f"]
    for garde in ("TLS.YouTube", "index.html", "v3.0.0", "12d 4h 31m", "87 %", "wg-toolbox"):
        assert garde in f, garde


def test_le_jeton_n_est_jamais_dans_le_script_et_l_absence_est_refusee():
    src = SCRIPT.read_text(encoding="utf-8")
    assert "os.environ.get(\"SBX_TOKEN\"" in src and "eyJ" not in src and "Bearer " not in src
    assert "SBX_BASE et SBX_TOKEN sont requis" in src
