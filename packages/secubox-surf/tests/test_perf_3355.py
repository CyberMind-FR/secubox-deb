# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3355 : charge de surf sur gk2 (~60 % d'un cœur). est_pisteur était ~70 % du coût d'une réécriture HTML (113 hôtes x
chaque URL de la page) : il est mis en cache ; la réécriture (CPU pur) quitte la boucle asyncio ; l'unité tourne en basse
priorité."""
import pathlib
import time
import warnings

warnings.simplefilter("ignore", SyntaxWarning)
from surf import relais  # noqa: E402

ICI = pathlib.Path(__file__).resolve().parents[1]


def test_est_pisteur_en_cache_et_inchange():
    assert hasattr(relais.est_pisteur, "cache_info")
    for h, attendu in (("connect.facebook.net", True), ("x.doubleclick.net", True), ("ads.example.com", True),
                       ("www.lemonde.fr", False), ("lespads.fr", False), ("CONNECT.FACEBOOK.NET", True), ("", False)):
        assert relais.est_pisteur(h) is attendu, h


def _page(n):
    return "".join(f'<a href="https://img{i % 40}.cdn{i % 7}.example.com/p/{i}">x</a>'
                   f'<img srcset="https://h{i % 30}.example.org/a.jpg 1x, https://h{i % 30}.example.org/b.jpg 2x">'
                   for i in range(n))


def test_reecriture_d_une_grosse_page_reste_rapide():
    page = _page(3000)

    def sur(h):
        return None if relais.est_pisteur(h) else relais.origine_de(h)
    rap = relais.Rapport(cible="www.example.com", egress="direct")
    relais.reecris_html(page, "https://www.example.com/", rap, sur)      # amorce
    t = time.perf_counter()
    relais.reecris_html(page, "https://www.example.com/", rap, sur)
    # avant #3355 : ~0,32 s sur ce poste (est_pisteur non mis en cache) ; borne large pour la CI
    assert time.perf_counter() - t < 0.12


def test_reecriture_hors_de_la_boucle_asyncio():
    s = (ICI / "surf" / "serveur.py").read_text()
    for f in ("reecris_html", "reecris_css", "reecris_manifeste", "reecris_portails", "fige"):
        assert "asyncio.to_thread(relais." + f + "," in s, f
        assert "relais." + f + "(" not in s, f          # plus aucun appel direct dans la boucle


def test_unite_en_basse_priorite():
    u = (ICI / "systemd" / "secubox-surf.service").read_text()
    for ligne in ("Nice=10", "CPUWeight=20", "IOWeight=20", "CPUQuota=50%"):
        assert "\n" + ligne + "\n" in u, ligne


def test_jarre_n_ecrit_pas_le_bocal_a_chaque_cookie(tmp_path, monkeypatch):
    """#3355 : les sites changent leurs identifiants à presque chaque réponse ; le bocal entier était réécrit à chaque
    fois. Au plus une écriture par fenêtre, la dernière valeur n'est jamais perdue (écriture différée)."""
    from surf import jarre
    monkeypatch.setattr(jarre, "CHEMIN", tmp_path / "jarre.json")
    ecrits = []
    vrai = jarre._ecrit_bocal
    monkeypatch.setattr(jarre, "_ecrit_bocal", lambda: ecrits.append(1) or vrai())
    for i in range(50):
        jarre.apprend("www.exemple.fr", [f"sid={i}; Path=/"])
    assert len(ecrits) <= 2
    jarre.vide_en_attente()
    import json
    assert json.loads((tmp_path / "jarre.json").read_text())["exemple.fr"]["sid"] == "49"


def test_jarre_appelee_hors_de_la_boucle():
    s = (ICI / "surf" / "serveur.py").read_text()
    assert "asyncio.to_thread(jarre.apprend," in s


def test_surf_ne_tourne_plus_en_root():
    u = (ICI / "systemd" / "secubox-surf.service").read_text()
    assert "\nUser=secubox-surf\n" in u and "\nGroup=secubox\n" in u
    pi = (ICI / "debian" / "postinst").read_text()
    assert "useradd --system --gid secubox" in pi and "secubox-surf" in pi
