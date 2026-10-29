# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2358 — le SOC rassemble les vues WAF, DPI et Actor Intelligence : une seule source, encadrées de même origine."""
import pathlib
import re

P = pathlib.Path(__file__).resolve().parents[2]
SOC = (P / "secubox-soc/www/soc/index.html").read_text(encoding="utf-8")
VUES = {"menaces": "/waf/menaces.html", "attaquants": "/waf/attaquants.html", "campagnes": "/waf/campagnes.html",
        "surfaces": "/waf/surfaces.html", "visites": "/waf/visites.html", "historique": "/waf/historique.html",
        "trafic": "/dpi/vue.html", "renseignement": "/actor-intelligence/"}


def test_chaque_vue_est_un_onglet_de_meme_origine():
    urls = re.findall(r'data-vue="([^"]+)"', SOC)
    assert len(urls) == len(VUES) + 1          # + « Réseau en direct » (#2364), page du SOC lui-même
    for u in VUES.values():
        assert any(x.startswith(u) for x in urls), u
    assert all(not x.startswith("//") and "://" not in x for x in urls)   # jamais une autre origine


def test_les_onglets_existants_sont_conserves():
    for t in ("t0", "t1", "t2", "t3"):
        assert f'id="{t}"' in SOC


def test_le_gestionnaire_ne_laisse_qu_un_ecran_visible():
    assert "e.hidden = e.id !== cible" in SOC          # plusieurs onglets pilotent le même écran
    assert "sbxWafVue || e.data.sbxdpiVue || e.data.sbxVue" in SOC


def test_les_pages_dpi_et_waf_mesurent_leur_cadre():
    for f in ("secubox-dpi/www/dpi/vue.html",):
        t = (P / f).read_text(encoding="utf-8")
        assert "documentElement.scrollHeight" not in t and "container-name:a;min-height:100vh" not in t


def _deps(pkg):
    c = P / f"secubox-{pkg}/debian/control"
    if not c.is_file():            # composant livré par un autre paquet (ex. ndpid, agrégé dans dpi)
        return set()
    t = "\n".join(ligne for ligne in c.read_text(encoding="utf-8").splitlines() if not ligne.lstrip().startswith("#"))
    m = re.search(r"^Depends:(.*?)(?=^[A-Z][A-Za-z-]*:|\Z)", t, re.S | re.M)
    return set(re.findall(r"secubox-([a-z0-9-]+)", m.group(1))) if m else set()


def _fermeture(racine):
    vu, pile = set(), [racine]
    while pile:
        x = pile.pop()
        if x in vu:
            continue
        vu.add(x)
        pile += list(_deps(x))
    return vu


def test_le_lite_embarque_les_vues_du_soc_avec_leurs_dependances():
    """Une vue du SOC dont le paquet est absent est un onglet vide : la fermeture des Depends du lite doit les contenir."""
    vu = _fermeture("lite")
    for requis in ("soc", "waf-ng", "webos"):
        assert requis in vu, requis


def test_le_dpi_quitte_lite_et_reste_dans_isp_3218():
    """#3218 : DPI et nDPId sortent du profil lite (décision du 2026-10-28) ; le SOC ne le tire plus (Suggests), isp le porte."""
    assert not {"dpi", "ndpid-engine"} & _fermeture("lite")
    assert {"dpi", "ndpid-engine"} <= _fermeture("isp")
    ctl = (P / "secubox-soc/debian/control").read_text(encoding="utf-8")
    assert re.search(r"^Suggests:.*secubox-dpi", ctl, re.M)
    assert not re.search(r"^Recommends:.*secubox-dpi", ctl, re.M)
