# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Alias de domaine d'un site (#1023)."""
from main import alias_du_site


def test_alias_simples():
    assert alias_du_site({"aliases": ["gk2.net", "www.gk2.net"]}) == \
        ["gk2.net", "www.gk2.net"]


def test_absence_rend_une_liste_vide():
    assert alias_du_site({}) == []
    assert alias_du_site({"aliases": None}) == []


def test_normalisation_casse_espaces_point_final():
    assert alias_du_site({"aliases": ["  GK2.NET  ", "www.gk2.net."]}) == \
        ["gk2.net", "www.gk2.net"]


def test_doublons_ecartes():
    assert alias_du_site({"aliases": ["gk2.net", "GK2.net"]}) == ["gk2.net"]


def test_injection_dans_server_name_refusee():
    # `server_name` se termine par un point-virgule : un nom qui en contient un
    # fermerait la directive et ouvrirait ce que l'auteur voudrait. Le motif
    # n'est pas de la cosmetique.
    mechants = ["evil.com; root /etc", "a b.com", "../../etc/passwd",
                "gk2.net\n    root /etc", "", "pasdepoint", "-debut.com",
                "*.gk2.net"]
    assert alias_du_site({"aliases": mechants}) == []


def test_type_inattendu_ignore_sans_lever():
    assert alias_du_site({"aliases": "gk2.net"}) == []
    assert alias_du_site({"aliases": [42, None, "gk2.net"]}) == ["gk2.net"]


def test_le_scan_remonte_les_alias(tmp_path):
    """Le defaut qui a fait le tour complet : ecrits, valides, jamais servis.

    Les alias etaient dans le site.json, `alias_du_site` les rendait
    correctement, le generateur savait les poser dans `server_name` — et le
    bloc n'en portait aucun, parce que le scan ne recopiait pas la cle. Aucune
    etape n'echouait ; le resultat etait seulement incomplet.
    """
    import json
    import sites_scan

    site = tmp_path / "sites" / "www"
    (site / "public").mkdir(parents=True)
    (site / "public" / "index.html").write_text("x")
    (site / "site.json").write_text(json.dumps({
        "name": "www", "domain": "www.gk2.secubox.in", "published": True,
        "aliases": ["gk2.net", "www.gk2.net"]}))

    entrees = sites_scan.scan_sites(tmp_path / "sites", tmp_path / "absent.conf")
    assert entrees[0]["aliases"] == ["gk2.net", "www.gk2.net"]
