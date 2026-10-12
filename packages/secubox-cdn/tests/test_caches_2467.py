# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2467 — supervision des caches réels : mesures exactes, illisible = null, symlinks ignorés, parcours borné."""
import os

from api import caches as C


def _fichier(p, n):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"x" * n)


def test_taille_fichiers_et_recent_sont_exacts(tmp_path):
    _fichier(tmp_path / "bbs" / "a.bin", 1000)
    _fichier(tmp_path / "bbs" / "sous" / "b.bin", 500)
    m = C.mesurer(tmp_path / "bbs")
    assert m["octets"] == 1500 and m["fichiers"] == 2 and m["lisible"] and not m["partiel"] and m["recent"] is not None


def test_dossier_ferme_donne_null_pas_zero(tmp_path):
    ferme = tmp_path / "fonts"; ferme.mkdir(); _fichier(ferme / "x", 10); os.chmod(ferme, 0)
    try:
        if os.access(ferme, os.R_OK):
            import pytest; pytest.skip("exécuté en root : le dossier reste lisible")
        m = C.mesurer(ferme)
        assert m == {"octets": None, "fichiers": None, "recent": None, "lisible": False, "partiel": False}
    finally:
        os.chmod(ferme, 0o755)


def test_lien_symbolique_n_est_jamais_suivi(tmp_path):
    _fichier(tmp_path / "cache" / "a", 100)
    gros = tmp_path / "ailleurs"; _fichier(gros / "enorme", 10_000)
    os.symlink(gros, tmp_path / "cache" / "lien")
    assert C.mesurer(tmp_path / "cache")["octets"] == 100


def test_parcours_borne_dit_qu_il_est_partiel(tmp_path):
    for i in range(20):
        _fichier(tmp_path / "gros" / f"f{i}", 1)
    m = C.mesurer(tmp_path / "gros", max_fichiers=5)
    assert m["partiel"] is True and m["fichiers"] == 5


def test_liste_triee_du_plus_gros_et_total_des_lisibles(tmp_path):
    _fichier(tmp_path / "petit" / "a", 10); _fichier(tmp_path / "grand" / "a", 5000); _fichier(tmp_path / "menu.json", 70)
    r = C.lister(tmp_path)
    assert [c["nom"] for c in r["caches"]] == ["grand", "menu.json", "petit"] and r["octets_total"] == 5080 and r["illisibles"] == 0
    assert C.lister(tmp_path / "absent") == {"disponible": False, "caches": [], "octets_total": None, "illisibles": None}


def test_route_rend_les_caches_et_dit_que_les_politiques_ne_sont_pas_appliquees(tmp_path, monkeypatch):
    import asyncio
    from unittest import mock
    import secubox_core.config as cfg
    cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "t"}, "auth": {"users": {}}}
    with mock.patch("pathlib.Path.mkdir"):
        from api import main
    _fichier(tmp_path / "bbs" / "a", 42)
    orig = C.lister
    monkeypatch.setattr(C, "lister", lambda racine=tmp_path, **k: orig(racine, **k))
    main._caches_cache.update(t=0.0, v=None)
    monkeypatch.setattr(main, "_conf", lambda: {"policies": [{"domain": "x.test"}], "rules": [], "enabled": True})
    r = asyncio.run(main.caches_reels(user={}))
    assert r["caches"][0]["nom"] == "bbs" and r["caches"][0]["octets"] == 42
    assert r["politiques"] == {"nombre": 1, "regles": 0, "actif": True, "appliquees": False, "note": r["politiques"]["note"]} and "aucun moteur" in r["politiques"]["note"]
