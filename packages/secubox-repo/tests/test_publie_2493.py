# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2493 — ce que le dépôt publie réellement : suites, paquets distincts, pool ; rien d'inventé ; les comptes de /stats ne viennent plus d'un autre socle reprepro."""
import asyncio

from api import publie as P

RELEASE = """Origin: SecuBox
Label: SecuBox-DEB
Suite: trixie
Codename: trixie
Version: 13
Date: Mon, 12 Oct 2026 08:34:59 UTC
Architectures: arm64 amd64 source
Components: main contrib
MD5Sum:
 d41d8cd98f00b204e9800998ecf8427e 0 main/binary-amd64/Packages
"""


def _depot(tmp_path):
    s = tmp_path / "dists" / "trixie"
    for arch, noms in (("amd64", ["a", "b", "c"]), ("arm64", ["a", "b"])):
        d = s / "main" / f"binary-{arch}"; d.mkdir(parents=True)
        (d / "Packages").write_text("".join(f"Package: {n}\nVersion: 1\n\n" for n in noms))
    (s / "Release").write_text(RELEASE)
    (tmp_path / "dists" / "copie.bak").mkdir()
    (tmp_path / "pool" / "main").mkdir(parents=True)
    (tmp_path / "pool" / "main" / "a.deb").write_bytes(b"x" * 2048)
    (tmp_path / "pool" / "main" / "autre.txt").write_bytes(b"y" * 10)
    return tmp_path


def test_suites_paquets_distincts_et_entrees_par_architecture(tmp_path):
    r = P.lire(_depot(tmp_path))
    assert r["disponible"] and [s["nom"] for s in r["suites"]] == ["trixie"]
    s = r["suites"][0]
    assert s["architectures"] == ["arm64", "amd64"] and "source" not in s["architectures"] and s["paquets"] == {"arm64": 2, "amd64": 3}
    assert s["uniques"] == 3 and r["paquets_uniques"] == 3                          # a, b, c : « a » et « b » existent dans les deux architectures
    assert r["derniere_publication"].startswith("Mon, 12 Oct 2026")
    assert r["pool"]["octets"] == 2048 and r["pool"]["paquets_deb"] == 1            # un .txt n'est pas un paquet


def test_depot_absent_ou_packages_manquants_donne_null_pas_zero(tmp_path):
    r = P.lire(tmp_path / "nulle-part")
    assert r == {"disponible": False, "racine": str(tmp_path / "nulle-part"), "suites": [], "pool": None, "paquets_uniques": None, "derniere_publication": None}
    d = _depot(tmp_path)
    for f in (d / "dists" / "trixie" / "main").glob("binary-*/Packages"):
        f.unlink()
    s = P.lire(d)["suites"][0]
    assert s["paquets"] == {"arm64": None, "amd64": None} and s["uniques"] is None and P.lire(d)["paquets_uniques"] is None


def test_une_suite_sans_release_n_est_pas_publiee(tmp_path):
    assert [s["nom"] for s in P.lire(_depot(tmp_path))["suites"]] == ["trixie"]


def test_stats_prend_les_comptes_du_depot_publie_pas_du_socle_reprepro(tmp_path, monkeypatch):
    from unittest import mock
    import secubox_core.config as cfg
    cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "t"}, "auth": {"users": {}}}
    with mock.patch("pathlib.Path.mkdir"):
        from api import main
    d = _depot(tmp_path)
    monkeypatch.setattr(main, "REPO_OUT", str(d))
    monkeypatch.setattr(main.stats_cache, "get", lambda k: None)
    monkeypatch.setattr(main.stats_cache, "set", lambda k, v: None)
    monkeypatch.setattr(main, "run_repoctl", lambda *a, **k: [])                     # repoctl « voit » un socle vide : c'est le bug
    st = asyncio.run(main.get_stats())
    assert st["distributions"]["trixie"] == 3 and st["distributions"].get("copie.bak") is None


def test_route_publie_est_une_coroutine_en_lecture(monkeypatch, tmp_path):
    from unittest import mock
    import secubox_core.config as cfg
    cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "t"}, "auth": {"users": {}}}
    with mock.patch("pathlib.Path.mkdir"):
        from api import main
    monkeypatch.setattr(main, "REPO_OUT", str(_depot(tmp_path)))
    main._publie_cache.update(t=0.0, v=None)
    r = asyncio.run(main.get_publie())
    assert r["paquets_uniques"] == 3 and main.get_publie.__code__.co_flags & 0x80
