# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2471 — dépôt APT local en lecture seule : entête Release, nombre de paquets, pool ; rien d'inventé quand une source manque."""
from api import depot as D

RELEASE = """Origin: SecuBox
Label: SecuBox-DEB
Suite: trixie
Codename: trixie
Version: 13
Date: Mon, 12 Oct 2026 08:34:59 UTC
Architectures: arm64 amd64
Components: main contrib
MD5Sum:
 d41d8cd98f00b204e9800998ecf8427e 0 main/binary-amd64/Packages
"""


def _depot(tmp_path):
    s = tmp_path / "dists" / "trixie"
    for arch, n in (("amd64", 3), ("arm64", 2)):
        d = s / "main" / f"binary-{arch}"; d.mkdir(parents=True)
        (d / "Packages").write_text("".join(f"Package: p{i}\nVersion: 1\n\n" for i in range(n)))
    (s / "Release").write_text(RELEASE)
    (tmp_path / "dists" / "copie.bak").mkdir()                       # pas de Release : pas une suite
    (tmp_path / "pool" / "main").mkdir(parents=True)
    (tmp_path / "pool" / "main" / "a.deb").write_bytes(b"x" * 2048)
    return tmp_path


def test_suites_architectures_et_nombre_de_paquets(tmp_path):
    r = D.lire(_depot(tmp_path))
    assert r["disponible"] and [s["nom"] for s in r["suites"]] == ["trixie"]
    s = r["suites"][0]
    assert s["architectures"] == ["arm64", "amd64"] and s["composants"] == ["main", "contrib"] and s["version"] == "13"
    assert s["paquets"] == {"arm64": 2, "amd64": 3} and r["paquets_total"] == 5            # « contrib » absent : compté pour rien, pas pour zéro inventé
    assert r["pool"]["octets"] == 2048 and r["pool"]["fichiers"] == 1


def test_entete_seul_les_sommes_de_controle_ne_sont_pas_lues(tmp_path):
    s = D._release(_depot(tmp_path) / "dists" / "trixie" / "Release")
    assert "MD5Sum" not in s and s["Codename"] == "trixie"


def test_depot_absent_donne_non_disponible(tmp_path):
    assert D.lire(tmp_path / "nulle-part") == {"disponible": False, "racine": str(tmp_path / "nulle-part"), "suites": [], "pool": None, "paquets_total": None}


def test_packages_manquant_donne_null_pas_zero(tmp_path):
    d = _depot(tmp_path)
    (d / "dists" / "trixie" / "main" / "binary-arm64" / "Packages").unlink()
    s = D.lire(d)["suites"][0]
    assert s["paquets"]["arm64"] is None and s["paquets"]["amd64"] == 3


def test_route_miroirs_rend_le_depot_et_les_miroirs_distants_non_configures(tmp_path, monkeypatch):
    import asyncio
    from unittest import mock
    import secubox_core.config as cfg
    cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "t"}, "auth": {"users": {}}}
    with mock.patch("pathlib.Path.mkdir"):
        from api import main
    d = _depot(tmp_path)
    orig = D.lire
    monkeypatch.setattr(D, "lire", lambda racine=d, **k: orig(racine, **k))
    main._depot_cache.update(t=0.0, v=None)
    r = asyncio.run(main.miroirs(user={}))
    assert r["disponible"] and r["paquets_total"] == 5 and r["suites"][0]["nom"] == "trixie" and r["distants"] is None
    assert main.miroirs.__code__.co_flags & 0x80
