# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3117 : l'ecriture du panneau va dans le filtre que le vhost inclut."""
from api import reach

VHOST = ("server {\n server_name actor.*;\n"
         " include /etc/nginx/snippets/exposure/actor.conf;\n}\n")


def test_ecriture_et_lecture_via_l_include(tmp_path, monkeypatch):
    sites = tmp_path / "sites"; sites.mkdir()
    snip = tmp_path / "snip"
    (sites / "actor.conf").write_text(VHOST)
    monkeypatch.setattr(reach, "SNIPPET_DIR", snip)
    monkeypatch.setenv("EXPOSURE_SITES_DIRS", str(sites))
    reach._index_cache["cle"] = None
    reach.write_snippet("actor.gk3.secubox.in", "lan", False)
    assert (snip / "actor.conf").exists()
    assert not (snip / "actor.gk3.secubox.in.conf").exists()
    assert reach.snippet_path("actor.gk3.secubox.in") == snip / "actor.conf"
    assert reach.load_record("actor.gk3.secubox.in", False)["reach"] == "lan"
