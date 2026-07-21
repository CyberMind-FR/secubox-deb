# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests câblage nginx phase-2 (nginx-sync)
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

from api.manifest import Manifest


def _vhost(dom):
    return (f"server {{\n    listen 0.0.0.0:9080;\n    server_name {dom};\n"
            f"    location / {{\n        proxy_pass http://10.100.0.80:8090/;\n    }}\n}}\n")


def _m(mid, dom, lc="on-demand"):
    return Manifest(id=mid, category="infra", runtime="native", exposure="public",
                    units=(f"{mid}.service",), portal_domain=dom, lifecycle=lc)


def test_find_config_matches_server_name_ignores_bak(tmp_path):
    from api import nginxgen
    (tmp_path / "yacy.conf").write_text(_vhost("yacy.gk2.secubox.in"))
    (tmp_path / "yacy.conf.bak").write_text(_vhost("yacy.gk2.secubox.in"))
    p = nginxgen.find_config("yacy.gk2.secubox.in", tmp_path)
    assert p is not None and p.name == "yacy.conf"
    assert nginxgen.find_config("nope.gk2", tmp_path) is None


def test_wire_injects_after_server_name_and_is_idempotent(tmp_path):
    from api import nginxgen
    p = tmp_path / "yacy.conf"
    p.write_text(_vhost("yacy.gk2.secubox.in"))
    assert nginxgen.wire(p, "yacy.gk2.secubox.in") is True
    text = p.read_text()
    lines = text.splitlines()
    i = next(n for n, l in enumerate(lines) if "server_name" in l)
    assert "secubox-waking.conf" in lines[i + 1]
    assert nginxgen.wire(p, "yacy.gk2.secubox.in") is False
    assert text == p.read_text()
    assert text.count("secubox-waking.conf") == 1


def test_wire_targets_the_right_block_in_multi_server_file(tmp_path):
    from api import nginxgen
    p = tmp_path / "multi.conf"
    p.write_text(_vhost("other.gk2") + _vhost("yacy.gk2.secubox.in"))
    nginxgen.wire(p, "yacy.gk2.secubox.in")
    lines = p.read_text().splitlines()
    yi = next(n for n, l in enumerate(lines) if "server_name yacy.gk2.secubox.in" in l)
    assert "secubox-waking.conf" in lines[yi + 1]
    oi = next(n for n, l in enumerate(lines) if "server_name other.gk2" in l)
    assert "secubox-waking.conf" not in lines[oi + 1]


def test_wire_no_matching_server_name_leaves_file_untouched(tmp_path):
    from api import nginxgen
    p = tmp_path / "x.conf"
    orig = _vhost("other.gk2")
    p.write_text(orig)
    assert nginxgen.wire(p, "yacy.gk2.secubox.in") is False
    assert p.read_text() == orig


def test_unwire_removes_the_include(tmp_path):
    from api import nginxgen
    p = tmp_path / "yacy.conf"
    p.write_text(_vhost("yacy.gk2.secubox.in"))
    nginxgen.wire(p, "yacy.gk2.secubox.in")
    assert nginxgen.unwire(p) is True
    assert "secubox-waking.conf" not in p.read_text()
    assert nginxgen.unwire(p) is False


def test_sync_and_reload_wires_ondemand_and_reloads(tmp_path):
    from api import nginxgen
    (tmp_path / "yacy.conf").write_text(_vhost("yacy.gk2.secubox.in"))
    (tmp_path / "podcaster.conf").write_text(_vhost("podcaster.gk2"))
    mans = {"yacy": _m("yacy", "yacy.gk2.secubox.in"),
            "podcaster": _m("podcaster", "podcaster.gk2"),
            "lyrion": _m("lyrion", "lyrion.gk2", lc="always-on")}
    calls = []
    def run(argv):
        calls.append(argv); return 0, ""
    rep = nginxgen.sync_and_reload(manifests=mans, sites_dir=tmp_path, run=run)
    assert sorted(rep["wired"]) == ["podcaster.gk2", "yacy.gk2.secubox.in"]
    assert rep["reloaded"] is True and rep["rolled_back"] is False
    assert ["nginx", "-t"] in calls and ["systemctl", "reload", "nginx"] in calls
    assert "secubox-waking.conf" in (tmp_path / "yacy.conf").read_text()


def test_sync_and_reload_rolls_back_when_nginx_test_fails(tmp_path):
    from api import nginxgen
    orig = _vhost("yacy.gk2.secubox.in")
    (tmp_path / "yacy.conf").write_text(orig)
    mans = {"yacy": _m("yacy", "yacy.gk2.secubox.in")}
    def run(argv):
        return (1, "bad") if argv == ["nginx", "-t"] else (0, "")
    rep = nginxgen.sync_and_reload(manifests=mans, sites_dir=tmp_path, run=run)
    assert rep["rolled_back"] is True and rep["reloaded"] is False
    assert (tmp_path / "yacy.conf").read_text() == orig


def test_sync_reports_ondemand_vhost_with_no_nginx_config(tmp_path):
    from api import nginxgen
    mans = {"ghost": _m("ghost", "ghost.gk2")}
    def run(argv): return 0, ""
    rep = nginxgen.sync_and_reload(manifests=mans, sites_dir=tmp_path, run=run)
    assert rep["no_config"] == ["ghost.gk2"] and rep["wired"] == []
    assert rep["reloaded"] is False


def test_wire_covers_multiple_ondemand_blocks_in_one_file(tmp_path):
    # #1 fix: file-wide marker used to skip the 2nd+ on-demand block; per-block
    # idempotency wires EACH domain's block.
    from api import nginxgen
    p = tmp_path / "multi.conf"
    p.write_text(_vhost("a.gk2") + _vhost("b.gk2"))
    assert nginxgen.wire(p, "a.gk2") is True
    assert nginxgen.wire(p, "b.gk2") is True          # 2nd block also wired now
    assert p.read_text().count("secubox-waking.conf") == 2
    # idempotent per block
    assert nginxgen.wire(p, "a.gk2") is False
    assert nginxgen.wire(p, "b.gk2") is False
    lines = p.read_text().splitlines()
    ai = next(n for n, l in enumerate(lines) if "server_name a.gk2" in l)
    bi = next(n for n, l in enumerate(lines) if "server_name b.gk2" in l)
    assert "secubox-waking.conf" in lines[ai + 1] and "secubox-waking.conf" in lines[bi + 1]
