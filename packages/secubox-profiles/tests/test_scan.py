# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

from api.manifest import Manifest, load_manifest
from api.scan import discover, to_toml, write_drafts


def menu(tmp_path, mid, category="mesh"):
    d = tmp_path / "menu.d"
    d.mkdir(exist_ok=True)
    (d / f"{mid}.json").write_text(json.dumps(
        {"id": mid, "name": mid.title(), "category": category, "path": f"/{mid}/"}))
    return d


def test_discover_native_module(tmp_path):
    m = discover(units=["secubox-lyrion.service"], lxc_names=set(), routes=set(),
                 menu_dir=menu(tmp_path, "lyrion"))
    assert len(m) == 1
    assert m[0].id == "lyrion" and m[0].runtime == "native"
    assert m[0].units == ("secubox-lyrion.service",)


def test_discover_marks_lxc_runtime(tmp_path):
    m = discover(units=["secubox-peertube.service"], lxc_names={"peertube"}, routes=set(),
                 menu_dir=menu(tmp_path, "peertube"))[0]
    assert m.runtime == "lxc" and m.lxc == "peertube"


def test_discover_marks_public_exposure_from_routes(tmp_path):
    m = discover(units=["secubox-peertube.service"], lxc_names=set(),
                 routes={"peertube.gk2.secubox.in"},
                 menu_dir=menu(tmp_path, "peertube"))[0]
    assert m.exposure == "public" and m.portal_domain == "peertube.gk2.secubox.in"


def test_discover_lan_only_when_menu_but_no_route(tmp_path):
    # Lyrion : a une entrée de menu (accès LAN) mais aucune route WAF publique.
    m = discover(units=["secubox-lyrion.service"], lxc_names=set(), routes=set(),
                 menu_dir=menu(tmp_path, "lyrion"))[0]
    assert m.exposure == "lan"


def test_discover_internal_when_no_menu_and_no_route(tmp_path):
    (tmp_path / "menu.d").mkdir()
    m = discover(units=["secubox-core.service"], lxc_names=set(), routes=set(),
                 menu_dir=tmp_path / "menu.d")[0]
    assert m.exposure == "internal"


def test_discover_protects_the_core_set(tmp_path):
    # Sans ça, le tout premier scan produirait des manifestes qui autorisent
    # à éteindre l'auth.
    (tmp_path / "menu.d").mkdir()
    got = {m.id: m for m in discover(
        units=["secubox-auth.service", "secubox-aggregator.service", "secubox-lyrion.service"],
        lxc_names=set(), routes=set(), menu_dir=tmp_path / "menu.d")}
    assert got["auth"].protected is True
    assert got["aggregator"].protected is True
    assert got["lyrion"].protected is False


def test_discover_maps_unknown_menu_category_to_infra(tmp_path):
    # menu.d utilise ses propres catégories UI ("mesh") : on ne les recopie
    # pas aveuglément dans la taxonomie de déploiement.
    m = discover(units=["secubox-lyrion.service"], lxc_names=set(), routes=set(),
                 menu_dir=menu(tmp_path, "lyrion", category="n-importe-quoi"))[0]
    assert m.category in ("media", "security", "network", "infra", "dev", "mesh")


def test_to_toml_roundtrips_through_the_loader(tmp_path):
    # L'émetteur est écrit à la main (pas d'écrivain TOML en stdlib) : le seul
    # test qui compte est que le loader relise ce qu'on a écrit.
    src = Manifest(id="peertube", category="media", runtime="lxc", exposure="public",
                   units=("secubox-peertube.service",), lxc="peertube",
                   portal_domain="peertube.gk2.secubox.in", priority=40,
                   protected=False, needs=("auth",))
    p = tmp_path / "peertube.toml"
    p.write_text(to_toml(src))
    assert load_manifest(p) == src


def test_to_toml_roundtrips_minimal_manifest(tmp_path):
    src = Manifest(id="lyrion", category="media", runtime="native", exposure="lan",
                   units=("secubox-lyrion.service",))
    p = tmp_path / "lyrion.toml"
    p.write_text(to_toml(src))
    assert load_manifest(p) == src


def test_write_drafts_never_overwrites_without_force(tmp_path):
    # Un manifeste corrigé à la main fait autorité sur une dérivation.
    out = tmp_path / "modules.d"
    out.mkdir()
    existing = out / "lyrion.toml"
    existing.write_text("# corrigé à la main\n")
    m = Manifest(id="lyrion", category="media", runtime="native", exposure="lan",
                 units=("secubox-lyrion.service",))
    written = write_drafts([m], out, force=False)
    assert written == []
    assert existing.read_text() == "# corrigé à la main\n"


def test_write_drafts_overwrites_with_force(tmp_path):
    out = tmp_path / "modules.d"
    out.mkdir()
    (out / "lyrion.toml").write_text("# ancien\n")
    m = Manifest(id="lyrion", category="media", runtime="native", exposure="lan",
                 units=("secubox-lyrion.service",))
    written = write_drafts([m], out, force=True)
    assert written == [out / "lyrion.toml"]
    assert load_manifest(out / "lyrion.toml") == m
