# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Les routes d'AFFICHAGE lisent le cache, elles ne balayent jamais (#1835).

Vécu sur gk2 le 2026-10-01 : la cardlet Metablog du Hall sondait
/public/mosaique toutes les cinq minutes ; chaque appel relançait load_sites()
— `git` + `du` sur ~170 sites, ~20 s, ~650 `git` par passage, une requête
abandonnée par le navigateur (499)."""
import asyncio
import json

import pytest


@pytest.fixture
def cache(monkeypatch, tmp_path):
    from api import main
    sites = tmp_path / "sites"
    (sites / "a" / "public").mkdir(parents=True)
    (sites / "a" / "site.json").write_text(json.dumps({"name": "a", "title": "Le site A", "published": True}))
    f = tmp_path / "sites.json"
    f.write_text(json.dumps({"generated_at": "2026-10-01T11:08:21+0200", "sites": [
        {"name": "a", "domain": "a.example.org", "published": True, "size": "12K", "directory": str(sites / "a")},
        {"name": "b", "domain": "b.example.org", "published": False, "size": "4K", "directory": str(sites / "b")},
    ]}))
    monkeypatch.setattr(main, "SITES_CACHE_PATH", f)
    monkeypatch.setattr(main, "SITES_ROOT", sites)

    def interdit():
        raise AssertionError("une route d'affichage a déclenché un balayage")
    monkeypatch.setattr(main, "load_sites", interdit)
    demandes = []
    monkeypatch.setattr(main, "_trigger_sites_cache_refresh", lambda: demandes.append(1))
    monkeypatch.setattr(main, "_MOSAIQUE", {"cle": None, "rendu": None, "manquantes": []})
    monkeypatch.setattr(main, "SHOTS_CACHE_DIR", tmp_path / "shots")

    def sans_git(*a, **k):
        raise AssertionError("la mosaïque a enrichi un site par git")
    monkeypatch.setattr(main, "_load_site_json", sans_git)
    return main, f, demandes


def test_mosaique_lit_le_cache(cache):
    main, _, _ = cache
    r = asyncio.run(main.public_mosaique())
    assert [x["name"] for x in r["sites"]] == ["a"] and r["sites"][0]["title"] == "Le site A"


def test_access_lit_le_cache(cache):
    main, _, _ = cache
    r = asyncio.run(main.get_access())
    assert r["count"] == 2 and {s["name"] for s in r["sites"]} == {"a", "b"}


def test_access_detaille_prend_la_taille_du_cache(cache, monkeypatch):
    main, _, _ = cache
    import subprocess
    vrai = subprocess.run

    def sans_du(cmd, *a, **k):
        assert cmd[0] != "du", "un du par site refait le balayage"
        return vrai(cmd, *a, **k)
    monkeypatch.setattr(subprocess, "run", sans_du)
    r = main.get_access_detailed()
    lignes = r["sites"] if isinstance(r, dict) else r
    assert any(x.get("size") == "12K" for x in lignes)


def test_cache_absent_demande_un_rafraichissement_sans_balayer(cache):
    main, f, demandes = cache
    f.unlink()
    r = asyncio.run(main.public_mosaique())
    assert r["sites"] == [] and demandes == [1]


def test_mosaique_memorisee_jusqu_a_une_vignette_apparue(cache):
    """« Ne reprendre que si les caches d'image sont manquants » (exploitant)."""
    main, f, _ = cache
    r1 = asyncio.run(main.public_mosaique())
    assert r1["vignettes_manquantes"] == 1 and r1["sites"][0]["vignette"] is False
    appels = []
    vrai = main._site_json_brut
    main._site_json_brut = lambda n: appels.append(n) or vrai(n)
    try:
        assert asyncio.run(main.public_mosaique()) is r1 and appels == []     # rien n'a bougé
        png = main._screenshots.png_path(main.SHOTS_CACHE_DIR, "a")
        png.parent.mkdir(parents=True, exist_ok=True)
        png.write_bytes(b"\x89PNG")
        r2 = asyncio.run(main.public_mosaique())                              # la manquante est arrivée
        assert appels == ["a"] and r2["sites"][0]["vignette"] is True and r2["vignettes_manquantes"] == 0
    finally:
        main._site_json_brut = vrai


def test_mosaique_recalculee_si_la_liste_change(cache):
    import os
    main, f, _ = cache
    r1 = asyncio.run(main.public_mosaique())
    d = json.loads(f.read_text())
    d["sites"].append({"name": "c", "domain": "c.example.org", "published": True})
    f.write_text(json.dumps(d))
    st = f.stat()
    os.utime(f, (st.st_atime, st.st_mtime + 5))
    r2 = asyncio.run(main.public_mosaique())
    assert r2 is not r1 and r2["total"] == 2
