# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import re, pathlib

PKG = pathlib.Path(__file__).resolve().parents[1]
SEED = PKG / "conf" / "mitm-bypass-seed.conf"


def _patterns(path):
    out = []
    for ln in path.read_text().splitlines():
        s = ln.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def test_seed_file_exists_and_nonempty():
    assert SEED.exists()
    assert len(_patterns(SEED)) >= 15


def test_seed_patterns_form_valid_ignore_hosts_alternation():
    pats = _patterns(SEED)
    alt = re.compile("(?:" + "|".join(pats) + ")")
    assert alt.search("api.whatsapp.net")
    assert alt.search("gateway.icloud.com")


import importlib, json


def test_load_bypass_tagged_dedups_priority(tmp_path, monkeypatch):
    seed = tmp_path / "seed.conf"; seed.write_text("# h\nseedonly.com\nshared.com\n")
    static = tmp_path / "static.conf"; static.write_text("# h\nstaticonly.com\nshared.com\n")
    dyn = tmp_path / "dyn.conf"; dyn.write_text("# h\nlearnedonly.com\nshared.com\n")
    import secubox_toolbox.api as api
    monkeypatch.setattr(api, "MITM_BYPASS_SEED_FILE", seed)
    monkeypatch.setattr(api, "MITM_BYPASS_FILE", static)
    monkeypatch.setattr(api, "MITM_BYPASS_DYNAMIC_FILE", dyn)
    tagged = api._load_bypass_tagged()
    by = {t["pattern"]: t["source"] for t in tagged}
    assert by["seedonly.com"] == "seed"
    assert by["staticonly.com"] == "static"
    assert by["learnedonly.com"] == "learned"
    assert by["shared.com"] == "seed"           # priority seed > static > learned
    assert sum(1 for t in tagged if t["pattern"] == "shared.com") == 1


def test_load_bypass_tagged_missing_source_skipped(tmp_path, monkeypatch):
    seed = tmp_path / "seed.conf"; seed.write_text("only.com\n")
    import secubox_toolbox.api as api
    monkeypatch.setattr(api, "MITM_BYPASS_SEED_FILE", seed)
    monkeypatch.setattr(api, "MITM_BYPASS_FILE", tmp_path / "nope1.conf")  # missing
    monkeypatch.setattr(api, "MITM_BYPASS_DYNAMIC_FILE", tmp_path / "nope2.conf")  # missing
    tagged = api._load_bypass_tagged()
    assert tagged == [{"pattern": "only.com", "source": "seed"}]
