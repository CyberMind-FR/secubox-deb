# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest

from api.manifest import Manifest, ManifestError, load_all, load_manifest

FULL = """
id        = "peertube"
category  = "media"
runtime   = "lxc"
exposure  = "public"
units     = ["secubox-peertube.service"]
lxc       = "peertube"
portal    = { domain = "peertube.gk2.secubox.in" }
priority  = 40
protected = false
needs     = ["auth"]
"""

MINIMAL = """
id       = "lyrion"
category = "media"
runtime  = "native"
exposure = "lan"
units    = ["secubox-lyrion.service"]
"""


def test_load_full_manifest(tmp_path):
    p = tmp_path / "peertube.toml"
    p.write_text(FULL)
    m = load_manifest(p)
    assert m == Manifest(
        id="peertube", category="media", runtime="lxc", exposure="public",
        units=("secubox-peertube.service",), lxc="peertube",
        portal_domain="peertube.gk2.secubox.in", priority=40,
        protected=False, needs=("auth",),
    )


def test_defaults_are_applied(tmp_path):
    # Un manifeste minimal doit rester valide : la plupart des 134 modules
    # n'ont ni LXC, ni portail, ni deps.
    p = tmp_path / "lyrion.toml"
    p.write_text(MINIMAL)
    m = load_manifest(p)
    assert m.lxc is None and m.portal_domain is None
    assert m.priority == 50 and m.protected is False and m.needs == ()


@pytest.mark.parametrize("field,original,bad", [
    ("runtime", 'runtime  = "native"', 'runtime  = "docker"'),
    ("exposure", 'exposure = "lan"', 'exposure = "world"'),
    ("category", 'category = "media"', 'category = "divers"'),
])
def test_rejects_unknown_enum(tmp_path, field, original, bad):
    # Une valeur inconnue doit échouer bruyamment : un manifeste mal typé
    # deviendrait une décision d'extinction erronée en Phase 3.
    src = MINIMAL.replace(original, bad)
    # Sanity check: the substitution must actually have happened, otherwise
    # this test would silently exercise the unchanged MINIMAL fixture.
    assert src != MINIMAL
    # The filename must match MINIMAL's id ("lyrion") so the id-vs-filename
    # check passes and the enum validator is the one actually reached.
    p = tmp_path / "lyrion.toml"
    p.write_text(src)
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_rejects_lxc_runtime_without_lxc_name(tmp_path):
    p = tmp_path / "lyrion.toml"
    p.write_text(MINIMAL.replace('runtime  = "native"', 'runtime  = "lxc"'))
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_rejects_priority_out_of_range(tmp_path):
    p = tmp_path / "lyrion.toml"
    p.write_text(MINIMAL + "\npriority = 101\n")
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_rejects_needs_as_bare_string(tmp_path):
    # `needs = "auth"` (forgotten brackets) must not silently explode into
    # ('a', 'u', 't', 'h') via tuple(str) — it must fail loudly.
    p = tmp_path / "lyrion.toml"
    p.write_text(MINIMAL + '\nneeds = "auth"\n')
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_rejects_protected_as_string(tmp_path):
    # `protected = "false"` must not be coerced by Python truthiness into
    # True — protected gates whether a module may ever be shut down.
    p = tmp_path / "lyrion.toml"
    p.write_text(MINIMAL + '\nprotected = "false"\n')
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_rejects_id_mismatching_filename(tmp_path):
    # L'id pilote pins/profils ; s'il diverge du nom de fichier, un pin
    # viserait un module fantôme.
    p = tmp_path / "autre.toml"
    p.write_text(MINIMAL)
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_load_all_indexes_by_id_and_skips_non_toml(tmp_path):
    (tmp_path / "lyrion.toml").write_text(MINIMAL)
    (tmp_path / "peertube.toml").write_text(FULL)
    (tmp_path / "notes.txt").write_text("ignore me")
    all_m = load_all(tmp_path)
    assert sorted(all_m) == ["lyrion", "peertube"]
    assert all_m["peertube"].runtime == "lxc"
