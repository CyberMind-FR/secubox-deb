# packages/secubox-metablogizer/api/tests/test_publish_backup.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import subprocess
from pathlib import Path

from publish.backup import export_site, import_site


def _git_site(tmp_path) -> Path:
    site = tmp_path / "zem"; (site / "public").mkdir(parents=True)
    (site / "public" / "index.html").write_text("<h1>zem</h1>")
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "PATH": __import__("os").environ["PATH"]}
    subprocess.run(["git", "init", "-q"], cwd=site, check=True, env=env)
    subprocess.run(["git", "add", "-A"], cwd=site, check=True, env=env)
    subprocess.run(["git", "commit", "-qm", "v1"], cwd=site, check=True, env=env)
    return site


def test_export_import_roundtrip_with_git(tmp_path):
    site = _git_site(tmp_path)
    manifest = {"name": "zem", "domain": "zem.gk2.secubox.in", "version": "v1"}
    art = export_site(site, manifest, tmp_path / "out")
    assert art.name == "zem.sbxsite" and art.exists()
    dest = tmp_path / "restored"; dest.mkdir()
    got = import_site(art, dest)
    assert got["domain"] == "zem.gk2.secubox.in"
    assert (dest / "zem" / "public" / "index.html").read_text() == "<h1>zem</h1>"


def test_export_without_git_uses_content_tar(tmp_path):
    site = tmp_path / "plain"; (site / "public").mkdir(parents=True)
    (site / "public" / "index.html").write_text("<h1>plain</h1>")
    art = export_site(site, {"name": "plain", "domain": "plain.gk2.secubox.in"}, tmp_path / "out")
    dest = tmp_path / "r2"; dest.mkdir()
    import_site(art, dest)
    assert (dest / "plain" / "public" / "index.html").read_text() == "<h1>plain</h1>"


def test_import_rejects_traversal_name(tmp_path):
    import json, tarfile
    from publish.backup import import_site
    staging = tmp_path / "s"; staging.mkdir()
    (staging / "public").mkdir()
    (staging / "public" / "i.html").write_text("x")
    with tarfile.open(staging / "content.tar", "w") as t:
        t.add(staging / "public", arcname="public")
    (staging / "manifest.json").write_text(json.dumps({"name": "../../etc"}))
    art = tmp_path / "evil.sbxsite"
    with tarfile.open(art, "w:gz") as t:
        t.add(staging / "content.tar", arcname="content.tar")
        t.add(staging / "manifest.json", arcname="manifest.json")
    dest = tmp_path / "dest"; dest.mkdir()
    import pytest
    with pytest.raises(ValueError):
        import_site(art, dest)
