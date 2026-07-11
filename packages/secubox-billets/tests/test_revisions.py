# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Gitea-backed revision store — content + style versioned per billet."""
from pathlib import Path

from api.services import revisions


def _meta(status="published"):
    return {"slug": "hello-01ab", "status": status, "created_at": "2026-07-11T12:00:00Z",
            "updated_at": "2026-07-11T12:00:00Z", "published_at": "2026-07-11T12:00:00Z",
            "style": "default"}


def test_commit_creates_history(tmp_path):
    repo_dir = tmp_path / "revs"
    r1 = revisions.commit_revision(repo_dir, "01AB", "**hello** v1", _meta(), "publish 01AB")
    assert r1["committed"] is True and r1["commit"]
    assert r1["reason"] == "no-remote"  # no origin configured
    # edit → second revision
    r2 = revisions.commit_revision(repo_dir, "01AB", "**hello** v2 edited", _meta(), "edit 01AB")
    assert r2["committed"] is True and r2["commit"] != r1["commit"]
    hist = revisions.list_revisions(repo_dir, "01AB")
    assert len(hist) == 2
    assert hist[0]["message"] == "edit 01AB"  # newest first


def test_no_change_is_noop(tmp_path):
    repo_dir = tmp_path / "revs"
    revisions.commit_revision(repo_dir, "01CD", "same body", _meta(), "publish")
    again = revisions.commit_revision(repo_dir, "01CD", "same body", _meta(), "publish again")
    assert again["committed"] is False and again["reason"] == "no-change"


def test_front_matter_carries_style_and_meta(tmp_path):
    repo_dir = tmp_path / "revs"
    revisions.commit_revision(repo_dir, "01EF", "body text", _meta(status="draft"), "draft")
    doc = (repo_dir / "billets" / "01EF.md").read_text()
    assert doc.startswith("---")
    assert '"draft"' in doc and '"default"' in doc  # status + style in front-matter
    assert "body text" in doc


def test_document_render_is_deterministic():
    doc = revisions.revision_document("hi", _meta())
    assert doc == revisions.revision_document("hi", _meta())
