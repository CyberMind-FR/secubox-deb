# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import io
import zipfile
from pathlib import Path

import pytest

from publish.content import extract_archive, ContentError


def _zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in members.items():
            z.writestr(name, body)
    return buf.getvalue()


def test_clean_zip_extracts(tmp_path):
    doc = tmp_path / "public"; doc.mkdir()
    res = extract_archive(doc, _zip({"index.html": "<h1>hi</h1>", "css/a.css": "body{}"}), "site.zip")
    assert (doc / "index.html").read_text() == "<h1>hi</h1>"
    assert (doc / "css" / "a.css").exists()
    assert res["index_present"] is True and res["files"] == 2


def test_zip_slip_rejected(tmp_path):
    doc = tmp_path / "public"; doc.mkdir()
    with pytest.raises(ContentError):
        extract_archive(doc, _zip({"../escape.html": "x"}), "evil.zip")
    assert not (tmp_path / "escape.html").exists()


def test_absolute_member_rejected(tmp_path):
    doc = tmp_path / "public"; doc.mkdir()
    with pytest.raises(ContentError):
        extract_archive(doc, _zip({"/etc/passwd": "x"}), "evil.zip")


def test_single_html_becomes_index(tmp_path):
    doc = tmp_path / "public"; doc.mkdir()
    res = extract_archive(doc, b"<h1>solo</h1>", "whatever.html")
    assert (doc / "index.html").read_text() == "<h1>solo</h1>"
    assert res["index_present"] is True


def test_zip_replaces_previous_content(tmp_path):
    doc = tmp_path / "public"; doc.mkdir()
    (doc / "old.html").write_text("old")
    extract_archive(doc, _zip({"index.html": "new"}), "s.zip")
    assert not (doc / "old.html").exists()
