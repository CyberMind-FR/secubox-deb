# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import pytest
from pydantic import ValidationError

from api.models import BilletIn, CommentIn, ReactionEmoji, ReactionIn, slugify


def test_slugify_ascii_folds_and_suffixes():
    s = slugify("Héllo, thé Wörld! Encore", suffix="Z29K")
    assert s == "hello-the-world-encore-z29k"
    assert slugify("", suffix="AB") == "billet-ab"


def test_billet_in_rejects_non_https():
    with pytest.raises(ValidationError):
        BilletIn(body="hi", ref_url="http://insecure.example/x")
    with pytest.raises(ValidationError):
        BilletIn(body="hi", embed_url="javascript:alert(1)")


def test_billet_in_accepts_https_and_empty():
    b = BilletIn(body="hi", ref_url="https://example.com/a", publish=True)
    assert str(b.ref_url) == "https://example.com/a"
    assert BilletIn(body="hi").ref_url is None


def test_billet_body_size_limit():
    with pytest.raises(ValidationError):
        BilletIn(body="x" * 8001)


def test_comment_name_bounds_and_email():
    with pytest.raises(ValidationError):
        CommentIn(author_name="x", body="valid body")          # name too short
    with pytest.raises(ValidationError):
        CommentIn(author_name="ok", body="valid", author_email="notanemail")
    c = CommentIn(author_name="Alice", body="nice post", author_email="a@b.co")
    assert c.author_email == "a@b.co"
    assert c.website == ""  # honeypot default empty


def test_reaction_enum_closed():
    assert ReactionIn(emoji="🔥").emoji is ReactionEmoji.fire
    with pytest.raises(ValidationError):
        ReactionIn(emoji="💩")
