# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Pydantic v2 models + closed enums + slug helper.

Every external input has strict validation and size limits (a hard security
requirement). URLs are constrained to https only (SSRF defence starts at the
type level; DNS/redirect checks happen at fetch time in services/)."""
from __future__ import annotations

import enum
import re
import unicodedata
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator


class BilletStatus(str, enum.Enum):
    draft = "draft"
    published = "published"
    archived = "archived"


class CommentStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


class ReactionEmoji(str, enum.Enum):
    thumbs_up = "👍"
    heart = "❤️"
    laugh = "😂"
    wow = "😮"
    sad = "😢"
    fire = "🔥"


# ── size limits (bytes/chars) ─────────────────────────────────────────────
BODY_MAX = 8000
COMMENT_MAX = 2000
AUTHOR_NAME_MIN, AUTHOR_NAME_MAX = 2, 40
URL_MAX = 2048

_HttpsUrl = Annotated[str, StringConstraints(strip_whitespace=True, max_length=URL_MAX)]


def _require_https(v: Optional[str]) -> Optional[str]:
    if v is None or v == "":
        return None
    if not re.match(r"^https://[^\s/$.?#].[^\s]*$", v, re.IGNORECASE):
        raise ValueError("URL must be an absolute https:// URL")
    return v


# ── slug ──────────────────────────────────────────────────────────────────
def slugify(text: str, *, suffix: str, max_words: int = 6) -> str:
    """Slug from the first words of the body + a short unique suffix.

    NFKD-fold to ASCII, lowercase, keep [a-z0-9-], collapse dashes. The suffix
    (caller-supplied, e.g. the ULID's tail) guarantees uniqueness."""
    norm = unicodedata.normalize("NFKD", text)
    ascii_txt = norm.encode("ascii", "ignore").decode("ascii").lower()
    words = re.findall(r"[a-z0-9]+", ascii_txt)[:max_words]
    base = "-".join(words) if words else "billet"
    base = base[:60].strip("-") or "billet"
    return f"{base}-{suffix.lower()}"


# ── input models ────────────────────────────────────────────────────────
class BilletIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    body: Annotated[str, StringConstraints(min_length=1, max_length=BODY_MAX)]
    ref_url: Optional[_HttpsUrl] = None
    embed_url: Optional[_HttpsUrl] = None
    style: Literal["default", "communique"] = "default"
    publish: bool = False

    @field_validator("ref_url", "embed_url")
    @classmethod
    def _https_only(cls, v: Optional[str]) -> Optional[str]:
        return _require_https(v)


class CommentIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    author_name: Annotated[str, StringConstraints(min_length=AUTHOR_NAME_MIN, max_length=AUTHOR_NAME_MAX)]
    author_email: Optional[Annotated[str, StringConstraints(max_length=254)]] = None
    body: Annotated[str, StringConstraints(min_length=2, max_length=COMMENT_MAX)]
    # anti-spam fields (validated in services/antispam, present on the form)
    website: str = ""          # honeypot — must stay empty
    ts_token: str = ""         # signed submission-time token

    @field_validator("author_email")
    @classmethod
    def _email_shape(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("invalid email")
        return v


class ReactionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    emoji: ReactionEmoji


# ── row models (what the DB returns) ──────────────────────────────────────
class Billet(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: str
    updated_at: str
    published_at: Optional[str] = None
    body: str
    ref_url: Optional[str] = None
    embed_url: Optional[str] = None
    embed_html: Optional[str] = None
    embed_provider: Optional[str] = None
    embed_fetched_at: Optional[str] = None
    slug: str
    status: BilletStatus
    style: str = "default"
    embed_snapshot: Optional[str] = None
    view_count: int = 0


class Comment(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    billet_id: str
    created_at: str
    author_name: str
    body: str
    status: CommentStatus
