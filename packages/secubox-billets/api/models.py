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

from urllib.parse import urlparse

from pydantic import (BaseModel, ConfigDict, Field, StringConstraints, field_validator,
                      model_validator)


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
COMMENT_MAX = 8000        # #1268 : aligné sur le corps d'un billet (était 2000)
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
# Un lien VIDEO posé dans le corps vaut un embed (#1268). Un producteur qui ne
# remplit pas `embed_url` — le relais BBS n'envoie que `body` + `ref_url`, la
# conversation, jamais la vidéo qu'elle contient — laissait sinon le billet en
# texte nu : pas de lecteur, pas de vignette souveraine, juste une URL brute au
# milieu de la page. On PROMEUT donc le premier lien vidéo du corps quand le
# champ est vide ; un `embed_url` explicite gagne toujours.
_VIDEO_HOSTS = ("youtube.com", "youtu.be", "youtube-nocookie.com",
                "vimeo.com", "dailymotion.com")
_URL_IN_TEXT = re.compile(r"https://[^\s<>\"'\)\]]+")


def video_url_in(body: str | None) -> Optional[str]:
    """Le premier lien vidéo du corps, ou None. Volontairement STRICT : seuls
    les hébergeurs vidéo connus (et les instances PeerTube) sont promus — une
    page ordinaire reste une référence, pas un lecteur."""
    for raw in _URL_IN_TEXT.findall(body or ""):
        url = raw.rstrip(".,;:!?")
        if len(url) > URL_MAX:
            continue
        host = (urlparse(url).hostname or "").lower()
        if not host:
            continue
        if (any(host == h or host.endswith("." + h) for h in _VIDEO_HOSTS)
                or "peertube" in host or host.startswith("tube.")):
            return url
    return None


# ── chronologie audio (#4058) ─────────────────────────────────────────────
# Le diaporama d'un billet qui porte un AUDIO suit sa lecture : chaque réplique dit de quand à quand montrer quelle diapositive
# (index 0-based dans l'ordre des médias IMAGE du billet). Bornes strictes : la chronologie vient d'une chaîne automatique.
CHRONO_MAX_ENTREES = 2000
CHRONO_MAX_OCTETS = 128 * 1024
CHRONO_DUREE_MAX_S = 6 * 3600.0
CHRONO_DIAPO_MAX = 499
REPLIQUE_MAX = 500
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")


class Replique(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=False)
    debut_s: float = Field(ge=0, le=CHRONO_DUREE_MAX_S, allow_inf_nan=False)
    fin_s: float = Field(gt=0, le=CHRONO_DUREE_MAX_S, allow_inf_nan=False)
    diapo: int = Field(ge=0, le=CHRONO_DIAPO_MAX)
    replique: str = Field(default="", max_length=REPLIQUE_MAX * 2)

    @field_validator("diapo", mode="before")
    @classmethod
    def _entier(cls, v):
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("diapo doit être un entier")
        return v

    @field_validator("replique")
    @classmethod
    def _assainir(cls, v: str) -> str:
        """Texte brut : contrôles et marques bidirectionnelles retirés, blancs repliés. L'échappement HTML reste à Jinja au rendu."""
        v = " ".join(_CTRL.sub("", unicodedata.normalize("NFC", v)).split())
        if len(v) > REPLIQUE_MAX:
            raise ValueError(f"replique dépasse {REPLIQUE_MAX} caractères")
        return v

    @model_validator(mode="after")
    def _ordre(self) -> "Replique":
        if self.fin_s <= self.debut_s:
            raise ValueError("fin_s doit être strictement supérieur à debut_s")
        return self


def valider_chronologie(v) -> Optional[list[dict]]:
    """Chronologie validée (liste de dicts) ou None (vide/absente). Lève ValueError au moindre écart : bornes, ordre CROISSANT sans
    chevauchement (debut_s >= fin_s de la précédente), taille. L'existence de la diapositive se vérifie contre les médias (repo)."""
    if v is None:
        return None
    if isinstance(v, (str, bytes)):
        if len(v) > CHRONO_MAX_OCTETS:
            raise ValueError("chronologie trop volumineuse")
        if not str(v).strip():
            return None
        import json
        try:
            v = json.loads(v)
        except ValueError as exc:
            raise ValueError("chronologie : JSON invalide") from exc
    if not isinstance(v, list):
        raise ValueError("chronologie : liste attendue")
    if not v:
        return None
    if len(v) > CHRONO_MAX_ENTREES:
        raise ValueError(f"chronologie : au plus {CHRONO_MAX_ENTREES} répliques")
    out = [Replique.model_validate(e).model_dump() for e in v]
    for a, b in zip(out, out[1:]):
        if b["debut_s"] < a["fin_s"]:
            raise ValueError("chronologie : répliques en ordre croissant, sans chevauchement")
    import json
    if len(json.dumps(out, ensure_ascii=False).encode()) > CHRONO_MAX_OCTETS:
        raise ValueError("chronologie trop volumineuse")
    return out


class BilletIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    body: Annotated[str, StringConstraints(min_length=1, max_length=BODY_MAX)]
    ref_url: Optional[_HttpsUrl] = None
    embed_url: Optional[_HttpsUrl] = None
    style: Literal["default", "communique"] = "default"
    publish: bool = False
    # Durée de vie en secondes (#2268) : le billet quitte le fil à publication + ttl_s. De 30 s à 24 h ; None = durable. Un brouillon n'expire pas.
    ttl_s: Optional[int] = None
    # Chronologie audio (#4058) : liste de répliques (cf. Replique) ou None.
    chronologie: Optional[list[dict]] = None

    @field_validator("chronologie", mode="before")
    @classmethod
    def _chrono(cls, v):
        return valider_chronologie(v)

    @field_validator("ttl_s")
    @classmethod
    def _ttl_borne(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (30 <= v <= 86400):
            raise ValueError("ttl_s doit être compris entre 30 et 86400 secondes")
        return v

    @model_validator(mode="after")
    def _ttl_exige_publication(self) -> "BilletIn":
        if self.ttl_s is not None and not self.publish:
            raise ValueError("ttl_s exige publish=True : l'horloge d'un billet éphémère part à sa publication")
        return self

    @field_validator("ref_url", "embed_url")
    @classmethod
    def _https_only(cls, v: Optional[str]) -> Optional[str]:
        return _require_https(v)

    @model_validator(mode="after")
    def _embed_depuis_le_corps(self) -> "BilletIn":
        if not self.embed_url:
            found = video_url_in(self.body)
            if found:
                self.embed_url = found
        return self


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
    expires_at: Optional[str] = None
    chronologie: Optional[str] = None


class Comment(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    billet_id: str
    created_at: str
    author_name: str
    body: str
    status: CommentStatus
