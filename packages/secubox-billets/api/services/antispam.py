# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Anti-spam primitives for the public comment form.

Three layers: an invisible honeypot field (bots fill it), a signed
submission-time token enforcing a minimum think-time (and a max age), and a
per-ip_hash rate limit (reused from services.security). Comment emails are
BLAKE2b-hashed at rest — never stored in clear, never displayed."""
from __future__ import annotations

import hashlib

from itsdangerous import BadSignature, Signer

_SALT = "billets.form.v1"


def honeypot_tripped(value: str | None) -> bool:
    return bool(value and value.strip())


def issue_form_token(secret: str, *, now_epoch: int) -> str:
    return Signer(secret, salt=_SALT).sign(str(int(now_epoch))).decode("ascii")


def form_token_etat(secret: str, token: str, *, now_epoch: int,
                    min_delay: int = 3, max_age: int = 3600) -> str:
    """POURQUOI le jeton est refusé : "ok", "trop_tot", "expire" ou "invalide".

    UN SEUL BOOLÉEN NE SUFFISAIT PAS, ET LE MESSAGE MENTAIT (#1372). Trois
    causes très différentes rendaient `False`, et l'appelant n'avait qu'un
    « non » pour les trois — il affichait donc « trop vite — réessayez » dans
    les trois cas.

    Or, depuis que le délai de réflexion vaut zéro par défaut (#1268),
    « trop tôt » ne peut PLUS arriver. Le seul refus que rencontre un visiteur
    réel est l'EXPIRATION — une page ouverte depuis plus d'une heure. Le
    message lui reprochait donc exactement l'inverse de ce qu'il avait fait :
    il avait été trop LENT.

    Un message qui accuse à contresens est pire qu'un message absent : il
    envoie la personne corriger un comportement qui n'était pas en cause, et
    elle réessaie plus lentement — ce qui échoue encore.
    """
    try:
        issued = int(Signer(secret, salt=_SALT).unsign(token).decode("ascii"))
    except (BadSignature, ValueError, Exception):
        return "invalide"
    delay = now_epoch - issued
    if delay < min_delay:
        return "trop_tot"
    if delay > max_age:
        return "expire"
    return "ok"


def form_token_ok(secret: str, token: str, *, now_epoch: int,
                  min_delay: int = 3, max_age: int = 3600) -> bool:
    """True when the token is authentic and its age is within [min_delay, max_age].

    Conservée : `form_token_etat` porte la nuance, celle-ci garde la forme
    booléenne pour les appelants qui n'en ont pas besoin.
    """
    return form_token_etat(secret, token, now_epoch=now_epoch,
                           min_delay=min_delay, max_age=max_age) == "ok"


def email_hash(email: str | None, secret: str) -> str | None:
    if not email:
        return None
    return hashlib.blake2b(f"{secret}\x1f{email.strip().lower()}".encode("utf-8"),
                           digest_size=16).hexdigest()
