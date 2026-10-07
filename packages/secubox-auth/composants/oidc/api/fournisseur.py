# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-oidc — le fournisseur, sans HTTP (#1589).

Un service de la box (PhotoPrism, Mastodon…) ouvre le compte d'une personne
d'après SA SESSION SECUBOX, sans mot de passe. Ce fichier tient ce qui doit
être juste indépendamment du transport : clés, clients, codes, jetons.

CE QUI TIENT LA SÉCURITÉ :
  - un CODE est à usage unique, vit 60 s, et reste lié au client, à la
    redirect_uri EXACTE et au défi PKCE qui l'ont demandé ;
  - les codes, jetons d'accès et secrets de clients ne sont gardés que HACHÉS ;
  - l'id_token est signé RS256 par une clé propre à la box (jamais le secret
    des sessions) ; la partie publique est publiée (JWKS) ;
  - une redirect_uri n'est jamais « presque » la bonne : égalité stricte.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CLE = Path(os.environ.get("SECUBOX_OIDC_CLE", "/etc/secubox/secrets/oidc/signing.pem"))
CLIENTS = Path(os.environ.get("SECUBOX_OIDC_CLIENTS", "/etc/secubox/oidc/clients.json"))
BASE = Path(os.environ.get("SECUBOX_OIDC_DB", "/var/lib/secubox/oidc/oidc.db"))

DUREE_CODE = 60
DUREE_JETON = 600
DUREE_ID = 300


class Refus(Exception):
    """Erreur OAuth : `code` est l'identifiant normalisé (invalid_grant…)."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code


def empreinte(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ── Clé de signature ────────────────────────────────────────────────────────

def cree_cle(chemin: Path = None) -> bool:
    """Crée la clé RSA si elle manque. Jamais réécrite : la changer
    invaliderait tout id_token en circulation. Rend True si créée."""
    chemin = chemin or CLE
    if chemin.exists():
        return False
    chemin.parent.mkdir(parents=True, exist_ok=True)
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
    fd, tmp = tempfile.mkstemp(dir=str(chemin.parent))
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    os.chmod(tmp, 0o600)
    os.replace(tmp, chemin)
    return True


def _cle_privee(chemin: Path = None):
    return serialization.load_pem_private_key((chemin or CLE).read_bytes(), password=None)


def jwks(chemin: Path = None) -> dict:
    pub = _cle_privee(chemin).public_key().public_numbers()
    n = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")
    e = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")
    j = {"kty": "RSA", "use": "sig", "alg": "RS256", "n": _b64u(n), "e": _b64u(e)}
    j["kid"] = empreinte(j["n"])[:16]
    return {"keys": [j]}


def signe_id_token(claims: dict, chemin: Path = None) -> str:
    kid = jwks(chemin)["keys"][0]["kid"]
    return jwt.encode(claims, _cle_privee(chemin), algorithm="RS256", headers={"kid": kid})


# ── Clients ────────────────────────────────────────────────────────────────

def clients(chemin: Path = None) -> dict:
    try:
        d = json.loads((chemin or CLIENTS).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def client(client_id: str, chemin: Path = None) -> Optional[dict]:
    c = clients(chemin).get(str(client_id or ""))
    return c if isinstance(c, dict) else None


def verifie_redirection(c: dict, redirect_uri: str) -> None:
    if redirect_uri not in (c.get("redirect_uris") or []):
        raise Refus("invalid_request", "redirect_uri non enregistrée pour ce client")


def authentifie_client(client_id: str, secret: str, chemin: Path = None) -> dict:
    c = client(client_id, chemin)
    if not c or not secret or not hmac.compare_digest(empreinte(secret), str(c.get("secret_sha256", ""))):
        raise Refus("invalid_client", "client inconnu ou secret faux")
    return c


# ── Codes et jetons ────────────────────────────────────────────────────────

def _db(chemin: Path = None) -> sqlite3.Connection:
    p = chemin or BASE
    p.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(p), timeout=5, isolation_level=None)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE IF NOT EXISTS codes (h TEXT PRIMARY KEY, client TEXT, redirect TEXT,"
              " claims TEXT, nonce TEXT, defi TEXT, methode TEXT, exp INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS jetons (h TEXT PRIMARY KEY, client TEXT, claims TEXT, exp INTEGER)")
    return c


def emet_code(client_id: str, redirect_uri: str, claims: dict, nonce: str = "",
              defi: str = "", methode: str = "", chemin: Path = None) -> str:
    if defi and methode not in ("S256",):
        raise Refus("invalid_request", "seul code_challenge_method=S256 est accepté")
    code = secrets.token_urlsafe(32)
    c = _db(chemin)
    try:
        now = int(time.time())
        c.execute("DELETE FROM codes WHERE exp < ?", (now,))
        c.execute("DELETE FROM jetons WHERE exp < ?", (now,))
        c.execute("INSERT INTO codes VALUES (?,?,?,?,?,?,?,?)",
                  (empreinte(code), client_id, redirect_uri, json.dumps(claims),
                   nonce or "", defi or "", methode or "", now + DUREE_CODE))
    finally:
        c.close()
    return code


def echange_code(code: str, client_id: str, redirect_uri: str, verifier: str = "",
                 chemin: Path = None) -> tuple[dict, str]:
    """Consomme le code (usage UNIQUE, même en cas d'échec) ; rend (claims, nonce)."""
    c = _db(chemin)
    try:
        c.execute("BEGIN IMMEDIATE")
        r = c.execute("SELECT client, redirect, claims, nonce, defi, methode, exp FROM codes WHERE h=?",
                      (empreinte(code or ""),)).fetchone()
        c.execute("DELETE FROM codes WHERE h=?", (empreinte(code or ""),))
        c.execute("COMMIT")
    finally:
        c.close()
    if not r:
        raise Refus("invalid_grant", "code inconnu ou déjà utilisé")
    cl, redir, claims, nonce, defi, methode, exp = r
    if exp < time.time():
        raise Refus("invalid_grant", "code expiré")
    if cl != client_id or redir != redirect_uri:
        raise Refus("invalid_grant", "code émis pour un autre client ou une autre redirect_uri")
    if defi:
        attendu = _b64u(hashlib.sha256((verifier or "").encode("ascii", "ignore")).digest())
        if not verifier or not hmac.compare_digest(attendu, defi):
            raise Refus("invalid_grant", "code_verifier PKCE invalide")
    return json.loads(claims), nonce


def emet_jeton(client_id: str, claims: dict, chemin: Path = None) -> str:
    j = secrets.token_urlsafe(32)
    c = _db(chemin)
    try:
        c.execute("INSERT INTO jetons VALUES (?,?,?,?)",
                  (empreinte(j), client_id, json.dumps(claims), int(time.time()) + DUREE_JETON))
    finally:
        c.close()
    return j


def lit_jeton(j: str, chemin: Path = None) -> dict:
    c = _db(chemin)
    try:
        r = c.execute("SELECT claims, exp FROM jetons WHERE h=?", (empreinte(j or ""),)).fetchone()
    finally:
        c.close()
    if not r or r[1] < time.time():
        raise Refus("invalid_token", "jeton d'accès inconnu ou expiré")
    return json.loads(r[0])


def id_token(issuer: str, client_id: str, claims: dict, nonce: str = "", chemin: Path = None) -> str:
    now = int(time.time())
    corps = {"iss": issuer, "aud": client_id, "iat": now, "exp": now + DUREE_ID,
             "auth_time": claims.get("auth_time", now), **{k: v for k, v in claims.items() if k != "auth_time"}}
    if nonce:
        corps["nonce"] = nonce
    return signe_id_token(corps, chemin)
