#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: fetch-signal-stickers
CyberMind — https://cybermind.fr

Récupère et DÉCHIFFRE un pack d'autocollants Signal (les nôtres, ex.
« zanimalos ») pour l'AUTO-HÉBERGER : aucune requête navigateur vers
signal.org (conforme CSPN). Sort un PNG par sticker + un manifest.json
(id → emoji), et sait renommer par RÔLE applicatif (published/draft/…).

Les packs Signal vivent chiffrés sur cdn2.signal.org. La pack_key dérive, via
HKDF-SHA256 (sel = 32×0x00, info = "Sticker Pack", 64 octets), en
[32 aesKey][32 hmacKey]. Chaque blob = [16 IV][AES-256-CBC][32 HMAC-SHA256].
Le manifest est un protobuf Pack{title=1, author=2, cover=3, stickers[]=4
{id=1, emoji=2}}.

Exemples :
  # tout le pack → PNG {id}.png + manifest.json
  fetch-signal-stickers.py --pack <ID> --key <KEY> --out /tmp/stickers

  # renommer par rôle applicatif (published←6, draft←2, archived←9)
  fetch-signal-stickers.py --pack <ID> --key <KEY> --out .../static/stickers \\
      --map published=6,draft=2,archived=9
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import urllib.request
from pathlib import Path

CDNS = ("https://cdn2.signal.org", "https://cdn.signal.org", "https://cdn-ca.signal.org")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1] if pt else 0
    return pt[:-pad] if 0 < pad <= 16 else pt


def decrypt(blob: bytes, key_hex: str) -> bytes:
    key = bytes.fromhex(key_hex)
    dk = hkdf_sha256(key, b"\x00" * 32, b"Sticker Pack", 64)
    aes_key, hmac_key = dk[:32], dk[32:]
    iv, ct, their_mac = blob[:16], blob[16:-32], blob[-32:]
    our_mac = hmac.new(hmac_key, blob[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(our_mac, their_mac):
        raise ValueError("HMAC invalide — mauvaise clé ou données corrompues")
    return _aes_cbc_decrypt(aes_key, iv, ct)


def fetch(path: str) -> bytes:
    last: Exception | None = None
    for base in CDNS:
        try:
            req = urllib.request.Request(base + path, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=25) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 — on essaie le CDN suivant
            last = e
    raise RuntimeError(f"échec de récupération {path} sur tous les CDN : {last}")


# ── Décodeur protobuf minimal (pas de dépendance protoc) ────────────────────
def _varint(b: bytes, i: int):
    v = s = 0
    while True:
        x = b[i]
        i += 1
        v |= (x & 0x7F) << s
        if not (x & 0x80):
            return v, i
        s += 7


def _parse_sticker(pb: bytes) -> dict:
    st = {"id": None, "emoji": ""}
    i = 0
    while i < len(pb):
        tag, i = _varint(pb, i)
        field, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = _varint(pb, i)
            if field == 1:
                st["id"] = v
        elif wt == 2:
            ln, i = _varint(pb, i)
            val, i = pb[i:i + ln], i + ln
            if field == 2:
                st["emoji"] = val.decode("utf-8", "replace")
        else:
            raise ValueError(f"wire type {wt} inattendu (sticker)")
    return st


def parse_pack(pb: bytes) -> dict:
    out = {"title": "", "author": "", "cover": None, "stickers": []}
    i = 0
    while i < len(pb):
        tag, i = _varint(pb, i)
        field, wt = tag >> 3, tag & 7
        if wt == 2:
            ln, i = _varint(pb, i)
            val, i = pb[i:i + ln], i + ln
            if field == 1:
                out["title"] = val.decode("utf-8", "replace")
            elif field == 2:
                out["author"] = val.decode("utf-8", "replace")
            elif field == 3:
                out["cover"] = _parse_sticker(val)
            elif field == 4:
                out["stickers"].append(_parse_sticker(val))
        elif wt == 0:
            _, i = _varint(pb, i)
        else:
            raise ValueError(f"wire type {wt} inattendu (pack)")
    return out


def _ext(data: bytes) -> str:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return "bin"


def parse_map(spec: str) -> dict:
    """« published=6,draft=2 » → {'published': 6, ...}."""
    out = {}
    for part in filter(None, (p.strip() for p in spec.split(","))):
        role, _, sid = part.partition("=")
        out[role.strip()] = int(sid)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Récupère + déchiffre un pack Signal (auto-hébergement).")
    ap.add_argument("--pack", required=True, help="pack_id (hex)")
    ap.add_argument("--key", required=True, help="pack_key (hex)")
    ap.add_argument("--out", required=True, type=Path, help="dossier de sortie")
    ap.add_argument("--map", default="", help="rôles → id, ex. published=6,draft=2,archived=9")
    ap.add_argument("--list", action="store_true", help="liste seulement (n'écrit rien)")
    a = ap.parse_args(argv)

    manifest = decrypt(fetch(f"/stickers/{a.pack}/manifest.proto"), a.key)
    pack = parse_pack(manifest)
    print(f"pack « {pack['title']} » par {pack['author']} — {len(pack['stickers'])} stickers")
    for s in pack["stickers"]:
        print(f"  id={s['id']:>3}  emoji={s['emoji']!r}")
    if a.list:
        return 0

    roles = parse_map(a.map)
    by_id = {v: k for k, v in roles.items()}
    a.out.mkdir(parents=True, exist_ok=True)
    written = []
    for s in pack["stickers"]:
        data = decrypt(fetch(f"/stickers/{a.pack}/full/{s['id']}"), a.key)
        ext = _ext(data)
        name = f"{by_id.get(s['id'], s['id'])}.{ext}"
        (a.out / name).write_bytes(data)
        written.append({"id": s["id"], "emoji": s["emoji"],
                        "role": by_id.get(s["id"]), "file": name})
        print(f"  écrit {name} ({len(data)} octets, {ext})")

    (a.out / "manifest.json").write_text(json.dumps(
        {"title": pack["title"], "author": pack["author"], "stickers": written},
        ensure_ascii=False, indent=2))
    print(f"manifest.json → {a.out/'manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
