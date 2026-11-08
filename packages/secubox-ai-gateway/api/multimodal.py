# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox AI Gateway :: entrées multimodales (#3571)

Messages au format OpenAI à parties : `{"type": "text"}`, `{"type": "image_url"}` (URL `data:` seulement) et
`{"type": "input_audio"}` et `{"type": "input_video"}` (alias `video_url`). Le décodage et la compréhension restent ceux du moteur (llama-server + libmtmd) :
la passerelle ne fait que valider, borner et router.

Règle de souveraineté : une requête qui porte un média ne quitte jamais la box (classée LOCAL_ONLY).
Seules les données incluses dans la requête sont acceptées : llama-server sait aussi lire une URL distante ou
un fichier local (`file://`), ce qui ferait de la passerelle un relais de téléchargement ou de lecture de
fichiers de la box. Toute clé `url` qui n'est pas un `data:` est donc refusée.
"""
import base64
import binascii
import re
from typing import Any, Dict, Iterable, List, Set

IMAGES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
AUDIOS = {"wav", "mp3"}                          # formats `input_audio` acceptés par llama-server
VIDEOS = {"video/mp4", "video/webm", "video/quicktime", "video/x-matroska"}   # découpées par FFmpeg côté moteur
MAX_OCTETS_MEDIA = 8 * 1024 * 1024               # par partie, une fois décodée
MAX_PARTIES_MEDIA = 8                            # par requête
MAX_OCTETS_VIDEO = 32 * 1024 * 1024              # une vidéo, une fois décodée

_DATA_URL = re.compile(r"^data:([a-z0-9.+-]+/[a-z0-9.+-]+);base64,([A-Za-z0-9+/=\s]+)$", re.I)


class MediaRefuse(ValueError):
    """Partie média invalide : la requête est refusée en 400, sans jamais être transmise."""


def _parties(content: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(content, list):
        for p in content:
            if isinstance(p, dict):
                yield p


def texte_de(content: Any) -> str:
    """Le texte d'un contenu, simple ou à parties : c'est lui que le classifieur lit."""
    if isinstance(content, str):
        return content
    return "\n".join(str(p.get("text", "")) for p in _parties(content) if p.get("type") == "text")


def _taille_b64(donnees: str) -> int:
    try:
        return len(base64.b64decode(re.sub(r"\s", "", donnees), validate=True))
    except (binascii.Error, ValueError):
        raise MediaRefuse("média : base64 illisible") from None


def modalites(messages: List[Dict[str, Any]]) -> Set[str]:
    """Valide chaque partie média et rend les modalités demandées ({"image", "audio", "video"})."""
    vues: Set[str] = set()
    n = 0
    for msg in messages:
        for p in _parties(msg.get("content")):
            t = p.get("type")
            if t == "text":
                continue
            n += 1
            if n > MAX_PARTIES_MEDIA:
                raise MediaRefuse(f"média : {MAX_PARTIES_MEDIA} parties au plus par requête")
            if t == "image_url":
                url = (p.get("image_url") or {}).get("url", "") if isinstance(p.get("image_url"), dict) else ""
                m = _DATA_URL.match(url)
                if not m:
                    raise MediaRefuse("image : seule une URL data: est acceptée (aucun téléchargement par la box)")
                if m.group(1).lower() not in IMAGES:
                    raise MediaRefuse(f"image : type {m.group(1)} refusé ({', '.join(sorted(IMAGES))})")
                if _taille_b64(m.group(2)) > MAX_OCTETS_MEDIA:
                    raise MediaRefuse(f"image : {MAX_OCTETS_MEDIA // (1024 * 1024)} Mo au plus")
                vues.add("image")
            elif t == "input_audio":
                a = p.get("input_audio") if isinstance(p.get("input_audio"), dict) else {}
                if a.get("url"):
                    raise MediaRefuse("audio : URL refusée, envoyez les données (champ data)")
                if str(a.get("format", "")).lower() not in AUDIOS:
                    raise MediaRefuse(f"audio : format refusé ({', '.join(sorted(AUDIOS))})")
                if _taille_b64(str(a.get("data", ""))) > MAX_OCTETS_MEDIA:
                    raise MediaRefuse(f"audio : {MAX_OCTETS_MEDIA // (1024 * 1024)} Mo au plus")
                vues.add("audio")
            elif t in ("input_video", "video_url"):
                v = p.get(t) if isinstance(p.get(t), dict) else {}
                url = str(v.get("data") or v.get("url") or "")
                m = _DATA_URL.match(url)
                if not m:
                    raise MediaRefuse("vidéo : seule une URL data: est acceptée (aucun fichier ni téléchargement)")
                if m.group(1).lower() not in VIDEOS:
                    raise MediaRefuse(f"vidéo : type {m.group(1)} refusé ({', '.join(sorted(VIDEOS))})")
                if _taille_b64(m.group(2)) > MAX_OCTETS_VIDEO:
                    raise MediaRefuse(f"vidéo : {MAX_OCTETS_VIDEO // (1024 * 1024)} Mo au plus")
                vues.add("video")
            else:
                raise MediaRefuse(f"partie de type {t!r} non prise en charge")
    return vues


def modalites_moteur(props: Dict[str, Any]) -> Dict[str, bool]:
    """Modalités déclarées par llama-server (`GET /props` → `modalities`). Rien n'est supposé : absent = non."""
    m = props.get("modalities") if isinstance(props, dict) else None
    m = m if isinstance(m, dict) else {}
    return {"text": True, "image": bool(m.get("vision")), "audio": bool(m.get("audio")),
            "video": bool(m.get("video"))}
