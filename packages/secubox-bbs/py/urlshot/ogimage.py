# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: BBS urlshot :: ogimage
CyberMind — https://cybermind.fr

Extraction de la miniature `og:image` (repli `twitter:image`) d'une page
HTML, puis téléchargement de l'image — les deux étapes passent par le garde
SSRF `egress.url_interdite()` (page ET image, cf. Global Constraints #1120).

Le client `cli` est duck-typé (`.get(url)` -> objet `.status_code` /
`.headers` / `.content` / `.text`) : les tests fournissent un client factice
sans dépendre de httpx (`Recommends` Debian, pas une dépendance dure).
Parsing HTML stdlib uniquement (`html.parser`), pas de BeautifulSoup.
"""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin

import egress

_MAX_HTML = 2 * 1024 * 1024  # 2 MiB
_MAX_IMAGE = 8 * 1024 * 1024  # 8 MiB


class _MetaOgImageParser(HTMLParser):
    """Cherche <meta property="og:image" content="..."> (ou name=), avec
    repli sur twitter:image. Insensible à la casse sur le nom d'attribut."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.og_image: str | None = None
        self.twitter_image: str | None = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "meta":
            return
        attrs_l = {k.lower(): (v or "") for k, v in attrs}
        cle = attrs_l.get("property") or attrs_l.get("name") or ""
        cle = cle.strip().lower()
        contenu = attrs_l.get("content")
        if not contenu:
            return
        if cle == "og:image" and self.og_image is None:
            self.og_image = contenu
        elif cle == "twitter:image" and self.twitter_image is None:
            self.twitter_image = contenu


def _extrait_image_meta(html: str) -> str | None:
    parser = _MetaOgImageParser()
    try:
        parser.feed(html)
    except Exception:
        # HTML malformé : ne pas planter, se contenter de ce qui a été vu.
        pass
    return parser.og_image or parser.twitter_image


def _corps_capped(resp, cap: int) -> bytes:
    """Renvoie le contenu de la réponse, tronqué à `cap` octets. Le client
    factice/httpx expose déjà `.content` en mémoire ; on borne ici en aval
    pour ne jamais retourner/traiter plus que le plafond annoncé."""
    contenu = resp.content
    if contenu is None:
        return b""
    return contenu[:cap]


def cherche_og_image(url: str, cli) -> bytes | None:
    """Renvoie les octets bruts de l'image og:image/twitter:image de `url`,
    ou None si la page/l'image est refusée, absente, ou invalide."""
    if egress.url_interdite(url):
        return None

    try:
        resp = cli.get(url)
    except Exception:
        return None

    if resp is None or getattr(resp, "status_code", None) is None:
        return None
    if not (200 <= resp.status_code < 300):
        return None

    content_type = str(resp.headers.get("content-type", "")).lower()
    if "text/html" not in content_type:
        return None

    html = getattr(resp, "text", None)
    if html is None:
        html = _corps_capped(resp, _MAX_HTML).decode("utf-8", errors="replace")
    else:
        html = html[: _MAX_HTML]

    image_ref = _extrait_image_meta(html)
    if not image_ref:
        return None

    image_url = urljoin(url, image_ref.strip())

    if egress.url_interdite(image_url):
        return None

    try:
        img_resp = cli.get(image_url)
    except Exception:
        return None

    if img_resp is None or getattr(img_resp, "status_code", None) is None:
        return None
    if not (200 <= img_resp.status_code < 300):
        return None

    img_content_type = str(img_resp.headers.get("content-type", "")).lower()
    if not img_content_type.startswith("image/"):
        return None

    return _corps_capped(img_resp, _MAX_IMAGE)
