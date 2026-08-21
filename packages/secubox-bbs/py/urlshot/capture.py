# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: BBS urlshot :: capture
CyberMind — https://cybermind.fr

Orchestrateur de capture de la vignette d'une URL citée dans un post BBS :

1. `ogimage.cherche_og_image()` — rapide, léger : une page HTML + une image,
   via le client d'égress `egress.client()` (proxy sbxmitm + CA de
   confiance).
2. Repli screenshot chromium (`secubox_core.shotter.capture`), UNIQUEMENT si
   aucune image og:image/twitter:image n'a été trouvée — chromium est
   nettement plus coûteux (processus, mémoire, plusieurs secondes) qu'une
   requête HTTP.

Garde SSRF (`egress.url_interdite`) appliquée EN PREMIER, avant même de
construire un client d'égress ou de songer à lancer chromium : une URL
refusée n'atteint jamais le réseau, quel que soit le chemin — voir Global
Constraints #1120.

Égress ONLY through the toolbox/WAF (#1120) : le repli screenshot route
chromium à travers le même proxy sbxmitm que og:image
(`http://127.0.0.1:8090` (instance CONNECT dédiée)), en lui faisant confiance en la même CA
(`/usr/share/secubox/egress-ca.pem`) — voir `secubox_core.shotter.capture`
(paramètres `proxy`/`ca`, ajoutés pour cet appelant, backward-compatible :
défaut `None` = comportement historique des appelants existants,
metablog-shotter et streamlit-shotter, inchangé). Si le proxy est
injoignable ou que la CA n'est pas approuvée, la capture chromium ÉCHOUE
(`ShotError`, traduit ici en `(None, False)`) — jamais de repli vers un
accès direct à Internet.

Ce module ne lève JAMAIS : `capture_vignette()` traduit toute exception
(réseau, timeout, chromium absent, parsing malformé...) en `(None, False)`.
C'est un contrat dur — le worker (tâche suivante) appelle cette fonction en
boucle sur une file de captures et ne doit jamais se faire surprendre par
une exception non rattrapée depuis ce module.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import egress
import ogimage

# common/secubox_core doit être importable sans installation pip — en
# production, `secubox-core` s'installe dans
# /usr/lib/python3/dist-packages/ (déjà sur sys.path par défaut) ; ce repli
# ne sert qu'en environnement de développement / source tree, exactement
# comme packages/secubox-streamlit/api/tests/conftest.py.
_COMMON = Path(__file__).resolve().parents[4] / "common"
if _COMMON.is_dir() and str(_COMMON) not in sys.path:
    sys.path.insert(0, str(_COMMON))

from secubox_core import shotter  # noqa: E402

# Égress ONLY through the toolbox/WAF — Global Constraints #1120. Mêmes
# valeurs que `egress.client()` : NE JAMAIS diverger de ce proxy/cette CA
# pour un accès sortant, quel que soit le chemin (og:image ou chromium).
_PROXY_URL = "http://127.0.0.1:8090"
_CA_PATH = "/usr/share/secubox/egress-ca.pem"


def capture_vignette(url: str) -> tuple[bytes | None, bool]:
    """Renvoie `(png, True)` en cas de succès, `(None, False)` sinon.

    Ne lève JAMAIS — voir la docstring du module. Ordre : garde SSRF, puis
    og:image, puis repli screenshot chromium (uniquement si og:image n'a
    rien trouvé)."""
    if egress.url_interdite(url):
        return None, False

    image = _essaie_og_image(url)
    if image is not None:
        return image, True

    return _essaie_screenshot(url)


def _essaie_og_image(url: str) -> bytes | None:
    """og:image/twitter:image via le client d'égress. `None` en cas
    d'échec/absence — jamais d'exception propagée."""
    try:
        cli = egress.client()
    except Exception:
        return None
    try:
        return ogimage.cherche_og_image(url, cli)
    except Exception:
        return None
    finally:
        try:
            cli.close()
        except Exception:
            pass


def _essaie_screenshot(url: str) -> tuple[bytes | None, bool]:
    """Repli chromium via `secubox_core.shotter`, routé à travers le proxy
    d'égress + CA de confiance. `wait_static_ready` : une URL citée dans un
    post est une page web quelconque, jamais une appli Streamlit —
    `wait_streamlit_ready` (le défaut de `shotter.capture`) ne conviendrait
    pas ici."""
    try:
        png = asyncio.run(shotter.capture(
            url,
            wait=shotter.wait_static_ready,
            proxy=_PROXY_URL,
            ca=_CA_PATH,
        ))
    except Exception:
        return None, False
    if not png:
        return None, False
    return png, True
