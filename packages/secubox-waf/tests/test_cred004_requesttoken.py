# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""cred-004 (#1858) : `requesttoken=` de Nextcloud n'est pas un jeton en URL."""

import json
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
JETON = "A" * 24


def _motif() -> re.Pattern:
    regles = json.loads((RACINE / "config" / "waf-rules.json").read_text(encoding="utf-8"))

    def cherche(o):
        if isinstance(o, dict):
            if o.get("id") == "cred-004":
                return o["pattern"]
            for v in o.values():
                if (r := cherche(v)):
                    return r
        elif isinstance(o, list):
            for v in o:
                if (r := cherche(v)):
                    return r
        return None

    return re.compile(cherche(regles))


def test_requesttoken_nextcloud_n_est_pas_un_jeton_en_url():
    m = _motif()
    assert not m.search(f"/index.php/login/flow?requesttoken={JETON}")
    assert not m.search(f"/index.php/login?a=1&requesttoken={JETON}")


def test_vrais_jetons_en_url_restent_vus():
    m = _motif()
    assert m.search(f"/x?token={JETON}")
    assert m.search(f"/x?a=1&access_token={JETON}")
    assert m.search(f"/x?id_token={JETON}")


def test_api_001_retiree_l_admin_legitime_n_est_pas_un_abus():
    """#1859 : « /api/.*/admin » bannissait l'administrateur (4 appels = ban)."""
    regles = (RACINE / "config" / "waf-rules.json").read_text(encoding="utf-8")
    assert '"api-001"' not in regles
