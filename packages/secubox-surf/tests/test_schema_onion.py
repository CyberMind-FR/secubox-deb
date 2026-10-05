# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Un service .onion se joint en http : il n'expose en général pas de TLS.

Le surfer forçait https:// vers toute cible ; sur le service caché de gk2
(HiddenServicePort 80 seulement) Tor répondait « destination refusée » et le
surfer renvoyait un 502 / 504.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from surf import egress  # noqa: E402

ONION = "3kdlpa3gegxallkk3qbm4vim5higxw4luammi6kubc2ew6mfsc2fayad.onion"


def test_un_onion_se_joint_en_http():
    assert egress.schema_pour(ONION) == "http"


def test_un_onion_avec_sous_domaine_aussi():
    assert egress.schema_pour("www." + ONION) == "http"


def test_un_site_ordinaire_reste_en_https():
    assert egress.schema_pour("example.org") == "https"
    assert egress.schema_pour("onion.example.org") == "https"
