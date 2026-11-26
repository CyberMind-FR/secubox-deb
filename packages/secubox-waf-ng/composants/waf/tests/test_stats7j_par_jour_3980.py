# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3980 — stats7j porte une série par jour (7 cases, la plus ancienne d'abord), calculée dans la même passe."""
import json
from datetime import datetime, timedelta, timezone

from .test_gestes_ia_3716 import _importer_waf


def test_par_jour(tmp_path):
    _importer_waf()
    from api import modes
    m = datetime(2026, 11, 26, 12, tzinfo=timezone.utc)
    lignes = [{"timestamp": (m - timedelta(days=d, hours=1)).isoformat(), "category": "sqli", "client_ip": "203.0.113.9"}
              for d in (0, 0, 3, 6)] + [{"timestamp": (m - timedelta(days=8)).isoformat(), "category": "sqli"}]
    j = tmp_path / "threats.log"
    j.write_text("\n".join(json.dumps(x) for x in lignes) + "\n")
    c = modes.calculer_stats7j([str(j)], m, set())["categories"]["sqli"]
    assert c["touches"] == 4 and c["par_jour"] == [1, 0, 0, 1, 0, 0, 2]
