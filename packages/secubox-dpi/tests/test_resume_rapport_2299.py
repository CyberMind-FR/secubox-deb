# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2299 : le résumé DPI du rapport quotidien est agrégé, tronqué, écrit atomiquement ; une source muette reste absente (None), jamais zéro."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api import resume_rapport as R  # noqa: E402


def sources(**sur):
    base = {"stats": lambda: {"connected": True, "total_flows": 10, "total_bytes": 2048, "updated_at": 5, "protocols": [{"name": f"P{i}", "bytes": i, "pct": i} for i in range(20)]},
            "usage": lambda: {"usages": [{"name": "ai", "bytes": 5, "pct": 50}]},
            "pays": lambda: [{"cc": "FR", "name": "France", "bytes": 9}] * 30,
            "clients": lambda: [{"name": "a", "bytes": 1, "usages": [{"name": f"u{i}", "bytes": 1} for i in range(9)], "top_dst": [{"host": f"h{i}", "bytes": 1} for i in range(9)]},
                                {"name": "b", "bytes": 99, "up_bytes": 60, "down_bytes": 39}],
            "suggestions": lambda: [{"domain": "x.fr", "bytes": 3, "reason": "r", "proposed_rule": {"secret": "ne pas copier"}}]}
    base.update(sur)
    return base


def test_le_resume_est_tronque_et_trie_par_volume():
    r = R.construire(sources(), now=100)
    assert r["genere_le"] == 100 and len(r["stats"]["protocoles"]) == R.TOP and len(r["pays"]) == 12
    assert [a["nom"] for a in r["appareils"]] == ["b", "a"] and r["appareils_total"] == 2
    assert len(r["appareils"][1]["usages"]) == 3 and len(r["appareils"][1]["destinations"]) == 3


def test_le_resume_ne_copie_pas_les_regles_proposees():
    assert "proposed_rule" not in json.dumps(R.construire(sources()))


def test_une_source_muette_reste_absente_pas_zero():
    def casse():
        raise RuntimeError("sbxdpi muet")
    r = R.construire(sources(stats=casse, clients=lambda: None))
    assert r["stats"] is None and r["appareils"] is None and r["appareils_total"] is None
    assert r["usages"] is not None


def test_l_ecriture_est_atomique_et_en_0640(tmp_path):
    chemin = tmp_path / "d" / "resume.json"
    R.ecrire({"a": 1}, chemin)
    assert json.loads(chemin.read_text()) == {"a": 1} and oct(os.stat(chemin).st_mode & 0o777) == "0o640"
    assert [p.name for p in chemin.parent.iterdir()] == ["resume.json"]          # aucun fichier temporaire oublié


def test_l_unite_est_durcie_et_ecrit_seulement_le_cache_dpi():
    u = (Path(__file__).resolve().parents[1] / "systemd" / "secubox-dpi-resume.service").read_text()
    assert "User=secubox" in u and "NoNewPrivileges=true" in u and "ProtectSystem=strict" in u
    assert "ReadWritePaths=/var/cache/secubox/dpi" in u and "RestrictAddressFamilies=AF_UNIX" in u
