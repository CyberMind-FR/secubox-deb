# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Classe d'effet, rôle minimal et paramètres texte des capacités (#1615)."""
import json
from pathlib import Path

from api.capabilities import Capabilities

RACINE = Path(__file__).resolve().parents[2]


def caps(tmp_path):
    for f in ("secubox-radio/capabilities.d/radio.json", "secubox-voice/capabilities.d/voice.json"):
        (tmp_path / Path(f).name).write_text((RACINE / f).read_text(encoding="utf-8"))
    (tmp_path / "zz.json").write_text(json.dumps({"service": "zz", "actions": {
        "porte.ouvre": {"message": {"sbx": "cmd", "action": "ouvre"}}}}))
    return Capabilities(str(tmp_path))


def test_effet_et_role_declares(tmp_path):
    c = caps(tmp_path)
    assert c.effet("radio", "media.pause") == "media"
    assert c.autorise("radio", "media.pause", "guest")
    assert c.effet("voice", "voice.listen") == "physique"
    assert not c.autorise("voice", "voice.speak", "guest") and c.autorise("voice", "voice.speak", "member")


def test_non_declare_ferme_par_defaut(tmp_path):
    c = caps(tmp_path)
    assert c.effet("zz", "porte.ouvre") == "ecriture"
    assert not c.autorise("zz", "porte.ouvre", "registered")
    assert not c.autorise("zz", "porte.ouvre", "inconnu")


def test_texte_garde_et_plafonne(tmp_path):
    c = caps(tmp_path)
    r = c.resolve("voice", "voice.speak", {"value": "Bonjour"})
    assert r.ok and r.message["texte"] == "Bonjour"
    assert not c.resolve("voice", "voice.speak", {"value": "x" * 301}).ok
    assert not c.resolve("voice", "voice.speak", {"value": "   "}).ok


def test_domaine_de_la_box(monkeypatch):
    import api.bus as bus
    monkeypatch.setattr("secubox_core.auth.domaine_box", lambda: "exemple.test")
    assert bus._hote("metanews") == "metanews.exemple.test"
