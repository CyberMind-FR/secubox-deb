# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""/devices : un relevé partagé, pas un par lecteur (#1835).

Chaque lecture lançait trois mosquitto_sub et un mosquitto_pub par appareil ;
la carte du Hall relit toutes les 10 s, chaque écran pour son compte.
"""
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(RACINE / "common"), str(Path(__file__).resolve().parents[1])]

from api import main as m  # noqa: E402

INVENTAIRE = [
    {"friendly_name": "lampe", "type": "Router",
     "definition": {"model": "L1", "exposes": [{"type": "light", "features": [{"name": "state"}]}]}},
    {"friendly_name": "coord", "type": "Coordinator"},
]


@pytest.fixture
def mqtt(monkeypatch, tmp_path):
    (tmp_path / "mqtt-z2m").write_text("secret-de-test\n")
    monkeypatch.setattr(m, "SECRETS_DIR", tmp_path)
    lances = []

    def faux_run(args, **kw):
        lances.append(args[0])
        topic = args[args.index("-t") + 1] if "-t" in args else ""
        if topic == "zigbee2mqtt/bridge/devices":
            return subprocess.CompletedProcess(args, 0, json.dumps(INVENTAIRE), "")
        if topic == "zigbee2mqtt/bridge/state":
            return subprocess.CompletedProcess(args, 0, '{"state":"online"}', "")
        return subprocess.CompletedProcess(args, 0, "", "")

    class FauxPopen:
        def __init__(self, args, **kw):
            lances.append(args[0])

        def communicate(self, timeout=None):
            return ('zigbee2mqtt/lampe {"state":"ON","brightness":200}\n', "")

        def kill(self):
            pass

    monkeypatch.setattr(m.subprocess, "run", faux_run)
    monkeypatch.setattr(m.subprocess, "Popen", FauxPopen)
    monkeypatch.setattr(m, "_memo_devices", {"t": 0.0, "val": None})
    monkeypatch.setattr(m, "_memo_inventaire", {"t": 0.0, "val": None})
    return lances


def test_deux_lectures_un_seul_releve(mqtt):
    a = m.devices()
    n = len(mqtt)
    b = m.devices()
    assert a == b and a["appareils"][0]["etat"] == "ON" and a["pont"] == "online"
    assert len(mqtt) == n, "la seconde lecture a relancé mosquitto"


def test_lecteurs_simultanes_un_seul_calcul(mqtt):
    sorties = []
    fils = [threading.Thread(target=lambda: sorties.append(m.devices())) for _ in range(5)]
    for f in fils:
        f.start()
    for f in fils:
        f.join()
    assert len(sorties) == 5 and all(s == sorties[0] for s in sorties)
    assert mqtt.count("mosquitto_sub") == 3      # inventaire + écoute + pont, une fois


def test_une_commande_efface_le_releve(mqtt):
    m.devices()
    m.set_device("lampe", {"etat": "OFF"})
    n = len(mqtt)
    m.devices()
    assert len(mqtt) > n, "après une commande, le relevé doit être refait"


def test_inventaire_memorise_pour_la_liste_blanche(mqtt):
    m.devices()
    avant = mqtt.count("mosquitto_sub")
    m.set_device("lampe", {"etat": "ON"})
    # set_device relit l'état de la lampe (une écoute), pas l'inventaire.
    assert mqtt.count("mosquitto_sub") - avant <= 1
    with pytest.raises(m.HTTPException):
        m.set_device("inconnue", {"etat": "ON"})
