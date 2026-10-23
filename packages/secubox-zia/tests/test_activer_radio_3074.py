# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3074 — « Activez la radio. » répondait « Je n'ai rien trouvé de visible » : le verbe n'était pas une commande, la
phrase partait en recherche d'objets puis en escalade distante. Une demande de LECTURE est `media.play` (idempotente :
une radio qui joue déjà n'est jamais mise en pause), et un service sans `media.play` retombe sur la bascule."""
import asyncio
import pathlib

import pytest

from api.bus import Bus
from api import runtime
from api.tools import Tools


def _bus(capdir="/nonexistent-capabilities-dir"):
    b = Bus({"capabilities_dir": capdir})

    async def _vide(role="guest", force=False):
        return []
    b.objets = _vide
    return b


def resp(msg, bus=None):
    return asyncio.run(runtime.respond(msg, "guest", Tools(bus or _bus()), {}, None))


@pytest.mark.parametrize("phrase", [
    "Activez la radio.", "active la radio", "Allume la radio", "allumez la radio", "lance la radio",
    "Lancez la radio", "joue la radio", "Jouez la radio", "démarre la radio", "Démarrez la radio", "écoute la radio",
    "Mets la radio", "mettez la radio", "play radio", "relance la radio", "reprends la radio",
])
def test_demande_de_lecture_vers_la_radio(phrase):
    o = resp(phrase)
    assert o["actions"], o["text"]
    a = o["actions"][0]
    assert a["service"] == "radio" and a["action"] == "media.play"
    assert "rien trouvé" not in o["text"]


def test_activer_sans_service_vise_la_radio():
    o = resp("Activez.")
    assert o["actions"] and o["actions"][0]["service"] == "radio"


def test_phrase_de_reponse():
    assert resp("Activez la radio.")["text"] == "Je lance radio."


def test_pause_et_volume_inchanges():
    assert resp("Mets la radio en pause")["actions"][0]["action"] == "media.pause"
    assert resp("Mets la radio à 30 %")["actions"][0]["action"] == "media.volume"
    assert resp("réactive le son")["actions"][0]["action"] == "media.mute"
    assert resp("rallume la radio")["actions"][0]["action"] == "media.mute"


def test_service_sans_play_retombe_sur_la_bascule():
    capdir = str(pathlib.Path(__file__).resolve().parents[2] / "secubox-podcaster" / "capabilities.d")
    o = resp("lance le podcast", _bus(capdir))
    assert o["actions"] and o["actions"][0]["service"] == "podcaster"
    assert o["actions"][0]["action"] in ("media.play", "media.toggle")


def test_une_recherche_reste_une_recherche():
    assert resp("trouve une vidéo sur le WAF").get("actions", []) == []


def test_ecouter_a_l_infinitif_reste_une_recherche():
    assert resp("trouve un podcast à écouter sur le WAF").get("actions", []) == []


def test_le_manifeste_installe_de_la_radio_declare_la_lecture():
    # Sur la box, le manifeste du paquet radio REMPLACE l'amorçage : sans media.play ici, « Activez la radio » retombait
    # sur la bascule (vu sur gk2 après le premier déploiement).
    capdir = str(pathlib.Path(__file__).resolve().parents[2] / "secubox-radio" / "capabilities.d")
    o = resp("Activez la radio.", _bus(capdir))
    assert o["actions"] and o["actions"][0]["action"] == "media.play"
    assert [t["args"]["action"] for t in o["trace"] if t["tool"] == "act"] == ["media.play"]
