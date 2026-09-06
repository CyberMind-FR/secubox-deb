# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""ZIA — Tools.act + policy + runtime : la couche d'actions de bout en bout.

Le bus est neutralisé (pas de socket) : ses adapters ne rendent rien, donc
`bus.get` renvoie None et `Tools.act` retombe sur le service déduit de la cible.
Le registre de capacités reste le bootstrap radio (déterministe)."""
import asyncio

import pytest

from api.bus import Bus
from api import policy, runtime
from api.tools import Tools


def bus_offline():
    b = Bus({"capabilities_dir": "/nonexistent-capabilities-dir"})

    async def _vide(role="guest", force=False):
        return []
    b.objets = _vide            # aucun adapter réseau pendant les tests
    return b


def call(coro):
    return asyncio.run(coro)


# ── Tools.act ────────────────────────────────────────────────────────────────
def test_act_mute_ok():
    t = Tools(bus_offline())
    r = call(t.call("act", {"target": "service:radio", "action": "media.mute",
                            "params": {"value": True}}, "guest"))
    assert r["ok"]
    assert r["result"] == {"kind": "sbx-action", "target": "service:radio",
                           "service": "radio", "action": "media.mute",
                           "params": {"value": True}}


def test_act_volume_clamp():
    t = Tools(bus_offline())
    r = call(t.call("act", {"target": "service:radio", "action": "media.volume",
                            "params": {"value": 2.5}}, "guest"))
    assert r["ok"] and r["result"]["params"] == {"value": 1.0}


def test_act_unknown_capability_refused():
    t = Tools(bus_offline())
    r = call(t.call("act", {"target": "service:radio", "action": "media.next"}, "guest"))
    assert not r["ok"] and "disponible" in r["error"]


def test_act_proto_pollution_refused():
    t = Tools(bus_offline())
    r = call(t.call("act", {"target": "service:radio", "action": "__proto__"}, "guest"))
    assert not r["ok"]


def test_act_external_url_refused():
    t = Tools(bus_offline())
    r = call(t.call("act", {"target": "http://evil.example/x", "action": "media.stop"}, "guest"))
    assert not r["ok"]


# ── policy : rôle hors LLM ────────────────────────────────────────────────────
def test_policy_action_floor():
    assert policy.action_role_ok("guest", "media.mute")
    assert policy.action_role_ok("guest", "ui.zoom")
    assert not policy.action_role_ok("guest", "admin.reload")   # admin en guest → refus
    assert policy.action_role_ok("admin", "admin.reload")
    assert not policy.action_role_ok("guest", "sys.wipe")


# ── runtime : langage naturel → action (ou refus explicite) ───────────────────
def resp(msg, role="guest"):
    t = Tools(bus_offline())
    return call(runtime.respond(msg, role, t, {}, None))


def test_nl_coupe_la_radio():
    o = resp("Coupe la radio")
    assert o["actions"] and o["actions"][0]["action"] == "media.mute"
    assert o["actions"][0]["params"] == {"value": True}


def test_nl_remets_le_son():
    o = resp("Remets le son")
    assert o["actions"][0]["action"] == "media.mute" and o["actions"][0]["params"] == {"value": False}


def test_nl_volume_pourcent():
    o = resp("Mets la radio à 30 %")
    assert o["actions"][0]["action"] == "media.volume"
    assert abs(o["actions"][0]["params"]["value"] - 0.30) < 1e-9


def test_nl_volume_clamp():
    o = resp("volume 250 %")
    assert o["actions"][0]["action"] == "media.volume" and o["actions"][0]["params"]["value"] == 1.0


def test_nl_pause_stop_zoom():
    assert resp("Mets la radio en pause")["actions"][0]["action"] == "media.pause"
    assert resp("Agrandis la radio")["actions"][0]["action"] == "ui.zoom"


def test_nl_piste_suivante_refusee():
    o = resp("piste suivante sur la radio")
    assert o["actions"] == []                       # aucune commande envoyée
    assert "disponible" in o["text"]                # refus clair


def test_nl_non_commande_reste_recherche():
    o = resp("trouve une vidéo sur le WAF")
    assert o.get("actions", []) == []               # pas d'action : c'est une recherche
