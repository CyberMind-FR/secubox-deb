# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""ZIA — registre de capacités : résolution, validation, bornage, manifestes."""
import json

from api.capabilities import Capabilities


def caps():
    # Répertoire inexistant → bootstrap radio seul (déterministe).
    return Capabilities("/nonexistent-capabilities-dir")


def test_bootstrap_radio_actions():
    c = caps()
    assert "radio" in c.services()
    for a in ["media.toggle", "media.pause", "media.stop", "media.mute",
              "media.volume", "ui.zoom"]:
        assert c.has("radio", a), a
    # prev/next ABSENTS de la radio (un direct ne se parcourt pas).
    assert not c.has("radio", "media.next")
    assert not c.has("radio", "media.prev")


def test_resolve_mute_boolean():
    c = caps()
    r = c.resolve("radio", "media.mute", {"value": True})
    assert r.ok and r.message == {"sbx": "cmd", "action": "muet", "v": True}
    r = c.resolve("radio", "media.mute", {"value": "false"})
    assert r.ok and r.message["v"] is False


def test_resolve_volume_number_and_clamp():
    c = caps()
    r = c.resolve("radio", "media.volume", {"value": 0.25})
    assert r.ok and r.message == {"sbx": "cmd", "action": "vol", "v": 0.25}
    # « volume 250 % » → borné à 1.0 (politique documentée : clamp).
    r = c.resolve("radio", "media.volume", {"value": 2.5})
    assert r.ok and r.message["v"] == 1.0
    r = c.resolve("radio", "media.volume", {"value": -3})
    assert r.ok and r.message["v"] == 0.0


def test_resolve_bad_value():
    c = caps()
    assert not c.resolve("radio", "media.volume", {"value": "abc"}).ok
    assert not c.resolve("radio", "media.volume", {}).ok            # valeur requise
    assert not c.resolve("radio", "media.mute", {"value": 3.14}).ok


def test_unknown_capability_and_module():
    c = caps()
    assert not c.resolve("radio", "media.next", {}).ok              # capacité inconnue
    assert not c.resolve("inconnu", "media.pause", {}).ok           # module inconnu
    # Nom d'action parasite (pas de « famille.nom ») — jamais dans le registre.
    assert not c.has("radio", "__proto__")
    assert not c.resolve("radio", "__proto__", {}).ok


def test_actions_for_contract():
    c = caps()
    by = {a["name"]: a for a in c.actions_for("radio")}
    assert by["media.volume"]["params"]["value"] == {"type": "number", "min": 0.0, "max": 1.0}
    assert by["media.mute"]["params"]["value"] == {"type": "boolean"}
    assert by["ui.zoom"]["params"] == {}


def test_manifest_loading(tmp_path):
    # Un module DÉCLARE ses capacités : ZIA les apprend (podcaster avec next/prev).
    (tmp_path / "podcaster.json").write_text(json.dumps({
        "service": "podcaster",
        "transport": "sbx-postmessage",
        "actions": {
            "media.toggle": {"message": {"sbx": "cmd", "action": "toggle"}},
            "media.next": {"message": {"sbx": "cmd", "action": "next"}},
            "media.prev": {"message": {"sbx": "cmd", "action": "prev"}},
            "media.volume": {"message": {"sbx": "cmd", "action": "vol"},
                             "value": {"field": "v", "type": "number", "min": 0, "max": 1}},
        },
    }), encoding="utf-8")
    # Manifeste cassé : ignoré, n'abat pas le registre.
    (tmp_path / "casse.json").write_text("{ pas du json", encoding="utf-8")
    c = Capabilities(str(tmp_path))
    assert c.has("podcaster", "media.next") and c.has("podcaster", "media.prev")
    assert c.has("radio", "media.toggle")           # bootstrap conservé
    # Une action au message non-cmd est rejetée à la normalisation.
    (tmp_path / "mauvais.json").write_text(json.dumps({
        "service": "x", "actions": {"media.go": {"message": {"sbx": "autre"}}}}), encoding="utf-8")
    c2 = Capabilities(str(tmp_path))
    assert "x" not in c2.services()


def test_registry_public_shape():
    c = caps()
    reg = c.registry()
    assert reg["radio"]["transport"] == "sbx-postmessage"
    assert reg["radio"]["actions"]["media.mute"]["message"]["action"] == "muet"
