# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: exposure — l'onion du webui passe par le frontal HAProxy dédié, jamais nginx :9080 (#3112).

Vu en production (gk2) : `HiddenServicePort 80 127.0.0.1:9080`, donc Tor → nginx en direct, hors HAProxy et hors
sbxwaf ; nginx croit X-Forwarded-For de 127.0.0.1 et classe 127.0.0.0/8 en LAN — chaque visiteur onion était
« poste du LAN ». Ces tests couvrent la cible des nouveaux onions, la migration des onions existants (même clé,
même adresse : HiddenServiceDir inchangé), son idempotence, la route sbxwaf et le refus d'un onion vers 9080.
"""
import asyncio
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-haproxy" / "composants" / "exposure"))

import api.main as m  # noqa: E402
from fastapi import HTTPException  # noqa: E402

ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"


@pytest.fixture
def box(monkeypatch, tmp_path):
    """Arborescence Tor / exposure / haproxy.toml isolée ; les commandes sont enregistrées, jamais lancées."""
    torrc = tmp_path / "torrc"
    torrc.write_text("SocksPort 9050\n%include /etc/tor/torrc.d/*.conf\n")
    monkeypatch.setattr(m, "TOR_CONFIG", torrc)
    monkeypatch.setattr(m, "TOR_DROPIN_DIR", tmp_path / "torrc.d")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path / "hs")
    monkeypatch.setattr(m, "CONFIG_FILE", tmp_path / "exposure.json")
    monkeypatch.setattr(m, "HAPROXY_TOML", tmp_path / "haproxy.toml")
    cmds, audits = [], []
    monkeypatch.setattr(m, "run_cmd", lambda cmd, *a, **k: cmds.append(cmd) or (True, "", ""))
    monkeypatch.setattr(m, "_audit_write", lambda line: audits.append(line))
    (tmp_path / "hs" / "webui").mkdir(parents=True)
    (tmp_path / "hs" / "webui" / "hostname").write_text(ONION + "\n")
    return {"tmp": tmp_path, "torrc": torrc, "cmds": cmds, "audits": audits,
            "dropin": tmp_path / "torrc.d" / "70-secubox-hs-webui.conf", "hs": tmp_path / "hs" / "webui"}


def _ancien_dropin(box, onion_port=80):
    box["dropin"].parent.mkdir(parents=True, exist_ok=True)
    box["dropin"].write_text(f"# SecuBox — service onion webui (#2050)\nHiddenServiceDir {box['hs']}\n"
                             f"HiddenServicePort {onion_port} 127.0.0.1:9080\n")


def _reloads(box):
    return [c for c in box["cmds"] if c == ["systemctl", "reload", "tor"]]


# ── nouveaux onions ──────────────────────────────────────────────────────────────────────────────────────────────
def test_emancipate_webui_ecrit_la_cible_du_frontal_onion_et_pose_la_route_waf(box, monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda s: None)   # _tor_add_sync attend l'adresse : inutile ici
    r = m.emancipate_webui(federate=False)
    assert box["dropin"].read_text().splitlines()[-1] == "HiddenServicePort 80 127.0.0.1:9180"
    assert "9080" not in box["dropin"].read_text()
    assert r["output"]["local_port"] == 9180
    assert ["secubox-waf-route", ONION, "9080"] in box["cmds"], "sbxwaf doit connaître l'onion (→ webui)"


def test_le_port_suit_haproxy_toml_mais_jamais_9080(box):
    (box["tmp"] / "haproxy.toml").write_text('mode = "native"\nonion_webui_port = 9280\n')
    assert m._port_onion_webui() == 9280
    (box["tmp"] / "haproxy.toml").write_text("onion_webui_port = 9080\n")
    assert m._port_onion_webui() == 9180, "9080 serait de nouveau nginx en direct"


def test_tor_add_refuse_un_onion_vers_nginx_en_direct(box):
    with pytest.raises(HTTPException) as e:
        asyncio.run(m.tor_add(m.TorAddRequest(service="bidule", local_port=9080), {"sub": "t"}))
    assert e.value.status_code == 400 and "#3112" in e.value.detail


def test_la_route_waf_n_accepte_qu_une_adresse_onion(box):
    assert m._route_waf_onion("") is False
    assert m._route_waf_onion("admin.gk2.secubox.in") is False
    assert m._route_waf_onion("x; rm -rf /.onion") is False
    assert box["cmds"] == []


# ── migration des onions existants ───────────────────────────────────────────────────────────────────────────────
def test_la_migration_reecrit_la_cible_et_garde_la_cle(box):
    _ancien_dropin(box, onion_port=80)
    cle = box["hs"] / "hs_ed25519_secret_key"
    cle.write_bytes(b"cle")
    r = m.migrer_onion_webui()
    lignes = box["dropin"].read_text().splitlines()
    assert r["migrated"] is True
    assert f"HiddenServiceDir {box['hs']}" in lignes, "même répertoire : même clé, même adresse .onion"
    assert lignes[-1] == "HiddenServicePort 80 127.0.0.1:9180"
    assert cle.read_bytes() == b"cle" and (box["hs"] / "hostname").read_text().strip() == ONION
    assert len(_reloads(box)) == 1
    assert any("migrate_onion_webui" in a and "ancienne_cible=127.0.0.1:9080" in a for a in box["audits"])


def test_la_migration_est_idempotente(box):
    _ancien_dropin(box)
    m.migrer_onion_webui()
    avant = box["dropin"].read_text()
    box["cmds"].clear()
    r = m.migrer_onion_webui()
    assert r["migrated"] is False
    assert box["dropin"].read_text() == avant
    assert _reloads(box) == [], "rien de changé : Tor n'est pas rechargé"


def test_la_migration_deplace_un_ancien_bloc_du_torrc_sans_doublon(box):
    """Un bloc d'avant #2050 dans /etc/tor/torrc : le laisser ET écrire le fichier ferait deux HiddenServiceDir
    identiques — Tor refuserait alors TOUTE sa configuration."""
    autre = box["tmp"] / "hs" / "autre"
    box["torrc"].write_text(
        "SocksPort 9050\n"
        f"\n# Hidden service: webui\nHiddenServiceDir {box['hs']}\nHiddenServicePort 80 127.0.0.1:9080\n"
        f"\n# Hidden service: autre\nHiddenServiceDir {autre}\nHiddenServicePort 80 127.0.0.1:80\n")
    m.migrer_onion_webui()
    t = box["torrc"].read_text()
    assert f"HiddenServiceDir {box['hs']}" not in t
    assert f"HiddenServiceDir {autre}" in t and "SocksPort 9050" in t, "les autres services restent intacts"
    assert box["dropin"].read_text().splitlines()[-1] == "HiddenServicePort 80 127.0.0.1:9180"


def test_la_migration_met_a_jour_l_entree_enregistree(box):
    _ancien_dropin(box)
    m._save_emancipated([{"name": "webui", "local_port": 9080, "onion_port": 80, "active": True},
                         {"name": "autre", "local_port": 80, "onion_port": 80, "active": True}])
    m.migrer_onion_webui()
    par_nom = {s["name"]: s for s in m._load_emancipated()}
    assert par_nom["webui"]["local_port"] == 9180
    assert par_nom["autre"]["local_port"] == 80


def test_la_migration_sans_onion_webui_ne_fait_rien(box):
    r = m.migrer_onion_webui()
    assert r["migrated"] is False and box["cmds"] == [] and not box["dropin"].exists()


def test_la_persistance_au_demarrage_migre_et_ne_reapplique_jamais_9080(box, monkeypatch):
    """Torrc remis à zéro, entrée encore à 9080 : la réparation doit viser le frontal, pas nginx."""
    m._save_emancipated([{"name": "webui", "local_port": 9080, "onion_port": 80, "active": True}])
    ajouts = []
    monkeypatch.setattr(m, "_tor_add_sync",
                        lambda name, local_port, onion_port: ajouts.append((name, local_port, onion_port)))
    r = m.tor_reconcile_persist()
    assert ajouts == [("webui", 9180, 80)]
    assert r["waf_route"] is True
    assert ["secubox-waf-route", ONION, "9080"] in box["cmds"]
