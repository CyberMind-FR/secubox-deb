# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3626 — Status Live v2 jalon 2 : relevé d'état signé par chaque box, vérifié et agrégé par l'agrégateur.

Contrat distinct de ModulesSnapshot (extra="forbid") ; aucun détail interne (ressources, noyau, adresses) ; collecte :
signature ET forme, DID attendu par adresse, séquence strictement croissante (anti-rejeu), box absentes nommées."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

PKG_ROOT = Path(__file__).resolve().parents[1]
CLI = PKG_ROOT / "sbin" / "sbx-fleetctl"
sys.path.insert(0, str(PKG_ROOT))

from annuaire import fleet  # noqa: E402
from annuaire.crypto import did_from_pubkey, generate_keypair, public_from_private  # noqa: E402

RELEVE = {"schema": "secubox.status.snapshot", "version": 2,
          "node": {"id": "gk3", "hostname": "gk3", "architecture": "amd64", "did": None},
          "sequence": 42, "collected_at": "2026-11-09T12:00:00+00:00",
          "release": {"kernel": "6.12.113", "profile": "full"},
          "health": {"overall": "degraded", "services": "degraded", "web": "unknown", "system": "operational",
                     "validation": "operational"},
          "resources": {"cpu_percent": 12.0, "memory_percent": 40.0, "disk_percent": 50.0, "load": [0.1, 0.1, 0.1],
                        "uptime_seconds": 10, "temperature_celsius": 55.0},
          "counts": {"modules_total": 30, "modules_ok": 29, "modules_sleeping": 0, "modules_degraded": 0,
                     "modules_down": 1},
          "sources": {"modules": "fresh", "vhosts": "stale", "profiles": "fresh", "system": "fresh"},
          "source_notes": {"vhosts": "relevé vieux de 99 s"}}
PUBLIC = {"nodes": [{"id": "appliance", "availability_30d": 99.5,
                     "hours": [{"hour": "2026-11-09T11:00:00+00:00", "status": "operational"}]}]}


def _acteur():
    priv, pub = generate_keypair()
    return priv, did_from_pubkey(pub)


def _champs(did, **sur):
    return {"node_did": did, "issued_by": did, "hostname": "gk3", "ts": "2026-11-09T12:00:30Z",
            "collected_at": "2026-11-09T12:00:00Z", "sequence": 42, "overall": "operational",
            "components": {"services": "operational"}, "sources": {"modules": "fresh"},
            "counts": {"modules_total": 30, "modules_ok": 30}, "availability_30d": 100.0,
            "hours": [{"hour": "2026-11-09T11:00:00Z", "status": "operational"}], **sur}


# ── modèle, signature, vérification ──────────────────────────────────────────

def test_signe_et_verifie():
    priv, did = _acteur()
    rec = fleet.sign_status(priv, _champs(did))
    assert fleet.normaliser_status(rec)["overall"] == "operational"


def test_un_releve_altere_ne_se_verifie_plus():
    priv, did = _acteur()
    rec = fleet.sign_status(priv, _champs(did))
    assert fleet.normaliser_status({**rec, "overall": "outage"}) is None
    assert fleet.normaliser_status({**rec, "sequence": 99}) is None


@pytest.mark.parametrize("sur", [{"overall": "excellent"}, {"components": {"cpu": "operational"}},
                                 {"sources": {"modules": "frais"}}, {"sequence": 0}, {"availability_30d": 101},
                                 {"hours": [{"hour": "x", "status": "operational"}]},
                                 {"hours": [{"hour": "2026-11-09T11:00:00Z", "status": "operational"}] * 25},
                                 {"ressources": {"cpu_percent": 1}}, {"hostname": "gk3; rm"}])
def test_hors_contrat_jamais_signe(sur):
    priv, did = _acteur()
    with pytest.raises(ValidationError):
        fleet.sign_status(priv, _champs(did, **sur))


def test_relevé_d_un_autre_did_refuse():
    priv, did = _acteur()
    _p2, autre = _acteur()
    rec = fleet.sign_status(priv, _champs(did))
    assert fleet.normaliser_status({**rec, "node_did": autre}) is None


# ── publish-status (CLI) ─────────────────────────────────────────────────────

@pytest.fixture()
def env(tmp_path):
    priv, _pub = generate_keypair()
    (tmp_path / "box.key").write_text(priv.hex())
    (tmp_path / "snapshot.json").write_text(json.dumps(RELEVE))
    (tmp_path / "public.json").write_text(json.dumps(PUBLIC))
    e = os.environ.copy()
    e.update(ANNUAIRE_LIB=str(PKG_ROOT), ANNUAIRE_KEY_PATH=str(tmp_path / "box.key"),
             FLEET_STATUS_PATH=str(tmp_path / "status.json"), FLEET_STATUS_PAIRS_PATH=str(tmp_path / "pairs.json"),
             SECUBOX_STATUS_RELEVE=str(tmp_path / "snapshot.json"), SECUBOX_STATUS_PUBLIC=str(tmp_path / "public.json"),
             SECUBOX_STATUS_CONF=str(tmp_path / "status.toml"), SECUBOX_CONF=str(tmp_path / "secubox.conf"))
    e.pop("DRYRUN", None)
    return e


def _cli(env, verbe):
    r = subprocess.run([sys.executable, str(CLI), verbe], env=env, capture_output=True, text=True, timeout=30)
    return r.returncode, (json.loads(r.stdout) if r.stdout.strip() else {}), r.stderr


def test_publie_le_releve_signe_sans_detail_interne(env):
    rc, out, err = _cli(env, "publish-status")
    assert rc == 0, err
    rec = json.loads(Path(env["FLEET_STATUS_PATH"]).read_text())
    priv = bytes.fromhex(Path(env["ANNUAIRE_KEY_PATH"]).read_text())
    assert fleet.normaliser_status(rec) and rec["node_did"] == did_from_pubkey(public_from_private(priv))
    assert rec["sequence"] == 42 and rec["overall"] == "degraded" and rec["availability_30d"] == 99.5
    texte = json.dumps(rec)
    for interdit in ("resources", "cpu_percent", "kernel", "6.12.113", "source_notes", "architecture", "release"):
        assert interdit not in texte, interdit


def test_releve_inchange_pas_republie(env):
    _cli(env, "publish-status")
    rc, out, _ = _cli(env, "publish-status")
    assert rc == 0 and out.get("skipped") == "relevé inchangé"


def test_sans_releve_status_rien_n_echoue(env):
    os.unlink(env["SECUBOX_STATUS_RELEVE"])
    rc, out, _ = _cli(env, "publish-status")
    assert rc == 0 and "skipped" in out


def test_collecte_seulement_sur_l_agregateur(env):
    Path(env["SECUBOX_STATUS_CONF"]).write_text('[status]\nnode_role = "agent"\n')
    rc, out, _ = _cli(env, "collect-status")
    assert rc == 0 and "skipped" in out and not Path(env["FLEET_STATUS_PAIRS_PATH"]).exists()


# ── collecte : anti-rejeu ────────────────────────────────────────────────────

def test_anti_rejeu_dans_la_collecte():
    src = CLI.read_text()
    assert "status-sequences.json" in src and "relevé rejoué (séquence ancienne)" in src
    assert "if not ts > str(vu.get(\"ts\") or \"\")" in src                  # réinitialisation : ts signé plus récent
    assert "ProxyHandler({})" in src and "_SansRedirection" in src and "limite: int = 256 * 1024" in src
    assert "r.read1(65536)" in src and "cancel_futures=True" in src
    assert "box non liée" in src and 'n["nom"] = nom_par_did.get(did)' in src
    assert 'n["signature_verified"] = True' in src


def test_publication_sur_l_ecoute_du_maillage():
    tpl = (PKG_ROOT / "nginx" / "annuaire-mesh.conf.tpl").read_text()
    assert "location = /api/v1/annuaire/fleet/status/self {" in tpl
    unite = (PKG_ROOT / "systemd" / "secubox-metrics-publish.service").read_text()
    assert "ExecStart=-/usr/sbin/sbx-fleetctl publish-status" in unite
    assert "ExecStart=-/usr/sbin/sbx-fleetctl collect-status" in unite
    for ligne in ("TimeoutStartSec=120", "NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/var/lib/secubox/annuaire"):
        assert ligne in unite, ligne


def test_source_locale_pairs_jamais_publiee(env):
    r = dict(RELEVE, sources={**RELEVE["sources"], "pairs": "fresh"})
    Path(env["SECUBOX_STATUS_RELEVE"]).write_text(json.dumps(r))
    rc, _out, err = _cli(env, "publish-status")
    assert rc == 0, err
    assert "pairs" not in json.loads(Path(env["FLEET_STATUS_PATH"]).read_text())["sources"]


def test_ecriture_atomique_0640(tmp_path, monkeypatch):
    import importlib.machinery, importlib.util
    loader = importlib.machinery.SourceFileLoader("fleetctl_mod", str(CLI))
    spec = importlib.util.spec_from_loader("fleetctl_mod", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    cible = tmp_path / "status-pairs.json"
    m._ecrire_json(str(cible), {"a": 1})
    assert json.loads(cible.read_text()) == {"a": 1} and (cible.stat().st_mode & 0o777) == 0o640
    assert [p.name for p in tmp_path.iterdir()] == ["status-pairs.json"]
    assert m._nom_lie({"boxname": "gk3"}) == "gk3" and m._nom_lie({"boxname": "10.10.0.5"}) == ""
    assert m._nom_lie({"boxname": "Gk3 évil"}) == ""
