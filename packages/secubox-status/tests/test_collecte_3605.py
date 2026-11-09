# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3605 — Status Live v2, jalon 1 : fraîcheur, normalisation, historique, projection publique (spec §10)."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_status import collecte, config, historique, normalise  # noqa: E402
from secubox_status.sources import Lecture, lire_source  # noqa: E402

T0 = datetime(2026, 11, 9, 9, 30, tzinfo=timezone.utc)
PLAT = {"hostname": "gk2", "architecture": "arm64", "kernel": "6.12.113"}
RESS = {"cpu_percent": 12.0, "memory_percent": 40.0, "disk_percent": 50.0, "load": [0.5, 0.4, 0.3],
        "uptime_seconds": 1000, "temperature_celsius": None}


def _mod(api="ok", overall="ok", critical=False):
    return {"name": "x", "critical": critical, "overall": overall,
            "layers": {"systemd": {"status": "down"}, "api": {"status": api}}}


def _ecrire(p: Path, d):
    p.write_text(json.dumps(d))
    return p


@pytest.fixture
def lieux(tmp_path):
    vh = _ecrire(tmp_path / "status.json", {"timestamp": T0.isoformat(), "vhosts": {"a": {"status": "ok"}}})
    mo = _ecrire(tmp_path / "modules.json", {"timestamp": T0.isoformat(),
                                             "modules": {"hub": _mod(), "dns": _mod()}})
    pr = _ecrire(tmp_path / "releve.json", {"releve_ts": T0.isoformat(), "profil_actif": "full", "partiel": []})
    cfg = config.charger(tmp_path / "absent.toml")
    for nom, p in (("vhosts", vh), ("modules", mo), ("profiles", pr)):
        cfg["sources"][nom]["path"] = str(p)
    cfg["status"]["node_id"] = "gk2"
    cfg["status"]["node_role"] = "aggregator"
    return tmp_path, cfg


def _collecte(lieux, quand=T0, ress=RESS):
    tmp, cfg = lieux
    return collecte.collecter(cfg, tmp / "etat", maintenant=quand, ressources=dict(ress), plateforme=PLAT)


# ── fraîcheur des sources ────────────────────────────────────────────────────

def test_cache_absent_rend_la_source_inconnue_pas_une_panne(lieux):
    tmp, cfg = lieux
    os.unlink(cfg["sources"]["modules"]["path"])
    r = _collecte(lieux)
    assert r["sources"]["modules"] == "absent"
    assert r["health"]["services"] == "unknown"
    assert r["health"]["overall"] == "operational"   # les composants connus vont bien
    assert r["counts"]["modules_total"] is None


def test_cache_perime_comme_le_status_json_de_gk2(lieux):
    tmp, cfg = lieux
    _ecrire(Path(cfg["sources"]["vhosts"]["path"]),
            {"timestamp": (T0 - timedelta(days=60)).isoformat(), "vhosts": {"a": {"status": "down"}}})
    r = _collecte(lieux)
    assert r["sources"]["vhosts"] == "stale"
    assert r["health"]["web"] == "unknown"          # 72 vhosts « down » d'il y a deux mois ne sont pas une panne
    assert "vieux" in r["source_notes"]["vhosts"]


def test_horodatage_futur_refuse(tmp_path):
    p = _ecrire(tmp_path / "f.json", {"timestamp": (T0 + timedelta(hours=1)).isoformat()})
    assert lire_source(p, lambda d: d["timestamp"], 300, T0).etat == "invalid"


def test_lien_symbolique_et_fichier_trop_gros_refuses(tmp_path):
    vrai = _ecrire(tmp_path / "vrai.json", {"timestamp": T0.isoformat()})
    lien = tmp_path / "lien.json"
    lien.symlink_to(vrai)
    assert lire_source(lien, lambda d: d["timestamp"], 300, T0).etat == "invalid"
    gros = tmp_path / "gros.json"
    gros.write_text('{"a":"' + "x" * (9 * 1024 * 1024) + '"}')
    assert lire_source(gros, lambda d: d.get("a"), 300, T0).etat == "invalid"


# ── normalisation ────────────────────────────────────────────────────────────

def test_module_servi_par_l_agregateur_juge_sur_son_api():
    # systemd inactif (monté dans l'agrégateur), API ok : opérationnel, pas « dégradé »
    assert normalise.etat_module(_mod(api="ok", overall="degraded")) == ("operational", False)


def test_module_on_demand_endormi_en_veille_pas_en_panne():
    assert normalise.etat_module(_mod(api="sleeping", overall="degraded")) == ("operational", True)


def test_module_optionnel_arrete_degrade_seulement(lieux):
    tmp, cfg = lieux
    _ecrire(Path(cfg["sources"]["modules"]["path"]),
            {"timestamp": T0.isoformat(), "modules": {"hub": _mod(), "peertube": _mod(api="down")}})
    r = _collecte(lieux)
    assert r["health"]["services"] == "degraded"
    assert r["health"]["overall"] == "degraded"
    assert r["counts"]["modules_down"] == 1


def test_module_critique_arrete_rend_l_appliance_indisponible(lieux):
    tmp, cfg = lieux
    _ecrire(Path(cfg["sources"]["modules"]["path"]),
            {"timestamp": T0.isoformat(), "modules": {"auth": _mod(api="down", critical=True)}})
    assert _collecte(lieux)["health"]["overall"] == "outage"


def test_sans_sonde_thermique_temperature_inconnue_pas_de_panne(lieux):
    r = _collecte(lieux)
    assert r["resources"]["temperature_celsius"] is None
    assert r["health"]["system"] == "operational"


def test_tout_inconnu_reste_inconnu():
    assert normalise.global_({"a": "unknown", "b": "unknown"}, False) == "unknown"


# ── historique et projection ─────────────────────────────────────────────────

def test_sequence_croissante_et_historique_conserve(lieux):
    tmp, _ = lieux
    a = _collecte(lieux)
    b = _collecte(lieux, T0 + timedelta(minutes=1))
    assert b["sequence"] == a["sequence"] + 1
    cx = historique.ouvrir(tmp / "etat" / "status.db")
    assert cx.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert cx.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 2
    cx.close()


def test_heures_sans_releve_sont_inconnues(lieux):
    tmp, _ = lieux
    _collecte(lieux)
    cx = historique.ouvrir(tmp / "etat" / "status.db")
    h = historique.heures(cx, "gk2", 24, T0)
    cx.close()
    assert len(h) == 24 and h[-1]["status"] == "operational" and h[0]["status"] == "unknown"


def test_projection_publique_sans_secret_ni_inventaire(lieux):
    tmp, cfg = lieux
    cfg["status"]["node_id"] = ""          # cas du TOML semé : jamais le nom de la machine (relecture #3605)
    _collecte(lieux)
    pub = json.loads((tmp / "etat" / "public" / "public-v2.json").read_text())
    texte = json.dumps(pub)
    assert pub["schema"] == "secubox.status.public" and pub["fleet"]["nodes_total"] == 1
    n = pub["nodes"][0]
    assert n["signature_verified"] is None and n["externally_confirmed"] is None
    assert n["id"] == "appliance"
    for interdit in ("kernel", "hostname", PLAT["hostname"], "6.12.113", "resources", "modules\"", "source_notes"):
        assert interdit not in texte, interdit


def test_releve_sans_nan(lieux):
    r = _collecte(lieux, ress={**RESS, "cpu_percent": None})
    json.dumps(r, allow_nan=False)


def test_rejeu_disponibilite_ignore_l_inconnu(lieux):
    tmp, cfg = lieux
    _collecte(lieux)
    os.unlink(cfg["sources"]["modules"]["path"])
    os.unlink(cfg["sources"]["vhosts"]["path"])
    os.unlink(cfg["sources"]["profiles"]["path"])
    _collecte(lieux, T0 + timedelta(minutes=1), ress={k: None for k in RESS})
    cx = historique.ouvrir(tmp / "etat" / "status.db")
    assert historique.disponibilite(cx, "gk2", 30, T0 + timedelta(minutes=2)) == 100.0
    cx.close()


def test_config_type_inattendu_ignore(tmp_path):
    p = tmp_path / "s.toml"
    p.write_text('[status]\nnode_role = "pirate"\n[history]\nretention_days = "beaucoup"\n')
    cfg = config.charger(p)
    assert cfg["status"]["node_role"] == "agent" and cfg["history"]["retention_days"] == 90
    assert config.nom_de_noeud({"status": {"node_id": "../x"}}, "gk2.secubox.in") == "gk2"


def test_lecture_inconnue_vide():
    assert normalise.services(Lecture("stale"))[0] == "unknown"


def test_json_trop_imbrique_ne_fait_pas_echouer_la_collecte(lieux):
    tmp, cfg = lieux
    Path(cfg["sources"]["profiles"]["path"]).write_text("[" * 100000 + "]" * 100000)
    r = _collecte(lieux)
    assert r["sources"]["profiles"] == "invalid"


def test_projection_lisible_par_le_groupe(lieux):
    tmp, _ = lieux
    _collecte(lieux)
    assert (tmp / "etat" / "public" / "public-v2.json").stat().st_mode & 0o777 == 0o640


def test_unites_durcies_socket_0660_et_apparmor():
    racine = Path(__file__).resolve().parent.parent
    api = (racine / "debian" / "secubox-status.service").read_text()
    col = (racine / "debian" / "secubox-status-collect.service").read_text()
    assert "chmod 660 /run/secubox/status.sock" in api and "UMask=0027" in api
    assert "RuntimeDirectory=secubox\n" not in api
    for u in (api, col):
        for ligne in ("User=secubox-status", "NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=\n",
                      "RestrictAddressFamilies=AF_UNIX", "AppArmorProfile=-secubox-status", "UMask=0027"):
            assert ligne in u, ligne
    assert "profile secubox-status" in (racine / "apparmor" / "secubox-status").read_text()


# ── jalon 2 (#3626) : pairs vérifiés par l'Annuaire ──────────────────────────
def _pairs(tmp, cfg, quand, noeuds, indispo=()):
    p = tmp / "pairs.json"
    p.write_text(json.dumps({"generated_at": quand.isoformat(), "noeuds": list(noeuds), "indisponibles": list(indispo)}))
    cfg["sources"]["pairs"]["path"] = str(p)


PAIR = {"hostname": "gk3", "overall": "degraded", "components": {"services": "degraded"}, "sources": {"modules": "fresh"},
        "collected_at": T0.isoformat(), "counts": {"modules_total": 9, "modules_ok": 8, "modules_down": 1},
        "availability_30d": 97.0, "hours": [{"hour": T0.isoformat(), "status": "degraded"}], "signature_verified": True,
        "stale": False, "node_did": "did:plc:" + "0" * 32, "sig": "x"}


def test_pairs_verifies_dans_la_flotte_sans_signature_brute(lieux):
    tmp, cfg = lieux
    _pairs(tmp, cfg, T0, [PAIR], [{"nom": "gk5", "mesh_ip": "10.10.0.10", "raison": "injoignable"}])
    _collecte(lieux)
    pub = json.loads((tmp / "etat" / "public" / "public-v2.json").read_text())
    ids = {n["id"]: n for n in pub["nodes"]}
    assert set(ids) == {"gk2", "gk3", "gk5"} and pub["fleet"]["nodes_total"] == 3
    assert ids["gk3"]["status"] == "degraded" and ids["gk3"]["signature_verified"] is True
    assert ids["gk5"]["status"] == "unknown" and ids["gk5"]["raison"] == "injoignable"
    assert pub["fleet"]["status"] == "degraded"
    texte = json.dumps(pub)
    assert "did:plc" not in texte and '"sig"' not in texte and "10.10.0.10" not in texte


def test_fichier_des_pairs_perime_rend_les_pairs_inconnus(lieux):
    tmp, cfg = lieux
    _pairs(tmp, cfg, T0 - timedelta(hours=1), [PAIR])
    _collecte(lieux)
    pub = json.loads((tmp / "etat" / "public" / "public-v2.json").read_text())
    assert {n["id"]: n["status"] for n in pub["nodes"]}["gk3"] == "unknown"


def test_un_agent_ne_lit_pas_les_pairs(lieux):
    tmp, cfg = lieux
    cfg["status"]["node_role"] = "agent"
    _pairs(tmp, cfg, T0, [PAIR])
    _collecte(lieux)
    pub = json.loads((tmp / "etat" / "public" / "public-v2.json").read_text())
    assert [n["id"] for n in pub["nodes"]] == ["gk2"]
