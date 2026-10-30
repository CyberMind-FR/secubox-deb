# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L5 tâche 6 (E4) — plan d'exposition écrit par le service pour secubox-relais-maillage (root) : noms et ports déclarés
par l'agent (Device.X_SECUBOX_Exposure), par adresse maillée, validés strictement ; aucune route sans jeton."""
import asyncio
import json
import time

from api.main import creer_app_admin
from pilotage import exposition as E
from pilotage.files import Files
from pilotage.identite import Box
from pilotage.inventaire import Inventaire
from pilotage.stockage import StockageSqlite
from outils import Horloge

GK5 = Box("gk5", "10.10.0.5", "maillage", None, None)
GK6 = Box("gk6", "10.10.0.6", "maillage", None, None)
CLI = Box("cli", "10.64.0.9", "autoload", "acme", "actif")


def expo(noms=("admin.gk5.secubox.in", "hub.gk5.secubox.in"), ports=(22, 9080), interface=None):
    v = {E.NOMS: list(noms), E.PORTS: list(ports)}
    if interface:
        v[E.INTERFACE] = interface
    return v


def ligne(nom="gk5", adresse="10.10.0.5", valeurs=None, reseau="maillage", releve_le=1000.0, tronques=()):
    return {"nom": nom, "adresse": adresse, "reseau": reseau,
            "inventaire": {"valeurs": expo() if valeurs is None else valeurs, "releve_le": releve_le, "tronques": list(tronques)}}


def test_plan_noms_et_ports_valides():
    p = E.plan([ligne(valeurs=expo(interface="distante"))])
    assert p == {"version": 1, "boxes": [{"adresse": "10.10.0.5", "box": "gk5", "distante": True,
                                          "noms": ["admin.gk5.secubox.in", "hub.gk5.secubox.in"], "ports": [22, 9080],
                                          "releve_le": 1000.0}]}


def test_plan_filtre_noms_hors_domaine_et_invalides():
    noms = ["hub.gk5.secubox.in", "hub.gk2.secubox.in", "gk5.secubox.in", "a.b.gk5.secubox.in", "HUB.gk5.secubox.in",
            "x" * 41 + ".gk5.secubox.in", "-x.gk5.secubox.in", "evil.com", 7, None, "meet.gk5.secubox.in"]
    ports = [0, 65536, 443, "80", True, 1.5, -1, 7881]
    b = E.plan([ligne(valeurs=expo(noms=noms, ports=ports))])["boxes"][0]
    assert b["noms"] == ["hub.gk5.secubox.in", "meet.gk5.secubox.in"]
    assert b["ports"] == [443, 7881]


def test_plan_listes_bornees():
    noms = [f"s{i}.gk5.secubox.in" for i in range(500)]
    b = E.plan([ligne(valeurs=expo(noms=noms, ports=range(1, 2000)))])["boxes"][0]
    assert len(b["noms"]) == E.NOMS_MAX and len(b["ports"]) == E.PORTS_MAX


def test_plan_ecarte_autoload_ambigus_tronques_et_sans_exposition():
    lignes = [ligne(nom="cli", adresse="10.64.0.9", reseau="autoload"),
              ligne(nom="gk6", adresse="10.10.0.6", tronques=[E.NOMS]),
              ligne(nom="gk7", adresse="10.10.0.7", valeurs={}),
              ligne(nom="gk8", adresse="10.10.0.8", valeurs={E.NOMS: "pas une liste", E.PORTS: []}),
              ligne(nom="gk9", adresse="10.10.0.9"), ligne(nom="gk9", adresse="10.10.0.19"),
              ligne(nom="GK1", adresse="10.10.0.1"), ligne(nom="gk3", adresse="192.168.1.3")]
    assert E.plan(lignes) == {"version": 1, "boxes": []}


def test_ecrire_plan_atomique(tmp_path):
    f = tmp_path / "exposition.json"
    assert E.ecrire_plan(f, E.plan([ligne()])) is True
    assert E.ecrire_plan(f, E.plan([ligne()])) is False
    assert oct(f.stat().st_mode & 0o777) == "0o640"
    assert json.loads(f.read_text())["boxes"][0]["box"] == "gk5"


def test_service_ecrit_le_plan_a_chaque_tour(tmp_path):
    h = Horloge(time.time())
    s = StockageSqlite(tmp_path / "p", horloge=h)
    f = Files()
    inv = Inventaire(f, s, horloge=h)
    cible = tmp_path / "exposition.json"
    creer_app_admin(s, f, inv, lambda *a: None, horloge=h, plan_exposition=cible)
    for box in (GK5, GK6, CLI):
        s.vu(box, {"agent_version": "0.4.2"})
        s.inventaire_enregistrer(box, {"results": [{"path": "Device.", "params": expo(
            noms=(f"hub.{box.nom}.secubox.in",), ports=(7881,))}]})
    asyncio.run(inv.tour())
    d = json.loads(cible.read_text())
    assert [(b["box"], b["adresse"], b["noms"]) for b in d["boxes"]] == [
        ("gk5", "10.10.0.5", ["hub.gk5.secubox.in"]), ("gk6", "10.10.0.6", ["hub.gk6.secubox.in"])]
