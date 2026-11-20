# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — SADE ACTIVE : bloc `auto` de /policies, marque « auto » de /proposals, bouton et textes de la page."""
# ruff: noqa: F811 — les fixtures pytest importées sont « redéfinies » par les paramètres des tests (faux positif).
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_defense_facade import faux, client, admin, LECTURE  # noqa: E402,F401
from api import defense, defense_etat  # noqa: E402

PAGE = (Path(__file__).resolve().parent.parent / "www" / "soc" / "defense.html").read_text(encoding="utf-8")


def test_policies_bloc_auto(faux, client):
    j = client.get("/defense/policies", headers=LECTURE).json()
    assert j["auto"] == {"plafond_heure": 20, "bans_derniere_heure": 0, "score": [60, 94],
                         "ttl_max_s": 86400, "adresses_max": 8}


def test_policies_auto_none_si_base_illisible(faux, client, monkeypatch):
    def casse(*a, **k):
        raise defense_etat.EtatIndisponible("x")
    monkeypatch.setattr(defense_etat, "bans_auto_depuis", casse)
    assert client.get("/defense/policies", headers=LECTURE).json()["auto"]["bans_derniere_heure"] is None


def test_proposals_marque_auto(faux, client, admin, monkeypatch, tmp_path):
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "audit.log"))
    defense_etat.changer_mode("active", "op")
    props = client.get("/defense/proposals", headers=LECTURE).json()["propositions"]
    assert all("auto" not in p for p in props)
    p = props[0]
    ips = p["cible"].split(", ")
    emp = p["empreinte"]
    defense_etat.reclamer(emp, p["menace_id"], "ban", ips[0], p["score"], 600, "sade-auto", "refuse",
                          "sade-auto-test", modes=("active",))
    j = client.get("/defense/proposals", headers=LECTURE).json()
    assert next(x for x in j["propositions"] if x["menace_id"] == p["menace_id"])["auto"] is True
    assert "sade-auto" not in str(j)


def test_proposals_humain_pas_auto(faux, client, admin, monkeypatch, tmp_path):
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "audit.log"))
    defense_etat.changer_mode("reactive", "op")
    p = client.get("/defense/proposals", headers=LECTURE).json()["propositions"][0]
    defense_etat.reclamer(p["empreinte"], p["menace_id"], "ban", "198.51.100.7", 90, 600, "alice", "refuse", "x")
    j = client.get("/defense/proposals", headers=LECTURE).json()
    assert all("auto" not in x for x in j["propositions"]) and "alice" not in str(j)


def test_bouton_active_actif_aggressive_non():
    b = re.search(r'<button[^>]*data-mode="active"[^>]*>', PAGE).group(0)
    assert " disabled" not in b
    b = re.search(r'<button[^>]*data-mode="aggressive"[^>]*>', PAGE).group(0)
    assert " disabled" in b


def test_texte_de_confirmation_active():
    m = re.search(r"\n    active:'(.*?)'\};", PAGE, re.S).group(1)
    assert "20 par heure" in m and "retour en OBSERVE" in m and "ban de 24 h au plus" in m


def test_page_compteur_et_marque_auto():
    assert "sur l\\'heure" in PAGE and "Bans automatiques" in PAGE
    assert "appliqué automatiquement" in PAGE and "p.auto === true" in PAGE
    assert "REACTIVE seulement" not in PAGE and "hors REACTIVE.'" not in PAGE
