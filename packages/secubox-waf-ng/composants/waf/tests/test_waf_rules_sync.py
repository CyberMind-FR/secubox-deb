# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""waf-rules-sync (#1858) : les règles livrées passent, les générées restent."""

import importlib.machinery
import importlib.util
import json
from pathlib import Path

CHEMIN = Path(__file__).resolve().parents[1] / "scripts" / "waf-rules-sync"
_loader = importlib.machinery.SourceFileLoader("waf_rules_sync", str(CHEMIN))
_spec = importlib.util.spec_from_loader("waf_rules_sync", _loader)
sync = importlib.util.module_from_spec(_spec)
_loader.exec_module(sync)


def cat(*ids, **kw):
    return {"patterns": [{"id": i, "pattern": i} for i in ids], **kw}


def test_les_categories_livrees_remplacent_celles_de_la_box():
    livre = {"categories": {"api_abuse": cat("api-002")}}
    vivant = {"categories": {"api_abuse": cat("api-001", "api-002")}}
    assert sync.fusionne(livre, vivant)["categories"]["api_abuse"] == cat("api-002")


def test_la_categorie_generee_de_la_box_est_gardee():
    gen_box = cat("w-1", generated=True, mode="detect")
    livre = {"categories": {"x": cat("a"), "product_absent_probes": cat("w-0", generated=True, mode="escalate")}}
    vivant = {"categories": {"x": cat("a"), "product_absent_probes": gen_box}}
    assert sync.fusionne(livre, vivant)["categories"]["product_absent_probes"] == gen_box


def test_une_generee_absente_de_la_box_est_posee_et_une_generee_orpheline_gardee():
    livre = {"categories": {"g": cat("g1", generated=True)}}
    assert "g" in sync.fusionne(livre, {"categories": {}})["categories"]
    orph = {"categories": {"vieille": cat("v1", generated=True)}}
    assert "vieille" in sync.fusionne({"categories": {}}, orph)["categories"]


def test_ecriture_avec_sauvegarde_et_idempotence(tmp_path, monkeypatch):
    livre = tmp_path / "livre.json"
    vivant = tmp_path / "vivant.json"
    livre.write_text(json.dumps({"categories": {"a": cat("a1")}}))
    vivant.write_text(json.dumps({"categories": {"a": cat("a1", "a0")}}))
    monkeypatch.setattr("sys.argv", ["x", "--livre", str(livre), "--vivant", str(vivant), "--version", "9"])
    assert sync.main() == 10
    assert (tmp_path / "vivant.json.avant-9").is_file()
    assert json.loads(vivant.read_text())["categories"]["a"] == cat("a1")
    assert sync.main() == 0                      # deuxième passage : rien à faire


def test_sync_propage_meta():
    """_meta de la copie livrée remplace celui de la box (#3257)."""
    livre = {"_meta": {"version": "1.6.0"}, "categories": {"sqli": cat("sqli-001")}}
    vivant = {"_meta": {"version": "1.5.2"}, "categories": {"sqli": cat("sqli-001")}}
    neuf = sync.fusionne(livre, vivant)
    assert neuf["_meta"] == {"version": "1.6.0"}
    assert neuf["categories"]["sqli"] == cat("sqli-001")


def test_sync_garde_generees():
    """Le remplacement de _meta ne touche pas aux catégories générées."""
    gen = cat("w-1", generated=True, mode="detect")
    livre = {"_meta": {"version": "1.6.0"}, "categories": {"sqli": cat("sqli-001")}}
    vivant = {"_meta": {"version": "1.5.2"},
              "categories": {"sqli": cat("sqli-001"), "product_absent_probes": gen}}
    neuf = sync.fusionne(livre, vivant)
    assert neuf["categories"]["product_absent_probes"] == gen
    assert neuf["_meta"]["version"] == "1.6.0"


# ── R14 (#3257, relecture finale I2b) : le choix « enabled » de la box tient ──

def test_sync_garde_enabled_false_de_la_box():
    """Une catégorie désactivée sur la box (faux positif) le reste à la mise à
    jour, mais ses motifs suivent la copie livrée."""
    livre = {"categories": {"php2shell": cat("p-2", enabled=True, mode="detect")}}
    vivant = {"categories": {"php2shell": cat("p-1", enabled=False, mode="detect")}}
    neuf = sync.fusionne(livre, vivant)["categories"]["php2shell"]
    assert neuf["enabled"] is False
    assert neuf["patterns"] == cat("p-2")["patterns"]


def test_sync_true_de_la_box_suit_la_copie_livree():
    """R16 (N1) : seul le « false » de l'opérateur est gardé ; un paquet doit
    pouvoir désactiver une catégorie, même si la box porte « true »."""
    livre = {"categories": {"x": cat("a", enabled=False)}}
    vivant = {"categories": {"x": cat("a", enabled=True)}}
    assert sync.fusionne(livre, vivant)["categories"]["x"]["enabled"] is False


def test_sync_sans_enabled_sur_la_box_prend_la_valeur_livree():
    livre = {"categories": {"x": cat("a", enabled=False), "y": cat("b")}}
    vivant = {"categories": {"x": cat("a"), "y": cat("b", enabled="oui")}}
    neuf = sync.fusionne(livre, vivant)["categories"]
    assert neuf["x"]["enabled"] is False          # clé absente sur la box
    assert "enabled" not in neuf["y"]             # valeur non booléenne : ignorée


def test_sync_ecarts_enabled():
    """Seul un « false » de la box face à une catégorie livrée active est un écart gardé."""
    livre = {"categories": {"a": cat("1"), "b": cat("2", enabled=True), "c": cat("3", enabled=False),
                            "d": cat("4", enabled=False)}}
    vivant = {"categories": {"a": cat("1", enabled=False), "b": cat("2", enabled=True), "c": cat("3"),
                             "d": cat("4", enabled=True)}}
    assert sync.ecarts_enabled(livre, vivant) == [("a", False, True)]


def test_sync_false_livre_et_false_box_rien_a_auditer(tmp_path, monkeypatch):
    livre, vivant, audit = tmp_path / "livre.json", tmp_path / "vivant.json", tmp_path / "audit.log"
    livre.write_text(json.dumps({"categories": {"x": cat("a1", enabled=False)}}))
    vivant.write_text(json.dumps({"categories": {"x": cat("a0", enabled=True)}}))
    assert _lancer_sync(monkeypatch, livre, vivant, audit) == 10
    assert json.loads(vivant.read_text())["categories"]["x"]["enabled"] is False
    assert not audit.exists()


def _lancer_sync(monkeypatch, livre, vivant, audit, *extra):
    monkeypatch.setattr("sys.argv", ["x", "--livre", str(livre), "--vivant", str(vivant),
                                     "--version", "9", "--audit", str(audit), *extra])
    return sync.main()


def test_sync_audite_un_enabled_garde_qui_differe(tmp_path, monkeypatch):
    livre, vivant, audit = tmp_path / "livre.json", tmp_path / "vivant.json", tmp_path / "audit.log"
    livre.write_text(json.dumps({"categories": {"php2shell": cat("p-2", enabled=True)}}))
    vivant.write_text(json.dumps({"categories": {"php2shell": cat("p-1", enabled=False)}}))
    assert _lancer_sync(monkeypatch, livre, vivant, audit, "--dry-run") == 10
    assert not audit.exists()                                  # essai à blanc : rien
    assert _lancer_sync(monkeypatch, livre, vivant, audit) == 10
    assert json.loads(vivant.read_text())["categories"]["php2shell"]["enabled"] is False
    lignes = [json.loads(x) for x in audit.read_text().splitlines()]
    assert len(lignes) == 1 and lignes[0]["action"] == "rules-sync-enabled"
    assert "php2shell" in lignes[0]["detail"] and "false" in lignes[0]["detail"]


def test_sync_n_audite_rien_sans_ecart(tmp_path, monkeypatch):
    livre, vivant, audit = tmp_path / "livre.json", tmp_path / "vivant.json", tmp_path / "audit.log"
    livre.write_text(json.dumps({"categories": {"a": cat("a1", enabled=True)}}))
    vivant.write_text(json.dumps({"categories": {"a": cat("a0", enabled=True)}}))
    assert _lancer_sync(monkeypatch, livre, vivant, audit) == 10
    assert not audit.exists()
