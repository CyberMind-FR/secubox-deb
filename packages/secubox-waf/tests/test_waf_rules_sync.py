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
