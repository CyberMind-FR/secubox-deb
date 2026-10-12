# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""build-image.yml (ref #2501) : un commit sans paquet a un run build-packages SANS agrégat.

L'étape « commit exact » finit alors en success (if_no_artifact_found: warn) avec 0 .deb : le repli doit se déclencher sur le NOMBRE de
.deb, pas sur l'issue de l'étape, et la provenance ne doit pas mentir."""
from pathlib import Path

import yaml

WF = Path(__file__).resolve().parents[1] / ".github/workflows/build-image.yml"


def _steps():
    wf = yaml.safe_load(WF.read_text())
    return {s.get("id"): s for s in wf["jobs"]["build-image"]["steps"] if s.get("id")}


def test_un_compte_des_deb_suit_l_etape_exacte():
    s = _steps()
    assert "debs-count" in s
    assert "find output/debs" in s["debs-count"]["run"]


def test_le_repli_part_aussi_quand_l_exact_n_a_rien_donne():
    cond = _steps()["debs-fallback"]["if"]
    assert "debs-exact.outcome" in cond
    assert "debs-count.outputs.n" in cond


def test_la_provenance_ne_dit_pas_agregat_du_commit_avec_zero_deb():
    run = next(s for s in yaml.safe_load(WF.read_text())["jobs"]["build-image"]["steps"]
               if s.get("name") == "Provenance des paquets")["run"]
    assert "debs-count.outputs.n" in run
