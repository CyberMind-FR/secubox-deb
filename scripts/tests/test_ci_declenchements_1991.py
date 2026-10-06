# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1991 — un push ne doit pas bloquer la release.

Chaque push sur master (et chaque PR) lançait la matrice complète de ~170 jobs, deux fois (build-packages
par lui-même ET appelé par sync-all), sans annuler les runs dépassés : la file de runners saturait et les
demandes de release attendaient. Et Aurora, en pré-alpha de développement, ne doit entrer dans AUCUN build."""
from pathlib import Path

import yaml

RACINE = Path(__file__).resolve().parents[2]
WF = RACINE / ".github" / "workflows"


def _wf(nom):
    return yaml.safe_load((WF / nom).read_text())


def _script_discover():
    d = _wf("build-packages.yml")
    etape = next(s for s in d["jobs"]["discover"]["steps"] if s.get("id") == "find")
    return etape["run"]


def test_aurora_est_exclu_de_tous_les_builds():
    run = _script_discover()
    i = run.index("*~aurora*")
    avant = run[max(0, i - 400):i]
    # l'exclusion ne dépend plus de l'étiquette : push, PR, release, tout
    assert 'GITHUB_REF_TYPE' not in avant and 'REF_TYPE' not in avant
    assert "continue" in run[i:i + 250]


def test_les_runs_depasses_sont_annules_sauf_sur_etiquette():
    d = _wf("build-packages.yml")
    conc = d.get("concurrency")
    assert conc and "github.ref" in str(conc.get("group"))
    expr = str(conc.get("cancel-in-progress"))
    assert "tag" not in expr or "!=" in expr or "branch" in expr          # jamais d'annulation d'un tag


def test_sync_all_ne_reconstruit_plus_a_chaque_push():
    sync = _wf("sync-all.yml")
    condition = str(sync["jobs"]["build-packages"]["if"])
    assert "workflow_dispatch" in condition or "force_rebuild" in condition
    assert "packages_changed" not in condition        # le push ne déclenche plus la matrice entière


def test_un_push_de_branche_ne_construit_que_les_paquets_modifies():
    run = _script_discover()
    assert "compare" in run or "pulls" in run         # fichiers modifiés demandés à l'API
    d = _wf("build-packages.yml")
    assert "!= '[]'" in str(d["jobs"]["build"].get("if")) or "!= '[]'" in str(d["jobs"]["build"].get("if", "")).replace('"', "'")
    assert "skipped" in str(d["jobs"]["collect"].get("if"))


def test_les_images_ne_se_lancent_plus_en_double_sur_etiquette():
    for nom in ("build-image.yml", "build-all-live-usb.yml"):
        on = _wf(nom).get(True) or _wf(nom).get("on")
        assert "push" not in on, nom                    # release.yml les appelle déjà
        assert "workflow_call" in on and "workflow_dispatch" in on, nom


def test_dispatch_manuel_n_annule_pas_et_accepte_une_liste():
    """Plusieurs dispatchs a la suite sur master s'annulaient mutuellement ; `package` n'acceptait qu'un nom."""
    wf = (Path(__file__).resolve().parents[2] / ".github/workflows/build-packages.yml").read_text()
    assert "github.event_name != 'workflow_dispatch'" in wf
    assert "tr ',' ' '" in wf and 'grep -q " $pkg "' in wf
