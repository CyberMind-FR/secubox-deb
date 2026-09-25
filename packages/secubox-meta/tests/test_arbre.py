# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""L'arbre des métapaquets (#1397) : cohérent, couvrant, et le control à jour."""
import importlib.util
import os
import subprocess
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(ICI)
spec = importlib.util.spec_from_file_location("gen_meta", os.path.join(RACINE, "gen-meta.py"))
gm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gm)


def _etat():
    depot = gm.paquets_du_depot(exclure_source="secubox-meta")
    noeuds, hors = gm.lit_arbre()
    return depot, noeuds, hors


def test_arbre_valide_et_couvrant():
    depot, noeuds, hors = _etat()
    assert gm.valide(noeuds, hors, depot) == []


def test_control_genere_a_jour():
    r = subprocess.run([sys.executable, os.path.join(RACINE, "gen-meta.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_deux_racines_imbriquees():
    _, noeuds, _ = _etat()
    m = {n["meta"]: n for n in noeuds}
    assert {n["meta"] for n in noeuds if n["niveau"] == "racine"} == {"sbxos", "secubox"}
    assert "secubox" in m["sbxos"]["requiert"]            # le Hall pose la box
    assert "secubox-service-hall" in m["sbxos"]["requiert"]


def test_le_courrier_absorbe_ses_trois_anciens_paquets():
    depot, noeuds, hors = _etat()
    r = gm.resolu(noeuds, hors, depot)
    assert set(r["paquets"]["secubox-mail"]["absorbe"]) >= {
        "secubox-mail-lxc", "secubox-webmail", "secubox-webmail-lxc"}


def test_refus():
    depot, noeuds, hors = _etat()
    import copy
    # arm64 seul en Depends
    n2 = copy.deepcopy(noeuds)
    svc = next(n for n in n2 if n["meta"] == "secubox-service-assistant")
    svc["suggere"].remove("secubox-zia-llm"); svc["requiert"].append("secubox-zia-llm")
    assert any("arm64" in e for e in gm.valide(n2, hors, depot))
    # cycle
    n3 = copy.deepcopy(noeuds)
    next(n for n in n3 if n["meta"] == "secubox-fonction-socle")["recommande"].append("secubox")
    assert any(e.startswith("cycle") for e in gm.valide(n3, hors, depot))
    # module neuf oublié
    d2 = dict(depot); d2["secubox-neuf"] = dict(depot["secubox-mail"], transitionnel=False)
    assert any("secubox-neuf" in e for e in gm.valide(noeuds, hors, d2))
    # transitionnel rangé
    n4 = copy.deepcopy(noeuds)
    next(n for n in n4 if n["meta"] == "secubox-service-mail")["recommande"].append("secubox-webmail")
    assert any("transitionnel" in e for e in gm.valide(n4, [h for h in hors if h != "secubox-webmail"], depot))
