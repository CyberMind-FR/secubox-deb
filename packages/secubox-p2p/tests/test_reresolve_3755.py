# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3755 — re-résolution du nom d'un pair wg-mesh muet (nœud mobile)."""
import importlib.machinery
import importlib.util
import json
import pathlib
import types

CHEMIN = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "sbx-mesh-reresolve"
_l = importlib.machinery.SourceFileLoader("sbx_mesh_reresolve", str(CHEMIN))
R = importlib.util.module_from_spec(importlib.util.spec_from_loader(_l.name, _l))
_l.exec_module(R)

K1 = "yM8rIAE2MPiH1vpLI6eWsU+2ZryBXyFq69D0D6mG1yM="
K2 = "MfbB17/IZthSsh91TWaIQaLRqGJcU/1REb8iEAWCNQw="
K3 = "Pq46I1Kz7+ApxKQaP6M9qmynWdktciXpTUJQ/npxDW0="


def test_nom_et_port():
    assert R.nom_et_port("gk2.secubox.in:51822") == ("gk2.secubox.in", 51822)
    assert R.nom_et_port("192.168.1.200:51822") is None          # IP littérale : roaming, jamais touchée
    assert R.nom_et_port("[2a01:e0a::200]:51822") is None
    assert R.nom_et_port("gk2.secubox.in:0") is None
    assert R.nom_et_port("gk2.secubox.in") is None
    assert R.nom_et_port("a;rm -rf /:51822") is None
    assert R.nom_et_port(None) is None


def test_seul_le_pair_nomme_et_muet():
    etat = {"peers": [{"public_key": K1, "endpoint": "gk2.secubox.in:51822"},      # muet 300 s : oui
                      {"public_key": K2, "endpoint": "192.168.1.2:51822"},        # IP : non
                      {"public_key": K3, "endpoint": "gk7.secubox.in:51822"},     # frais : non
                      {"public_key": "pas-une-cle", "endpoint": "x.secubox.in:1"}]}
    vues = {K1: 1000, K2: 0, K3: 1290}
    assert R.a_reresoudre(etat, vues, 1300) == [(K1, "gk2.secubox.in:51822")]
    assert R.a_reresoudre(etat, {K1: 0}, 1300) == [(K1, "gk2.secubox.in:51822")]   # jamais de poignée
    assert R.a_reresoudre(etat, {}, 1300) == []                                     # pair inconnu de l'interface


def test_main_appelle_wg_set_en_liste(tmp_path, monkeypatch):
    f = tmp_path / "wg_mesh.json"
    f.write_text(json.dumps({"peers": [{"public_key": K1, "endpoint": "gk2.secubox.in:51822"}]}))
    monkeypatch.setattr(R, "ETAT", str(f))
    appels = []

    def executer(argv, **kw):
        appels.append(argv)
        out = "%s\t1000\n" % K1 if argv[:3] == ["wg", "show", "wg-mesh"] else ""
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")
    assert R.main(executer, maintenant=2000) == 0
    assert appels[-1] == ["wg", "set", "wg-mesh", "peer", K1, "endpoint", "gk2.secubox.in:51822"]


def test_main_sans_etat_ni_interface(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "ETAT", str(tmp_path / "absent.json"))
    assert R.main(lambda *a, **k: None) == 0
