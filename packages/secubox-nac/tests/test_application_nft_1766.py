# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""NAC : l'état voulu, sa validation par le service root, et les règles d'application (#1766)."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path

NAC = Path(__file__).resolve().parents[1]


def _charge(chemin, nom):
    loader = importlib.machinery.SourceFileLoader(nom, str(chemin))
    spec = importlib.util.spec_from_loader(nom, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


desired = _charge(NAC / "api" / "nft_desired.py", "nft_desired_t")
apply_ = _charge(NAC / "sbin" / "secubox-nac-apply", "nac_apply_t")
REGLES = (NAC / "nft" / "secubox-nac.nft").read_text()


def test_ajout_retrait_lecture(tmp_path, monkeypatch):
    monkeypatch.setattr(desired, "DESIRED", tmp_path / "d.json")
    assert desired.add("blocked", "AA:BB:CC:DD:EE:FF")
    assert desired.members("blocked") == ["aa:bb:cc:dd:ee:ff"]       # canonisée en minuscules
    assert desired.add("blocked", "aa:bb:cc:dd:ee:ff")                # idempotent
    assert desired.members("blocked") == ["aa:bb:cc:dd:ee:ff"]
    assert desired.remove("blocked", "aa:bb:cc:dd:ee:ff")
    assert desired.members("blocked") == []


def test_refuse_ce_qui_n_est_pas_une_mac_ou_un_ensemble(tmp_path, monkeypatch):
    monkeypatch.setattr(desired, "DESIRED", tmp_path / "d.json")
    assert not desired.add("blocked", "1.2.3.4")
    assert not desired.add("blocked", "aa:bb:cc:dd:ee:ff } ; flush ruleset ; { x")
    assert not desired.add("inconnu", "aa:bb:cc:dd:ee:ff")
    assert not (tmp_path / "d.json").exists()


def test_service_root_ecarte_ce_qui_est_invalide(tmp_path):
    f = tmp_path / "d.json"
    f.write_text(json.dumps({
        "blocked": ["aa:bb:cc:dd:ee:ff", "x } ; flush ruleset", 5, "AA:BB:CC:DD:EE:00"],
        "inconnu": ["aa:bb:cc:dd:ee:11"],
        "iot_zone": "pas une liste"}))
    voulu = apply_.lire_voulu(f)
    assert voulu["blocked"] == ["aa:bb:cc:dd:ee:00", "aa:bb:cc:dd:ee:ff"]
    assert "inconnu" not in voulu and voulu["iot_zone"] == []


def test_fichier_absent_ou_casse_donne_des_ensembles_vides(tmp_path):
    assert apply_.lire_voulu(tmp_path / "absent.json") == {s: [] for s in apply_.SETS}
    (tmp_path / "x.json").write_text("{pas du json")
    assert apply_.lire_voulu(tmp_path / "x.json") == {s: [] for s in apply_.SETS}


def test_script_nft_une_transaction_regles_puis_elements():
    script = apply_.construire(REGLES, {"blocked": ["aa:bb:cc:dd:ee:ff"], "iot_zone": []})
    assert script.index("delete table inet secubox_nac") < script.index("add element")
    assert "add element inet secubox_nac blocked { aa:bb:cc:dd:ee:ff }" in script
    assert "iot_zone {" not in script.split("add element", 1)[1]      # ensemble vide : pas d'ajout


def test_les_ensembles_sont_enfin_references_par_des_regles():
    # Avant #1766 : aucune règle ne les référençait, remplis ils ne filtraient rien.
    for ens in ("blocked", "quarantine_zone", "iot_zone", "guest_zone"):
        assert f"@{ens}" in REGLES, ens
    assert "ether saddr @blocked counter drop" in REGLES and "ether daddr @blocked counter drop" in REGLES
    assert "priority filter - 5" in REGLES                              # avant les bases à priorité 0


def test_quarantaine_garde_dhcp_et_dns():
    assert "ether saddr @quarantine_zone udp dport { 53, 67, 68 } return" in REGLES


def test_ensembles_alignes_entre_api_service_et_regles():
    assert tuple(desired.SETS) == tuple(apply_.SETS)
    for ens in desired.SETS:
        assert f"set {ens}" in REGLES
