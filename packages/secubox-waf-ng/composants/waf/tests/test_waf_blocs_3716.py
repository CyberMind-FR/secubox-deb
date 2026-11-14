# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""waf-blocs (#3716) : forme des blocs /24 et gardes (privé, protégées, box, pairs)."""

import importlib.machinery
import importlib.util
import ipaddress
import json
import subprocess
from pathlib import Path

import pytest

CHEMIN = Path(__file__).resolve().parents[1] / "scripts" / "waf-blocs"


@pytest.fixture
def wb():
    chargeur = importlib.machinery.SourceFileLoader("waf_blocs", str(CHEMIN))
    spec = importlib.util.spec_from_loader("waf_blocs", chargeur)
    module = importlib.util.module_from_spec(spec)
    chargeur.exec_module(module)
    return module


def test_bloc_exact_24_seulement(wb):
    assert str(wb.normaliser_bloc("203.0.113.0/24")) == "203.0.113.0/24"
    for faux in ("203.0.113.0/23", "203.0.113.0/25", "203.0.113.7/24", "2001:db8::/64", "203.0.113.0", "x"):
        with pytest.raises(ValueError):
            wb.normaliser_bloc(faux)


def test_interdits_refuses(wb):
    for b in ("10.1.2.0/24", "192.168.1.0/24", "172.16.5.0/24", "127.0.0.0/24", "169.254.1.0/24"):
        assert wb.motif_refus(wb.normaliser_bloc(b), [], set(), set()) == "privee"


def test_documentation_n_est_pas_privee(wb):
    assert wb.motif_refus(wb.normaliser_bloc("203.0.113.0/24"), [], set(), set()) is None


def test_protegees_env_recoupe(wb, tmp_path):
    f = tmp_path / "protegees.env"
    f.write_text("SECUBOX_WAF_PROTEGEES=203.0.113.7/32,198.51.100.0/22\n")
    p = wb.lire_protegees(f)
    assert wb.motif_refus(wb.normaliser_bloc("203.0.113.0/24"), p, set(), set()) == "protegee"
    assert wb.motif_refus(wb.normaliser_bloc("198.51.101.0/24"), p, set(), set()) == "protegee"
    assert wb.motif_refus(wb.normaliser_bloc("192.0.2.0/24"), p, set(), set()) is None


def test_protegees_absent_est_vide(wb, tmp_path):
    assert wb.lire_protegees(tmp_path / "absent.env") == []


def test_adresse_de_la_box(wb):
    locales = {ipaddress.ip_address("198.51.100.10")}
    assert wb.motif_refus(wb.normaliser_bloc("198.51.100.0/24"), [], locales, set()) == "box"


def test_pair_wireguard(wb):
    sortie = "wg-mesh\tAbC=\t192.0.2.5:51820\nwg0\tDeF=\t(none)\n"
    pairs = wb.adresses_pairs(lambda argv: sortie)
    assert pairs == {ipaddress.ip_address("192.0.2.5")}
    assert wb.motif_refus(wb.normaliser_bloc("192.0.2.0/24"), [], set(), pairs) == "pair"


def test_pair_ipv6_entre_crochets(wb):
    sortie = "wg0\tAbC=\t[2001:db8::1]:51820\n"
    assert wb.adresses_pairs(lambda argv: sortie) == {ipaddress.ip_address("2001:db8::1")}


def test_wg_absent_n_est_pas_un_refus(wb):
    def absent(argv):
        raise FileNotFoundError(argv[0])
    assert wb.adresses_pairs(absent) == set()


def test_wg_en_echec_ferme(wb):
    def echec(argv):
        raise subprocess.CalledProcessError(1, argv)
    with pytest.raises(wb.GardeIllisible):
        wb.adresses_pairs(echec)


def test_endpoint_wg_illisible_ferme(wb):
    with pytest.raises(wb.GardeIllisible):
        wb.adresses_pairs(lambda argv: "wg0\tAbC=\tpas-une-adresse:1\n")


def test_adresses_locales(wb):
    sortie = json.dumps([{"addr_info": [{"local": "198.51.100.10"}, {"local": "fe80::1"}]}, {"addr_info": []}])
    assert wb.adresses_locales(lambda argv: sortie) == {
        ipaddress.ip_address("198.51.100.10"), ipaddress.ip_address("fe80::1")}


def test_ip_en_echec_ferme(wb):
    def echec(argv):
        raise FileNotFoundError("ip")
    with pytest.raises(wb.GardeIllisible):
        wb.adresses_locales(echec)
    with pytest.raises(wb.GardeIllisible):
        wb.adresses_locales(lambda argv: "pas du json")


def test_garde_illisible_ferme(wb, tmp_path):
    f = tmp_path / "protegees.env"
    f.write_text("SECUBOX_WAF_PROTEGEES=pas-une-plage\n")
    with pytest.raises(wb.GardeIllisible):
        wb.lire_protegees(f)
    f.write_text("ligne sans egal\n")
    with pytest.raises(wb.GardeIllisible):
        wb.lire_protegees(f)


def test_protegees_non_fichier_ferme(wb, tmp_path):
    with pytest.raises(wb.GardeIllisible):
        wb.lire_protegees(tmp_path)  # un dossier : OSError, pas « absent »


def test_adresse_seule_verifiee_pareil(wb):
    assert wb.motif_refus(wb.normaliser_cible("192.168.1.20"), [], set(), set()) == "privee"
    assert wb.motif_refus(wb.normaliser_cible("198.51.100.10"), [], {ipaddress.ip_address("198.51.100.10")}, set()) == "box"
    assert wb.motif_refus(wb.normaliser_cible("fd00::1"), [], set(), set()) == "privee"


def _cli(wb, monkeypatch, tmp_path, cible, env=None, ip="[]", wg=""):
    f = tmp_path / "protegees.env"
    if env is not None:
        f.write_text(env)
    monkeypatch.setattr(wb, "PROTEGEES_ENV", f)

    def faux(argv):
        if argv[0] == "ip":
            return ip
        return wg
    monkeypatch.setattr(wb, "executer", faux)
    return wb.main(["verifier", cible])


def test_sortie_json_une_ligne(wb, monkeypatch, capsys, tmp_path):
    assert _cli(wb, monkeypatch, tmp_path, "203.0.113.0/24") == 0
    assert capsys.readouterr().out == '{"ok": true, "motif": null}\n'


def test_cli_codes_de_sortie(wb, monkeypatch, capsys, tmp_path):
    assert _cli(wb, monkeypatch, tmp_path, "x") == 1
    assert json.loads(capsys.readouterr().out) == {"ok": False, "motif": "invalide"}
    assert _cli(wb, monkeypatch, tmp_path, "10.0.0.0/24") == 2
    assert _cli(wb, monkeypatch, tmp_path, "203.0.113.0/24", env="SECUBOX_WAF_PROTEGEES=203.0.113.0/25\n") == 3
    loc = json.dumps([{"addr_info": [{"local": "198.51.100.10"}]}])
    assert _cli(wb, monkeypatch, tmp_path, "198.51.100.0/24", ip=loc) == 4
    assert _cli(wb, monkeypatch, tmp_path, "192.0.2.0/24", wg="wg0\tK=\t192.0.2.5:1\n") == 5
    capsys.readouterr()
    assert _cli(wb, monkeypatch, tmp_path, "203.0.113.0/24", env="SECUBOX_WAF_PROTEGEES=zzz\n") == 6
    assert json.loads(capsys.readouterr().out) == {"ok": False, "motif": "garde_illisible"}


def test_cli_ip_en_echec_donne_6(wb, monkeypatch, tmp_path):
    monkeypatch.setattr(wb, "PROTEGEES_ENV", tmp_path / "absent.env")
    monkeypatch.setattr(wb, "executer", lambda argv: (_ for _ in ()).throw(FileNotFoundError("ip")))
    assert wb.main(["verifier", "203.0.113.0/24"]) == 6
