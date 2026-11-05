# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3467 : activation et retrait de la clé : DNS unique, origine rendue, jamais d'écrasement."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path

import pytest

CHEMIN = Path(__file__).resolve().parents[1] / "sbin/secubox-mobilectl"
_l = importlib.machinery.SourceFileLoader("mobilectl", str(CHEMIN))
_s = importlib.util.spec_from_loader("mobilectl", _l)
C = importlib.util.module_from_spec(_s)
_l.exec_module(C)


class Faux:
    def __init__(self, dns=("192.168.1.254",), autorise=True, droit=True, ip="192.168.1.50"):
        self.dns, self.autorise, self.droit, self.ip, self.appels = list(dns), autorise, droit, ip, []

    def __call__(self, cmd):
        self.appels.append(cmd)
        if cmd[:2] == ["ip", "-j"]:
            return 0, json.dumps([{"prefsrc": self.ip, "dev": "eth0"}])
        if cmd[0] == "runuser":
            v = cmd[5:]
            if not self.autorise:
                return 1, json.dumps({"erreur": "non autorisé"})
            if v[0] == "dns-lire":
                return 0, json.dumps({"dns": self.dns})
            if not self.droit:
                return 1, json.dumps({"erreur": "droit"})
            if v[0] == "dns-regler":
                self.dns = [x for x in v[1].split(",") if x]
            return 0, json.dumps({"mac": "AA:BB"})
        if cmd[:3] == ["nft", "-a", "list"]:
            return 0, 'udp dport 53 accept comment "secubox-mobile" # handle 7\nautre # handle 8'
        return 0, ""


@pytest.fixture
def lieux(tmp_path):
    src = tmp_path / "src"
    src.write_text("x")
    return dict(etat_f=tmp_path / "e.json", retire=tmp_path / "r", conf=tmp_path / "u.conf"), src


def test_activation_pose_un_seul_dns_et_garde_l_origine(lieux):
    k, src = lieux
    f = Faux()
    r = C.activer(f, source=src, **k)
    assert r["etat"] == "actif" and f.dns == ["192.168.1.50"]
    assert json.loads(k["etat_f"].read_text())["dns_origine"] == ["192.168.1.254"]


def test_deuxieme_activation_ne_prend_pas_la_cle_pour_l_origine(lieux):
    k, src = lieux
    f = Faux()
    C.activer(f, source=src, **k)
    C.activer(f, source=src, **k)
    assert json.loads(k["etat_f"].read_text())["dns_origine"] == ["192.168.1.254"]


def test_retrait_rend_le_dns_et_ferme(lieux):
    k, src = lieux
    f = Faux()
    C.activer(f, source=src, **k)
    r = C.retirer(f, **k)
    assert r["dns_rendu"] and f.dns == ["192.168.1.254"]
    assert not k["conf"].exists() and not k["etat_f"].exists()
    assert ["nft", "delete", "rule", "inet", "filter", "input", "handle", "7"] in f.appels


def test_retrait_n_ecrase_pas_un_dns_change_depuis(lieux):
    k, src = lieux
    f = Faux()
    C.activer(f, source=src, **k)
    f.dns = ["9.9.9.9"]
    C.retirer(f, **k)
    assert f.dns == ["9.9.9.9"]


def test_retrait_echoue_garde_l_etat(lieux):
    k, src = lieux
    f = Faux()
    C.activer(f, source=src, **k)
    f.autorise = False
    assert C.retirer(f, **k)["etat"] == "dns_non_rendu" and k["etat_f"].exists()


def test_autre_pc_suit_l_adresse_sans_perdre_l_origine(lieux):
    k, src = lieux
    f = Faux()
    C.activer(f, source=src, **k)
    f.ip = "192.168.1.77"
    C.activer(f, source=src, **k)
    assert f.dns == ["192.168.1.77"]
    assert json.loads(k["etat_f"].read_text())["dns_origine"] == ["192.168.1.254"]


def test_sans_autorisation_le_reste_marche_et_freebox_intacte(lieux):
    k, src = lieux
    f = Faux(autorise=False)
    r = C.activer(f, source=src, **k)
    assert r["freebox"] == "autorisation_requise" and r["etat"] == "partiel" and k["conf"].exists()


def test_adresse_publique_jamais_ecoutee(lieux):
    k, src = lieux
    r = C.activer(Faux(ip="82.67.100.75"), source=src, **k)
    assert r["etat"] == "pas_de_reseau" and not k["conf"].exists()


def test_retrait_manuel_empeche_la_reactivation(lieux):
    k, src = lieux
    f = Faux()
    C.activer(f, source=src, **k)
    C.retirer(f, manuel=True, **k)
    assert C.activer(f, source=src, **k)["etat"] == "retiree"


def test_etat_ne_livre_ni_origine_ni_mac(lieux, tmp_path):
    k, src = lieux
    f = Faux()
    C.activer(f, source=src, **k)
    r = C.etat_complet(f, k["etat_f"], k["retire"], src, tmp_path / "absent")
    assert r["freebox"] == "actif" and r["ip"] == "192.168.1.50"
    assert "dns_origine" not in r and "mac" not in r


def test_routes_gardees():
    api = (CHEMIN.parents[1] / "api/main.py").read_text()
    assert '@app.post("/retirer", dependencies=[Depends(require_jwt)])' in api
    assert '@app.post("/reactiver", dependencies=[Depends(require_jwt)])' in api
    assert '@app.get("/etat", dependencies=[Depends(require_lecture)])' in api


def test_page_guide_le_retrait_et_la_freebox():
    page = (CHEMIN.parents[1] / "www/mobile/index.html").read_text(encoding="utf-8")
    for t in ("Retirer la clé", "Modification des réglages", "Clé arrachée", "sbx_token"):
        assert t in page
