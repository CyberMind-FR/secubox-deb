# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3305 : services du maillage par formule, formule interne « atelier », abonnement des pairs du maillage, grâce de 5 jours,
projection publique `droits-maillage.json`."""
import json

import pytest
from fastapi.testclient import TestClient

from secubox_core import auth
from autoload import jetons as J, projection as P, tunnel as T
from api import main as A

T0 = 1_800_000_000
JOUR = 86400
CLE = "A" * 43 + "="
HUB = "H" * 43 + "="


class Horloge:
    def __init__(self):
        self.t = float(T0)

    def __call__(self):
        return self.t


@pytest.fixture
def h():
    return Horloge()


@pytest.fixture
def reg(tmp_path, h):
    return J.Registre(tmp_path / "j.db", tmp_path / "audit.log", horloge=h)


def test_formule_atelier_semee_avec_tous_les_services(reg):
    f = {x["nom"]: x for x in reg.formules()}
    assert f["atelier"]["services"] == list(J.SERVICES_MAILLAGE)
    assert J.SERVICES_MAILLAGE == ("annuaire-offres", "bans-waf")        # openpgp et macro : pas encore câblés


def test_formule_atelier_jamais_ecrasee_au_redemarrage(tmp_path, h, reg):
    reg.fixer_formule("atelier", "Atelier", "full", 120, services=["bans-waf"])
    J.Registre(tmp_path / "j.db", tmp_path / "audit.log", horloge=h)
    assert {x["nom"]: x for x in reg.formules()}["atelier"]["services"] == ["bans-waf"]


def test_services_d_une_formule_liste_fermee(reg):
    reg.fixer_formule("passerelle", "Passerelle", "secure-gateway", 12, services=["bans-waf", "annuaire-offres", "bans-waf"])
    assert {x["nom"]: x for x in reg.formules()}["passerelle"]["services"] == ["annuaire-offres", "bans-waf"]
    with pytest.raises(ValueError):
        reg.fixer_formule("x", "X", "lite", 12, services=["tout"])


def test_formule_sans_services_par_defaut(reg):
    reg.fixer_formule("leger", "Léger", "lite", 12)
    assert {x["nom"]: x for x in reg.formules()}["leger"]["services"] == []


def test_grace_de_5_jours_fixee_a_la_premiere_migration(tmp_path, h, reg):
    d = reg.droits_maillage()
    assert d["grace_jusqu_a"] == T0 + 5 * JOUR
    h.t += 3 * JOUR
    J.Registre(tmp_path / "j.db", tmp_path / "audit.log", horloge=h)          # redémarrage : la grâce ne repart pas
    assert reg.droits_maillage()["grace_jusqu_a"] == T0 + 5 * JOUR


def test_pair_du_maillage_rattache_a_l_atelier(reg):
    reg.fixer_maillage("gk5", "atelier", empreinte="sbx-f0ad4e08ab71")
    p = reg.droits_maillage()["pairs"]
    assert p == [{"nom": "gk5", "empreinte": "sbx-f0ad4e08ab71", "formule": "atelier", "statut": "actif", "expire_le": None,
                  "services": list(J.SERVICES_MAILLAGE)}]


def test_pair_suspendu_ou_echu_sans_services(reg, h):
    reg.fixer_formule("passerelle", "Passerelle", "secure-gateway", 12, services=["bans-waf"])
    reg.fixer_maillage("lgm-ebin", "passerelle", mois=1)
    reg.fixer_maillage("gk4", "passerelle", statut="suspendu", motif="impayé")
    h.t += 40 * JOUR
    p = {x["nom"]: x for x in reg.droits_maillage()["pairs"]}
    assert p["lgm-ebin"]["statut"] == "echu" and p["lgm-ebin"]["services"] == []
    assert p["gk4"]["statut"] == "suspendu" and p["gk4"]["services"] == []


def test_fixer_maillage_valide_et_audite(reg, tmp_path):
    with pytest.raises(ValueError):
        reg.fixer_maillage("GK5;rm", "atelier")
    with pytest.raises(ValueError):
        reg.fixer_maillage("gk5", "inconnue")
    with pytest.raises(ValueError):
        reg.fixer_maillage("gk5", "atelier", statut="suspendu")              # suspension : motif obligatoire
    reg.fixer_maillage("gk5", "atelier")
    assert "maillage" in (tmp_path / "audit.log").read_text()


def test_projection_publique_droits(tmp_path, reg):
    reg.fixer_maillage("gk5", "atelier", empreinte="sbx-f0ad4e08ab71")
    dossier = tmp_path / "pub"
    chemin, n = P.exporter_droits(tmp_path / "j.db", dossier)
    doc = json.loads(chemin.read_text())
    assert chemin.name == "droits-maillage.json" and n == 1
    assert doc["version"] == 1 and doc["grace_jusqu_a"] == T0 + 5 * JOUR
    assert doc["services"] == list(J.SERVICES_MAILLAGE)
    assert doc["pairs"][0]["nom"] == "gk5" and doc["pairs"][0]["services"] == list(J.SERVICES_MAILLAGE)
    assert oct(chemin.stat().st_mode & 0o777) == "0o644"


def test_projection_droits_base_absente(tmp_path):
    with pytest.raises(P.ProjectionErreur):
        P.exporter_droits(tmp_path / "absente.db", tmp_path / "pub")         # jamais de politique vide publiée par erreur


def test_api_maillage(tmp_path, h, reg):
    publies = []
    app = A.creer_app(reg, T.Pairs(tmp_path / "j.db", horloge=h), HUB, lambda: publies.append(1), horloge=h)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    c = TestClient(app)
    r = c.post("/formules", json={"nom": "passerelle", "libelle": "Passerelle", "profil": "secure-gateway", "mois": 12,
                                                  "services": ["bans-waf"]})
    assert r.status_code == 200
    r = c.post("/maillage/gk5", json={"formule": "atelier", "empreinte": "sbx-f0ad4e08ab71"})
    assert r.status_code == 200 and publies
    r = c.post("/maillage/gk4", json={"formule": "passerelle", "statut": "suspendu"})
    assert r.status_code == 422
    d = c.get("/maillage").json()
    assert d["pairs"][0]["nom"] == "gk5" and d["grace_jusqu_a"] == T0 + 5 * JOUR
    assert c.post("/maillage/gk5", json={"formule": "atelier", "x": 1}).status_code == 422


def _ctl():
    import importlib.machinery
    import importlib.util
    from pathlib import Path
    ldr = importlib.machinery.SourceFileLoader("autoloadctl_3305", str(Path(__file__).resolve().parents[1] / "sbin" / "autoloadctl"))
    spec = importlib.util.spec_from_loader("autoloadctl_3305", ldr)
    m = importlib.util.module_from_spec(spec)
    ldr.exec_module(m)
    return m


def test_ctl_maillage_puis_export_publie_les_droits(tmp_path, monkeypatch):
    var = tmp_path / "var"
    var.mkdir(mode=0o750)
    monkeypatch.setenv("SECUBOX_AUTOLOAD_DB", str(var / "jetons.db"))
    monkeypatch.setenv("SECUBOX_AUTOLOAD_AUDIT", str(tmp_path / "audit.log"))
    ctl = _ctl()
    assert ctl.main(["maillage", "--nom", "gk5", "--formule", "atelier", "--empreinte", "sbx-f0ad4e08ab71"]) == 0
    assert ctl.main(["maillage", "--nom", "gk4", "--formule", "nulle"]) == 2
    doc = json.loads((tmp_path / "autoload-public" / "droits-maillage.json").read_text())        # republié par « maillage » lui-même
    assert [p["nom"] for p in doc["pairs"]] == ["gk5"]


def _pairs_enroles(tmp_path, noms):
    f = tmp_path / "pairs-enroles.json"
    f.write_text(json.dumps({"version": 1, "pairs": [{"name": n, "mesh_ip": f"10.10.0.{i + 2}", "fingerprint": f"sbx-{i:012x}"}
                                                     for i, n in enumerate(noms)]}))
    return f


def test_inscription_atelier_des_pairs_enroles(reg, tmp_path):
    reg.fixer_formule("passerelle", "Passerelle", "secure-gateway", 12, services=["bans-waf"])
    reg.fixer_maillage("lgm-ebin", "passerelle")                                   # déjà abonné : jamais touché
    n = reg.inscrire_atelier(_pairs_enroles(tmp_path, ["gk1", "gk5", "lgm-ebin"]))
    assert n == 2
    p = {x["nom"]: x for x in reg.droits_maillage()["pairs"]}
    assert p["gk1"]["formule"] == "atelier" and p["gk5"]["empreinte"] == "sbx-000000000001"
    assert p["lgm-ebin"]["formule"] == "passerelle"
    assert reg.inscrire_atelier(_pairs_enroles(tmp_path, ["gk1", "gk5"])) == 0         # idempotente
    assert "maillage-atelier" in (tmp_path / "audit.log").read_text()


def test_inscription_atelier_fichier_absent_ou_abime(reg, tmp_path):
    assert reg.inscrire_atelier(tmp_path / "absent.json") == 0
    (tmp_path / "x.json").write_text("{abime")
    assert reg.inscrire_atelier(tmp_path / "x.json") == 0
    f = tmp_path / "y.json"
    f.write_text(json.dumps({"pairs": [{"name": "GK;rm", "fingerprint": "zz"}]}))
    assert reg.inscrire_atelier(f) == 0


def test_ctl_maillage_atelier(tmp_path, monkeypatch):
    var = tmp_path / "var"
    var.mkdir(mode=0o750)
    monkeypatch.setenv("SECUBOX_AUTOLOAD_DB", str(var / "jetons.db"))
    monkeypatch.setenv("SECUBOX_AUTOLOAD_AUDIT", str(tmp_path / "audit.log"))
    f = _pairs_enroles(tmp_path, ["gk4", "gk6"])
    assert _ctl().main(["maillage-atelier", "--pairs", str(f)]) == 0
    doc = json.loads((tmp_path / "autoload-public" / "droits-maillage.json").read_text())
    assert [p["nom"] for p in doc["pairs"]] == ["gk4", "gk6"]


def test_postinst_inscrit_l_atelier():
    from pathlib import Path
    post = (Path(__file__).resolve().parents[1] / "debian" / "postinst").read_text()
    assert "autoloadctl maillage-atelier" in post
