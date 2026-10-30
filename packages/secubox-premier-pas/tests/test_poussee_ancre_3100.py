# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3100 — le panneau maître pousse l'ANCRE avec l'étape maillage ; la box neuve l'écrit avant de rejoindre."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from premier_pas import maitre as MA, moteur as M, profil as P, remplir as R  # noqa: E402

SOURCE_ANCRE = Path(__file__).resolve().parents[2] / "secubox-p2p" / "api" / "ancre.py"
CLE = "A" * 43 + "="
AUTRE = "B" * 43 + "="
EMP = hashlib.sha256(CLE.encode()).hexdigest()[:16]
EMPREINTE = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2g"
JETON = "ab" * 16


def _profil(**maillage):
    m = {"mode": "rejoindre", "rejoindre": "10.0.0.2", "jeton": JETON}
    m.update(maillage)
    return {"box": {"nom": "gk3", "fuseau": "Europe/Paris"},
            "admin": {"mot_de_passe": EMPREINTE},
            "reseau": {"mode": "lan"}, "services": {"profil": "actuel"},
            "maillage": m, "apt": {"auto": False}}


ANCRE = {"ancre_cle": CLE, "ancre_adresse": "10.0.0.2", "ancre_nom": "gk2", "ancre_empreinte": EMP}


class _Rep:
    status_code = 200

    def json(self):
        return {"jeton": "x", "complet": True}


class _Client:
    def __init__(self):
        self.puts = {}

    def post(self, url, **k):
        return _Rep()

    def get(self, url, **k):
        return _Rep()

    def put(self, url, json=None, **k):
        self.puts[url.rsplit("/", 1)[1]] = json
        return _Rep()


def test_profil_pousse_contient_l_ancre_du_maitre(tmp_path, monkeypatch):
    monkeypatch.setenv("SBX_P2P_ANCRE_PY", str(SOURCE_ANCRE))
    monkeypatch.setenv("PREMIER_PAS_MAITRE_DIR", str(tmp_path / "maitre"))
    mesh = tmp_path / "wg_mesh.json"
    mesh.write_text(json.dumps({"public_key": CLE}))
    monkeypatch.setattr(MA, "WG_MESH_JSON", mesh)
    monkeypatch.setattr(MA.socket, "gethostname", lambda: "gk2")
    monkeypatch.setattr(MA, "_mes_adresses", lambda: [])
    MA.enregistre("gk3", {"box": {"fuseau": "Europe/Paris"}, "admin": {"mot_de_passe": EMPREINTE},
                          "reseau": {"mode": "lan"}, "services": {"profil": "actuel"},
                          "maillage": {"mode": "rejoindre", "rejoindre": "10.0.0.2", "jeton": JETON},
                          "apt": {"auto": False}})
    c = _Client()
    r = MA.pousse("gk3", "192.168.1.9", "code", "remplir", client=c)
    assert r["ok"], r
    m = c.puts["maillage"]
    assert m["ancre_cle"] == CLE and m["ancre_adresse"] == "10.0.0.2"
    assert m["ancre_nom"] == "gk2" and m["ancre_empreinte"] == EMP
    assert m["jeton"] == JETON                       # la source du jeton est inchangée


def test_maitre_sans_cle_de_maillage_ne_pousse_pas_d_ancre(tmp_path, monkeypatch):
    monkeypatch.setenv("PREMIER_PAS_MAITRE_DIR", str(tmp_path / "maitre"))
    monkeypatch.setattr(MA, "WG_MESH_JSON", tmp_path / "absent.json")
    monkeypatch.setattr(MA, "_mes_adresses", lambda: [])
    MA.enregistre("gk3", _profil() | {"admin": {"mot_de_passe": EMPREINTE}})
    c = _Client()
    assert MA.pousse("gk3", "192.168.1.9", "code", "remplir", client=c)["ok"]
    assert not any(k.startswith("ancre_") for k in c.puts["maillage"])


def _isole(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "ETAT", tmp_path / "etat.json")
    monkeypatch.setattr(M, "JOURNAL", tmp_path / "journal.log")
    monkeypatch.setattr(M.time, "sleep", lambda s: None)
    monkeypatch.setattr(M, "_pose_empreinte_admin", lambda e: None)
    monkeypatch.setattr(M, "_ecrit_conf", lambda d: None)
    monkeypatch.setattr(M, "_majauto", lambda a, h: None)
    monkeypatch.setattr(M, "_reseau_existant_conserve", lambda *a: None)
    monkeypatch.setattr(M, "ANCRE_CHEMIN", tmp_path / "ancre-maitre.json")
    monkeypatch.setattr(M, "AUDIT_CHEMIN", tmp_path / "audit.log")
    monkeypatch.setenv("SBX_P2P_ANCRE_PY", str(SOURCE_ANCRE))


def _execute(appels):
    def ex(argv):
        appels.append(argv[0])
        return 0, ""
    return ex


def test_application_ecrit_l_ancre_avant_la_jonction(tmp_path, monkeypatch):
    _isole(tmp_path, monkeypatch)
    avant = []
    ancre_fichier = tmp_path / "ancre-maitre.json"

    def ex(argv):
        if argv[0] == "sbx-mesh-join":
            avant.append(ancre_fichier.exists())
        return 0, ""
    r = M.appliquer(_profil(**ANCRE), ex, ["actuel"], marqueur=tmp_path / "fait")
    assert r.ok, r.detail
    assert avant == [True]
    d = json.loads(ancre_fichier.read_text())
    assert d["cle_publique"] == CLE and d["adresse"] == "10.0.0.2" and d["nom"] == "gk2" and d["empreinte"] == EMP


def test_ancre_existante_d_un_autre_maitre_empeche_la_jonction(tmp_path, monkeypatch):
    _isole(tmp_path, monkeypatch)
    (tmp_path / "ancre-maitre.json").write_text(json.dumps({"cle_publique": AUTRE, "adresse": "10.9.9.9", "nom": "autre", "empreinte": "x"}))
    appels = []
    r = M.appliquer(_profil(**ANCRE), _execute(appels), ["actuel"], marqueur=tmp_path / "fait")
    assert not r.ok and r.echec == "maillage"
    assert "sbx-mesh-join" not in appels
    assert json.loads((tmp_path / "ancre-maitre.json").read_text())["cle_publique"] == AUTRE


def test_meme_ancre_deja_posee_la_jonction_continue(tmp_path, monkeypatch):
    _isole(tmp_path, monkeypatch)
    (tmp_path / "ancre-maitre.json").write_text(json.dumps({"cle_publique": CLE, "adresse": "10.0.0.2", "nom": "gk2", "empreinte": EMP}))
    appels = []
    assert M.appliquer(_profil(**ANCRE), _execute(appels), ["actuel"], marqueur=tmp_path / "fait").ok
    assert "sbx-mesh-join" in appels


def test_module_ancre_absent_l_etape_echoue_sans_jonction(tmp_path, monkeypatch):
    _isole(tmp_path, monkeypatch)
    monkeypatch.setattr(M, "_charge_ancre", lambda: (_ for _ in ()).throw(RuntimeError("module ancre absent")))
    appels = []
    r = M.appliquer(_profil(**ANCRE), _execute(appels), ["actuel"], marqueur=tmp_path / "fait")
    assert not r.ok and "sbx-mesh-join" not in appels


def test_sans_ancre_le_plan_est_inchange(tmp_path, monkeypatch):
    _isole(tmp_path, monkeypatch)
    appels = []
    assert M.appliquer(_profil(), _execute(appels), ["actuel"], marqueur=tmp_path / "fait").ok
    assert not (tmp_path / "ancre-maitre.json").exists()


def test_cles_d_ancre_acceptees_dans_maillage():
    assert "maillage" not in P.examine(_profil(**ANCRE), ["actuel"]).erreurs
    assert {"ancre_cle", "ancre_adresse", "ancre_nom", "ancre_empreinte"} <= R.CHAMPS["maillage"][1]


def test_cle_d_ancre_mal_formee_refusee():
    assert "maillage" in P.examine(_profil(**{**ANCRE, "ancre_cle": "pas-une-cle"}), ["actuel"]).erreurs
    assert "maillage" in P.examine(_profil(**{**ANCRE, "ancre_nom": 3}), ["actuel"]).erreurs


def test_cles_d_ancre_inconnues_toujours_refusees_ailleurs():
    p = _profil()
    p["reseau"]["ancre_cle"] = CLE
    assert "reseau" in P.examine(p, ["actuel"]).erreurs
    p = _profil()
    p["box"]["ancre_nom"] = "x"
    assert "nom" in P.examine(p, ["actuel"]).erreurs
    with pytest.raises(R.Refus):
        R.enregistre("reseau", {"ancre_cle": CLE})
    with pytest.raises(R.Refus):
        R.enregistre("maillage", {"inconnue": "x"})


def _audit(tmp_path):
    f = tmp_path / "audit.log"
    return [json.loads(l) for l in f.read_text().splitlines()] if f.exists() else []


def test_audit_ancre_ecrite_conservee_refusee(tmp_path, monkeypatch):
    _isole(tmp_path, monkeypatch)
    assert M.appliquer(_profil(**ANCRE), _execute([]), ["actuel"], marqueur=tmp_path / "fait").ok
    (tmp_path / "fait").unlink()
    assert M.appliquer(_profil(**ANCRE), _execute([]), ["actuel"], marqueur=tmp_path / "fait").ok
    (tmp_path / "ancre-maitre.json").write_text(json.dumps({"cle_publique": AUTRE, "adresse": "x", "nom": "o", "empreinte": "e1"}))
    assert not M.appliquer(_profil(**ANCRE), _execute([]), ["actuel"], marqueur=tmp_path / "fait2").ok
    lignes = _audit(tmp_path)
    assert [l["evenement"] for l in lignes] == ["ancre_ecrite", "ancre_conservee", "ancre_refusee"]
    for l in lignes:
        assert l["maitre"] == "gk2" and l["adresse"] == "10.0.0.2" and l["empreinte"] == EMP
        assert not {"code", "jeton", "token"} & set(l)
    assert lignes[2]["empreinte_existante"] == "e1"


def test_audit_illisible_n_arrete_pas_l_etape(tmp_path, monkeypatch):
    _isole(tmp_path, monkeypatch)
    monkeypatch.setattr(M, "AUDIT_CHEMIN", tmp_path / "pas-de-dossier" / "audit.log")
    assert M.appliquer(_profil(**ANCRE), _execute([]), ["actuel"], marqueur=tmp_path / "fait").ok


def test_le_module_ne_se_charge_que_du_chemin_installe(tmp_path, monkeypatch):
    from premier_pas import ancre_p2p
    monkeypatch.delenv("SBX_P2P_ANCRE_PY", raising=False)
    monkeypatch.setattr(ancre_p2p, "INSTALLE", tmp_path / "absent.py")
    with pytest.raises(RuntimeError):
        ancre_p2p.charge()


class _RepRefus:
    status_code = 400

    def __init__(self, detail):
        self._d = detail

    def json(self):
        return {"detail": self._d}


class _ClientAncienne(_Client):
    """Box d'avant premier-pas 0.8.0 : les champs ancre_* de l'étape maillage sont inconnus."""

    def __init__(self, detail=None):
        super().__init__()
        self.essais = []
        self.detail = detail

    def put(self, url, json=None, **k):
        etape = url.rsplit("/", 1)[1]
        if etape == "maillage":
            self.essais.append(dict(json))
            inconnus = sorted(c for c in json if c.startswith("ancre_"))
            if inconnus or self.detail:
                return _RepRefus(self.detail or "Champs inconnus : " + ", ".join(inconnus))
        return super().put(url, json=json, **k)


def _maitre_avec_cle(tmp_path, monkeypatch):
    monkeypatch.setenv("SBX_P2P_ANCRE_PY", str(SOURCE_ANCRE))
    monkeypatch.setenv("PREMIER_PAS_MAITRE_DIR", str(tmp_path / "maitre"))
    mesh = tmp_path / "wg_mesh.json"
    mesh.write_text(json.dumps({"public_key": CLE}))
    monkeypatch.setattr(MA, "WG_MESH_JSON", mesh)
    monkeypatch.setattr(MA, "_mes_adresses", lambda: [])
    MA.enregistre("gk3", _profil() | {"admin": {"mot_de_passe": EMPREINTE}})


def test_box_ancienne_maillage_repris_sans_ancre(tmp_path, monkeypatch, caplog):
    _maitre_avec_cle(tmp_path, monkeypatch)
    c = _ClientAncienne()
    r = MA.pousse("gk3", "192.168.1.9", "code", "remplir", client=c)
    assert r["ok"], r
    assert len(c.essais) == 2
    assert any(k.startswith("ancre_") for k in c.essais[0])
    assert not any(k.startswith("ancre_") for k in c.essais[1]) and c.essais[1]["jeton"] == JETON
    assert "ancre" in r["avertissements"][0].lower()
    assert "trop ancienne" in caplog.text


def test_autre_refus_du_maillage_pas_de_reprise(tmp_path, monkeypatch):
    _maitre_avec_cle(tmp_path, monkeypatch)
    c = _ClientAncienne(detail="Champs inconnus : ancre_cle, inconnue")
    r = MA.pousse("gk3", "192.168.1.9", "code", "remplir", client=c)
    assert not r["ok"] and r["code"] == 400 and len(c.essais) == 1
