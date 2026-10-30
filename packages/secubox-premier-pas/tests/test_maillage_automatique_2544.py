# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2544 — maillage « automesh » : la box préparée rejoint son parent toute seule, s'inscrit chez lui, et peut publier UNE demande d'aide « première installation ».

Aucun secret dans le fichier de réponses signé : le code d'invitation est déposé à part par l'atelier Auto-Load (secubox-autoload-agent) et consommé par
secubox-automesh. Le code ne donne aucun droit ; la demande d'aide ne donne aucune session sans le consentement du demandeur."""
import tomllib
from pathlib import Path

import pytest

from premier_pas import moteur as M, profil as P, provision as PV

EXEMPLE = Path(__file__).resolve().parents[1] / "exemples" / "reponses-autoload.toml"
EMPREINTE = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2g"


@pytest.fixture
def profil():
    p = tomllib.loads(EXEMPLE.read_text())
    p["admin"]["mot_de_passe"] = EMPREINTE
    return p


def _examen(p):
    return P.examine(p, ["full"])


def test_le_mode_automesh_est_valide_sans_adresse_ni_jeton(profil):
    profil["maillage"] = {"mode": "automesh"}
    ex = _examen(profil)
    assert "maillage" not in ex.erreurs and "maillage" not in ex.manquantes


@pytest.mark.parametrize("aide", ["demander", "non"])
def test_aide_demander_ou_non(profil, aide):
    profil["maillage"] = {"mode": "automesh", "aide": aide}
    assert "maillage" not in _examen(profil).erreurs


def test_aide_inconnue_ou_sans_maillage_est_refusee(profil):
    for m in ({"mode": "automesh", "aide": "toujours"}, {"mode": "plus_tard", "aide": "demander"}, {"mode": "premiere", "aide": "demander"}):
        profil["maillage"] = m
        assert "maillage" in _examen(profil).erreurs, m


def test_un_fichier_signe_accepte_automesh_et_aide_mais_toujours_pas_de_jeton():
    assert "aide" in PV.CLES["maillage"] and "mode" in PV.CLES["maillage"] and "jeton" not in PV.CLES["maillage"]


def _isole(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "ETAT", tmp_path / "etat.json")
    monkeypatch.setattr(M, "JOURNAL", tmp_path / "journal.log")
    monkeypatch.setattr(M.time, "sleep", lambda s: None)
    monkeypatch.setattr(M, "_pose_empreinte_admin", lambda e: None)
    monkeypatch.setattr(M, "_ecrit_conf", lambda d: None)
    monkeypatch.setattr(M, "_majauto", lambda a, h: None)
    monkeypatch.setattr(M, "MARQUEUR_AIDE", tmp_path / "aide-demandee", raising=False)


def _plan(profil):
    return [a for a in M.plan(profil) if a.etape == "maillage"]


def test_le_plan_active_jonction_annuaire_et_assistance_et_ne_bloque_pas(profil):
    profil["maillage"] = {"mode": "automesh"}
    a = _plan(profil)
    assert len(a) == 1 and a[0].souple is True and "automatique" in a[0].quoi


def test_le_plan_ajoute_la_demande_d_aide_seulement_si_elle_est_voulue(profil):
    profil["maillage"] = {"mode": "automesh", "aide": "demander"}
    assert len(_plan(profil)) == 2
    profil["maillage"] = {"mode": "automesh", "aide": "non"}
    assert len(_plan(profil)) == 1


def test_les_unites_sont_activees_une_a_une_et_une_absente_n_arrete_rien(monkeypatch):
    vus = []

    def sub(argv, **k):
        vus.append(argv)

        class R:
            returncode = 5 if "secubox-assist.service" in argv else 0
            stdout = stderr = ""
        return R()
    monkeypatch.setattr(M.subprocess, "run", sub)
    M._activer_maillage()
    cibles = [a[-1] for a in vus]
    assert cibles == ["secubox-automesh.timer", "secubox-annuaire.service", "secubox-assist.service"]
    assert all(a[:3] == ["systemctl", "enable", "--now"] for a in vus)


def test_la_demande_d_aide_est_publiee_une_fois_en_tant_que_secubox(tmp_path, monkeypatch):
    _isole(tmp_path, monkeypatch)
    cle = tmp_path / "node.key"
    cle.write_text("00")
    monkeypatch.setattr(M, "CLE_ANNUAIRE", cle, raising=False)
    appels = []

    def sub(argv, **k):
        appels.append(argv)

        class R:
            returncode = 0
            stdout = '{"req_id": "x"}'
            stderr = ""
        return R()
    monkeypatch.setattr(M.subprocess, "run", sub)
    M._demander_aide("gk1")
    M._demander_aide("gk1")                                              # deuxième application : pas de doublon
    assert len(appels) == 1
    a = appels[0]
    assert a[:4] == ["runuser", "-u", "secubox", "--"] and "secubox-assistctl" in a[4] and "request-open" in a
    assert "premiere-installation" in a and "gk1" in " ".join(a)


def test_sans_identite_d_annuaire_la_demande_est_remise_et_dite(tmp_path, monkeypatch):
    _isole(tmp_path, monkeypatch)
    monkeypatch.setattr(M, "CLE_ANNUAIRE", tmp_path / "absente", raising=False)
    with pytest.raises(RuntimeError, match="identité"):
        M._demander_aide("gk1")
