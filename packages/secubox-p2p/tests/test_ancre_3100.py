# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3100 — ancre du maître sur la box : identité du maître qui l'a flashée, refus de tout autre."""
import json
import os
import stat

import pytest

from api import ancre as A


def test_ecrire_puis_lire(tmp_path):
    ch = str(tmp_path / "ancre.json")
    assert A.ecrire("cle-pub", "192.168.1.200", "gk2", "0123456789abcdef", chemin=ch) is True
    a = A.lire(ch)
    assert a["cle_publique"] == "cle-pub" and a["adresse"] == "192.168.1.200"
    assert a["nom"] == "gk2" and a["empreinte"] == "0123456789abcdef"
    assert stat.S_IMODE(os.stat(ch).st_mode) == 0o644


def test_lire_absent_ou_illisible(tmp_path):
    assert A.lire(str(tmp_path / "nul.json")) is None
    p = tmp_path / "casse.json"
    p.write_text("{pas du json")
    assert A.lire(str(p)) is None


def test_ecrire_n_ecrase_pas_sans_le_demander(tmp_path):
    ch = str(tmp_path / "ancre.json")
    A.ecrire("k1", "10.0.0.1", "a", "e1", chemin=ch)
    assert A.ecrire("k2", "10.0.0.2", "b", "e2", chemin=ch) is False
    assert A.lire(ch)["cle_publique"] == "k1"
    assert A.ecrire("k2", "10.0.0.2", "b", "e2", chemin=ch, ecraser=True) is True
    assert A.lire(ch)["cle_publique"] == "k2"
    assert [f.name for f in tmp_path.iterdir()] == ["ancre.json"]


def test_accepte_sans_ancre_et_meme_cle_refuse_autre_cle():
    assert A.accepte(None, "n-importe-laquelle") is True
    assert A.accepte({"cle_publique": "k1"}, "k1") is True
    assert A.accepte({"cle_publique": "k1"}, "k2") is False


def test_audit_ecrit_une_ligne_json(tmp_path):
    ch = str(tmp_path / "audit.log")
    A.audit("ancre_posee", chemin=ch, nom="gk2")
    A.audit("ancre_refusee", chemin=ch)
    lignes = [json.loads(x) for x in open(ch)]
    assert lignes[0]["module"] == "p2p" and lignes[0]["evenement"] == "ancre_posee"
    assert lignes[0]["nom"] == "gk2" and "ts" in lignes[0] and len(lignes) == 2


@pytest.mark.parametrize("champ", ["code", "jeton", "token"])
def test_audit_refuse_un_jeton(tmp_path, champ):
    ch = tmp_path / "audit.log"
    with pytest.raises(ValueError):
        A.audit("x", chemin=str(ch), **{champ: "secret"})
    assert not ch.exists()


def test_empreinte_16_hex_stable():
    e = A.empreinte("cle-pub")
    assert len(e) == 16 and all(c in "0123456789abcdef" for c in e)
    assert e == A.empreinte("cle-pub") != A.empreinte("autre")
