# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""La clé du dépôt se déverrouille avec une phrase RANGÉE AU COFFRE (#2007), avec un vrai gpg.

Scénario du propriétaire : la phrase de la clé est un secret du Coffre ; la connexion
d'un administrateur ouvre le Coffre ; une minuterie la donne alors à gpg-agent, pour
toute la durée utile (pas les 60 minutes d'une session), sans rien écrire sur le disque.
"""
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from coffre import depot as d

pytestmark = pytest.mark.skipif(not shutil.which("gpg") or not shutil.which("gpg-connect-agent")
                                or not Path(d.PRESET).exists(), reason="gnupg absent")


@pytest.fixture
def cle_protegee():
    """Clé jetable fermée par une phrase que seul `coffre` connaît ; l'agent l'a oubliée."""
    home = tempfile.mkdtemp(prefix="g", dir="/tmp")
    subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key",
                    "depot <depot@exemple.invalid>", "ed25519", "sign", "never"],
                   env=d._env(home), capture_output=True, check=True)
    fpr = d.empreinte_signature(distributions=Path("/nonexistent"), gnupghome=home)
    coffre = {}
    d.proteger(fpr, lambda nom, v: coffre.__setitem__(nom, v), gnupghome=home)
    d.oublier(fpr, home)
    yield fpr, home, coffre
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=d._env(home), capture_output=True)
    shutil.rmtree(home, ignore_errors=True)


def test_la_phrase_du_coffre_deverrouille_la_cle_sans_echeance(cle_protegee):
    fpr, home, coffre = cle_protegee
    assert not d._signe_essai(fpr, home)
    e = d.deverrouiller_depuis_coffre(fpr, lambda nom: coffre.get(nom), gnupghome=home)
    assert d._signe_essai(fpr, home) and e["en_cache"]
    assert e.get("deja") is False


def test_rien_n_est_planifie_pour_oublier(cle_protegee, monkeypatch):
    fpr, home, coffre = cle_protegee
    monkeypatch.setattr(d, "planifier_oubli", lambda *a, **k: pytest.fail("aucun oubli planifié attendu"))
    d.deverrouiller_depuis_coffre(fpr, lambda nom: coffre.get(nom), gnupghome=home)


def test_si_la_cle_signe_deja_le_coffre_n_est_pas_sollicite(cle_protegee):
    fpr, home, coffre = cle_protegee
    d.deverrouiller_depuis_coffre(fpr, lambda nom: coffre.get(nom), gnupghome=home)

    def interdit(nom):
        pytest.fail("le Coffre ne doit pas être lu quand la clé signe déjà")

    e = d.deverrouiller_depuis_coffre(fpr, interdit, gnupghome=home)
    assert e["deja"] is True and d._signe_essai(fpr, home)


def test_secret_absent_refuse_et_laisse_la_cle_fermee(cle_protegee):
    fpr, home, _ = cle_protegee
    with pytest.raises(d.ErreurDepot, match="secret"):
        d.deverrouiller_depuis_coffre(fpr, lambda nom: None, gnupghome=home)
    assert not d._signe_essai(fpr, home)


def test_mauvaise_phrase_refuse_et_l_agent_n_en_garde_pas_trace(cle_protegee):
    fpr, home, _ = cle_protegee
    with pytest.raises(d.ErreurDepot):
        d.deverrouiller_depuis_coffre(fpr, lambda nom: "pas-la-bonne-phrase", gnupghome=home)
    assert not d._signe_essai(fpr, home)


def test_le_ttl_de_l_agent_est_long(cle_protegee):
    fpr, home, coffre = cle_protegee
    d.deverrouiller_depuis_coffre(fpr, lambda nom: coffre.get(nom), gnupghome=home)
    conf = (Path(home) / "gpg-agent.conf").read_text()
    assert f"default-cache-ttl {d.TTL_LONG}" in conf


def test_les_distributions_sont_cherchees_sur_srv_et_sur_data(tmp_path, monkeypatch):
    """gk2 héberge le dépôt sous /data/apt, pas /srv/apt : la clé doit s'y trouver aussi."""
    alt = tmp_path / "distributions"
    alt.write_text("Codename: trixie\nSignWith: ABCDEF\n")
    monkeypatch.setattr(d, "DISTRIBUTIONS_CANDIDATS", (tmp_path / "absent", alt))
    assert d.distributions_par_defaut() == alt
    monkeypatch.setattr(d, "DISTRIBUTIONS_CANDIDATS", (tmp_path / "a", tmp_path / "b"))
    assert d.distributions_par_defaut() == tmp_path / "a"


def test_l_unite_ne_se_lance_que_sur_la_machine_qui_heberge_le_depot():
    """gk3 n'a pas de clé de signature : sans condition la minuterie y échouait chaque minute."""
    unite = (Path(__file__).resolve().parents[1] / "debian" / "secubox-depot-coffre.service").read_text()
    conditions = [l for l in unite.splitlines() if l.startswith("ConditionPathExists=")]
    assert conditions, "l'unité doit être conditionnée à la présence du dépôt apt"
    assert all(l.startswith("ConditionPathExists=|") for l in conditions), "conditions en OU (préfixe |)"
    assert any("/data/apt/conf/distributions" in l for l in conditions)
    assert any("/srv/apt/conf/distributions" in l for l in conditions)
