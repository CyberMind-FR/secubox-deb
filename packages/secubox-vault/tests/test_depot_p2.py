# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Session de signature du dépôt (Coffre P2, #1367), avec un vrai gpg.

Une clé jetable sans phrase, comme 219BA872 l'était : `proteger` la ferme
avec une phrase que seul le Coffre connaît, `session` la rouvre pour un
temps, `oublier` la referme. Un échec de vérification rend la clé d'avant.
"""
import shutil
import subprocess
import tempfile

import pytest

from coffre import depot as d

pytestmark = pytest.mark.skipif(not shutil.which("gpg") or not shutil.which("gpg-connect-agent")
                                or not __import__("os").path.exists(d.PRESET), reason="gnupg absent")


@pytest.fixture
def cle():
    home = tempfile.mkdtemp(prefix="g", dir="/tmp")          # socket de l'agent : chemin court
    subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key",
                    "depot <depot@exemple.invalid>", "ed25519", "sign", "never"],
                   env=d._env(home), capture_output=True, check=True)
    fpr = d.empreinte_signature(distributions=__import__("pathlib").Path("/nonexistent"), gnupghome=home)
    yield fpr, home
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=d._env(home), capture_output=True)
    shutil.rmtree(home, ignore_errors=True)


def test_proteger_puis_session_puis_oubli(cle):
    fpr, home = cle
    coffre, planifie = {}, []
    assert d.etat(fpr, home)["protegee"] is False and d._signe_essai(fpr, home)
    d.proteger(fpr, lambda nom, v: coffre.__setitem__(nom, v), gnupghome=home)
    assert list(coffre) == [d.nom_secret(fpr)] and len(coffre[d.nom_secret(fpr)]) >= 40
    assert d.etat(fpr, home)["protegee"] is True
    assert not d._signe_essai(fpr, home)                  # fermée sans la phrase
    e = d.session(fpr, coffre[d.nom_secret(fpr)], 15, planifier=lambda m, q: planifie.append(m), gnupghome=home)
    assert e["en_cache"] and planifie == [15] and d._signe_essai(fpr, home)
    d.oublier(fpr, home)
    assert not d._signe_essai(fpr, home)
    with pytest.raises(d.ErreurDepot):
        d.proteger(fpr, lambda nom, v: None, gnupghome=home)    # déjà protégée
    with pytest.raises(d.ErreurDepot):
        d.session(fpr, "pas-la-bonne-phrase", 15, planifier=lambda m, q: None, gnupghome=home)


def test_echec_de_verification_rend_la_cle_d_avant(cle, monkeypatch):
    fpr, home = cle
    vrai = d._signe_essai
    appels = []

    def faux(f, h):                     # « signe encore sans phrase » : protection ratée
        appels.append(1)
        return True if len(appels) == 1 else vrai(f, h)

    monkeypatch.setattr(d, "_signe_essai", faux)
    with pytest.raises(d.ErreurDepot):
        d.proteger(fpr, lambda nom, v: None, gnupghome=home)
    monkeypatch.setattr(d, "_signe_essai", vrai)
    assert d.etat(fpr, home)["protegee"] is False and d._signe_essai(fpr, home)


def test_session_bornee(cle):
    fpr, home = cle
    for m in (0, 61):
        with pytest.raises(d.ErreurDepot):
            d.session(fpr, "x", m, planifier=lambda m, q: None, gnupghome=home)


# ── Niveau 0 : sans phrase humaine, déverrouillée au démarrage (#1366) ─────────

class _Niveau0Faux:
    """systemd-creds est root et lié à la clé d'hôte : on le remplace par un dictionnaire."""
    class ErreurNiveau0(RuntimeError):
        pass

    def __init__(self):
        self.creds = {}

    def chiffrer(self, nom, valeur):
        self.creds[nom] = valeur

    def dechiffrer(self, nom):
        if nom not in self.creds:
            raise self.ErreurNiveau0("absente")
        return self.creds[nom]


@pytest.fixture
def niv0(monkeypatch):
    import coffre.niveau0 as n
    faux = _Niveau0Faux()
    monkeypatch.setattr(n, "chiffrer", faux.chiffrer)
    monkeypatch.setattr(n, "dechiffrer", faux.dechiffrer)
    monkeypatch.setattr(n, "ErreurNiveau0", _Niveau0Faux.ErreurNiveau0)
    return faux


def test_proteger_demarrage_sans_humain_ni_coffre(cle, niv0):
    fpr, home = cle
    assert d.etat(fpr, home)["protegee"] is False and d._signe_essai(fpr, home)
    d.proteger_demarrage(fpr, gnupghome=home)                 # aucun Coffre, aucune phrase saisie
    assert list(niv0.creds) == [d.nom_secret(fpr)] and len(niv0.creds[d.nom_secret(fpr)]) >= 40
    e = d.etat(fpr, home)
    assert e["protegee"] is True                              # le fichier de clé est chiffré sur disque
    assert e["en_cache"] is True and d._signe_essai(fpr, home)    # et déverrouillée : reprepro signe


def test_apres_un_redemarrage_de_l_agent_deverrouiller_rend_la_signature(cle, niv0):
    fpr, home = cle
    d.proteger_demarrage(fpr, gnupghome=home)
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=d._env(home), capture_output=True)   # « reboot »
    assert not d._signe_essai(fpr, home)                      # l'agent a tout oublié : la clé est fermée
    d.deverrouiller(fpr, gnupghome=home)                      # ce que fait l'unité au démarrage
    assert d._signe_essai(fpr, home) and d.etat(fpr, home)["en_cache"]


def test_une_copie_du_disque_ne_signe_pas(cle, niv0):
    fpr, home = cle
    d.proteger_demarrage(fpr, gnupghome=home)
    import os
    import shutil as sh
    copie = tempfile.mkdtemp(prefix="g", dir="/tmp")
    try:
        sh.copytree(home, copie, dirs_exist_ok=True, ignore=sh.ignore_patterns("S.*", "*.lock"))
        os.chmod(copie, 0o700)
        assert not d._signe_essai(fpr, copie)                 # le disque seul ne suffit pas
    finally:
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=d._env(copie), capture_output=True)
        sh.rmtree(copie, ignore_errors=True)


def test_deverrouiller_sans_credence_refuse(cle, niv0):
    fpr, home = cle
    with pytest.raises(d.ErreurDepot):
        d.deverrouiller(fpr, gnupghome=home)


def test_credence_illisible_ne_modifie_pas_la_cle(cle, niv0, monkeypatch):
    fpr, home = cle
    import coffre.niveau0 as n
    monkeypatch.setattr(n, "dechiffrer", lambda nom: b"autre chose")        # ne se relit pas à l'identique
    with pytest.raises(d.ErreurDepot):
        d.proteger_demarrage(fpr, gnupghome=home)
    assert d.etat(fpr, home)["protegee"] is False and d._signe_essai(fpr, home)   # clé intacte
