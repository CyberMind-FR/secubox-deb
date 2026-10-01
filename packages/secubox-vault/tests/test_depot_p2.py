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
