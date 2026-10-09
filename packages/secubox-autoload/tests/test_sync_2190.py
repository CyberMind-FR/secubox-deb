# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2190 : demande et accusé de synchronisation du tunnel entre le service (non root) et l'unité root."""
import stat

import pytest

from autoload import tunnel as T


class Horloge:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def dormir(self, s):
        self.t += s


def test_la_demande_attend_l_accuse_de_la_meme_marque(tmp_path):
    h = Horloge()
    etapes = []

    def dormir(s):
        h.dormir(s)
        etapes.append(1)
        if len(etapes) == 3:
            T.accuser_sync(tmp_path)                                            # l'unité root a terminé
    T.demander_sync(tmp_path, attente_s=10, horloge=h, dormir=dormir)
    assert len(etapes) == 3
    assert stat.S_IMODE((tmp_path / "sync.fait").stat().st_mode) == 0o600


def test_sans_accuse_la_demande_echoue_proprement(tmp_path):
    h = Horloge()
    with pytest.raises(T.TunnelErreur):
        T.demander_sync(tmp_path, attente_s=2, horloge=h, dormir=h.dormir)


def test_un_ancien_accuse_ne_valide_pas_une_nouvelle_demande(tmp_path):
    (tmp_path / "sync.fait").write_text("0" * 32)
    h = Horloge()
    with pytest.raises(T.TunnelErreur):
        T.demander_sync(tmp_path, attente_s=2, horloge=h, dormir=h.dormir)


@pytest.mark.parametrize("contenu", ["", "pas-hex", "../../etc/passwd", "A" * 32, "0" * 31, "0" * 33, "0" * 32 + "\nPostUp"])
def test_une_demande_malformee_n_est_jamais_accusee(tmp_path, contenu):
    (tmp_path / "sync.demande").write_text(contenu)
    T.accuser_sync(tmp_path)
    assert not (tmp_path / "sync.fait").exists()


def test_accuser_sans_demande_ne_fait_rien(tmp_path):
    T.accuser_sync(tmp_path)
    assert not (tmp_path / "sync.fait").exists()
