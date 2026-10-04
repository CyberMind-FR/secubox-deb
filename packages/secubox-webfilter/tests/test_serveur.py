# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import os
import stat

from webfilter import serveur


def test_socket_creee_en_0660_meme_avec_un_umask_ouvert(tmp_path):
    ancien = os.umask(0)
    try:
        s = serveur.creer_socket(str(tmp_path / "w.sock"))
        try:
            assert stat.S_IMODE(os.stat(tmp_path / "w.sock").st_mode) == 0o660
            assert os.umask(0) == 0                                      # l'umask du processus est restitué
        finally:
            s.close()
    finally:
        os.umask(ancien)


def test_une_socket_perimee_est_remplacee(tmp_path):
    chemin = str(tmp_path / "w.sock")
    serveur.creer_socket(chemin).close()
    s = serveur.creer_socket(chemin)
    s.close()
    assert stat.S_IMODE(os.stat(chemin).st_mode) == 0o660
