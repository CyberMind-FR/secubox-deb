# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 — notifications de secubox-garde : courriel, SMS Free Mobile, file d'attente."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))

from garde import base, notifs  # noqa: E402


def test_sms_un_par_appareil_et_par_heure(tmp_path):
    cx = base.ouvrir(tmp_path / "g.db")
    assert notifs.mettre_en_file(cx, "sms", "aa:bb", "x", 1000) is True
    assert notifs.mettre_en_file(cx, "sms", "aa:bb", "x", 1060) is False
    assert notifs.mettre_en_file(cx, "sms", "cc:dd", "x", 1060) is True
    assert notifs.mettre_en_file(cx, "sms", "aa:bb", "x", 1000 + 3601) is True
    assert notifs.mettre_en_file(cx, "courriel", "aa:bb", "x", 1001) is True
    assert notifs.mettre_en_file(cx, "courriel", "aa:bb", "x", 1002) is True


def test_file_sms_rejouee_sans_doublon(tmp_path):
    cx = base.ouvrir(tmp_path / "g.db")
    notifs.mettre_en_file(cx, "sms", "bans", "texte", 1000)
    reponses = iter([False, True])
    appels = []

    def sms(u, k, t):
        appels.append((u, t))
        return next(reponses)

    def mail(d, s, t):
        return True

    r = {"sms_utilisateur": "12345678", "courriel": "a@b.fr"}
    assert notifs.vider_file(cx, r, sms, mail, 1100, cle_sms="k") == {"envoyes": 0, "en_attente": 1}
    assert notifs.vider_file(cx, r, sms, mail, 1200, cle_sms="k") == {"envoyes": 1, "en_attente": 0}
    assert notifs.vider_file(cx, r, sms, mail, 1300, cle_sms="k") == {"envoyes": 0, "en_attente": 0}
    assert len(appels) == 2 and appels[0][0] == "12345678"


def test_courriel_sujet_premiere_ligne(tmp_path):
    cx = base.ouvrir(tmp_path / "g.db")
    notifs.mettre_en_file(cx, "courriel", "k", "Titre\ncorps", 1000)
    vus = []
    notifs.vider_file(cx, {"courriel": "a@b.fr"}, lambda *a: True,
                      lambda d, s, t: vus.append((d, s, t)) or True, 1001)
    assert vus == [("a@b.fr", "Titre", "Titre\ncorps")]


def test_abandon_apres_48_essais(tmp_path, caplog):
    cx = base.ouvrir(tmp_path / "g.db")
    notifs.mettre_en_file(cx, "courriel", "k", "t", 1000)
    caplog.set_level("WARNING")
    for i in range(48):
        r = notifs.vider_file(cx, {"courriel": "a@b.fr"}, lambda *a: False,
                              lambda *a: False, 1001 + i)
    assert r == {"envoyes": 0, "en_attente": 0}
    assert cx.execute("SELECT envoye FROM file_notifs").fetchone()[0] == -1
    assert "abandonnée" in caplog.text


class FauxHttp:
    def __init__(self, code=200):
        self.code, self.url = code, None

    def urlopen(self, url, timeout=None):
        self.url = url
        code = self.code

        class R:
            status = code

            def __enter__(s):
                return s

            def __exit__(s, *a):
                return False
        return R()


def test_sms_free_url_et_cle_absente_du_journal(caplog):
    http = FauxHttp()
    with caplog.at_level("DEBUG"):
        assert notifs.sms_free("12345678", "SECRETKEY", "bonjour à tous", http=http) is True
    assert "user=12345678" in http.url
    assert "msg=" in http.url
    assert "SECRETKEY" in http.url  # la clé part bien dans la requête, seulement pas dans le journal
    assert "SECRETKEY" not in caplog.text
    assert notifs.sms_free("1", "K", "m", http=FauxHttp(500)) is False


def test_lire_cle_absente_et_nettoyee(tmp_path):
    assert notifs.lire_cle_sms(tmp_path / "nope") == ""
    p = tmp_path / "c"
    p.write_text(" abc\n")
    assert notifs.lire_cle_sms(p) == "abc"


def test_expediteur_nom_du_noeud(monkeypatch):
    from secubox_core import auth
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "gk2")
    assert notifs.expediteur() == "gk2@secubox.in"


def test_courriel_defaut_passe_expediteur(monkeypatch):
    from secubox_core import auth, courriel
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "gk2")
    vus = {}
    monkeypatch.setattr(courriel, "envoie", lambda d, s, t, expediteur=None: vus.update(
        d=d, s=s, t=t, e=expediteur))
    assert notifs._courriel_defaut("a@b.fr", "S", "T") is True
    assert vus["e"] == "gk2@secubox.in"


def test_reglage_manquant_averti_puis_perime(tmp_path, caplog):
    cx = base.ouvrir(tmp_path / "g.db")
    notifs.mettre_en_file(cx, "sms", "k", "t", 1000)
    caplog.set_level("WARNING")
    r = notifs.vider_file(cx, {}, lambda *a: True, lambda *a: True, 2000, cle_sms="")
    assert r == {"envoyes": 0, "en_attente": 1}
    assert caplog.text.count("réglage manquant") == 1
    assert "sms_utilisateur" in caplog.text
    r = notifs.vider_file(cx, {}, lambda *a: True, lambda *a: True, 1000 + 604801, cle_sms="")
    assert r == {"envoyes": 0, "en_attente": 0}
    assert cx.execute("SELECT envoye FROM file_notifs").fetchone()[0] == -1


def test_mise_en_file_atomique_en_transaction_ouverte(tmp_path):
    cx = base.ouvrir(tmp_path / "g.db")
    cx.execute("INSERT INTO recidives(ip, n, dernier) VALUES ('1.1.1.1',1,1)")
    assert notifs.mettre_en_file(cx, "sms", "m", "x", 10) is True
    assert notifs.mettre_en_file(cx, "sms", "m", "x", 11) is False
    assert not cx.in_transaction
