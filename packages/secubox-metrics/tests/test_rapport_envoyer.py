# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""rapport.envoyer : soumission authentifiée (destinataire externe) + trace Bcc.

Le relais port 25 ne remet que le courrier LOCAL (l'hôte n'est pas dans le
mynetworks de la LXC mail). Pour un destinataire EXTERNE (Gmail), envoyer doit
passer en STARTTLS + login. Une copie cachée interne laisse une trace webmail.
"""
import rapport


class FauxSMTP:
    instances = []

    def __init__(self, hote, port, timeout=None):
        self.hote, self.port = hote, port
        self.starttls_called = False
        self.login_args = None
        self.sent = None
        FauxSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        self.starttls_called = True

    def login(self, user, mdp):
        self.login_args = (user, mdp)

    def send_message(self, msg):
        self.sent = msg


def test_envoyer_authentifie_avec_bcc(monkeypatch, tmp_path):
    """smtp_user configuré → STARTTLS + login(user, mot de passe du fichier),
    et copie_cachee → Bcc interne (trace webmail)."""
    passf = tmp_path / "smtp.pass"
    passf.write_text("Gk24@SECUBOX;001\n", encoding="utf-8")  # ; et \n gérés
    monkeypatch.setattr(rapport, "config", lambda: {
        "smtp_hote": "10.100.0.10", "smtp_port": 587,
        "expediteur": "gk2@secubox.in", "destinataire": "x@localdomain",
        "smtp_user": "gk2@secubox.in", "smtp_pass_file": str(passf),
        "copie_cachee": "gk2@secubox.in",
    })
    FauxSMTP.instances.clear()
    monkeypatch.setattr(rapport.smtplib, "SMTP", FauxSMTP)

    res = rapport.envoyer(b"%PDF-1.4 x", destinataire="Anibal Amiot <a@gmail.com>",
                          portee="anibal-amiot", periode="jour")

    s = FauxSMTP.instances[-1]
    assert (s.hote, s.port) == ("10.100.0.10", 587)
    assert s.starttls_called is True
    assert s.login_args == ("gk2@secubox.in", "Gk24@SECUBOX;001")
    assert s.sent["To"] == "Anibal Amiot <a@gmail.com>"
    assert s.sent["From"] == "gk2@secubox.in"
    assert s.sent["Bcc"] == "gk2@secubox.in"
    assert res["envoye"] is True


def test_envoyer_local_reste_sans_auth(monkeypatch):
    """Sans smtp_user : comportement #1059 inchangé — port 25, ni STARTTLS ni
    login (le relais interne remet localement)."""
    monkeypatch.setattr(rapport, "config", lambda: {
        "smtp_hote": "10.100.0.10", "smtp_port": 25,
        "expediteur": "secubox@localdomain", "destinataire": "admin@localdomain",
    })
    FauxSMTP.instances.clear()
    monkeypatch.setattr(rapport.smtplib, "SMTP", FauxSMTP)

    rapport.envoyer(b"%PDF-1.4 x", destinataire="admin@localdomain")

    s = FauxSMTP.instances[-1]
    assert s.starttls_called is False
    assert s.login_args is None
    assert s.sent["Bcc"] is None
