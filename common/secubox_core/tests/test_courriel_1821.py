# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Un message court par le relais de la box (#1821)."""
import pytest

from secubox_core import courriel


class _SMTP:
    envois, tls, logins = [], [], []

    def __init__(self, hote, port, timeout=0):
        self.hote, self.port = hote, port

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        _SMTP.tls.append(True)

    def login(self, u, p):
        _SMTP.logins.append(u)

    def send_message(self, m):
        _SMTP.envois.append((self.hote, self.port, m["To"], m["Subject"], m.get_content()))


@pytest.fixture
def relais(tmp_path, monkeypatch):
    for x in (_SMTP.envois, _SMTP.tls, _SMTP.logins):
        x.clear()
    monkeypatch.setattr(courriel.smtplib, "SMTP", _SMTP)
    m = tmp_path / "metrics.toml"
    m.write_text('[rapport]\nsmtp_hote = "10.100.0.10"\nsmtp_port = 25\nexpediteur = "gk2@secubox.in"\n'
                 'destinataire = "ailleurs@exemple.org"\n')
    monkeypatch.setattr(courriel, "METRICS", m)
    monkeypatch.setattr(courriel, "SECUBOX", tmp_path / "absent.conf")
    return tmp_path


def test_relais_local(relais):
    courriel.envoie("gk2@secubox.in", "Sujet\nInjecté", "corps")
    hote, port, to, sujet, corps = _SMTP.envois[0]
    assert (hote, port, to) == ("10.100.0.10", 25, "gk2@secubox.in")
    assert "\n" not in sujet and _SMTP.tls == [] and _SMTP.logins == []


def test_adresse_de_la_box(relais):
    assert courriel.adresse_de_la_box() == "gk2@secubox.in"


def test_soumission_authentifiee(relais, monkeypatch):
    s = relais / "secret"
    s.write_text("mdp\n")
    (relais / "secubox.conf").write_text(f'[courriel]\nsmtp_port = 587\nsmtp_user = "gk2"\nsmtp_pass_file = "{s}"\n')
    monkeypatch.setattr(courriel, "SECUBOX", relais / "secubox.conf")
    courriel.envoie("x@exemple.org", "s", "c")
    assert _SMTP.envois[0][1] == 587 and _SMTP.tls == [True] and _SMTP.logins == ["gk2"]


@pytest.mark.parametrize("mauvaise", ["", "pas-une-adresse", "a@b.c\nBcc: x@y.z"])
def test_adresse_invalide(relais, mauvaise):
    with pytest.raises(ValueError):
        courriel.envoie(mauvaise, "s", "c")
    assert _SMTP.envois == []
