# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3967 : pas de fausse alerte vitale (sonde sans root, veille voulue, hub servi par l'agrégateur), pas de panne cachée."""
import importlib.util
import socketserver
import threading
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("checks_3967", Path(__file__).resolve().parents[1] / "api" / "checks.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


@pytest.fixture
def lieux(monkeypatch, tmp_path):
    for nom in ("CGROUP", "MODULES_D"):
        (tmp_path / nom).mkdir()
        monkeypatch.setattr(checks, nom, tmp_path / nom)
    monkeypatch.setattr(checks, "MAIL_TOML", tmp_path / "mail.toml")
    actives = set()
    monkeypatch.setattr(checks, "_systemd_active", lambda u: u in actives)
    monkeypatch.setattr(checks, "_tcp_open", lambda *a, **k: True)

    def conteneur(nom, peuple=1):
        d = tmp_path / "CGROUP" / f"lxc.payload.{nom}"
        d.mkdir()
        (d / "cgroup.events").write_text(f"populated {peuple}\nfrozen 0\n")
    return tmp_path, actives, conteneur


def test_conteneur_lu_par_son_cgroup(lieux):
    _, _, conteneur = lieux
    conteneur("gitea", 0)
    assert not checks._lxc_running("gitea") and not checks._lxc_running("mail")
    conteneur("gitea-1")
    assert checks._lxc_running("gitea")
    conteneur("mail-vieux")
    assert not checks._lxc_running("mail")


def test_gitea_arrete_normal_seulement_a_la_demande(lieux, monkeypatch):
    tmp, _, conteneur = lieux
    assert checks.check_gitea_lxc()[0] is False
    (tmp / "MODULES_D/gitea.toml").write_text('lifecycle = "always-on"\n')
    assert checks.check_gitea_lxc()[0] is False
    (tmp / "MODULES_D/gitea.toml").write_text('lifecycle = "on-demand"\n')
    assert checks.check_gitea_lxc() == (True, {"lxc_state": "STOPPED", "veille_normale": True})
    conteneur("gitea")
    monkeypatch.setattr(checks, "_tcp_open", lambda *a, **k: False)
    assert checks.check_gitea_lxc()[0] is False                # en marche mais muet : panne


@pytest.mark.parametrize("toml,minuterie,attendu", [
    ("[fenetre]\nactif = true\n", True, True), ("[fenetre]\nactif = true\n", False, False),
    ("[fenetre]\nactif = false\n", True, False), ("illisible [", True, False), (None, True, False)])
def test_mail_en_veille_seulement_si_les_fenetres_vivent(lieux, toml, minuterie, attendu):
    tmp, actives, _ = lieux
    if toml is not None:
        (tmp / "mail.toml").write_text(toml)
    if minuterie:
        actives.add("secubox-mail-fenetre.timer")
    assert checks.check_mail_lxc()[0] is attendu


@pytest.mark.parametrize("code,attendu", [(200, True), (502, False), (None, False)])
def test_hub_servi_par_l_agregateur(lieux, monkeypatch, tmp_path, code, attendu):
    sock = str(tmp_path / "a.sock")
    reel = checks._http_200
    monkeypatch.setattr(checks, "_http_200", lambda s, c, **k: reel(sock, c))
    if code is None:
        assert checks.check_secubox_hub()[0] is attendu
        return

    class H(socketserver.StreamRequestHandler):
        def handle(self):
            self.rfile.readline()
            self.wfile.write(f"HTTP/1.1 {code} X\r\nContent-Length: 0\r\n\r\n".encode())
    with socketserver.UnixStreamServer(sock, H) as s:
        threading.Thread(target=s.serve_forever, daemon=True).start()
        assert checks.check_secubox_hub()[0] is attendu
        s.shutdown()
