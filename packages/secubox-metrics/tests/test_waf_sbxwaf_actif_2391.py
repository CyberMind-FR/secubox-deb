# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2391 — l'état du WAF suit sbxwaf (secubox-waf-ng + port 8085), pas le mitmproxy d'avant la bascule."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
import waf_etat as M  # noqa: E402


def test_actif_quand_le_service_est_actif_et_le_port_repond(monkeypatch):
    monkeypatch.setattr(M, "_systemctl_actif", lambda unite: True)
    import socket

    class _C:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _C())
    assert M.sbxwaf_actif() is True


def test_inactif_si_le_service_est_arrete(monkeypatch):
    monkeypatch.setattr(M, "_systemctl_actif", lambda unite: False)
    assert M.sbxwaf_actif() is False


def test_inactif_si_le_port_ne_repond_pas(monkeypatch):
    monkeypatch.setattr(M, "_systemctl_actif", lambda unite: True)
    import socket

    def _refuse(*a, **k):
        raise ConnectionRefusedError()
    monkeypatch.setattr(socket, "create_connection", _refuse)
    assert M.sbxwaf_actif() is False


def test_la_sante_ne_depend_plus_de_mitmdump():
    src = (Path(__file__).resolve().parents[1] / "api/main.py").read_text(encoding="utf-8")
    assert "mitmproxy_up = sbxwaf_actif() or" in src
    assert "mitmproxy_running = sbxwaf_actif() or" in src
    assert "from waf_etat import sbxwaf_actif" in src
