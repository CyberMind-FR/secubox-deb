# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2629 — secubox-waf-route ne signale plus le WAF.

sbxwaf relit haproxy-routes.json A CHAUD (mtime a chaque requete) et n'a aucun gestionnaire SIGHUP : le « systemctl reload secubox-waf-ng » que l'outil
envoyait apres chaque route posee tuait le demon « avec succes » (ExecReload=kill -HUP), sans relance : 503 sur tous les vhosts publics (gk2, 14 oct., 3 min 30)."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
PAQUETS = PKG.parent
loader = importlib.machinery.SourceFileLoader("waf_route_2629", str(PKG / "usr" / "sbin" / "secubox-waf-route"))
spec = importlib.util.spec_from_loader("waf_route_2629", loader)
w = importlib.util.module_from_spec(spec)
loader.exec_module(w)


def test_poser_une_route_n_envoie_aucun_signal_au_waf(tmp_path, monkeypatch):
    table = tmp_path / "haproxy-routes.json"
    table.write_text(json.dumps({"deja.exemple": ["127.0.0.1", 9080]}))
    monkeypatch.setattr(w, "TABLE", str(table))
    appels = []
    monkeypatch.setattr(w.subprocess, "run", lambda cmd, **k: appels.append(cmd) or type("R", (), {"returncode": 0})())
    assert w.main(["secubox-waf-route", "nouveau.exemple", "9080"]) == 0
    assert json.loads(table.read_text())["nouveau.exemple"] == ["127.0.0.1", 9080]          # la route est bien posee (ecriture atomique)
    assert appels == [], f"aucun systemctl attendu, vu : {appels}"


def test_un_reload_du_waf_ne_peut_plus_le_tuer():
    unite = (PAQUETS / "secubox-waf-ng" / "systemd" / "secubox-waf-ng.service").read_text()
    exec_reload = [l for l in unite.splitlines() if l.startswith("ExecReload=")]
    assert exec_reload and not any("kill" in l and "HUP" in l for l in exec_reload)
    assert any("haproxy-routes.json" in l for l in exec_reload)       # un « reload » force la relecture a chaud
