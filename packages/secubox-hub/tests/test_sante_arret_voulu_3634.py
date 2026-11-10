# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3634 — Santé : une unité arrêtée par conception n'est pas « dégradé » (vu sur le RPi4, image mobile)."""
import importlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")

# systemctl show réel du RPi4 (secubox-rpi), réduit aux propriétés lues
SHOW = """Id=secubox-autoload-agent.service
ActiveState=inactive
LoadState=loaded
Result=success
ConditionResult=no

Id=secubox-p2p-mesh.service
ActiveState=inactive
LoadState=loaded
Result=exec-condition
ConditionResult=no

Id=secubox-mail.service
ActiveState=failed
LoadState=loaded
Result=exit-code
ConditionResult=yes

Id=secubox-hub.service
ActiveState=inactive
LoadState=loaded
Result=success
ConditionResult=yes
"""

LIST_UNITS = """secubox-autoload-agent.service loaded inactive dead Agent
secubox-premier-pas-console.service loaded inactive dead Console
secubox-lan-dhcp.service loaded inactive dead DHCP
secubox-mail.service loaded failed failed Mail
secubox-nextcloud.service loaded inactive dead Nextcloud
secubox-torrent.service loaded inactive dead Torrent
"""
SHOW_RPI = """Id=secubox-autoload-agent.service
ActiveState=inactive
LoadState=loaded
Result=success
ConditionResult=no

Id=secubox-premier-pas-console.service
ActiveState=inactive
LoadState=loaded
Result=success
ConditionResult=no
"""
UNIT_FILES = """secubox-lan-dhcp.service disabled enabled
secubox-nextcloud.service disabled enabled
secubox-autoload-agent.service enabled enabled
"""


def test_unites_sautees():
    assert main.unites_sautees(SHOW) == frozenset({"autoload-agent", "p2p-mesh"})
    assert main.unites_sautees("") == frozenset()


def test_releve_de_sante_rpi4(monkeypatch):
    def faux_run(args, **kw):
        if args[:2] == ["systemctl", "list-unit-files"]:
            out = UNIT_FILES
        elif args[:2] == ["systemctl", "show"] and "ConditionResult" in " ".join(args):
            out = SHOW_RPI
        else:
            out = ""
        return subprocess.CompletedProcess(args, 0, out, "")
    monkeypatch.setattr(main.subprocess, "run", faux_run)
    monkeypatch.setattr(main, "unites_au_repos", lambda noms: (frozenset(), frozenset()))
    monkeypatch.setattr(main, "_load_sleepable_modules", lambda: {"nextcloud"})
    monkeypatch.setattr(main, "modules_montes", lambda *a, **k: frozenset())
    monkeypatch.setattr(main, "superposer_lxc", lambda *a, **k: None)
    monkeypatch.setattr(main, "_load_menu_definitions", lambda: [])
    main._au_repos["ts"] = 0
    main._cache["units_brut"] = LIST_UNITS
    main._cache["units_ts"] = __import__("time").time()
    main._cache.pop("health_batch", None)
    main._refresh_health_batch()
    m = main._cache["health_batch"]["modules"]
    assert "lan-dhcp" not in m                                         # désactivée : pas surveillée
    for ident in ("autoload-agent", "premier-pas-console"):            # condition non remplie : veille
        assert m[ident]["status"] == "ok" and m[ident]["veille"] is True, m[ident]
        assert "condition" in m[ident]["msg"]
    assert m["nextcloud"]["msg"] == "Asleep (on-demand)"               # module à veille désactivé : gardé
    assert m["mail"]["status"] == "error"                              # une vraie panne reste une panne
    assert m["torrent"]["status"] == "warn"                            # arrêt inexpliqué : toujours dégradé
