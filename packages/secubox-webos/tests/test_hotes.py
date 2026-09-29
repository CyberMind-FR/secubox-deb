# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Hôtes locaux (#1670) : seuls les noms exacts du domaine de la box, et joignables."""
import asyncio

from api import hotes


def test_candidats_exacts_du_domaine():
    t = ["server_name radio.gk3.secubox.in radio.gk3.net;",
         "  server_name hall.gk2.net hall.gk3.secubox.in hall.* ~^x\\.gk3\\.secubox\\.in$;",
         "server_name admin.gk2.secubox.in;"]
    assert hotes.candidats(t, "gk3.secubox.in") == ["hall.gk3.secubox.in", "radio.gk3.secubox.in"]
    assert hotes.candidats(t, "") == []
    # « mood.* » (#1680) : le service de la box sous son propre domaine.
    assert hotes.candidats(["server_name mood.gk2.secubox.in mood.*;"], "gk3.secubox.in") == ["mood.gk3.secubox.in"]


def test_seuls_les_joignables_sont_locaux(monkeypatch):
    monkeypatch.setattr(hotes, "lire_sites", lambda: ["server_name a.gk3.secubox.in b.gk3.secubox.in;"])

    async def joignable(nom):
        return nom.startswith("a.")
    monkeypatch.setattr(hotes, "_joignable", joignable)
    assert asyncio.run(hotes.recalculer("gk3.secubox.in")) == ["a.gk3.secubox.in"]
    assert hotes.locaux() == ["a.gk3.secubox.in"]
