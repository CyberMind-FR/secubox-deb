# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#1105 — l'étape certificat ne bloque JAMAIS la requête : wildcard *.gk2
réutilisé (attendu, rapide) ; domaine custom (certbot lent) → tâche de fond."""
import asyncio

import pytest

from routers import publish as pub


@pytest.mark.asyncio
async def test_cert_step_wildcard_is_awaited(monkeypatch):
    seen = []
    monkeypatch.setattr(pub, "provision_cert",
                        lambda d: (seen.append(d), {"mode": "reused", "detail": "wildcard"})[1])
    res = await pub._cert_step("z.gk2.secubox.in")
    assert res["mode"] == "reused"
    assert seen == ["z.gk2.secubox.in"]          # obtenu AVANT le retour


@pytest.mark.asyncio
async def test_cert_step_custom_is_backgrounded(monkeypatch):
    done = asyncio.Event()
    seen = []

    def fake(d):
        seen.append(d)
        done.set()
        return {"mode": "issued"}

    monkeypatch.setattr(pub, "provision_cert", fake)
    res = await pub._cert_step("all.gk2.net")
    assert res["mode"] == "provisioning"          # rendu tout de suite, PAS attendu
    assert seen == []                              # certbot n'a pas encore tourné
    await asyncio.wait_for(done.wait(), 2)         # …mais la tâche de fond finit par le faire
    assert seen == ["all.gk2.net"]
