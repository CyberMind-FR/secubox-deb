# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Un relevé systemd en un appel, partagé, hors de la boucle (#1835).

La surveillance de c3box lançait vingt `is-active` toutes les 30 s, bloquants,
sur la boucle partagée de son groupe ; chaque lecture de /services ajoutait
vingt `show`.
"""
import asyncio
import subprocess

import pytest

from api import main as m

# Unités actives (nom sans « secubox- » ni « .service ») : les VRAIES unités
# du WAF, de l'équilibreur et du DNS ; secubox-haproxy et secubox-dns restent
# arrêtées, comme sur gk2.
ACTIFS = {"waf-ng", "haproxy", "unbound"}


def _sortie(noms):
    blocs = []
    for unite in noms:
        n = unite.removeprefix("secubox-").removesuffix(".service")
        actif = n in ACTIFS
        blocs.append(f"Id={unite}\nActiveState={'active' if actif else 'inactive'}\n"
                     f"ActiveEnterTimestamp={'Thu 2026-10-01 10:00:00 CEST' if actif else ''}\n"
                     f"MemoryCurrent={'1048576' if actif else '[not set]'}")
    return "\n\n".join(blocs) + "\n"


@pytest.fixture
def lancements(monkeypatch):
    vus = []

    def faux_run(args, **kw):
        vus.append(args)
        assert args[:2] == ["systemctl", "show"], args
        return subprocess.CompletedProcess(args, 0, _sortie(args[args.index("--") + 1:]), "")

    monkeypatch.setattr(m.subprocess, "run", faux_run)
    monkeypatch.setattr(m, "_releve", {"t": 0.0, "etats": {}})
    m.stats_cache.clear()
    return vus


def test_services_en_un_appel(lancements):
    r = asyncio.run(m.list_services())
    assert len(lancements) == 1
    par = {s["name"]: s for s in r["services"]}
    assert par["waf"]["running"] and par["waf"]["uptime"] == "Thu 2026-10-01 10:00:00 CEST"
    assert not par["nac"]["running"] and par["nac"]["uptime"] is None
    assert r["running"] == len(ACTIFS) and r["total"] == len(m.SERVICES)


def test_releve_partage_par_les_lecteurs(lancements):
    asyncio.run(m.list_services())
    m.stats_cache.clear()
    asyncio.run(m.health_check())          # relevé encore frais : rien de relancé
    assert len(lancements) == 1


def test_detail_d_un_service_un_appel(lancements):
    r = asyncio.run(m.get_service("waf"))
    assert len(lancements) == 1 and r["memory_bytes"] == 1048576 and r["running"]


def test_surveillance_hors_boucle_et_sans_fausse_alerte(monkeypatch, lancements):
    evenements = []
    monkeypatch.setattr(m, "_record_event", lambda *a, **k: evenements.append(a))

    async def rien(*a, **k):
        return None

    monkeypatch.setattr(m, "_notify_webhooks", rien)
    monkeypatch.setattr(m, "_previous_states", {s["name"]: True for s in m.SERVICES})

    def echec(args, **kw):
        raise subprocess.TimeoutExpired(args, 10)

    monkeypatch.setattr(m.subprocess, "run", echec)

    async def un_tour():
        tache = asyncio.create_task(m._monitor_services())
        await asyncio.sleep(0.05)
        tache.cancel()

    asyncio.run(un_tour())
    # systemctl en échec : aucun service déclaré « tombé ».
    assert evenements == []


def test_unites_reelles_plus_de_faux_critique(lancements):
    """secubox-haproxy et secubox-dns arrêtées, haproxy et unbound actifs :
    la box est saine (#1835) — elle s'affichait « critical »."""
    h = asyncio.run(m.health_check())
    assert h["critical_down"] == [] and h["status"] != "critical"
    unites = lancements[0][lancements[0].index("--") + 1:]
    assert {"haproxy.service", "unbound.service", "secubox-waf-ng.service"} <= set(unites)
    assert "secubox-haproxy.service" not in unites and "secubox-dns.service" not in unites
