# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Contrat public de LiveHosts : journaux nginx par vhost (#1777).

CE FICHIER TESTAIT L'ANCIENNE SOURCE (socket d'administration HAProxy, un
compteur par frontend). c15727290 l'a remplacee sur master — cette topologie
n'a qu'UN frontend HAProxy, donc aucun signal par vhost — sans mettre ces tests
a jour ; la fusion 7ebe27403a a ensuite remis l'implementation HAProxy, qu'ils
validaient. Les deux fichiers de tests se contredisaient : l'un des deux
echouait toujours. La lecture incrementale elle-meme est figee par
test_live_hosts_incremental.py ; ici, ce que voient le bandeau et le taux de
blocage du WAF : `entries` (top N) et `total_requests` (le denominateur).
"""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

import live_hosts
from live_hosts import LiveHostsAggregator


@pytest.fixture(autouse=True)
def _cache_jetable(tmp_path, monkeypatch):
    monkeypatch.setattr(live_hosts, "CACHE_PATH", tmp_path / "cache" / "live-hosts.json")


def _ligne(quand: datetime) -> str:
    return ('1.2.3.4 - - [%s] "GET / HTTP/1.1" 200 12 "-" "curl"\n'
            % quand.strftime("%d/%b/%Y:%H:%M:%S +0000"))


def _journal(rep, hote, n, age_min=1):
    quand = datetime.now(timezone.utc) - timedelta(minutes=age_min)
    with open(rep / f"{hote}_access.log", "a", encoding="utf-8") as f:
        f.write(_ligne(quand) * n)


def _cfg(rep, **kw):
    return dict({"enabled": True, "log_dir": str(rep), "window_minutes": 60, "top_n": 2}, **kw)


def test_desactive_rend_un_payload_vide_avec_total_nul(tmp_path):
    out = asyncio.run(LiveHostsAggregator(_cfg(tmp_path, enabled=False)).refresh_once())
    assert out["enabled"] is False
    assert out["entries"] == [] and out["total_requests"] == 0


def test_top_n_trie_et_total_sur_tous_les_hotes(tmp_path):
    logs = tmp_path / "nginx"
    logs.mkdir()
    _journal(logs, "a.fr", 5)
    _journal(logs, "b.fr", 9)
    _journal(logs, "c.fr", 2)
    out = asyncio.run(LiveHostsAggregator(_cfg(logs)).refresh_once())
    assert out["enabled"] is True
    assert out["entries"] == [{"host": "b.fr", "count": 9}, {"host": "a.fr", "count": 5}]
    # Le denominateur du taux de blocage compte TOUT le trafic, pas le top N.
    assert out["total_requests"] == 16


def test_hors_fenetre_et_fichiers_etrangers_ignores(tmp_path):
    logs = tmp_path / "nginx"
    logs.mkdir()
    _journal(logs, "a.fr", 3)
    _journal(logs, "vieux.fr", 7, age_min=120)
    (logs / "error.log").write_text(_ligne(datetime.now(timezone.utc)) * 4)
    out = asyncio.run(LiveHostsAggregator(_cfg(logs)).refresh_once())
    assert out["entries"] == [{"host": "a.fr", "count": 3}]
    assert out["total_requests"] == 3


def test_repertoire_absent_ne_leve_pas(tmp_path):
    out = asyncio.run(LiveHostsAggregator(_cfg(tmp_path / "absent")).refresh_once())
    assert out["entries"] == [] and out["total_requests"] == 0
