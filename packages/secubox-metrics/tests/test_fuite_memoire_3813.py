# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3813 — fuite rapide de secubox-metrics (52 -> 450 Mo en 15 min sur gk2).

Cause : bans.jsonl (11 Mo) relu en entier a chaque build_waf_stats, par
plusieurs fils a la fois (boucle du cache leger lancee deux fois, ruee des
requetes du bandeau de sante sur un cache perime).
"""
import asyncio
import json
import threading
import time
import tracemalloc
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]


@pytest.fixture
def M(tmp_path, monkeypatch):
    from secubox_core import config as _c
    if _c._CONFIG is None:  # poste de dev : /etc/secubox/secubox.conf illisible
        monkeypatch.setattr(_c, "_CONFIG", {})
    from api import main as m
    monkeypatch.setattr(m, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(m, "CACHE_FILE", tmp_path / "metrics-cache.json")
    return m


def _ligne(ip, action="ban", exp=None, cat="lfi"):
    return json.dumps({"ip": ip, "cat": cat, "sev": "high", "at": 1, "exp": exp,
                       "action": action}) + "\n"


# ── bans.jsonl incremental ─────────────────────────────────────────────────

def test_bans_meme_regle_que_la_relecture_complete(tmp_path):
    from bans_actifs import BansActifs
    f = tmp_path / "bans.jsonl"
    now = 1_000_000
    f.write_text(
        _ligne("1.1.1.1", exp=now + 100)            # actif
        + _ligne("2.2.2.2", exp=now - 1)            # echu
        + _ligne("3.3.3.3", exp=None)               # sans echeance : actif
        + _ligne("4.4.4.4", exp=now + 100)
        + _ligne("4.4.4.4", action="unban")         # leve : la derniere ligne compte
        + "pas du json\n"
        + _ligne("5.5.5.5", exp="n/a"))             # echeance illisible : non compte
    b = BansActifs(f)
    assert b.compter(now) == 2
    # ajout : seule la queue est lue
    with f.open("a") as fh:
        fh.write(_ligne("6.6.6.6", exp=now + 50) + _ligne("1.1.1.1", action="unban"))
    assert b.compter(now) == 2          # 3.3.3.3 + 6.6.6.6
    # ligne partielle : pas consommee avant d'etre complete
    with f.open("a") as fh:
        fh.write('{"ip":"7.7.7.7","action":"ban"')
    assert b.compter(now) == 2
    with f.open("a") as fh:
        fh.write(',"exp":null}\n')
    assert b.compter(now) == 3
    # le temps passe : les bans echus sortent de la memoire
    assert b.compter(now + 60) == 2
    # rotation : on repart du nouveau fichier
    f.unlink()
    f.write_text(_ligne("8.8.8.8"))
    assert b.compter(now) == 1


def test_bans_memoire_bornee_par_les_bans_actifs(tmp_path):
    """100 000 lignes (gk2 : 105 000) : la memoire gardee suit les bans ACTIFS."""
    from bans_actifs import BansActifs
    f = tmp_path / "bans.jsonl"
    now = int(time.time())
    with f.open("w") as fh:
        for i in range(100_000):
            ip = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
            fh.write(_ligne(ip, exp=now - 10 if i % 100 else now + 3600))
    b = BansActifs(f)
    tracemalloc.start()
    try:
        assert b.compter(now) == 1000
        _courant, pic = tracemalloc.get_traced_memory()
        garde = tracemalloc.get_traced_memory()[0]
        # second passage : rien a relire
        tracemalloc.reset_peak()
        assert b.compter(now) == 1000
        _c2, pic2 = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # l'ancienne relecture complete montait a ~30 Mo de pic pour ce volume
    assert pic < 8 * 1024 * 1024, pic
    assert garde < 2 * 1024 * 1024, garde
    assert pic2 - garde < 256 * 1024, pic2 - garde


def test_build_waf_stats_ne_relit_plus_tout_le_journal():
    src = (PKG / "api" / "main.py").read_text()
    debut = src.index("def build_waf_stats")
    corps = src[debut:src.index("\ndef ", debut + 10)]
    assert "bans.jsonl\").read_text()" not in corps
    assert "bans_actifs()" in corps


# ── une seule reconstruction a la fois ─────────────────────────────────────

def test_build_cache_une_seule_reconstruction_concurrente(M, monkeypatch):
    en_cours, maxi, appels = 0, 0, 0
    verrou = threading.Lock()

    def lent():
        nonlocal en_cours, maxi, appels
        with verrou:
            en_cours += 1
            appels += 1
            maxi = max(maxi, en_cours)
        time.sleep(0.3)
        M.write_cache({"overview": {}, "waf": {}, "connections": {}, "timestamp": "t"})
        with verrou:
            en_cours -= 1
        return {"overview": {}}

    monkeypatch.setattr(M, "build_cache", lent)
    # un cache existe deja (perime) : les suivants le servent sans reconstruire
    M.write_cache({"overview": {"vieux": 1}})
    fils = [threading.Thread(target=M.build_cache_unique) for _ in range(20)]
    [t.start() for t in fils]
    [t.join() for t in fils]
    assert maxi == 1 and appels == 1


def test_build_cache_sans_cache_attend_la_reconstruction(M, monkeypatch):
    appels = 0

    def lent():
        nonlocal appels
        appels += 1
        time.sleep(0.2)
        d = {"overview": {"neuf": 1}}
        M.write_cache(d)
        return d

    monkeypatch.setattr(M, "build_cache", lent)
    res = []
    fils = [threading.Thread(target=lambda: res.append(M.build_cache_unique())) for _ in range(10)]
    [t.start() for t in fils]
    [t.join() for t in fils]
    assert appels == 1
    assert all(r == {"overview": {"neuf": 1}} for r in res)


def test_memoise_pas_de_ruee(M, monkeypatch):
    monkeypatch.setattr(M, "_memo", {})
    appels = 0

    def lent():
        nonlocal appels
        appels += 1
        time.sleep(0.2)
        return {"n": appels}

    res = []
    fils = [threading.Thread(target=lambda: res.append(M._memoise("sante", 60, lent)))
            for _ in range(20)]
    [t.start() for t in fils]
    [t.join() for t in fils]
    assert appels == 1 and len(res) == 20
    # perime : un seul recalcule, les autres servent l'ancienne valeur sans attendre
    M._memo["sante"] = (0, {"n": "vieux"})
    res.clear()
    fils = [threading.Thread(target=lambda: res.append(M._memoise("sante", 60, lent)))
            for _ in range(20)]
    [t.start() for t in fils]
    [t.join() for t in fils]
    assert appels == 2


def test_memoise_borne_les_cles(M, monkeypatch):
    """`ssl:<domaine>` vient de l'en-tete Host : pas une entree par domaine invente."""
    monkeypatch.setattr(M, "_memo", {})
    for i in range(M._MEMO_MAX + 300):
        M._memoise(f"ssl:x{i}.example", 900, lambda: {"ok": True})
    assert len(M._memo) <= M._MEMO_MAX


# ── boucles lancees une seule fois ─────────────────────────────────────────

def test_lifespan_lance_chaque_boucle_une_fois(M, monkeypatch):
    lances = []

    def compteur(nom):
        async def boucle(*_a, **_k):
            lances.append(nom)
            await asyncio.sleep(3600)
        return boucle

    monkeypatch.setattr(M, "_boucle_cache_leger", compteur("cache_leger"))
    monkeypatch.setattr(M, "_prechauffer_cache", compteur("prechauffage"))
    monkeypatch.setattr(M, "_rendre_memoire_glibc", compteur("glibc"))
    monkeypatch.setattr(M, "_prechauffer_rapport", lambda: None)
    monkeypatch.setattr(M, "_collecte", None)
    monkeypatch.setattr(M, "_tache_cache_leger", None)
    for nom in ("visitor_origin_agg", "live_hosts_agg", "cert_status_agg",
                "cookie_audit_agg", "vhost_stats_agg"):
        monkeypatch.setattr(getattr(M, nom), "run_forever", compteur(nom))

    async def scenario():
        async with M.lifespan(M.app):
            await asyncio.sleep(0.05)
            # une requete qui amorce la collecte (mode agregateur) ne double rien
            M.amorcer_collecte()
            await asyncio.sleep(0.05)
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    restantes = asyncio.run(scenario())
    assert lances.count("cache_leger") == 1, lances
    assert lances.count("vhost_stats_agg") == 1, lances
    assert sorted(set(lances)) == sorted(lances), lances
    assert restantes == []      # tout est annule a l'arret (arret propre, pas de SIGKILL)


def test_logs_journalctl_hors_de_la_boucle():
    src = (PKG / "api" / "logs.py").read_text()
    debut = src.index("async def refresh_cache")
    corps = src[debut:src.index("\ndef ", debut)]
    assert "await asyncio.to_thread(_get_all_logs" in corps


# ── garde-fou systemd ──────────────────────────────────────────────────────

def test_unite_bornee_en_memoire():
    u = (PKG / "debian" / "secubox-metrics.service").read_text()
    lignes = {x.split("=", 1)[0]: x.split("=", 1)[1] for x in u.splitlines()
              if "=" in x and not x.lstrip().startswith("#")}
    assert lignes.get("MemoryHigh") and lignes.get("MemoryMax")
    assert lignes.get("Restart") == "always"
    assert lignes.get("MemorySwapMax") == "0"


def test_bans_compactage_par_rename_3816(tmp_path, monkeypatch):
    """sbxwaf compacte bans.jsonl par rename (#3816) : l'identite est celle du descripteur ouvert. Meme si un stat du
    chemin (fait juste avant le rename) rendait encore l'ancien inode, le nouveau fichier est relu depuis le debut,
    jamais a la position de l'ancien."""
    import os
    import pathlib
    from bans_actifs import BansActifs
    f = tmp_path / "bans.jsonl"
    now = 1_000_000
    f.write_text("".join(_ligne(f"10.0.0.{i}", exp=now - 1) for i in range(50)) + _ligne("1.1.1.1", exp=now + 100))
    b = BansActifs(f)
    assert b.compter(now) == 1
    ancien = os.stat(f)
    # compactage : nouveau fichier (plus long que la position deja lue) mis en place par rename
    tmp = tmp_path / "bans.jsonl.tmp-1"
    tmp.write_text(_ligne("1.1.1.1", exp=now + 100) + "".join(_ligne(f"10.1.0.{i}", exp=now + 100) for i in range(80)))
    os.rename(tmp, f)
    monkeypatch.setattr(pathlib.Path, "stat", lambda self, **kw: ancien)   # stat perime : ignore
    assert b.compter(now) == 81
