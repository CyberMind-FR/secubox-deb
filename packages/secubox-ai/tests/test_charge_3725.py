# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Profils de charge de la veille V2 (#3725) : 100, 500 et 1 000 événements par minute par le vrai chemin
(source menaces, normalisation, collecte, corrélation, dossiers) avec un client gk2 simulé. Ce sont des MESURES
imprimées, pas des garanties : seules la santé (aucune exception) et un temps de passe borné sont vérifiés.

Ignoré par défaut. Lancer :
    SECUBOX_CHARGE=1 python -m pytest packages/secubox-ai/tests/test_charge_3725.py -q -s
(-s pour voir les mesures ; SECUBOX_CHARGE_MINUTES=<n> change la durée simulée, 10 par défaut.)
"""
import asyncio
import json
import os
import random
import statistics
import time
from datetime import datetime, timedelta, timezone

import pytest

from api import radar
from veille import base, collecte, correlation, dossiers
from veille.sources import menaces

pytestmark = [pytest.mark.charge,
              pytest.mark.skipif(os.environ.get("SECUBOX_CHARGE") != "1", reason="profils de charge : SECUBOX_CHARGE=1")]

T0 = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
PASSE_S = 30                       # intervalle de la source menaces
LIMITE_PASSE_S = 60                # borne de santé par passe (collecte + corrélation + dossiers) à 1 000/min
CATEGORIES = ("scanners:nmap", "sqli:union", "xss:reflet", "robots:ua", "product_absent_probes:wp", "auth_smtp:sasl_failed",
              "honeypot:ssh", "host_anomaly:x", "unrouted:y")
GRAVITES = ("low", "medium", "high")


class Flux:
    """Client gk2 simulé : le flux des menaces produit `par_minute` événements par minute de temps simulé."""

    def __init__(self, par_minute, graine=3725):
        self.par_passe = par_minute * PASSE_S // 60
        self.rng = random.Random(graine)
        self.n = 0
        self.maintenant = T0

    async def get(self, nom, params=None):
        assert nom == "menaces_flux"
        debut = int((params or {}).get("depuis").split(":")[1]) if (params or {}).get("depuis") else 0
        lignes = []
        for i in range(self.par_passe):
            ip = f"100.64.{self.rng.randrange(0, 64)}.{self.rng.randrange(1, 255)}"      # ~16 000 acteurs possibles
            ts = self.maintenant - timedelta(seconds=PASSE_S * (self.par_passe - i) / self.par_passe)
            lignes.append({"position": f"1:{debut + i + 1}", "ligne": json.dumps({
                "timestamp": ts.isoformat(), "category": self.rng.choice(CATEGORIES), "client_ip": ip,
                "severity": self.rng.choice(GRAVITES), "host": f"site{self.rng.randrange(5)}.example.net",
                "country": self.rng.choice(("CN", "RU", "US", "NL", "BR")),
                "message": "motif de la règle " + str(self.rng.randrange(40))})})
        return {"lignes": lignes, "suivant": f"1:{debut + len(lignes)}", "rotation": False, "trou": False}


def _taille(chemin):
    return sum(p.stat().st_size for p in chemin.parent.glob(chemin.name + "*") if p.is_file())


@pytest.mark.parametrize("par_minute", [100, 500, 1000])
def test_profil_de_charge(tmp_path, monkeypatch, par_minute):
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path))
    minutes = int(os.environ.get("SECUBOX_CHARGE_MINUTES", "10"))
    db = base.ouvrir(tmp_path / "veille.db")
    client = Flux(par_minute)
    source = menaces.Menaces()
    collectes, correlations, constructions = [], [], []
    try:
        for k in range(minutes * 60 // PASSE_S):
            quand = T0 + timedelta(seconds=PASSE_S * (k + 1))
            client.maintenant = quand
            t = time.perf_counter()
            etats = asyncio.run(collecte.passe(db, client, [source], quand))
            collectes.append(time.perf_counter() - t)
            assert etats == {"menaces": "ok"}
            t = time.perf_counter()
            correlation.correler(db, quand)
            correlations.append(time.perf_counter() - t)
            t = time.perf_counter()
            dossiers.construire(db, quand)
            constructions.append(time.perf_counter() - t)
        total = db.execute("SELECT COUNT(*) FROM evenements").fetchone()[0]
        n_inc = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        n_dos = db.execute("SELECT COUNT(*) FROM dossiers").fetchone()[0]
        assert total >= minutes * par_minute * 0.95          # sanité : l'essentiel est collecté (doublons de position exclus)
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        octets = _taille(tmp_path / "veille.db")
        try:
            gros = db.execute("SELECT name, SUM(pgsize) FROM dbstat GROUP BY name ORDER BY 2 DESC LIMIT 4").fetchall()
        except Exception:                   # dbstat absent de certaines compilations de SQLite
            gros = []

        # /radar : le calcul des routes de la console (tendances et chaîne), puis la liste des dossiers, lecture seule.
        fin = (T0 + timedelta(minutes=minutes)).timestamp()
        radar_s = []
        for _ in range(3):
            t = time.perf_counter()
            tend, chaine = radar.calculer(None, fin)
            radar_s.append(time.perf_counter() - t)
        t = time.perf_counter()
        page = asyncio.run(radar.dossiers_liste(None, 100, None))
        liste_s = time.perf_counter() - t
    finally:
        db.close()

    pire = max(a + b + c for a, b, c in zip(collectes, correlations, constructions))
    projete = octets / total * par_minute * 60 * 24 * 30 if total else 0
    print(f"\n[charge {par_minute}/min, {minutes} min simulées] événements={total} incidents={n_inc} dossiers={n_dos}\n"
          f"  collecte par passe de {PASSE_S} s : moy {statistics.mean(collectes) * 1000:.0f} ms, max {max(collectes) * 1000:.0f} ms\n"
          f"  corrélation : moy {statistics.mean(correlations) * 1000:.0f} ms, max {max(correlations) * 1000:.0f} ms\n"
          f"  dossiers : moy {statistics.mean(constructions) * 1000:.0f} ms, max {max(constructions) * 1000:.0f} ms\n"
          f"  retard de bout en bout (pire passe) : {pire * 1000:.0f} ms\n"
          f"  /radar (calculer) : {min(radar_s) * 1000:.0f} à {max(radar_s) * 1000:.0f} ms ; /dossiers (100) : {liste_s * 1000:.0f} ms\n"
          f"  base : {octets / 1e6:.1f} Mo pour {total} événements ; projetée à 30 j (rétention) : {projete / 1e9:.2f} Go\n"
          f"  plus gros objets : {', '.join(f'{n} {o / 1e6:.1f} Mo' for n, o in gros) or 'dbstat indisponible'}\n"
          f"  (acteurs tirés au hasard parmi ~16 000 adresses : presque un dossier par adresse, cas défavorable)")
    assert pire < LIMITE_PASSE_S
    assert chaine["disponible"] and isinstance(page["dossiers"], list)
