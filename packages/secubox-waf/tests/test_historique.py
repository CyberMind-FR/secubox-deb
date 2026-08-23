# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Historique WAF (#1062) : agrège les threat logs TOURNÉS (gzip compris) en
tendances par jour, pour un rapport bien plus complet que le seul jour courant.
"""
import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api.historique import agreger_historique, bucket_ip  # noqa: E402


def _ecrire(path: Path, entrees, gz=False):
    lignes = "\n".join(json.dumps(e) for e in entrees) + "\n"
    if gz:
        with gzip.open(path, "wt") as f:
            f.write(lignes)
    else:
        path.write_text(lignes)


def test_agrege_par_jour_sur_journaux_tournes_gzip(tmp_path):
    # Jour 1 dans un .gz (tourné), jour 2 dans le .log courant.
    _ecrire(tmp_path / "waf-threats.log.1.gz", [
        {"timestamp": "2026-08-18T10:00:00+02:00", "client_ip": "1.1.1.1",
         "category": "scanners", "severity": "medium", "action": "warning"},
        {"timestamp": "2026-08-18T11:00:00+02:00", "client_ip": "1.1.1.1",
         "category": "lfi", "severity": "critical", "action": "banned"},
    ], gz=True)
    _ecrire(tmp_path / "waf-threats.log", [
        {"timestamp": "2026-08-19T09:00:00+02:00", "client_ip": "2.2.2.2",
         "category": "scanners", "severity": "medium", "action": "warning"},
    ])

    h = agreger_historique(sorted(tmp_path.glob("waf-threats.log*")))

    jours = h["jours"]
    assert jours["2026-08-18"]["total"] == 2
    assert jours["2026-08-18"]["categories"]["scanners"] == 1
    assert jours["2026-08-18"]["categories"]["lfi"] == 1
    assert jours["2026-08-18"]["severites"]["critical"] == 1
    assert jours["2026-08-19"]["total"] == 1
    # Le top IP est fusionné sur TOUTE la fenêtre (courant + tournés).
    assert h["top_ips"]["1.1.1.1"] == 2
    assert h["total"] == 3


def test_une_ligne_corrompue_ne_casse_pas_le_reste(tmp_path):
    p = tmp_path / "waf-threats.log"
    p.write_text('{"timestamp":"2026-08-19T09:00:00+02:00","category":"scanners",'
                 '"severity":"low","client_ip":"3.3.3.3"}\n'
                 'CECI N EST PAS DU JSON\n')
    h = agreger_historique([p])
    assert h["total"] == 1
    assert h["jours"]["2026-08-19"]["total"] == 1


def test_bucket_ip_regroupe_loopback_et_prive_sous_local():
    """Loopback / privé / link-local = trafic INTERNE → « local » (faux positif,
    comme sbxwaf #1163). Le reste passe tel quel."""
    for ip in ("127.0.0.1", "127.0.0.188", "10.100.0.1", "192.168.1.200",
               "172.16.5.9", "169.254.1.1", "::1", "fc00::1"):
        assert bucket_ip(ip) == "local", ip
    for ip in ("34.138.27.236", "8.8.8.8", "1.1.1.1"):
        assert bucket_ip(ip) == ip
    # Une valeur non parsable n'est pas « local » : on ne masque pas l'inconnu.
    assert bucket_ip("pas-une-ip") == "pas-une-ip"


def test_top_ips_agrege_les_locales_sous_local(tmp_path):
    """Les IP internes (loopback/privées) sont fondues sous « local » dans le
    top attaquants, au lieu de trôner comme « attaquant persistant »."""
    _ecrire(tmp_path / "waf-threats.log", [
        {"timestamp": "2026-08-23T09:00:00+02:00", "client_ip": "127.0.0.188",
         "category": "host_anomaly:unrouted", "severity": "medium"},
        {"timestamp": "2026-08-23T09:01:00+02:00", "client_ip": "127.0.0.1",
         "category": "host_anomaly:unrouted", "severity": "medium"},
        {"timestamp": "2026-08-23T09:02:00+02:00", "client_ip": "10.100.0.1",
         "category": "scanners", "severity": "low"},
        {"timestamp": "2026-08-23T09:03:00+02:00", "client_ip": "34.138.27.236",
         "category": "scanners", "severity": "high"},
    ])
    h = agreger_historique(sorted(tmp_path.glob("waf-threats.log*")))
    # Les trois lignes internes sont fusionnées sous « local ».
    assert h["top_ips"]["local"] == 3
    # L'attaquant public reste distinct et visible.
    assert h["top_ips"]["34.138.27.236"] == 1
    # Aucune IP interne ne subsiste comme entrée séparée.
    assert "127.0.0.188" not in h["top_ips"]
    assert "10.100.0.1" not in h["top_ips"]
