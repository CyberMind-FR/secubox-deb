# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# detect-mode records must never inflate the WAF dashboard's block counters.
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# Make the package importable without an install step
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Stub out secubox_core before importing waf.api — production deps
# (auth, config) aren't needed for these unit tests.
from types import ModuleType

if "secubox_core" not in sys.modules:
    secubox_core = ModuleType("secubox_core")
    auth_mod = ModuleType("secubox_core.auth")
    auth_mod.require_jwt = lambda: None
    # Le parc est passe en lecture gardee (#1256) : le stub doit porter
    # les DEUX gardes, sinon l'import de waf.api echoue en designant le
    # bon nom pour la mauvaise raison (« unknown location »).
    auth_mod.require_lecture = lambda: None
    config_mod = ModuleType("secubox_core.config")
    config_mod.get_config = lambda *_a, **_k: {}
    secubox_core.auth = auth_mod
    secubox_core.config = config_mod
    sys.modules["secubox_core"] = secubox_core
    sys.modules["secubox_core.auth"] = auth_mod
    sys.modules["secubox_core.config"] = config_mod

# geoip2 may or may not be installed in CI; stub it out.
if "geoip2" not in sys.modules:
    geoip2 = ModuleType("geoip2")
    geoip2_db = ModuleType("geoip2.database")
    geoip2_db.Reader = object
    geoip2_err = ModuleType("geoip2.errors")
    class _AddressNotFoundError(Exception): ...
    geoip2_err.AddressNotFoundError = _AddressNotFoundError
    sys.modules["geoip2"] = geoip2
    sys.modules["geoip2.database"] = geoip2_db
    sys.modules["geoip2.errors"] = geoip2_err

from api import main as waf_main  # noqa: E402
import time


def _write_log(tmp_path, *entries):
    import json as _json
    p = tmp_path / "threats.log"
    p.write_text("\n".join(_json.dumps(e) for e in entries) + "\n")
    return p


def test_detect_records_excluded_from_block_counters(tmp_path, monkeypatch):
    """A detect-mode match is observed, not blocked. Counting it as a block
    would make blocked_24h a lie the instant an operator arms a detect
    category — the whole reason action='detect' exists."""
    today = time.strftime("%Y-%m-%d")
    logp = _write_log(
        tmp_path,
        {"action": "banned", "category": "sqli", "severity": "critical",
         "timestamp": today + "T10:00:00", "client_ip": "203.0.113.1"},
        {"action": "detect", "category": "cve_2024", "severity": "critical",
         "timestamp": today + "T10:00:01", "client_ip": "203.0.113.2"},
        {"action": "detect", "category": "cve_2024", "severity": "critical",
         "timestamp": today + "T10:00:02", "client_ip": "203.0.113.3"},
    )
    monkeypatch.setattr(waf_main, "THREATS_LOG", str(logp))
    monkeypatch.setattr(waf_main, "STATS_DISK_CACHE", str(tmp_path / "cache.json"))

    stats = waf_main._get_threat_stats()

    assert stats["total_threats"] == 1, "detect records leaked into total_threats"
    assert stats["observed_threats"] == 2
    assert "cve_2024" not in stats["by_category"]
    assert stats["by_category"].get("sqli") == 1


def test_detect_only_log_reports_zero_blocked(tmp_path, monkeypatch):
    """A log of pure detect matches must report zero blocks, not N."""
    today = time.strftime("%Y-%m-%d")
    logp = _write_log(
        tmp_path,
        {"action": "detect", "category": "cve_2024", "severity": "high",
         "timestamp": today + "T09:00:00", "client_ip": "203.0.113.9"},
    )
    monkeypatch.setattr(waf_main, "THREATS_LOG", str(logp))
    monkeypatch.setattr(waf_main, "STATS_DISK_CACHE", str(tmp_path / "cache.json"))

    stats = waf_main._get_threat_stats()
    assert stats["total_threats"] == 0
    assert stats["observed_threats"] == 1


# #3176 : blocked_24h valait total_threats — tout le journal depuis sa rotation (≈ minuit, ou plus tôt au-delà de 20 Mo). Il égalait « Menaces
# du jour » et retombait à zéro en pleine journée. Les menaces sont désormais comptées PAR HEURE (UTC), conservées à travers les rotations.
def _il_y_a(heures, **k):
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(hours=heures, **k)).astimezone().isoformat(timespec="seconds")


def _menace(ts, action="banned", ip="203.0.113.1"):
    return {"action": action, "category": "sqli", "severity": "high", "timestamp": ts, "client_ip": ip}


def _banc(tmp_path, monkeypatch, *entries):
    logp = _write_log(tmp_path, *entries)
    monkeypatch.setattr(waf_main, "THREATS_LOG", str(logp))
    monkeypatch.setattr(waf_main, "STATS_DISK_CACHE", str(tmp_path / "cache.json"))
    return logp


def test_menaces_24h_fenetre_glissante_pas_le_journal_entier_3176(tmp_path, monkeypatch):
    _banc(tmp_path, monkeypatch, _menace(_il_y_a(30)), _menace(_il_y_a(2)), _menace(_il_y_a(0, minutes=5)),
          _menace(_il_y_a(0, minutes=1), action="detect"))
    s = waf_main._get_threat_stats()
    assert s["total_threats"] == 3                                       # le journal entier, comme avant
    assert s["menaces_24h"] == 2                                         # la ligne d'il y a 30 h sort de la fenêtre ; detect n'est pas une menace bloquée
    assert len(s["hourly_blocks"]) == 24 and sum(s["hourly_blocks"]) == 2 and s["hourly_blocks"][-1] >= 1   # la plus récente à droite


def test_une_rotation_ne_remet_pas_les_24h_a_zero_3176(tmp_path, monkeypatch):
    import json as _json
    logp = _banc(tmp_path, monkeypatch, _menace(_il_y_a(3)), _menace(_il_y_a(2)))
    assert waf_main._get_threat_stats()["menaces_24h"] == 2
    logp.write_text(_json.dumps(_menace(_il_y_a(0, minutes=2))) + "\n")     # journal tourné : nouveau fichier, plus court
    s = waf_main._get_threat_stats()
    assert s["total_threats"] == 1 and s["menaces_24h"] == 3


def test_aucune_ligne_n_est_comptee_deux_fois_3176(tmp_path, monkeypatch):
    import json as _json
    _banc(tmp_path, monkeypatch, _menace(_il_y_a(1)), _menace(_il_y_a(0, minutes=30)))
    assert waf_main._get_threat_stats()["menaces_24h"] == 2
    assert waf_main._get_threat_stats()["menaces_24h"] == 2              # rien de nouveau : rien d'ajouté
    cache = tmp_path / "cache.json"
    etat = _json.loads(cache.read_text())
    del etat["counters"]["par_heure"]                                    # cache d'avant #3176 : reprise complète, une seule fois
    cache.write_text(_json.dumps(etat))
    assert waf_main._get_threat_stats()["menaces_24h"] == 2


def test_blocked_24h_lit_la_fenetre_et_non_le_journal_3176(monkeypatch):
    monkeypatch.setattr(waf_main, "_compiled_patterns", {})
    monkeypatch.setattr(waf_main, "_cfg", lambda: {"enabled": True})
    s = waf_main._decorate_dashboard_stats({"total_threats": 1263, "threats_today": 1263, "menaces_24h": 2104})
    assert s["blocked_24h"] == 2104 and s["blocked_today"] == 1263


# #3257 (relecture finale M1) : une ligne d'ÉTAT n'est pas une menace. Chaque
# pièce jointe de plus de 1 Mio écrit multipart-tronque ; elle gonflait
# total_threats et threats_today et plaçait l'usager dans top_ips.
def test_lignes_d_etat_comptees_a_part_3257(tmp_path, monkeypatch):
    today = time.strftime("%Y-%m-%d")
    usager = "203.0.113.50"

    def etat(cat, sev="audit"):
        return {"action": cat, "category": cat, "severity": sev,
                "timestamp": today + "T11:00:00", "client_ip": usager}
    _banc(tmp_path, monkeypatch,
          {"action": "banned", "category": "sqli", "severity": "critical",
           "timestamp": today + "T10:00:00", "client_ip": "203.0.113.1"},
          etat("multipart-tronque"), etat("multipart-malforme"), etat("multipart-limite"),
          etat("multipart-concurrence"), etat("body-inspect-truncated"),
          etat("body-inspect-skipped"),
          {"action": "autre", "category": "x", "severity": "audit",
           "timestamp": today + "T11:00:01", "client_ip": usager},
          {"action": "detect", "category": "php2shell", "severity": "critical", "mode": "detect",
           "timestamp": today + "T11:00:02", "client_ip": "203.0.113.9"})
    s = waf_main._get_threat_stats()
    assert s["total_threats"] == 1 and s["threats_today"] == 1
    assert s["observed_threats"] == 1
    assert s["etats"] == 7 and s["etats_today"] == 7
    assert usager not in s["top_ips"]
    assert not any(c.startswith(("multipart-", "body-inspect-")) for c in s["by_category"])
    assert s["menaces_24h"] == 1


def test_cache_d_avant_les_etats_relu_une_fois_3257(tmp_path, monkeypatch):
    import json as _json
    today = time.strftime("%Y-%m-%d")
    _banc(tmp_path, monkeypatch,
          {"action": "multipart-tronque", "category": "multipart-tronque", "severity": "audit",
           "timestamp": today + "T11:00:00", "client_ip": "203.0.113.50"})
    waf_main._get_threat_stats()
    cache = tmp_path / "cache.json"
    etat = _json.loads(cache.read_text())
    del etat["counters"]["etats"]                     # cache d'avant M1 : reprise complète
    etat["counters"]["total_threats"] = 1             # l'ancienne lecture la comptait en menace
    cache.write_text(_json.dumps(etat))
    s = waf_main._get_threat_stats()
    assert s["total_threats"] == 0 and s["etats"] == 1
