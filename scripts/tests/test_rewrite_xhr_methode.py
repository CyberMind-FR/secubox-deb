# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""rewrite-xhr.py : une méthode RPCD qui agit part en POST, une lecture en GET (#3126, L5).

Une action nommée sans suffixe (« restart », « stop », « start », « reload ») partait en GET :
une portée « lecture » (méthodes GET seulement) pouvait alors relancer un service.
"""
import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "rewrite-xhr.py"
_spec = importlib.util.spec_from_file_location("rewrite_xhr", _SCRIPT)
rewrite_xhr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rewrite_xhr)


@pytest.mark.parametrize("nom", ["restart", "stop", "start", "reload", "restart_service", "stop_all", "set_config"])
def test_action_part_en_post(nom):
    assert rewrite_xhr.methode_http(nom) == "POST"


@pytest.mark.parametrize("nom", ["status", "get_config", "stats", "list_rules", "startup_info_get"])
def test_lecture_part_en_get(nom):
    assert rewrite_xhr.methode_http(nom) == "GET"


# ── #3126, relecture de sécurité de L5 (R-L5-14, M5) ──────────────────────────────────────────────────────────────
_NOUVELLES_ACTIONS = ("reboot", "sync", "toggle", "reset", "flush", "preload_url", "sync_zones")


@pytest.mark.parametrize("nom", _NOUVELLES_ACTIONS)
def test_actions_exactes_ajoutees_partent_en_post(nom):
    assert rewrite_xhr.methode_http(nom) == "POST"


@pytest.mark.parametrize("nom", ["sync_status", "reset_count_get", "toggles", "flush_stats", "reboot_history"])
def test_noms_exacts_seulement(nom):
    """Noms EXACTS : « sync_status » ou « reboot_history » restent des lectures."""
    assert rewrite_xhr.methode_http(nom) == "GET"


def test_les_pages_portees_suivent_la_regle():
    """Une page portée appelle chaque action exacte avec la méthode que donne la règle : aucune n'est restée en GET."""
    import re
    depot = Path(__file__).resolve().parents[2]
    appel = re.compile(r"sbxFetch\('/api/v1/[a-z0-9-]+/([A-Za-z0-9_]+)',\s*[^,]+,\s*'([A-Z]+)'\)")
    ecarts = []
    for js in depot.glob("packages/*/www/**/*.js"):
        for nom, methode in appel.findall(js.read_text(encoding="utf-8", errors="replace")):
            if nom in rewrite_xhr._ACTIONS_EXACTES and methode != rewrite_xhr.methode_http(nom):
                ecarts.append((str(js.relative_to(depot)), nom, methode))
    assert not ecarts, ecarts


# ── #3126, R-L5-16 : GET qui agissent ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("nom", ["check_updates", "run_diagnostic_test", "send_test_alert", "clear_stats"])
def test_get_qui_agissent_partent_en_post(nom):
    assert rewrite_xhr.methode_http(nom) == "POST"


@pytest.mark.parametrize("module", ["system", "nac", "ad-guard", "freebox", "cdn"])
def test_aucune_route_get_ne_porte_un_nom_d_action(module):
    """La règle de rewrite-xhr appliquée aux routes GET de l'API : un segment littéral nommé comme une action
    (selon `methode_http`) ne peut pas être servi en GET."""
    import re
    depot = Path(__file__).resolve().parents[2]
    lectures_connues = set()               # Final (R-L5-17 M3) : `ban` est exact, « banner » n'a plus besoin d'exception
    ecarts = []
    for py in (depot / "packages" / f"secubox-{module}" / "api").rglob("*.py"):
        for chemin in re.findall(r'@\w+\.get\(\s*"([^"]+)"', py.read_text(encoding="utf-8")):
            for seg in chemin.split("/"):
                if seg and not seg.startswith("{") and seg not in lectures_connues \
                        and rewrite_xhr.methode_http(seg.replace("-", "_")) == "POST":
                    ecarts.append((py.name, chemin, seg))
    assert not ecarts, ecarts


# ── Final (R-L5-17) : `ban` exact, plus un préfixe qui prend `bandwidth_*` ou `banner` ────────────────────────────────
@pytest.mark.parametrize("nom", ["ban", "ban_client", "ban_ip", "unban", "unban_client"])
def test_bannir_part_en_post(nom):
    assert rewrite_xhr.methode_http(nom) == "POST"


@pytest.mark.parametrize("nom", ["bandwidth_rates", "bandwidth_savings", "bandwidth", "banner", "banner_config"])
def test_bande_passante_et_banniere_restent_des_lectures(nom):
    assert rewrite_xhr.methode_http(nom) == "GET"
