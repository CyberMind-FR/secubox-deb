# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2838 — profil d'activation `minimal` : ce que `secubox-profilectl apply --profile minimal` laisse allume (DPI, dns-guard, ad-guard, NAC, Freebox, WebUI admin)."""
from pathlib import Path

from api.state import load_profile

MINIMAL = load_profile(Path(__file__).resolve().parent.parent / "profiles" / "minimal.toml")


def test_les_modules_du_profil_minimal_sont_allumes():
    for mid in ("dpi", "ndpid-engine", "dns-guard", "ad-guard", "nac", "freebox", "ipv6guard", "webfilter", "hub", "portal", "auth", "aggregator", "core", "system", "hardening", "autoload-agent"):
        assert mid in MINIMAL.on, mid


def test_ce_que_minimal_exclut_reste_eteint():
    for mid in ("waf", "waf-ng", "haproxy", "metrics", "webos", "kiosk", "isp", "wireguard", "toolbox-tor", "mail", "nextcloud", "gitea"):
        assert mid not in MINIMAL.on, mid


def test_le_profil_porte_un_nom_et_un_libelle():
    assert MINIMAL.name == "minimal" and "inimal" in MINIMAL.label
