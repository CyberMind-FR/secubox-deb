# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3105 — composition des profils isp et full.

Arbitrage du 2026-10-24 : gk1 flashée en isp portait 15 modules installés qui ne tournaient pas, et socialrelay (retiré).
isp = socle SecuBox (lite : protections, haproxy, waf-ng) + opérateur + metablogizer ; full = isp + suite sbxos + plugins du
Hall ; matrix, gitea, mesh : App Store seulement."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]


def _depends(paquet: str) -> set:
    # Les commentaires en colonne 0 (« # … », permis dans debian/control) ne ferment pas le champ : avant #3259, le
    # commentaire DPI de #3248 coupait Depends d'isp à « secubox-lite » et ce test échouait.
    texte = (RACINE / "packages" / paquet / "debian" / "control").read_text()
    bloc = [ligne for ligne in texte.split(f"Package: {paquet}", 1)[1].splitlines() if not ligne.startswith("#")]
    dep = re.search(r"^Depends:(.*?)(?=^\S|\Z)", "\n".join(bloc), re.M | re.S).group(1)
    return {re.sub(r"\s*\(.*", "", d).strip() for d in dep.split(",") if d.strip() and "${" not in d}


ISP = {"secubox-lite", "secubox-modem", "secubox-cdn", "secubox-saas-relay", "secubox-p2p", "secubox-federation",
       "secubox-metrics", "secubox-mail", "secubox-metablogizer",
       # #3218 : DPI et nDPId quittent lite pour isp ; #3259 : la toolbox et l'intercepteur aussi
       "secubox-dpi", "secubox-ndpid-engine",
       "secubox-toolbox", "secubox-toolbox-ng", "secubox-interceptor"}
PLUGINS_DU_HALL = {"secubox-billets", "secubox-metanews", "secubox-messagerie", "secubox-nextcloud", "secubox-bbs"}
APP_STORE_SEULEMENT = {"secubox-matrix", "secubox-gitea", "secubox-mesh"}
RETIRES = {"secubox-socialrelay", "secubox-reality", "secubox-ai-insights", "secubox-zkp"}


def test_isp_est_le_socle_operateur_et_metablogizer():
    assert _depends("secubox-isp") == ISP


def test_full_porte_les_plugins_du_hall():
    full = _depends("secubox-full")
    assert "secubox-isp" in full
    assert PLUGINS_DU_HALL <= full


def test_aucun_profil_ne_ramene_un_module_retire_ou_reserve_a_l_app_store():
    for p in ("secubox-lite", "secubox-isp", "secubox-full"):
        assert not _depends(p) & (RETIRES | APP_STORE_SEULEMENT), p
