# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3259 — lite et minimal sans toolbox (cabine numérique Gondwana) ni moteur d'interception.

Décision du propriétaire du 2026-10-29. Comme pour le DPI (#3218) : isp et full DÉPENDENT de lite, donc pas de Conflicts
dans lite ; la toolbox passe dans isp, dont full hérite. ad-guard ne la recommande plus (il ne lit sa base qu'en option),
sinon apt la ramenait dans lite par les recommandations."""
import re
import tomllib
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
TOOLBOX = {"secubox-toolbox", "secubox-toolbox-ng", "secubox-interceptor"}
UNITES_TOOLBOX = {"toolbox", "toolbox-wg-restore", "authwatch", "toolbox-egress-proxy", "toolbox-mitm", "interceptor"}


def _relations(paquet: str, champ: str) -> set:
    """Paquets d'un champ de relation ; les commentaires (« # » en colonne 0, permis dans debian/control) n'arrêtent pas
    le champ : seuls un autre champ ou une ligne vide le ferment. Une alternative « a | b » compte pour a."""
    texte = (RACINE / "packages" / paquet / "debian" / "control").read_text()
    bloc = texte.split(f"Package: {paquet}", 1)[1].splitlines()
    valeurs, dedans = [], False
    for ligne in bloc:
        if ligne.startswith("#"):
            continue
        if re.match(r"^[A-Za-z][A-Za-z-]*:", ligne):
            dedans = ligne.startswith(f"{champ}:")
            if dedans:
                valeurs.append(ligne.split(":", 1)[1])
            continue
        if not ligne.strip():
            dedans = False
        elif dedans:
            valeurs.append(ligne)
    return {re.split(r"[\s(|]", d.strip())[0] for d in ",".join(valeurs).split(",") if d.strip() and "${" not in d}


def _profil(nom: str) -> dict:
    return tomllib.loads((RACINE / "packages" / "secubox-profiles" / "profiles" / f"{nom}.toml").read_text())


def test_lite_ne_tire_plus_la_toolbox():
    assert not (_relations("secubox-lite", "Depends") | _relations("secubox-lite", "Recommends")) & TOOLBOX


def test_isp_reprend_la_toolbox_pour_isp_et_full():
    assert TOOLBOX <= _relations("secubox-isp", "Depends")


def test_ad_guard_ne_recommande_plus_la_toolbox():
    assert "secubox-toolbox" not in _relations("secubox-ad-guard", "Depends") | _relations("secubox-ad-guard", "Recommends")


def test_profils_lite_et_minimal_sans_unites_toolbox():
    for nom in ("lite", "minimal"):
        p = _profil(nom)
        assert not set(p["on"]) & UNITES_TOOLBOX, nom
        assert "toolbox" in p["menu_off"], nom


def test_minimal_garde_ses_conflits():
    assert {"secubox-toolbox", "secubox-toolbox-ng"} <= _relations("secubox-minimal", "Conflicts")
