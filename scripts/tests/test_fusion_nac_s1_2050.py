# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 S1 : mac-guard, device-intel et iot-guard (déjà des redirections vers nac) deviennent des paquets
transitoires ; nac porte les redirections et plus rien ne les exige."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
SHIMS = ("mac-guard", "device-intel", "iot-guard")
PAQ = RACINE / "packages"


def _control(p):
    return (PAQ / p / "debian/control").read_text()


def test_les_trois_paquets_sont_retires_du_depot():
    for s in SHIMS:
        assert not (PAQ / f"secubox-{s}").exists(), f"secubox-{s} : transitoire à retirer (publié dans alpha.10)"


def test_nac_porte_les_redirections_et_casse_les_anciens():
    conf = (PAQ / "secubox-nac/nginx/nac-legacy.conf").read_text()
    for s in SHIMS:
        assert f"location /{s}/" in conf and f"location /api/v1/{s}/" in conf
    c = _control("secubox-nac")
    for s in SHIMS:
        assert re.search(rf"Breaks:.*secubox-{s} \(<<", c) or re.search(rf"secubox-{s} \(<<", c), s
    rules = (PAQ / "secubox-nac/debian/rules").read_text()
    assert "nac-legacy.conf" in rules and "secubox-routes.d" in rules


def test_plus_aucun_paquet_ne_depend_des_anciens():
    motif = re.compile(r"secubox-(mac-guard|device-intel|iot-guard)\b")
    liens = ("Depends", "Pre-Depends", "Recommends", "Suggests", "Enhances")
    for ctrl in PAQ.glob("*/debian/control"):
        nom = ctrl.parts[-3].removeprefix("secubox-")
        if nom in SHIMS or "/debian/secubox-" in str(ctrl):
            continue
        champ = None
        for ligne in ctrl.read_text().splitlines():
            if ligne and not ligne[0].isspace():
                champ = ligne.split(":", 1)[0]
            if champ in liens and motif.search(ligne):
                raise AssertionError(f"{ctrl} : {ligne.strip()}")


def test_arbre_les_met_hors_arbre():
    arbre = (PAQ / "secubox-meta/arbre.yaml").read_text()
    avant, _, apres = arbre.partition("# ═══ RACINES")
    for s in SHIMS:
        assert f"secubox-{s} " in avant or f"secubox-{s}\n" in avant, f"{s} hors-arbre"
        assert f"  - secubox-{s}" not in apres, f"{s} encore dans l'arbre"


