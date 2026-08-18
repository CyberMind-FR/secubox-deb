# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Invariant central du design du mur mosaïque (#957 §3.1, #958) : la
capture d'une vignette est déclenchée par ÉVÉNEMENT (première inscription,
mise à jour, clic manuel) — JAMAIS par une boucle. Un timer qui balaierait
le parc réveillerait toutes les applis en permanence, exactement ce que ce
système existe pour éviter.

Ce test échoue si une unité systemd livrée dans ce paquet vient un jour
appeler le captureur (`streamlit-shotter`, `api/shots.py`, ou
`secubox_core.shotter.capture` directement) — que ce soit un
OnCalendar/OnUnitActiveSec neuf, ou un service oneshot déjà existant
(comme `secubox-streamlit-idle.service` ou `streamlit-audit.service`)
qu'on aurait étendu pour appeler le captureur en plus de son travail
actuel.

secubox-metablogizer a fait le choix inverse (timer de 2 minutes, #956) —
défendable pour des sites toujours actifs, mais explicitement PAS le choix
retenu ici : les applis Streamlit dorment, et c'est tout l'objet du
système (#958, issue originale).
"""
from pathlib import Path

PKG = Path(__file__).resolve().parents[2]

FORBIDDEN_TOKENS = ("streamlit-shotter", "shots.py", "shots.main", "shotter.capture")


def _unit_files():
    debian = PKG / "debian"
    return sorted(list(debian.glob("*.timer")) + list(debian.glob("*.service")))


def test_some_unit_files_exist_so_this_test_is_not_vacuous():
    assert _unit_files(), "no systemd unit found under debian/ — this test would check nothing"


def test_no_systemd_unit_invokes_the_shotter():
    offenders = {}
    for f in _unit_files():
        text = f.read_text()
        hits = [tok for tok in FORBIDDEN_TOKENS if tok in text]
        if hits:
            offenders[f.name] = hits
    assert offenders == {}, f"unit(s) referencing the capturer: {offenders}"


def test_the_existing_idle_and_audit_timers_stay_generic_oneshots():
    """Pins the two timers already shipped by this package to their known-
    safe ExecStart, so a future edit that folds capture logic into either
    "while we're at it" gets caught immediately rather than by the more
    generic token scan above having to guess every possible spelling.

    Note: "oneshot" (the systemd unit Type=) legitimately contains the
    substring "shot" — checked here with the same specific FORBIDDEN_TOKENS
    as the scan above, never a naive "shot" substring match, to avoid that
    false positive.
    """
    idle_service = (PKG / "debian" / "secubox-streamlit-idle.service").read_text()
    assert "streamlitctl app idle-check" in idle_service
    assert not any(tok in idle_service for tok in FORBIDDEN_TOKENS)

    audit_service = (PKG / "debian" / "streamlit-audit.service").read_text()
    assert "streamlitctl app audit" in audit_service
    assert not any(tok in audit_service for tok in FORBIDDEN_TOKENS)
