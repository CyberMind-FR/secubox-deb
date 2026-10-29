# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3258 — un seul chemin pour piloter une unité depuis Python : secubox_core.unites.piloter.

L'ancien `secubox_core.system.service_control` passait le nom tel quel à systemctl (ni motif, ni « -- », ni unité
protégée, ni audit). Sans appelant dans le dépôt, il est retiré : personne ne peut plus le réutiliser par mégarde."""
import secubox_core
from secubox_core import system, unites


def test_l_ancien_service_control_sans_garde_est_retire():
    assert not hasattr(system, "service_control")
    assert not hasattr(secubox_core, "service_control")
    assert "service_control" not in secubox_core.__all__


def test_le_controle_partage_reste_disponible():
    assert callable(unites.piloter)
    assert unites.MOTIF_UNITE.fullmatch("secubox-dpi.service")
    assert not unites.MOTIF_UNITE.fullmatch("--now")


# ---------- tour 3 : une erreur système est auditée et rendue proprement ----------
# _systemctl n'attrapait que CalledProcessError et TimeoutExpired : une OSError (systemctl absent, fork impossible)
# remontait en 500 SANS ligne d'audit.
import json  # noqa: E402

import pytest  # noqa: E402
from fastapi import HTTPException  # noqa: E402


@pytest.mark.parametrize("erreur", [FileNotFoundError(2, "No such file or directory: 'systemctl'"),
                                    BlockingIOError(11, "Resource temporarily unavailable"), PermissionError(13, "x")])
def test_une_erreur_systeme_est_auditee_et_rendue_proprement(monkeypatch, tmp_path, erreur):
    journal = tmp_path / "audit.log"
    monkeypatch.setattr(unites, "AUDIT_LOG", journal)

    def run(*a, **k):
        raise erreur

    monkeypatch.setattr(unites.subprocess, "run", run)
    try:
        unites.piloter("system", "admin", "restart", "secubox-dpi")
        rendu = None
    except Exception as exc:  # noqa: BLE001 — on veut VOIR ce qui remonte, pas seulement le bon type
        rendu = exc
    assert isinstance(rendu, HTTPException), f"erreur brute remontée : {rendu!r}"
    assert rendu.status_code == 503 and "systemctl" in rendu.detail
    assert journal.exists(), "aucune ligne d'audit"
    lignes = [json.loads(x) for x in journal.read_text(encoding="utf-8").splitlines()]
    assert len(lignes) == 1
    assert lignes[0]["resultat"] == "echec" and lignes[0]["code"] == 503
    assert lignes[0]["unite"] == "secubox-dpi.service" and type(erreur).__name__ in lignes[0]["motif"]
