# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — chemins snapshot 4R / audit partagés par les actionneurs
CyberMind — https://cybermind.fr

`secubox-wakectl` (wake un module) et le sleeper (`run_once`, endort les
modules idle) délèguent tous deux à `apply.apply_plan` — comme
`secubox-profilectl apply/rollback`. En production (root == DEFAULT_ROOT) les
trois DOIVENT écrire dans la MÊME chaîne 4R (SNAP_DIR) et le MÊME journal
d'audit (AUDIT_LOG) : un wake ou un sleep qui écrirait ailleurs romprait la
cohérence rollback/audit que CSPN exige.

Le confinement sous un `--root` non-défaut n'est QU'une isolation de test —
garder les tests non mockés (ex. test_wake_starts_a_down_on_demand_module,
test_run_once_stops_only_idle_sleepable) hors de la vraie chaîne 4R du
système qui exécute la suite. cli.py (`_cmd_apply`/`_cmd_rollback`) ne fait
PAS varier ces chemins selon --root ; un futur déploiement multi-root réel
(ex. cellule-in-a-box #843, un --root par tenant) romprait cette symétrie —
il faudra alors aligner cli.py de la même façon (suivi #896), pas dans cette
tâche.
"""
from __future__ import annotations

from pathlib import Path

from .audit import AUDIT_LOG
from .portal_routes import REMEMBER_FILE
from .snapshot import SNAP_DIR

DEFAULT_ROOT = Path("/etc/secubox")


def snap_root_for(root: Path) -> Path:
    return SNAP_DIR if root == DEFAULT_ROOT else root / "profiles" / "rollback"


def audit_path_for(root: Path) -> Path:
    return AUDIT_LOG if root == DEFAULT_ROOT else root / "audit.log"


def remember_path_for(root: Path) -> Path:
    return REMEMBER_FILE if root == DEFAULT_ROOT else root / "profiles" / "portal-routes.json"
