# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Un délai dépassé tue aussi les enfants (#3546)."""
import os
import subprocess
import time

import pytest

import secubox_core.config as _cfg  # noqa: F401
from api import main as M


def test_le_delai_tue_tout_le_groupe(tmp_path):
    temoin = tmp_path / "pid"
    with pytest.raises(subprocess.TimeoutExpired):
        M._lancer(["bash", "-c", f"sleep 60 & echo $! > {temoin}; wait"], 0.5)
    pid = int(temoin.read_text())
    time.sleep(0.3)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
