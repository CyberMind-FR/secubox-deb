# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import subprocess, sys, os
GUARD = os.path.join(os.path.dirname(__file__), "..", "sbin", "secubox-frigate-diskguard")

def test_guard_fires_below_threshold(tmp_path):
    # DF override: guard reads SECUBOX_FRIGATE_DF_PCT for testability
    env = {**os.environ, "SECUBOX_FRIGATE_DF_PCT": "95", "SECUBOX_FRIGATE_DISK_LIMIT": "90"}
    r = subprocess.run(["bash", GUARD], capture_output=True, text=True, env=env)
    assert r.returncode == 2, "guard must exit 2 when over the limit"
    assert "disk pressure" in (r.stdout + r.stderr).lower()

def test_guard_ok_below_limit():
    env = {**os.environ, "SECUBOX_FRIGATE_DF_PCT": "40", "SECUBOX_FRIGATE_DISK_LIMIT": "90"}
    r = subprocess.run(["bash", GUARD], capture_output=True, text=True, env=env)
    assert r.returncode == 0
