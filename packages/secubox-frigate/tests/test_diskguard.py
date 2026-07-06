# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import subprocess, sys, os
GUARD = os.path.join(os.path.dirname(__file__), "..", "sbin", "secubox-frigate-diskguard")

def test_guard_fires_over_threshold(tmp_path):
    # DF override: guard reads SECUBOX_FRIGATE_DF_PCT for testability
    env = {**os.environ, "SECUBOX_FRIGATE_DF_PCT": "95", "SECUBOX_FRIGATE_DISK_LIMIT": "90"}
    r = subprocess.run(["bash", GUARD], capture_output=True, text=True, env=env)
    assert r.returncode == 2, "guard must exit 2 when over the limit"
    assert "disk pressure" in (r.stdout + r.stderr).lower()

def test_guard_ok_below_limit():
    env = {**os.environ, "SECUBOX_FRIGATE_DF_PCT": "40", "SECUBOX_FRIGATE_DISK_LIMIT": "90"}
    r = subprocess.run(["bash", GUARD], capture_output=True, text=True, env=env)
    assert r.returncode == 0

def test_guard_survives_missing_data_dir(tmp_path):
    # Regression test: DATA_DIR missing/unmounted (normal pre-provisioning
    # state right after package install) must NOT abort the guard under
    # set -euo pipefail — it must report "nothing to guard yet" and exit 0.
    missing_dir = str(tmp_path / "frigate-nonexistent-821")
    env = {**os.environ, "SECUBOX_FRIGATE_DATA": missing_dir}
    env.pop("SECUBOX_FRIGATE_DF_PCT", None)
    r = subprocess.run(["bash", GUARD], capture_output=True, text=True, env=env)
    assert r.returncode == 0, "guard must not fail when the data dir is absent"
    assert "unavailable" in (r.stdout + r.stderr).lower()
