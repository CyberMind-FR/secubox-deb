# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import pytest
from api.federation import HealthStore


def test_debounce_up_down_up():
    """Test debouncing: failures are buffered until threshold, recovery resets counter."""
    store = HealthStore(fail_threshold=3)

    # Service starts up
    store.record("s", True)
    assert store.status_of("s")["status"] == "up"

    # First failure: status unchanged (debounce, 1 < 3)
    store.record("s", False)
    assert store.status_of("s")["status"] == "up"

    # Second failure: status unchanged (debounce, 2 < 3)
    store.record("s", False)
    assert store.status_of("s")["status"] == "up"

    # Third failure: status changes to "down" (threshold reached)
    store.record("s", False)
    assert store.status_of("s")["status"] == "down"

    # Recovery: status goes back to "up", failures reset, latency recorded
    store.record("s", True, 12.0)
    status = store.status_of("s")
    assert status["status"] == "up"
    assert status["consecutive_failures"] == 0
    assert status["latency_ms"] == 12.0


def test_unknown_service():
    """Test that an unknown service returns 'unknown' status."""
    store = HealthStore()
    status = store.status_of("never")
    assert status["status"] == "unknown"


def test_save_load_roundtrip_0600(tmp_path):
    """Test persistence: save to file with 0600 perms, load into new store, verify snapshot."""
    store = HealthStore()

    # Record some services
    store.record("svc1", True, 5.0)
    store.record("svc2", False)
    store.record("svc2", False)

    snapshot_before = store.snapshot()

    # Save to file
    db_file = tmp_path / "h.json"
    store.save(db_file)

    # Verify file permissions are 0600
    mode = db_file.stat().st_mode & 0o777
    assert mode == 0o600, f"Expected 0600, got {oct(mode)}"

    # Load into new store
    store2 = HealthStore()
    store2.load(db_file)
    snapshot_after = store2.snapshot()

    # Verify snapshots match
    assert snapshot_before == snapshot_after
