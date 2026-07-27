# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from pydantic import ValidationError
from annuaire.model import MetricSnapshot

DID = "did:plc:" + "a" * 32


def test_snapshot_shape_and_extra_forbid():
    s = MetricSnapshot(node_did=DID, hostname="gk2", ts="2026-07-27T10:00:00Z",
                       cpu_pct=12.5, mem_pct=40.0, disk_pct=55.0, load1=0.7,
                       uptime_s=3600, modules_up=30, modules_down=["secubox-x"],
                       counters={"bans": 3, "assist_sessions": 0, "soc_alerts": 1},
                       issued_by=DID)
    assert s.node_did == DID and s.counters["bans"] == 3
    with pytest.raises(ValidationError):
        MetricSnapshot(node_did=DID, hostname="g", ts="t", cpu_pct=1, mem_pct=1,
                       disk_pct=1, load1=1, uptime_s=1, modules_up=1,
                       modules_down=[], counters={}, issued_by=DID, sneaky=True)


def test_modules_down_capped_at_20():
    s = MetricSnapshot(node_did=DID, hostname="g", ts="t", cpu_pct=1, mem_pct=1,
                       disk_pct=1, load1=1, uptime_s=1, modules_up=1,
                       modules_down=[f"m{i}" for i in range(40)], counters={},
                       issued_by=DID)
    assert len(s.modules_down) == 20


def test_counters_defaults():
    """Ensure counters dict gets default keys bans/assist_sessions/soc_alerts as 0."""
    s = MetricSnapshot(node_did=DID, hostname="g", ts="t", cpu_pct=1, mem_pct=1,
                       disk_pct=1, load1=1, uptime_s=1, modules_up=1,
                       modules_down=[], counters={}, issued_by=DID)
    assert "bans" in s.counters
    assert "assist_sessions" in s.counters
    assert "soc_alerts" in s.counters
    assert s.counters["bans"] == 0
    assert s.counters["assist_sessions"] == 0
    assert s.counters["soc_alerts"] == 0


def test_signer_pub_field_exists():
    """Ensure signer_pub field is present and optional."""
    s = MetricSnapshot(node_did=DID, hostname="g", ts="t", cpu_pct=1, mem_pct=1,
                       disk_pct=1, load1=1, uptime_s=1, modules_up=1,
                       modules_down=[], counters={}, issued_by=DID)
    assert hasattr(s, "signer_pub")
    assert s.signer_pub is None

    # Test with signer_pub value
    s2 = MetricSnapshot(node_did=DID, hostname="g", ts="t", cpu_pct=1, mem_pct=1,
                        disk_pct=1, load1=1, uptime_s=1, modules_up=1,
                        modules_down=[], counters={}, issued_by=DID,
                        signer_pub="abc123def456")
    assert s2.signer_pub == "abc123def456"
