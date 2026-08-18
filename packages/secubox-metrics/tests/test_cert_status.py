# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Unit tests for CertStatusAggregator."""
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_status import CertStatusAggregator


CFG_BASE = {
    "enabled": True,
    "warn_days": 30,
    "critical_days": 7,
}


def _make_cert(host: str, days_left: int, out_dir: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.now(timezone.utc)
    # For already-expired certs (days_left < 0), not_valid_before must be
    # earlier than not_valid_after, so push it back far enough.
    not_before_offset = max(1, abs(days_left) + 1) if days_left < 0 else 1
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=not_before_offset))
        .not_valid_after(now + timedelta(days=days_left))
        .sign(key, hashes.SHA256())
    )
    host_dir = out_dir / host
    host_dir.mkdir(parents=True, exist_ok=True)
    pem_path = host_dir / "cert.pem"
    pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return pem_path


@pytest.fixture
def live_dir(tmp_path):
    _make_cert("good.example.com",  60, tmp_path)
    _make_cert("soon.example.com",  14, tmp_path)
    _make_cert("crit.example.com",   3, tmp_path)
    _make_cert("dead.example.com",  -2, tmp_path)
    return tmp_path


def test_summary_counts_by_state(live_dir):
    agg = CertStatusAggregator(dict(CFG_BASE, letsencrypt_live_dir=str(live_dir)))
    out = asyncio.run(agg.refresh_once())
    s = out["summary"]
    assert s["total"] == 4
    assert s["valid"] == 1
    assert s["expiring_soon"] == 1
    assert s["expiring_critical"] == 1
    assert s["expired"] == 1


def test_next_renewal_is_soonest_non_expired(live_dir):
    agg = CertStatusAggregator(dict(CFG_BASE, letsencrypt_live_dir=str(live_dir)))
    out = asyncio.run(agg.refresh_once())
    # Soonest non-expired is crit.example.com at 3d
    assert out["next_renewal"]["host"] == "crit.example.com"
    assert out["next_renewal"]["days"] == 3


def test_missing_live_dir_disabled(tmp_path):
    agg = CertStatusAggregator(
        dict(CFG_BASE, letsencrypt_live_dir=str(tmp_path / "missing"))
    )
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is False


def test_corrupt_cert_doesnt_kill_scan(live_dir):
    bad_dir = live_dir / "bad.example.com"
    bad_dir.mkdir()
    (bad_dir / "cert.pem").write_bytes(b"not a real cert")
    agg = CertStatusAggregator(dict(CFG_BASE, letsencrypt_live_dir=str(live_dir)))
    out = asyncio.run(agg.refresh_once())
    # Still surfaces the other four
    assert out["summary"]["total"] == 4
