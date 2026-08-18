# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: SSL Status Tests
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "packages/secubox-metrics/api"))
from main import get_ssl_status


def test_ssl_status_ok():
    """Cert with 45 days remaining returns status ok."""
    now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    mock_cert = MagicMock()
    mock_cert.not_valid_after_utc = now + timedelta(days=45)

    with patch.object(Path, 'exists', return_value=True), \
         patch.object(Path, 'read_bytes', return_value=b'cert data'), \
         patch('main.x509.load_pem_x509_certificate', return_value=mock_cert), \
         patch('main.datetime') as mock_datetime:
        mock_datetime.now.return_value = now
        result = get_ssl_status("example.com")
        assert result["status"] == "ok"
        assert result["days_remaining"] == 45


def test_ssl_status_warn():
    """Cert with 5 days remaining returns status warn."""
    now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    mock_cert = MagicMock()
    mock_cert.not_valid_after_utc = now + timedelta(days=5)

    with patch.object(Path, 'exists', return_value=True), \
         patch.object(Path, 'read_bytes', return_value=b'cert data'), \
         patch('main.x509.load_pem_x509_certificate', return_value=mock_cert), \
         patch('main.datetime') as mock_datetime:
        mock_datetime.now.return_value = now
        result = get_ssl_status("example.com")
        assert result["status"] == "warn"
        assert result["days_remaining"] == 5


def test_ssl_status_error():
    """Cert with 2 days remaining returns status error."""
    now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    mock_cert = MagicMock()
    mock_cert.not_valid_after_utc = now + timedelta(days=2)

    with patch.object(Path, 'exists', return_value=True), \
         patch.object(Path, 'read_bytes', return_value=b'cert data'), \
         patch('main.x509.load_pem_x509_certificate', return_value=mock_cert), \
         patch('main.datetime') as mock_datetime:
        mock_datetime.now.return_value = now
        result = get_ssl_status("example.com")
        assert result["status"] == "error"
        assert result["days_remaining"] == 2


def test_ssl_status_expired():
    """Cert with -3 days (expired) returns status expired."""
    now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    mock_cert = MagicMock()
    mock_cert.not_valid_after_utc = now - timedelta(days=3)

    with patch.object(Path, 'exists', return_value=True), \
         patch.object(Path, 'read_bytes', return_value=b'cert data'), \
         patch('main.x509.load_pem_x509_certificate', return_value=mock_cert), \
         patch('main.datetime') as mock_datetime:
        mock_datetime.now.return_value = now
        result = get_ssl_status("example.com")
        assert result["status"] == "expired"
        assert result["days_remaining"] == -3


def test_ssl_status_not_found():
    """Missing cert file returns status unknown."""
    with patch.object(Path, 'exists', return_value=False):
        result = get_ssl_status("nonexistent.com")
        assert result["status"] == "unknown"
        assert result["days_remaining"] is None
