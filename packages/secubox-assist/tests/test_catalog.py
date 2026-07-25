# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from assist import catalog


def test_status_all_is_readonly_argv():
    argv = catalog.resolve("status.all", None)
    assert isinstance(argv, list) and argv  # never a shell string


def test_service_restart_allowed_module():
    argv = catalog.resolve("service.restart", "secubox-dns")
    assert "secubox-dns" in argv
    assert not any(";" in a or "&&" in a or "|" in a for a in argv)


def test_unknown_action_rejected():
    with pytest.raises(catalog.CatalogError):
        catalog.resolve("rm.rf", "/")


def test_module_outside_allowlist_rejected():
    with pytest.raises(catalog.CatalogError):
        catalog.resolve("service.restart", "sshd")


def test_secrets_scope_rejected():
    with pytest.raises(catalog.CatalogError):
        catalog.resolve("config.reload", "secrets")
    with pytest.raises(catalog.CatalogError):
        catalog.resolve("config.reload", "auth")


def test_shell_metachars_in_arg_rejected():
    with pytest.raises(catalog.CatalogError):
        catalog.resolve("logs.tail", "secubox-dns; rm -rf /")
