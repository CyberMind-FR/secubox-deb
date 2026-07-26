# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.catalog — the ONLY actions a center may run in a session.

Each action maps to a fixed argv (a scoped ctl or a read command). No entry
ever yields a shell string; every argument is validated against a strict
allow-list so a compromised center can never widen the surface. auth/secrets
scopes are unreachable (NON_DELEGATABLE parity).
"""
from __future__ import annotations

import re
from typing import List, Optional

NON_DELEGATABLE = {"auth", "secrets"}
_MODULE_RE = re.compile(r"^secubox-[a-z0-9][a-z0-9-]{1,40}$")
_SCOPE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,40}$")

# Allow-listed modules a center may restart/toggle/reload. Conservative on
# purpose; extend deliberately. (No secubox-auth, no secubox-core.)
MODULE_ALLOW = frozenset({
    "secubox-dns", "secubox-dpi", "secubox-crowdsec", "secubox-netdata",
    "secubox-wireguard", "secubox-qos", "secubox-vhost", "secubox-nextcloud",
    "secubox-mediaflow", "secubox-cdn", "secubox-nac", "secubox-netmodes",
})


class CatalogError(Exception):
    """Unknown action, disallowed target, or unsafe argument."""


def _safe(arg: str, pattern: re.Pattern) -> str:
    if arg is None or not pattern.match(arg):
        raise CatalogError(f"invalid argument: {arg!r}")
    return arg


def _module(arg: str) -> str:
    m = _safe(arg, _MODULE_RE)
    if m not in MODULE_ALLOW:
        raise CatalogError(f"module not allow-listed: {m}")
    return m


def _scope(arg: str) -> str:
    s = _safe(arg, _SCOPE_RE)
    if s in NON_DELEGATABLE:
        raise CatalogError(f"scope not delegatable: {s}")
    return s


def resolve(action: str, arg: Optional[str]) -> List[str]:
    """Return the exact argv for a catalog action, or raise CatalogError."""
    if action == "status.all":
        return ["/usr/sbin/secubox-assistctl", "diag", "status"]
    if action == "diag.collect":
        return ["/usr/sbin/secubox-assistctl", "diag", "bundle"]
    if action == "logs.tail":
        unit = _module(arg)  # only secubox-* units, allow-listed
        return ["journalctl", "-u", unit, "-n", "200", "--no-pager"]
    if action == "service.restart":
        return ["sudo", "-n", "/usr/sbin/secubox-assistctl", "service", "restart", _module(arg)]
    if action == "service.toggle":
        # arg form "secubox-dns:on" | "secubox-dns:off"
        mod, _, state = (arg or "").partition(":")
        if state not in ("on", "off"):
            raise CatalogError("toggle needs <module>:on|off")
        return ["sudo", "-n", "/usr/sbin/secubox-assistctl", "service", "toggle", _module(mod), state]
    if action == "config.reload":
        return ["sudo", "-n", "/usr/sbin/secubox-assistctl", "config", "reload", _scope(arg)]
    if action == "config.rollback":
        return ["sudo", "-n", "/usr/sbin/secubox-assistctl", "config", "rollback", _scope(arg)]
    raise CatalogError(f"unknown action: {action}")


CATALOG = {
    "status.all": {"kind": "diag", "argv": ["/usr/sbin/secubox-assistctl", "diag", "status"], "needs": None},
    "diag.collect": {"kind": "diag", "argv": ["/usr/sbin/secubox-assistctl", "diag", "bundle"], "needs": None},
    "logs.tail": {"kind": "read", "argv": ["journalctl", "-u", "<module>", "-n", "200", "--no-pager"], "needs": "module"},
    "service.restart": {"kind": "ctl", "argv": ["sudo", "-n", "/usr/sbin/secubox-assistctl", "service", "restart", "<module>"], "needs": "module"},
    "service.toggle": {"kind": "ctl", "argv": ["sudo", "-n", "/usr/sbin/secubox-assistctl", "service", "toggle", "<module>", "<state>"], "needs": "module"},
    "config.reload": {"kind": "ctl", "argv": ["sudo", "-n", "/usr/sbin/secubox-assistctl", "config", "reload", "<scope>"], "needs": "scope"},
    "config.rollback": {"kind": "ctl", "argv": ["sudo", "-n", "/usr/sbin/secubox-assistctl", "config", "rollback", "<scope>"], "needs": "scope"},
}
