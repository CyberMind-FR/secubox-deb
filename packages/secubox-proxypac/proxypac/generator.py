# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.generator — compose + atomic fail-safe PAC write."""
import logging
import os
from pathlib import Path

from .catalog import read_services, service_rules
from .pac_template import render
from .rules import Rule, compose, parse_rules_dir

_log = logging.getLogger("secubox.proxypac")
DEFAULT_OUT = Path("/var/lib/secubox/proxypac/proxy.pac")


def generate(rules_dir, services, toolbox_directive=None):
    overrides = parse_rules_dir(rules_dir)
    svc_rules = service_rules(services)
    toolbox = Rule("*", toolbox_directive, "toolbox") if toolbox_directive else None
    return render(compose(overrides, svc_rules, toolbox))


def write_atomic(pac_str, out=DEFAULT_OUT):
    """Validate then atomically swap. Invalid input raises ValueError, last-good kept."""
    out = Path(out)
    if "function FindProxyForURL" not in pac_str or 'return "DIRECT"' not in pac_str:
        raise ValueError("refusing to write PAC without FindProxyForURL/terminal DIRECT")
    out.parent.mkdir(parents=True, exist_ok=True)
    shadow = out.with_suffix(".shadow")
    shadow.write_text(pac_str)
    os.replace(shadow, out)


def run_once(rules_dir="/etc/secubox/proxypac/rules.d",
             sock="/run/secubox/p2p.sock", out=DEFAULT_OUT, toolbox_directive=None):
    """Regenerate the PAC. Fail-safe: on any error the previous file is untouched."""
    try:
        pac = generate(rules_dir, read_services(sock), toolbox_directive)
        write_atomic(pac, out)
        return True
    except Exception as exc:  # noqa: BLE001
        _log.warning("proxypac regen failed, keeping last-good: %s", exc)
        return False
