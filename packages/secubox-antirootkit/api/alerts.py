# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit alerting + IOC matching

Pure/injectable building blocks:
- ioc_match: exact-IP IOC lookup (v1; domain/asn matching is out of scope)
- build_alert: assemble an alert dict from a suspicious ExecEvent
- emit: fan out an alert to SOC/mail/mesh sinks, resiliently

Sinks are injected callables (soc_post, mailer, mesh) — this module never
touches the network or sends mail itself, and each sink call is isolated
so one failing sink never blocks the others.
"""


def ioc_match(dest_ip: str, ioc: dict) -> bool:
    """Return True if dest_ip is in ioc.get("ips", [])."""
    return dest_ip in (ioc or {}).get("ips", [])


def build_alert(ev, score: int, reasons: list, dest: str | None = None, ioc: dict = None) -> dict:
    """Build an alert dict from a suspicious ExecEvent.

    ioc is the (optional) loaded IOC dict, e.g. antirootkit.toml [ioc].
    The "ioc" key is True only when a dest is given AND it matches ioc["ips"].
    """
    return {
        "exe": ev.exe,
        "pid": ev.pid,
        "score": score,
        "reasons": reasons,
        "dest": dest,
        "ioc": ioc_match(dest, ioc or {}) if dest else False,
    }


def emit(alert: dict, soc_post, mailer, mesh) -> None:
    """Fan an alert out to the SOC, mail and mesh sinks.

    Each sink is called in its own try/except: a sink raising is logged
    away and never propagates, so it can never prevent the remaining
    sinks from being called nor raise out of emit().
    """
    for sink in (soc_post, mailer, mesh):
        try:
            sink(alert)
        except Exception:
            pass
