# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""TLS certificate provisioning for a published domain. *.gk2 subdomains reuse
the existing wildcard cert; custom domains get certbot HTTP-01. All actual work
is done by `secubox-publishctl cert`."""
from __future__ import annotations

from publish.routing import _sudo_publishctl

GK2_SUFFIX = ".gk2.secubox.in"


def is_wildcard_domain(domain: str) -> bool:
    return domain.endswith(GK2_SUFFIX)


def provision_cert(domain: str, runner=_sudo_publishctl) -> dict:
    res = runner("cert", domain)
    if res.get("ok"):
        return {"mode": res.get("detail", "issued"), "detail": res.get("detail", "")}
    return {"mode": "pending", "detail": res.get("detail", "cert failed")}
