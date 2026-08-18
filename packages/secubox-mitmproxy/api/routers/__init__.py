# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox Mitmproxy WAF API Routers"""
from .status import router as status_router
from .settings import router as settings_router
from .alerts import router as alerts_router
from .haproxy import router as haproxy_router
from .waf import router as waf_router

__all__ = ["status_router", "settings_router", "alerts_router", "haproxy_router", "waf_router"]
