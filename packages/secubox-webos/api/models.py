# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — modèles Pydantic du registre normalisé (P1)."""
from typing import List, Optional, Literal
from pydantic import BaseModel


class ServiceUrls(BaseModel):
    lan: Optional[str] = None
    wan: Optional[str] = None
    path: str


class ServiceRouting(BaseModel):
    mode: Literal["localhost", "lan", "wan", "unknown"] = "unknown"
    available: bool = True


class ServiceHealth(BaseModel):
    state: Literal["online", "degraded", "offline", "unknown"] = "unknown"
    latency_ms: Optional[float] = None
    stale: bool = False
    checked_at: Optional[str] = None


class ServiceAuth(BaseModel):
    mode: Literal["none", "jwt", "cookie", "zkp", "unknown"] = "unknown"


class Service(BaseModel):
    id: str
    name: str
    description: str = ""
    category: str
    icon: str = ""
    urls: ServiceUrls
    routing: ServiceRouting
    health: ServiceHealth
    auth: ServiceAuth
    capabilities: List[str] = []
    cardlet: Optional[dict] = None
    installed: bool = True
    active: bool = True
