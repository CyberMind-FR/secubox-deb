# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — normalize_services : composition du registre normalisé (P1)."""
import http.client
import json
import socket
from pathlib import Path
from typing import List, Optional
from api.models import Service, ServiceUrls, ServiceRouting, ServiceHealth, ServiceAuth
from api.idmap import resolve

HEALTH_MAP = {"ok": "online", "warn": "degraded", "error": "offline"}


def load_menu_cache(path: str = "/var/cache/secubox/menu.json") -> dict:
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return {"categories": []}


def load_exposure_cache(path: str = "/var/cache/secubox/webos/exposure-health.json") -> dict:
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return {}


def normalize_services(menu: dict, health: dict, exposure: Optional[dict] = None,
                       sockets: frozenset = frozenset()) -> List[Service]:
    exposure = exposure or {}
    out: List[Service] = []
    for cat in menu.get("categories", []):
        for item in cat.get("items", []):
            _raw = (health.get(item["id"]) or {}).get("status")
            state = HEALTH_MAP.get(_raw, "unknown")
            # Vérité opérationnelle SecuBox : ~110 modules sont servis IN-PROCESS
            # par l'agrégateur, donc leur unité systemd est inactive/dead alors que
            # le module RÉPOND via sa socket /run/secubox/<id>.sock. La socket est
            # le vrai signal de joignabilité : présente ⇒ online, SAUF si l'unité a
            # réellement échoué (`failed` = alarme, jamais masquée par une socket
            # périmée).
            if item["id"] in sockets and _raw != "error":
                state = "online"
            domain, same_origin = resolve(item)
            rec = exposure.get(domain) if domain else None
            latency = rec.get("latency_ms") if rec else None
            reach = rec.get("reach") if rec else "unknown"
            lan = f"https://{domain}" if domain else None
            wan = lan if reach == "wan" else None
            out.append(Service(
                id=item["id"], name=item.get("name", item["id"]),
                description=item.get("description", ""),
                category=item.get("category", "root"), icon=item.get("icon", ""),
                urls=ServiceUrls(lan=lan, wan=wan, path=item.get("path", "/")),
                routing=ServiceRouting(
                    mode=reach if reach in ("localhost", "lan", "wan") else "unknown",
                    available=(state != "offline")),
                health=ServiceHealth(state=state, latency_ms=latency),
                auth=ServiceAuth(),
                installed=bool(item.get("installed", True)),
                active=bool(item.get("active", True)),
            ))
    return out


class _ConnexionUnix(http.client.HTTPConnection):
    """HTTP sur un socket unix (stdlib : le Hall n'a pas besoin de httpx ici)."""

    def __init__(self, chemin: str, timeout: float = 3.0):
        super().__init__("localhost", timeout=timeout)
        self._chemin = chemin

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._chemin)


def reveille_hub(socket_agregateur: str = "/run/secubox/aggregator.sock") -> bool:
    """Réveille le rafraîchisseur du hub, qui réécrit menu.json.

    Le hub servi par l'agrégateur ne reçoit ni startup ni lifespan : son
    rafraîchissement ne démarre qu'à la première requête de statut (public).
    Sans cet appel, un menu.json supprimé par un postinst n'est jamais réécrit.
    """
    try:
        c = _ConnexionUnix(socket_agregateur, timeout=3.0)
        try:
            c.request("GET", "/api/v1/hub/status")
            c.getresponse().read()
        finally:
            c.close()
        return True
    except Exception:
        return False
