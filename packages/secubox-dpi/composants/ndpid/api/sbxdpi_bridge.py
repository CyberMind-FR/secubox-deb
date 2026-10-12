# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Pont de l'API ndpid vers la surface VIVANTE de sbxdpi (nDPId → nDPIsrvd → sbxdpi → /run/secubox/dpi-live.sock).

Le client « ZMQ / JSON-RPC » historique de ce module ne parle pas au vrai nDPIsrvd (flux JSON encadré sur socket Unix) : il ne voyait jamais le moteur,
et la page restait vide. sbxdpi, lui, consomme ce flux et publie des agrégats ; ce pont les met au format que la page attend.

Honnêteté des données : ce sont des CUMULS depuis le démarrage de sbxdpi, pas des événements datés. Les « risques » sont donc des compteurs par type
(source et destination inconnues : « — »), triés par gravité, sans le bruit de gravité basse ; les empreintes sont du JA4 seulement.
"""
from __future__ import annotations

import http.client
import json
import socket
import re
import time
from datetime import datetime, timezone
from typing import Callable, List, Optional

SOCKET = "/run/secubox/dpi-live.sock"
SOURCE = "nDPId → sbxdpi"
_GRAVITE = {"High": 80, "Medium": 50, "Low": 20}
# Risques de gravité « Medium » qui sont du BRUIT sur un réseau réel (mesuré sur gk2 : 12 M de « Known Proto on Non Std Port »). Ils noient les vrais signaux.
BRUIT = {"Known Proto on Non Std Port", "TCP Connection Issues", "Missing SNI TLS Extn", "Error Code", "Unidirectional Traffic"}


class _Unix(http.client.HTTPConnection):
    def __init__(self, chemin: str, timeout: float = 3.0):
        super().__init__("sbxdpi", timeout=timeout)
        self._chemin = chemin

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._chemin)


def lire_socket(chemin: str, socket_path: str = SOCKET):
    """GET /api/v1/dpi/<chemin> sur le socket de sbxdpi ; None si injoignable ou illisible."""
    try:
        c = _Unix(socket_path)
        c.request("GET", "/api/v1/dpi/" + chemin)
        r = c.getresponse()
        data = json.loads(r.read()) if r.status == 200 else None
        c.close()
        return data
    except (OSError, ValueError, http.client.HTTPException):
        return None


_JA4 = re.compile(r"^t(\d\d|s3|s2|00)([di])(\d\d)(\d\d)([0-9a-z]{2})_[0-9a-f]{12}_[0-9a-f]{12}$")
_VERSIONS = {"13": "TLS 1.3", "12": "TLS 1.2", "11": "TLS 1.1", "10": "TLS 1.0", "s3": "SSL 3", "s2": "SSL 2"}


def profil_ja4(ja4: str) -> dict:
    """Décode la FORME d'un JA4 (version, SNI, nombre de suites et d'extensions, ALPN)
    et en tire une famille PROBABLE : « nav » (poignée de main de navigateur),
    « lib » (bibliothèque ou outil minimal), « aut » (indéterminé). C'est une
    déduction de forme, pas une identité d'application."""
    m = _JA4.match(ja4 or "")
    if not m:
        return {}
    ver, sni, suites, exts, alpn = m.group(1), m.group(2) == "d", int(m.group(3)), int(m.group(4)), m.group(5)
    texte = " · ".join([_VERSIONS.get(ver, "TLS ?"), "avec SNI" if sni else "sans SNI", f"{suites} suites", f"{exts} extensions",
                        "sans ALPN" if alpn == "00" else f"ALPN {alpn}"])
    if ver == "13" and sni and alpn in ("h2", "h3") and suites >= 8 and exts >= 12:
        fam = "nav"
    elif sni and (alpn in ("00", "h1") or suites < 8 or exts < 8):
        fam = "lib"
    else:
        fam = "aut"
    return {"profil": texte, "famille_deduite": fam}


class SbxdpiBridge:
    def __init__(self, lire: Callable[[str], Optional[object]] = lire_socket, ttl: float = 5.0):
        self._lire = lire
        self._ttl = ttl
        self._cache: dict = {}

    def _get(self, chemin: str):
        now = time.monotonic()
        v = self._cache.get(chemin)
        if v and now < v[0]:
            return v[1]
        try:
            data = self._lire(chemin)
        except Exception:                                        # un socket qui échoue n'est jamais une erreur de l'API
            data = None
        self._cache[chemin] = (now + self._ttl, data)
        return data

    def _stats(self) -> dict:
        s = self._get("stats")
        return s if isinstance(s, dict) else {}

    def available(self) -> bool:
        s = self._stats()
        return bool(s.get("connected") and int(s.get("total_flows") or 0) > 0)

    def _risques_notables(self) -> List[dict]:
        return [r for r in (self._stats().get("risks") or []) if r.get("severity") in ("High", "Medium") and r.get("name") not in BRUIT]

    def status(self) -> dict:
        s = self._stats()
        notables = sum(int(r.get("count") or 0) for r in self._risques_notables())
        return {"daemon": {"running": bool(s.get("connected")), "socket_available": True, "source": SOURCE},
                "database": {"total_flows": int(s.get("total_flows") or 0), "total_fingerprints": len(s.get("fingerprints") or []) + len(s.get("fingerprints_ja3") or []),
                             "total_risk_events": notables, "risks_24h": notables, "flows_24h": int(s.get("total_flows") or 0), "source": SOURCE}}

    def top_protocols(self, limit: int = 20) -> List[dict]:
        return [{"protocol": p.get("name", ""), "flow_count": p.get("flows", 0), "bytes_total": p.get("bytes", 0)} for p in (self._stats().get("protocols") or [])[:limit]]

    def top_applications(self, limit: int = 20) -> List[dict]:
        return [{"application": a.get("name", ""), "flow_count": a.get("flows", 0), "bytes_total": a.get("bytes", 0)} for a in (self._stats().get("apps") or [])[:limit]]

    def risks(self, limit: int = 100) -> List[dict]:
        quand = datetime.fromtimestamp(int(self._stats().get("updated_at") or time.time()), timezone.utc).isoformat()
        notables = sorted(self._risques_notables(), key=lambda r: (-_GRAVITE.get(r.get("severity"), 0), -int(r.get("count") or 0)))
        return [{"timestamp": quand, "src_ip": "—", "dst_ip": "—", "risk_type": r.get("name", ""), "risk_score": _GRAVITE.get(r.get("severity"), 0),
                 "description": f"{int(r.get('count') or 0)} flux (cumul depuis le démarrage de sbxdpi)"} for r in notables[:limit]]

    def fingerprints(self, kind: str, limit: int = 100) -> List[dict]:
        """Empreintes TLS des clients, calculées par sbxdpi depuis le ClientHello.
        `kind` : "ja4", "ja3", ou vide pour les deux (page Empreintes).
        Première/dernière vue et SNI viennent de sbxdpi ; le profil est DÉDUIT de la
        forme du JA4 (jamais une identité d'application)."""
        st = self._stats()
        defaut = datetime.fromtimestamp(int(st.get("updated_at") or time.time()), timezone.utc).isoformat()
        meta = st.get("fingerprint_meta") or {}
        sources = {"ja4": st.get("fingerprints") or [], "ja3": st.get("fingerprints_ja3") or []}
        types = [kind] if kind in sources else ["ja4", "ja3"]

        def iso(ts):
            return datetime.fromtimestamp(int(ts), timezone.utc).isoformat() if ts else defaut

        out = []
        for t in types:
            for f in sources[t]:
                nom = f.get("name", "")
                m = meta.get(nom) or {}
                ligne = {"fingerprint": nom, "fp_type": t, "known_app": "", "hit_count": f.get("flows", 0),
                         "first_seen": iso(m.get("first")), "last_seen": iso(m.get("last")),
                         "snis": [{"name": x.get("name", ""), "n": x.get("flows", 0)} for x in (m.get("sni") or [])]}
                if t == "ja4":
                    ligne.update(profil_ja4(nom))
                out.append(ligne)
        out.sort(key=lambda f: -int(f["hit_count"] or 0))
        return out[:limit]

    def flows(self, limit: int = 100) -> List[dict]:
        ss = self._get("sessions")
        out = []
        for s in (ss if isinstance(ss, list) else [])[:limit]:
            hotes = s.get("hosts") or []
            out.append({"src_ip": s.get("device", ""), "dst_ip": hotes[0] if hotes else "", "l7_protocol": s.get("usage", ""),
                        "application": s.get("application") or s.get("infra") or "", "bytes_sent": s.get("bytes", 0), "bytes_recv": 0,
                        "flow_count": s.get("flows", 1), "active": True})
        return out
