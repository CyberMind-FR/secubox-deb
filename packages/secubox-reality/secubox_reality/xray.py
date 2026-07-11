# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Reality — Xray-core config/identity generation
CyberMind — https://cybermind.fr

Hamiltonian hooks implemented in this file:

  AUTH  auth_provision_identity()        x25519 keypair + UUID + shortIds
  WALL  wall_build_routing_rules()       split-tunnel rules + optional shaping
  MESH  mesh_build_stream_settings()     Reality transport (streamSettings)

``build_server_config`` composes the three into a full Xray JSON config that
also wires a loopback ``dokodemo-door`` API inbound + ``StatsService`` so
``monitor.py`` can query cumulative traffic counters (see #AUTH/#MESH below).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import uuid as _uuid
from typing import Any, Dict, List, Optional

# --- Compat constants (kept stable across xray-core versions) --------------
NETWORK_KEY = "raw"
TARGET_KEY = "target"
LINK_TYPE = "tcp"

# Loopback API inbound used by monitor.py for StatsService queries.
API_LISTEN = "127.0.0.1"
API_PORT = 10085
API_TAG = "api"

XRAY_BIN = "xray"
_KEYPAIR_TIMEOUT = 10


class XrayError(RuntimeError):
    """Raised when xray-core cannot be invoked or its output is unusable."""


# --- AUTH: identity provisioning --------------------------------------------


def _parse_x25519_output(raw: str) -> Dict[str, str]:
    """Defensively parse ``xray x25519`` output across known variants.

    Observed variants across xray-core releases:
      - "Private key: <b64>" / "Public key: <b64>"           (older releases)
      - "PrivateKey: <b64>" / "Password: <b64>"               (newer releases,
        "Password" is xray's label for the derived public key)
    Any unrecognized line is ignored rather than raising — we only require
    that *both* a private and a public value were found somewhere.
    """
    private_key: Optional[str] = None
    public_key: Optional[str] = None

    for line in raw.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        label, _, value = line.partition(":")
        label_norm = re.sub(r"[^a-z]", "", label.strip().lower())
        value = value.strip()
        if not value:
            continue
        if label_norm in ("privatekey",):
            private_key = value
        elif label_norm in ("publickey", "password"):
            public_key = value

    if not private_key or not public_key:
        raise XrayError(
            "unable to parse 'xray x25519' output "
            f"(private={'set' if private_key else 'missing'}, "
            f"public={'set' if public_key else 'missing'}); raw={raw!r}"
        )
    return {"private_key": private_key, "public_key": public_key}


def generate_x25519_keypair(xray_bin: str = XRAY_BIN) -> Dict[str, str]:
    """Invoke ``xray x25519`` and defensively parse its stdout.

    Never raises on unexpected *formatting* — only on a hard subprocess
    failure (binary missing / non-zero exit) or output that truly contains
    neither key.
    """
    try:
        proc = subprocess.run(
            [xray_bin, "x25519"],
            capture_output=True,
            text=True,
            timeout=_KEYPAIR_TIMEOUT,
            check=False,
        )
    except FileNotFoundError as exc:
        raise XrayError(f"xray binary not found: {xray_bin}") from exc
    except subprocess.TimeoutExpired as exc:
        raise XrayError("xray x25519 timed out") from exc

    if proc.returncode != 0:
        raise XrayError(f"xray x25519 exited {proc.returncode}: {proc.stderr.strip()}")

    return _parse_x25519_output(proc.stdout)


def generate_uuid() -> str:
    return str(_uuid.uuid4())


def generate_short_ids(count: int = 1, length: int = 8) -> List[str]:
    """Generate ``count`` shortIds as even-length lowercase hex strings.

    Reality shortIds are matched byte-pairwise by clients, so an odd hex
    length is invalid — ``length`` is forced to the nearest even number.
    """
    if length % 2 != 0:
        length += 1
    nbytes = length // 2
    return [secrets.token_hex(nbytes) for _ in range(max(1, count))]


def auth_provision_identity(short_id_count: int = 1, xray_bin: str = XRAY_BIN) -> Dict[str, Any]:
    """AUTH stage entry point: emit a full identity bundle for a new server."""
    keys = generate_x25519_keypair(xray_bin=xray_bin)
    return {
        "private_key": keys["private_key"],
        "public_key": keys["public_key"],
        "uuid": generate_uuid(),
        "short_ids": generate_short_ids(short_id_count),
    }


# --- WALL: split-tunnel routing + shaping -----------------------------------


def wall_build_routing_rules(
    api_inbound_tag: str = API_TAG,
    shaping: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the ``routing`` block: API traffic stays local, everything else
    egresses via the ``direct`` outbound. ``shaping`` (optional) feeds a
    bandwidth-limited outbound tag consumers may route specific domains to.
    """
    rules: List[Dict[str, Any]] = [
        {
            "type": "field",
            "inboundTag": [api_inbound_tag],
            "outboundTag": api_inbound_tag,
        },
    ]
    if shaping and shaping.get("domains"):
        rules.append(
            {
                "type": "field",
                "domain": list(shaping["domains"]),
                "outboundTag": shaping.get("outbound_tag", "shaped"),
            }
        )
    return {"domainStrategy": "AsIs", "rules": rules}


# --- MESH: transport (Reality streamSettings) -------------------------------


def mesh_build_stream_settings(
    private_key: str,
    short_ids: List[str],
    dest: str,
    dest_port: int,
    sni: str,
) -> Dict[str, Any]:
    """Reality streamSettings block for the VLESS inbound."""
    return {
        "network": NETWORK_KEY,
        "security": "reality",
        "realitySettings": {
            "show": False,
            TARGET_KEY: f"{dest}:{dest_port}",
            "xver": 0,
            "serverNames": [sni],
            "privateKey": private_key,
            "shortIds": short_ids,
        },
    }


# --- Full server config composition -----------------------------------------


def build_server_config(server: Dict[str, Any], clients: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Compose a full Xray-core JSON config for one egress point.

    ``server`` is a plain dict shaped like ``models.Server`` (or the dict
    returned by ``store.get_server``). ``clients`` is a list of dicts shaped
    like ``models.Client``; if empty, a single client is derived from the
    server's own identity so the egress point is immediately usable.
    """
    clients = clients or []
    vless_clients = [
        {
            "id": c["uuid"],
            "email": c.get("email", server["remark"]),
            "flow": c.get("flow") or server.get("flow") or "xtls-rprx-vision",
        }
        for c in clients
    ] or [
        {
            "id": server["uuid"],
            "email": server["remark"],
            "flow": server.get("flow") or "xtls-rprx-vision",
        }
    ]

    inbounds = [
        {
            "tag": "reality-in",
            "listen": "0.0.0.0",
            "port": server["listen_port"],
            "protocol": "vless",
            "settings": {
                "clients": vless_clients,
                "decryption": "none",
            },
            "streamSettings": mesh_build_stream_settings(
                private_key=server["private_key"],
                short_ids=server["short_ids"],
                dest=server["dest"],
                dest_port=server["dest_port"],
                sni=server["sni"],
            ),
        },
        # Loopback stats API inbound (dokodemo-door) — never exposed off-box.
        {
            "tag": API_TAG,
            "listen": API_LISTEN,
            "port": API_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": API_LISTEN},
        },
    ]

    outbounds = [
        {"tag": "direct", "protocol": "freedom", "settings": {}},
        {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    ]

    config: Dict[str, Any] = {
        "log": {"loglevel": "warning"},
        "stats": {},
        "api": {
            "tag": API_TAG,
            "listen": f"{API_LISTEN}:{API_PORT}",
            "services": ["StatsService"],
        },
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": wall_build_routing_rules(api_inbound_tag=API_TAG, shaping=server.get("shaping")),
    }
    return config


def write_config_atomic(path: str, config: Dict[str, Any]) -> None:
    """Write ``config`` as JSON to ``path`` atomically (tempfile + os.replace)."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = None, None
    try:
        import tempfile

        fd, tmp_path = tempfile.mkstemp(prefix=".reality-", suffix=".json.tmp", dir=directory)
        with os.fdopen(fd, "w") as fh:
            fd = None  # fdopen took ownership
            json.dump(config, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
        tmp_path = None
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None and os.path.exists(tmp_path):
            os.unlink(tmp_path)


# --- Client link (vless:// URI) + QR ----------------------------------------


def build_vless_uri(
    uuid_value: str,
    host: str,
    port: int,
    public_key: str,
    short_id: str,
    sni: str,
    flow: str = "xtls-rprx-vision",
    remark: str = "secubox-reality",
) -> str:
    """Build a ``vless://`` URI, keeping ``pbk=`` and ``type=tcp`` intact
    per the compat constants (``LINK_TYPE``)."""
    from urllib.parse import quote, urlencode

    params = {
        "type": LINK_TYPE,
        "security": "reality",
        "pbk": public_key,
        "fp": "chrome",
        "sni": sni,
        "sid": short_id,
        "flow": flow,
    }
    query = urlencode(params, safe=",")
    return f"vless://{uuid_value}@{host}:{port}?{query}#{quote(remark)}"


def generate_qr_svg(uri: str) -> str:
    """Render ``uri`` as an SVG QR code using the ``segno`` library.

    Imported lazily so the rest of this module (config generation, identity
    provisioning) works without ``segno`` installed — e.g. under unit tests
    or ``py_compile`` sanity checks on a bare interpreter.
    """
    import io

    import segno

    qr = segno.make(uri, error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=4, dark="#104A88", xmldecl=False)
    return buf.getvalue().decode("utf-8")
