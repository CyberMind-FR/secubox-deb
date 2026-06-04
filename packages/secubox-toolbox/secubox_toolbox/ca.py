# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""CA gen + iOS mobileconfig + Android DER cert serving."""
from __future__ import annotations

import base64
import logging
import subprocess
import uuid
from pathlib import Path

import jinja2

log = logging.getLogger("secubox.toolbox")

CA_DIR = Path("/etc/secubox/toolbox/ca")
CA_PEM = CA_DIR / "ca.pem"
CA_KEY = CA_DIR / "key.pem"

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "conf"


def _env() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,
        keep_trailing_newline=True,
    )


def ensure_ca(common_name: str = "Gondwana ToolBoX CA") -> None:
    """Generate CA pair if absent. Idempotent — runs from postinst."""
    CA_DIR.mkdir(parents=True, exist_ok=True)
    CA_DIR.chmod(0o700)
    if CA_PEM.exists() and CA_KEY.exists():
        return
    log.warning("Generating Gondwana ToolBoX CA (one-time, %s)", common_name)
    # openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out ca.pem -days 3650 -subj "/CN=..."
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(CA_KEY), "-out", str(CA_PEM),
            "-days", "3650",
            "-subj", f"/CN={common_name}/O=CyberMind Gondwana/C=FR",
        ],
        check=True, capture_output=True,
    )
    CA_KEY.chmod(0o600)
    CA_PEM.chmod(0o644)


def ca_der() -> bytes:
    """Return CA cert as DER (Android-friendly)."""
    pem = CA_PEM.read_bytes()
    proc = subprocess.run(
        ["openssl", "x509", "-in", str(CA_PEM), "-outform", "DER"],
        capture_output=True, check=True,
    )
    return proc.stdout


def ca_pem_b64() -> str:
    """Return CA PEM body (sans header/footer) base64'd for mobileconfig."""
    pem = CA_PEM.read_text()
    body_lines = [ln for ln in pem.splitlines() if ln and not ln.startswith("-----")]
    return "\n".join(body_lines)


def render_mobileconfig(profile_name: str = "Gondwana ToolBoX") -> str:
    """Render conf/ios.mobileconfig.j2 with CA cert embedded."""
    payload_uuid = str(uuid.uuid4()).upper()
    cert_uuid = str(uuid.uuid4()).upper()
    return _env().get_template("ios.mobileconfig.j2").render(
        profile_name=profile_name,
        payload_uuid=payload_uuid,
        cert_uuid=cert_uuid,
        ca_b64=ca_pem_b64(),
    )
