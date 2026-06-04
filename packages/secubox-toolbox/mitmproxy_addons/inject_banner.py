# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addon :: inject MITM transparency banner into HTML responses.

CSPN R2 requirement (CM-WALL-EGRESS-2026-06 §3) : transparency obligatoire.
The user being inspected MUST see at all times that R2 inspection is active +
be able to verify the CA fingerprint against their device trust store.

Skip non-HTML and non-200 responses. Idempotent (won't double-inject).
"""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from mitmproxy import http

log = logging.getLogger("secubox.toolbox.banner")

CA_PEM = Path("/etc/secubox/toolbox/ca/ca.pem")
PORTAL_URL = "http://10.99.0.1:8088"

_RE_BODY_CLOSE = re.compile(rb"</body\s*>", re.I)
_GUARD = b"__GONDWANA_MITM_BANNER__"


def _ca_sha1() -> str:
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(CA_PEM), "-noout", "-fingerprint", "-sha1"],
            capture_output=True, text=True, timeout=2, check=False,
        ).stdout
        # Format: "sha1 Fingerprint=XX:YY:..."
        if "=" in out:
            return out.split("=", 1)[1].strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "?"


_CA_SHA1 = _ca_sha1()


def _banner_html(sha1: str) -> bytes:
    """Render the injection payload — pure HTML+CSS+JS, no external resources."""
    # Light/dark friendly amber theme. z-index max. Closable.
    return (
        b"<script>(function(){"
        b"if(window." + _GUARD + b")return;window." + _GUARD + b"=1;"
        b"function inject(){"
        b"if(!document.body)return setTimeout(inject,30);"
        b"var b=document.createElement('div');"
        b"b.id='gondwana-mitm-banner';"
        b"b.setAttribute('role','status');"
        b"b.style.cssText='position:fixed!important;top:0!important;left:0!important;right:0!important;"
        b"z-index:2147483647!important;background:linear-gradient(90deg,#ffb347,#9A6010)!important;"
        b"color:#0a0a0f!important;font-family:Menlo,Consolas,monospace!important;"
        b"padding:6px 12px!important;font-size:11px!important;line-height:1.4!important;"
        b"border-bottom:2px solid #C04E24!important;box-shadow:0 2px 8px rgba(0,0,0,0.3)!important;"
        b"text-align:left!important';"
        b"b.innerHTML='<b style=\"color:#0a0a0f\">\\xf0\\x9f\\x93\\xa1 Gondwana ToolBoX \\xe2\\x80\\x94 R2 inspection ACTIVE</b>"
        b" \\xc2\\xb7 CA SHA1: <code style=\"background:rgba(0,0,0,0.1);padding:1px 4px;border-radius:2px\">' + "
        b"'" + sha1.encode() + b"' + '</code>"
        b" \\xc2\\xb7 <a href=\"" + PORTAL_URL.encode() + b"\" style=\"color:#0a5840;text-decoration:underline;font-weight:bold\">Session info</a>"
        b" \\xc2\\xb7 <a href=\"javascript:void(0)\" onclick=\"this.parentNode.style.display=\\'none\\'\" "
        b"style=\"float:right;color:#0a0a0f;text-decoration:none;font-weight:bold\">[\\xc3\\x97]</a>';"
        b"if(document.body.firstChild){document.body.insertBefore(b,document.body.firstChild);}"
        b"else{document.body.appendChild(b);}"
        b"document.body.style.paddingTop='28px';"
        b"}"
        b"if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',inject);}"
        b"else{inject();}"
        b"})();</script>"
    )


class InjectBanner:
    def response(self, flow: http.HTTPFlow) -> None:
        # Guard rails
        if not flow.response:
            return
        ct = flow.response.headers.get("content-type", "")
        if "text/html" not in ct.lower():
            return
        if flow.response.status_code < 200 or flow.response.status_code >= 400:
            return
        # Skip if already injected (idempotent)
        body = flow.response.content
        if body is None or _GUARD in body:
            return
        # Inject before </body>
        m = _RE_BODY_CLOSE.search(body)
        if not m:
            return
        snippet = _banner_html(_CA_SHA1)
        new_body = body[: m.start()] + snippet + body[m.start():]
        flow.response.content = new_body
        # Adjust Content-Length implicitly (mitmproxy handles it).


addons = [InjectBanner()]
