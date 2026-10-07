# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.pac_template — PAC JS rendering (pure)."""
import json

_HEADER = "function FindProxyForURL(url, host) {\n"
_FOOTER = '  return "DIRECT";\n}\n'


def directive(proxy_type: str, address: str) -> str:
    """Build a PAC return directive with a fail-open DIRECT fallback."""
    if proxy_type == "socks5":
        return f"SOCKS5 {address}; DIRECT"
    if proxy_type in ("http", "gateway"):
        return f"PROXY {address}; DIRECT"
    return "DIRECT"


def render(rules):
    """rules: ordered list of (host_glob, directive_string). First match wins."""
    out = [_HEADER]
    for glob, direct in rules:
        out.append(f"  if (shExpMatch(host, {json.dumps(glob)})) "
                   f"return {json.dumps(direct)};\n")
    out.append(_FOOTER)
    return "".join(out)
