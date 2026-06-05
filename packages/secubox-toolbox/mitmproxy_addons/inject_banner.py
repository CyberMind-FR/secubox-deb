# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addon :: inject MITM transparency banner into HTML responses.

CSPN R2 requirement (CM-WALL-EGRESS-2026-06 §3) : transparency obligatoire.
The user being inspected MUST see at all times that R2 inspection is active +
be able to verify the CA fingerprint against their device trust store.

Phase 3 (#492) : the banner is now data-rich per-site (status + quality grade
+ country flag + ASN + app emoji from secubox_core.classifiers), with CSP-
aware fallback : strict-CSP sites get a JS-less HTML+style pill, lax sites
get the interactive version.

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
REPORT_URL = "http://10.99.0.1:8088/report/me/html"

_RE_BODY_CLOSE = re.compile(rb"</body\s*>", re.I)
_GUARD = b"__GONDWANA_MITM_BANNER__"

# Phase 3 classifiers (soft import : ToolBoX runs even if not deployed)
try:
    from secubox_core.classifiers import host_app as _host_app
    from secubox_core.classifiers import security_quality as _sec_quality
    from secubox_core import whitelist as _whitelist_mod
    _HAS_CLASSIFIERS = True
except ImportError:
    _HAS_CLASSIFIERS = False

# Geo lookup (toolbox-local, falls back gracefully)
try:
    import sys as _sys
    _sys.path.insert(0, "/usr/lib/secubox/toolbox")
    from secubox_toolbox import geo as _geo_mod  # type: ignore
    _HAS_GEO = True
except Exception:
    _HAS_GEO = False


def _ca_sha1() -> str:
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(CA_PEM), "-noout", "-fingerprint", "-sha1"],
            capture_output=True, text=True, timeout=2, check=False,
        ).stdout
        if "=" in out:
            return out.split("=", 1)[1].strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "?"


_CA_SHA1 = _ca_sha1()


def _compute_site_context(flow: http.HTTPFlow) -> dict:
    """Compute per-site signals for the dynamic right-side of the banner."""
    host = (flow.request.host or "").lower()
    ctx = {
        "host": host[:50],
        "app_emoji": "❔",
        "app": host,
        "grade": "?",
        "grade_color": "#888",
        "flag": "",
        "country": "",
        "asn": "",
        "status": "inspected",
        "status_icon": "🔍",
    }
    if not _HAS_CLASSIFIERS:
        return ctx

    # App classification
    try:
        cls = _host_app.classify_host(host)
        ctx["app_emoji"] = cls.get("emoji", "❔")
        ctx["app"] = cls.get("app", host) if cls.get("app") != "?" else host
    except Exception:
        pass

    # Whitelist / status
    try:
        wl = _whitelist_mod.match(host)
        if wl:
            ctx["status"] = "bypassed-whitelist"
            ctx["status_icon"] = "🛡"
        # E2E pattern check (cheap)
        elif re.search(r"\.(signal|whispersystems|threema|simplex|matrix|proton|tutanota)\.", host):
            ctx["status"] = "e2e-opaque"
            ctx["status_icon"] = "🔐"
    except Exception:
        pass

    # Geo (flag + country + ASN)
    if _HAS_GEO:
        try:
            info = _geo_mod.lookup(host) or {}
            ctx["flag"] = info.get("flag", "")
            ctx["country"] = info.get("country_iso", "")
            ctx["asn"] = (info.get("asn_org") or "")[:24]
        except Exception:
            pass

    # Quality grade (passive — we only see response headers + transport)
    try:
        # Detect TLS version from connection metadata if available
        tls_v = None
        if hasattr(flow, "server_conn") and hasattr(flow.server_conn, "tls_version"):
            v = flow.server_conn.tls_version or ""
            if "1.3" in v or "13" in v:
                tls_v = "13"
            elif "1.2" in v or "12" in v:
                tls_v = "12"
        is_e2e = ctx["status"] == "e2e-opaque"
        if ctx["status"] == "inspected":
            # Use active grading with response headers
            cookies_attrs = []
            for sc in (flow.response.headers.get_all("set-cookie") or [])[:10]:
                attrs = {"secure": "secure" in sc.lower(),
                         "httponly": "httponly" in sc.lower(),
                         "samesite": "strict" if "samesite=strict" in sc.lower()
                                     else "lax" if "samesite=lax" in sc.lower() else None}
                cookies_attrs.append(attrs)
            g = _sec_quality.grade_active(
                tls_version=tls_v or "13",  # mitm-decrypted ≥ TLS 1.2
                sni=host,
                headers=dict(flow.response.headers.items()),
                cookies_attrs=cookies_attrs,
            )
        else:
            g = _sec_quality.grade_passive(
                tls_version=tls_v,
                sni=host,
                is_e2e_messaging=is_e2e,
            )
        ctx["grade"] = g.get("grade", "?")
        if ctx["grade"] in ("A+", "A"):
            ctx["grade_color"] = "#00cc44"
        elif ctx["grade"] == "B":
            ctx["grade_color"] = "#88cc00"
        elif ctx["grade"] == "C":
            ctx["grade_color"] = "#ffaa00"
        else:
            ctx["grade_color"] = "#ff4466"
    except Exception:
        pass

    return ctx


def _detect_csp_strict(flow: http.HTTPFlow) -> bool:
    """Returns True if the site has a CSP that blocks inline scripts."""
    csp = flow.response.headers.get("content-security-policy", "")
    if not csp:
        return False
    csp_l = csp.lower()
    # If CSP defines script-src but doesn't include 'unsafe-inline' or nonce
    if "script-src" in csp_l or "default-src" in csp_l:
        if "'unsafe-inline'" not in csp_l and "nonce-" not in csp_l:
            return True
    return False


def _banner_html_dynamic(sha1: str, ctx: dict, csp_strict: bool) -> bytes:
    """Render the injection payload.

    Two flavors depending on CSP strictness :
      - csp_strict=True  : pure HTML+inline-style, NO JS. Non-dismissible.
      - csp_strict=False : JS-driven, dismissible, dynamic insertion.
    """
    # Compose the per-site right-side text
    right_parts = [f"{ctx['status_icon']} {ctx['status']}"]
    if ctx["flag"]:
        right_parts.append(ctx["flag"])
    if ctx["app_emoji"] and ctx["app"]:
        right_parts.append(f"{ctx['app_emoji']} {ctx['app']}")
    if ctx["asn"]:
        right_parts.append(ctx["asn"])
    right_text = " · ".join(right_parts)
    grade = ctx["grade"]
    grade_color = ctx["grade_color"]

    if csp_strict:
        # JS-less HTML banner — visible only, no close button, no padding-top hack.
        # Uses position:fixed with inline styles (style-src 'unsafe-inline' usually allowed
        # even when script-src is strict). If style-src is also strict, the banner becomes
        # an unstyled inline block — still visible, just ugly.
        html = (
            f"<div id=\"gondwana-mitm-banner\" role=\"status\" "
            f"style=\"position:fixed;top:0;left:0;right:0;z-index:2147483647;"
            f"background:linear-gradient(90deg,#ffb347 60%,#0a0a0f 100%);"
            f"color:#0a0a0f;font-family:Menlo,Consolas,monospace;"
            f"padding:6px 12px;font-size:11px;line-height:1.4;"
            f"border-bottom:2px solid #C04E24;text-align:left;"
            f"display:flex;justify-content:space-between;align-items:center;gap:8px\">"
            f"<span><b>📡 ToolBoX R2</b> · CA SHA1: "
            f"<code style=\"background:rgba(0,0,0,0.1);padding:1px 4px;border-radius:2px\">{sha1[:23]}</code>"
            f" · <span style=\"opacity:0.7;font-size:10px\">CSP-safe mode (no JS)</span></span>"
            f"<span style=\"color:#e8e6d9;background:rgba(0,0,0,0.4);padding:3px 8px;border-radius:3px\">"
            f"{right_text}"
            f" · <b style=\"color:{grade_color};background:#0a0a0f;padding:1px 5px;border-radius:2px\">{grade}</b>"
            f"</span></div>"
        )
        # Mark guard via HTML comment (CSP-safe — no script)
        return (b"<!-- " + _GUARD + b" -->" + html.encode("utf-8"))

    # Interactive JS version with full features
    # Pre-encode the dynamic strings to JS-safe form
    import json as _json
    right_js = _json.dumps(right_text)
    grade_js = _json.dumps(grade)
    grade_col_js = _json.dumps(grade_color)
    sha1_js = _json.dumps(sha1[:23])
    report_js = _json.dumps(REPORT_URL)

    js = f"""
(function(){{
  if(window.{_GUARD.decode()})return;
  window.{_GUARD.decode()}=1;
  function inject(){{
    if(!document.body)return setTimeout(inject,30);
    var b=document.createElement('div');
    b.id='gondwana-mitm-banner';
    b.setAttribute('role','status');
    b.style.cssText='position:fixed!important;top:0!important;left:0!important;right:0!important;'+
      'z-index:2147483647!important;'+
      'background:linear-gradient(90deg,#ffb347 60%,#0a0a0f 100%)!important;'+
      'color:#0a0a0f!important;font-family:Menlo,Consolas,monospace!important;'+
      'padding:6px 12px!important;font-size:11px!important;line-height:1.4!important;'+
      'border-bottom:2px solid #C04E24!important;box-shadow:0 2px 8px rgba(0,0,0,0.3)!important;'+
      'text-align:left!important;display:flex!important;'+
      'justify-content:space-between!important;align-items:center!important;gap:8px!important';
    var rightText={right_js};
    var grade={grade_js};
    var gradeCol={grade_col_js};
    var sha1={sha1_js};
    var reportUrl={report_js};
    b.innerHTML='<span><b>📡 ToolBoX R2</b> · CA SHA1: '+
      '<code style=\"background:rgba(0,0,0,0.1);padding:1px 4px;border-radius:2px\">'+sha1+'</code>'+
      ' · <a href=\"'+reportUrl+'\" style=\"color:#0a5840;text-decoration:underline;font-weight:bold\">Mon rapport</a></span>'+
      '<span style=\"display:flex;align-items:center;gap:8px\">'+
        '<span style=\"color:#e8e6d9;background:rgba(0,0,0,0.4);padding:3px 8px;border-radius:3px\">'+
          rightText+' · <b style=\"color:'+gradeCol+';background:#0a0a0f;padding:1px 5px;border-radius:2px\">'+grade+'</b>'+
        '</span>'+
        '<a href=\"javascript:void(0)\" onclick=\"document.getElementById(\\'gondwana-mitm-banner\\').style.display=\\'none\\';document.body.style.paddingTop=0\" style=\"color:#0a0a0f;text-decoration:none;font-weight:bold;cursor:pointer\">[×]</a>'+
      '</span>';
    if(document.body.firstChild){{document.body.insertBefore(b,document.body.firstChild)}}
    else{{document.body.appendChild(b)}}
    document.body.style.paddingTop='32px';
  }}
  if(document.readyState==='loading'){{document.addEventListener('DOMContentLoaded',inject)}}
  else{{inject()}}
}})();
""".strip()
    return b"<script>" + js.encode("utf-8") + b"</script>"


class InjectBanner:
    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        ct = flow.response.headers.get("content-type", "")
        if "text/html" not in ct.lower():
            return
        if flow.response.status_code < 200 or flow.response.status_code >= 400:
            return
        body = flow.response.content
        if body is None or _GUARD in body:
            return
        m = _RE_BODY_CLOSE.search(body)
        if not m:
            return
        # Phase 3 : compute per-site context + CSP awareness
        try:
            ctx = _compute_site_context(flow)
            csp_strict = _detect_csp_strict(flow)
            snippet = _banner_html_dynamic(_CA_SHA1, ctx, csp_strict)
        except Exception as e:
            log.warning("banner compute failed for %s: %s", flow.request.host, e)
            # Fail-open : skip injection rather than break the page
            return
        new_body = body[: m.start()] + snippet + body[m.start():]
        flow.response.content = new_body


addons = [InjectBanner()]
