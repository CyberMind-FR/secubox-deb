# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""SecuBox-Deb ToolBoX :: FastAPI routes (Phase 1)."""
from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path

import jinja2
from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

# #785 — PDF rendering (fpdf2 + matplotlib) is CPU-heavy (~9 s on the board) and
# matplotlib's pyplot API is NOT thread-safe. Three defences, together, keep a
# slow render — or a 504-page auto-retry storm hammering the PDF URL — from
# wedging the single uvicorn worker:
#   1. run the render OFF the event loop (threadpool) so other routes stay live;
#   2. serialize renders through one lock so pyplot's global state can't race and
#      concurrent renders can't starve the CPU in parallel;
#   3. cache the rendered bytes per key for a short TTL, with a double-checked
#      lock, so a retry storm triggers exactly ONE render, not one per retry.
_pdf_render_lock = asyncio.Lock()
_pdf_cache: dict = {}          # key -> (expires_at_epoch, pdf_bytes)
_PDF_CACHE_TTL = 120           # seconds — a report is a live snapshot; 2 min stale is fine


def _pdf_cache_get(key: str):
    ent = _pdf_cache.get(key)
    if ent and ent[0] > time.time():
        return ent[1]
    return None


def _pdf_cache_put(key: str, blob: bytes) -> None:
    _pdf_cache[key] = (time.time() + _PDF_CACHE_TTL, blob)
    if len(_pdf_cache) > 64:    # bound memory: drop expired entries
        now = time.time()
        for k in [k for k, v in _pdf_cache.items() if v[0] <= now]:
            _pdf_cache.pop(k, None)


async def _render_pdf_offloaded(render_fn, data, cache_key: str | None = None):
    """Render a PDF off the event loop, one at a time, with a short per-key cache.

    The cache re-check INSIDE the lock is the storm defence: the first request
    renders and caches; every request queued behind it on the lock then finds the
    fresh entry and returns instantly instead of re-rendering."""
    if cache_key:
        cached = _pdf_cache_get(cache_key)
        if cached is not None:
            return cached
    async with _pdf_render_lock:
        if cache_key:
            cached = _pdf_cache_get(cache_key)
            if cached is not None:
                return cached
        blob = await run_in_threadpool(render_fn, data)
        if cache_key:
            _pdf_cache_put(cache_key, blob)
        return blob

from . import (
    avatar_analysis,
    beaconing,
    bundle as bundlemod,
    ca,
    cookie_analysis,
    cumulative,
    dga,
    dpi_class,
    geo,
    mac as macmod,
    nft,
    reports,
    scoring,
    sentinel_link,
    store,
    threat_intel,
)


def _cumulative_stats() -> dict:
    """Cached anonymous cumulative stats — see secubox_toolbox.cumulative."""
    try:
        return cumulative.get_cached()
    except Exception:
        return {}
# Phase 3 (#492) : transparency layer
try:
    from secubox_core import whitelist as _whitelist_mod
    from secubox_core.classifiers import security_quality as _sec_quality
    _HAS_TRANSPARENCY = True
except ImportError:
    _HAS_TRANSPARENCY = False
from pathlib import Path as _Path
NETSTATS_SNAPSHOT = _Path("/var/lib/secubox/hub/netstats.json")
from .config import load_config, resolve_secret
from .models import AcceptResp, ClientRow, Config, StatusResp

log = logging.getLogger("secubox.toolbox")

router = APIRouter(tags=["toolbox"])


# ── #620 phase 1 : TTFB cosmetic loader + per-host decision bundle ──────────
@router.get("/__toolbox/loader.js")
async def toolbox_loader_js() -> Response:
    """Static cosmetic loader (applies the banner client-side from the bundle)."""
    # no-store: the loader is the banner entry point and evolves (SPA re-assert,
    # CSP proof, …). A long cache (was max-age=3600) pins stale loaders in clients
    # for up to an hour — so loader changes never reach already-visited sites. It's
    # 4 KB; serve it fresh every load so updates propagate immediately.
    return Response(
        content=bundlemod.LOADER_JS,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@router.get("/__toolbox/bundle")
async def toolbox_bundle(mh: str = Query(default=""), wg: int = Query(default=0)) -> JSONResponse:
    """Per-client cosmetic decision bundle. ``mh`` = client identity hash (supplied
    by the streaming injector); fail-open to a minimal r1 bundle."""
    return JSONResponse(
        content=bundlemod.get_bundle(mh, bool(wg)),
        headers={"Cache-Control": "no-store"},
    )


@router.get("/__toolbox/set-level")
async def toolbox_set_level(mh: str = Query(default=""), level: str = Query(default="")) -> JSONResponse:
    """#724 — banner self-service level switch. Reverse-proxied to the portal by
    sbxmitm (same-origin from the page) like /__toolbox/bundle, so it carries no
    cookies/CSRF and is identified by the client's baked ``mh`` hash. Persists the
    analysis tier for that hash (R3 wg peers have no captive MAC, so this is the
    by-hash setter, not the nft-based /change-level)."""
    mh = (mh or "").strip().lower()
    level = (level or "").strip().lower()
    if not (mh and all(c in "0123456789abcdef" for c in mh) and 8 <= len(mh) <= 64):
        return JSONResponse({"ok": False, "error": "bad mh"}, status_code=400,
                            headers={"Cache-Control": "no-store"})
    if level not in ("r0", "r1", "r2", "r3", "r4"):
        return JSONResponse({"ok": False, "error": "bad level"}, status_code=400,
                            headers={"Cache-Control": "no-store"})
    # honour the same gates as /change-level
    try:
        cfg = _get_cfg()
        if level == "r2" and not cfg.r2.enabled:
            level = "r1"
    except Exception:
        pass
    # R3 + R4 (the analyst/reverse-catcher tier, #736) are wg-path tiers.
    if level in ("r3", "r4") and not Path("/etc/secubox/toolbox/wg/server.pubkey").exists():
        level = "r1"
    try:
        store.set_client_level(mh, level)
        bundlemod.invalidate(mh)  # drop cached bundle so the new level shows at once
    except Exception as e:  # pragma: no cover
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500,
                            headers={"Cache-Control": "no-store"})
    return JSONResponse({"ok": True, "level": level}, headers={"Cache-Control": "no-store"})


@router.get("/__toolbox/inline")
async def toolbox_inline(
    mh: str = Query(default=""),
    wg: int = Query(default=0),
    csp: int = Query(default=0),
) -> Response:
    """#662 — COMPLETE self-contained inline banner script BODY.

    Sites with a SERVICE WORKER (leparisien, cnn…) intercept every same-origin
    request, so the legacy ``<script src="/__toolbox/loader.js">`` + its
    ``fetch("/__toolbox/bundle")`` are hijacked by the SW (404 / app-shell)
    before reaching our MITM engine → no banner. The Go engine fetches THIS
    body server-side at inject time and bakes it into a self-contained
    ``<script>…</script>`` — no same-origin fetch for the SW to touch.

    ``mh`` / ``wg`` / ``csp`` come from the query params (baked as JS literals,
    not data-attrs / currentScript); the bundle is ``get_bundle(mh, wg)`` baked
    as a JSON literal (not fetched). no-store like the loader (it evolves)."""
    return Response(
        content=bundlemod.inline_script(mh, bool(wg), bool(csp)),
        media_type="application/javascript",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


# #753 — SW-neuter auto-learn ingest: sbxmitm records every host it sees
# fetching a Service Worker that is NOT on the sw-neuter allow-list, and POSTs
# them here every 30 s. We dedup-append to a candidates file for operator review.
# The operator promotes wanted hosts to sw-neuter-hosts.txt to activate neuter.
# UNAUTHENTICATED — same trust perimeter as /__toolbox/ad-event (loopback / WG).
SW_CANDIDATES_FILE = Path("/var/lib/secubox/toolbox/sw-neuter-candidates.txt")


def _append_sw_candidates(hosts: list[str]) -> None:
    """Append new hosts to the sw-neuter candidates file, deduped against what is
    already there. Best-effort; never raises into the request path."""
    try:
        existing: set[str] = set()
        if SW_CANDIDATES_FILE.exists():
            existing = {l.strip() for l in SW_CANDIDATES_FILE.read_text().splitlines() if l.strip()}
        fresh = [h for h in hosts if h not in existing]
        if not fresh:
            return
        SW_CANDIDATES_FILE.parent.mkdir(parents=True, exist_ok=True)
        with SW_CANDIDATES_FILE.open("a", encoding="utf-8") as fh:
            for h in fresh:
                fh.write(h + "\n")
    except OSError as e:
        log.debug("sw-candidate append failed: %s", e)


@router.post("/__toolbox/sw-candidate")
async def toolbox_sw_candidate(request: Request) -> Response:
    """#753 — record SW-PWA hosts proposed for the sw-neuter allow-list. sbxmitm
    POSTs hosts it saw fetching a Service Worker that are NOT yet allow-listed.
    Deduped-appends to the candidates file for operator review; the operator
    promotes wanted hosts to sw-neuter-hosts.txt."""
    try:
        body = await request.json()
        hosts = [h for h in (body.get("hosts") or []) if isinstance(h, str) and h]
    except Exception:
        hosts = []
    if hosts:
        _append_sw_candidates(hosts)
    return Response(status_code=204)


# #662 — ad-block metrics ingest from the Go MITM engine (sbxmitm). The #662
# cutover moved the BLOCK decision (204 on ad/tracker hosts) into the Go engine
# but left the METRICS unported, so the #ads dashboard froze. The engine now
# aggregates blocks in-memory and POSTs a snapshot here every ~10s; we persist it
# to the SAME SQLite tables (ad_block_stats / ad_block_client_host) the dashboard
# reads via store.ad_stats().
#
# UNAUTHENTICATED, by design — exactly like /__toolbox/loader.js + /__toolbox/
# bundle above: the engine reaches the portal only over the R3 nft perimeter
# (loopback / WG ingress), which is the trust boundary. No JWT is required for
# these engine↔portal banner/metrics channels.
_AD_EVENT_ROW_CAP = 2000  # bound each list so a misbehaving engine can't flood us


@router.post("/__toolbox/ad-event")
async def toolbox_ad_event(request: Request) -> Response:
    """Ingest a batch of ad-block tallies from the Go engine. Best-effort: never
    500s the engine (it is fire-and-forget) — always returns 204. See the trust
    note above for why this is unauthenticated."""
    try:
        # Body-size guard: this is the only unauthenticated POST-with-body on the
        # R3 perimeter, and the portal serves the whole board — bound the body
        # BEFORE parsing so a misbehaving/compromised WG peer can't pressure
        # portal memory. The legit payload (≤5000 keys × 2 maps) is well under 2 MB.
        try:
            clen = int(request.headers.get("content-length") or 0)
        except (TypeError, ValueError):
            clen = 0
        if clen > 2 * 1024 * 1024:
            return Response(status_code=204)
        body = await request.json()
        if not isinstance(body, dict):
            return Response(status_code=204)
        blocks = body.get("blocks") or []
        clients = body.get("clients") or []
        # #662 — the Go engine now also feeds the AUTO-LEARN loop: 3rd-party
        # ad-path requests it saw on the allow/mitm path (ad_ghost's _AD_PATH
        # heuristic), recorded as candidates here for secubox-toolbox-autolearn
        # to promote into learned-trackers.txt at AD_MIN_SITES distinct sites.
        candidates = body.get("candidates") or []
        if not isinstance(blocks, list):
            blocks = []
        if not isinstance(clients, list):
            clients = []
        if not isinstance(candidates, list):
            candidates = []
        blocks = blocks[:_AD_EVENT_ROW_CAP]
        clients = clients[:_AD_EVENT_ROW_CAP]
        candidates = candidates[:_AD_EVENT_ROW_CAP]

        block_rows = [
            (b["ad_host"], b.get("site", ""), "block", int(b.get("hits", 0)), int(b.get("bytes", 0)))
            for b in blocks
            if isinstance(b, dict) and b.get("ad_host")
        ]
        client_rows = [
            (c["mac_hash"], c["ad_host"], int(c.get("hits", 0)), int(c.get("bytes", 0)))
            for c in clients
            if isinstance(c, dict) and c.get("mac_hash") and c.get("ad_host")
        ]
        cand_rows = [
            (c["host"], c.get("site", ""), int(c.get("hits", 0)))
            for c in candidates
            if isinstance(c, dict) and c.get("host")
        ]
        if block_rows:
            store.record_ad_blocks(block_rows)
        if client_rows:
            store.record_ad_client_blocks(client_rows)
        if cand_rows:
            store.record_ad_candidates(cand_rows)
        # #755 — cosmetic-pages counter: Go engine reports how many R3 HTML pages
        # received the cosmetic ad-hide style in this flush window.
        cp = body.get("cosmetic_pages")
        if cp:
            store.record_cosmetic_pages(cp)
    except Exception as e:  # never raise into the engine's fire-and-forget POST
        log.debug("ad-event ingest failed: %s", e)
    return Response(status_code=204)


# #662 — cross-site cookie-tracker edge ingest from the Go MITM engine (sbxmitm).
# The #662 Phase-7 cutover decommissioned the in-process Python social_graph addon
# that fed social.record_edge(), so the kbin /social graph (social_edges →
# social_nodes/social_links) froze. The engine now computes the SAME 3rd-party
# cookie-tracker edges (FAITHFUL port of social_graph.py: deny-list, eTLD+1
# 3rd-party check, cookie_id_hash, CMP consent_state) and POSTs a batch here. We
# call social.record_edge() per row, which writes raw social_edges; the existing
# app.py social_fold_loop folds them into nodes/links.
#
# Raw cookie VALUES never reach this endpoint — only the truncated cookie_id_hash
# (privacy/CSPN; this is exactly why the original ran in-process).
#
# UNAUTHENTICATED, same trust note as /__toolbox/ad-event: the engine reaches the
# portal only over the R3 nft perimeter (loopback / WG ingress).
_SOCIAL_EVENT_ROW_CAP = 5000  # bound the edge list so a misbehaving engine can't flood us
_SOCIAL_FOLD_DEBOUNCE = 60  # seconds: floor between in-handler safety folds
_social_last_fold = 0.0  # module-level throttle timestamp


@router.post("/__toolbox/social-event")
async def toolbox_social_event(request: Request) -> Response:
    """Ingest a batch of cross-site tracker edges from the Go engine. Best-effort:
    never 500s the engine (it is fire-and-forget) — always returns 204. See the
    trust note above for why this is unauthenticated."""
    global _social_last_fold
    try:
        # Body-size guard BEFORE parsing (mirrors /__toolbox/ad-event): the legit
        # payload (≤5000 edges) is well under 2 MB; reject larger outright so a
        # misbehaving/compromised WG peer can't pressure portal memory.
        try:
            clen = int(request.headers.get("content-length") or 0)
        except (TypeError, ValueError):
            clen = 0
        if clen > 2 * 1024 * 1024:
            return Response(status_code=204)
        body = await request.json()
        if not isinstance(body, dict):
            return Response(status_code=204)
        edges = body.get("edges") or []
        if not isinstance(edges, list):
            edges = []
        edges = edges[:_SOCIAL_EVENT_ROW_CAP]

        from . import social as _social

        recorded = 0
        for e in edges:
            if not isinstance(e, dict):
                continue
            try:
                _social.record_edge(
                    client_mac_hash=e.get("client_mac_hash") or "",
                    src_site=e.get("src_site") or "",
                    tracker_domain=e.get("tracker_domain") or "",
                    cookie_id_hash_val=e.get("cookie_id_hash_val") or "",
                    ja4_hash=e.get("ja4_hash") or None,
                    consent_state=e.get("consent_state") or "none_seen",
                )
                recorded += 1
            except Exception as row_err:  # one bad row never fails the batch
                log.debug("social-event row failed: %s", row_err)

        # Safety fold: the app.py social_fold_loop already folds every 5 min, but
        # fold here too (debounced to ≤ once / 60 s via a module-level timestamp)
        # so a freshly-ingested edge surfaces in the d3 graph promptly even between
        # loop ticks. Cheap (indexed window scan) and self-throttling; a fold
        # failure is swallowed (the loop will catch up).
        if recorded:
            now = time.time()
            if now - _social_last_fold >= _SOCIAL_FOLD_DEBOUNCE:
                _social_last_fold = now
                try:
                    _social.fold_recent(window_seconds=600)
                except Exception as fold_err:
                    log.debug("social-event fold failed: %s", fold_err)
    except Exception as e:  # never raise into the engine's fire-and-forget POST
        log.debug("social-event ingest failed: %s", e)
    return Response(status_code=204)


# Cap geo/UA enrichment on /admin/clients/rich to the rows the UI actually shows
# (top-5 + headroom). Beyond this, clients get bare fields — avoids ~51 cached
# geo lookups per poll (ref #644).
ENRICH_LIMIT = 12

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "conf"
_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
    autoescape=True,
    keep_trailing_newline=True,
)

_cfg: Config | None = None
_salt: str | None = None


def _get_cfg() -> Config:
    global _cfg
    if _cfg is None:
        _cfg = load_config()
    return _cfg


def _get_salt() -> str:
    global _salt
    if _salt is None:
        cfg = _get_cfg()
        try:
            _salt = resolve_secret(cfg.portal.mac_salt_ref)
        except Exception as e:
            log.error("salt unavailable: %s — using transient", e)
            import secrets as _s
            _salt = _s.token_urlsafe(24)
    return _salt


def _resolve(request: Request) -> tuple[str | None, str | None]:
    """Return (ip, mac) for the request client.

    Phase 7 (#498) : for WG R3 peers the FastAPI runs behind nginx and
    behind mitm-wg, so `request.client.host` is the upstream proxy IP
    (unix socket peer for nginx or HAProxy's address). The real source
    IP is in X-Forwarded-For — set by mitm-wg's inject_xff addon for
    tunneled requests and by nginx for everyone else.
    """
    ip = _client_ip(request)
    if not ip:
        return None, None
    return ip, macmod.mac_of(ip)


def _client_ip(request: Request) -> str | None:
    """Pick the most trustworthy client IP : X-Through-R3-Tunnel sentinel
    set by mitm-wg's inject_xff > leftmost X-Forwarded-For > raw socket
    peer. The sentinel header is the cleanest signal because it can only
    be set by our own proxy chain."""
    # Sentinel : mitm-wg always populates this for 10.99.1.x peers
    r3 = request.headers.get("X-R3-Peer")
    if r3 and r3.startswith("10.99.1."):
        return r3
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        # leftmost = original client
        first = xff.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else None


def _client_mac_hash(request: Request, salt: str) -> str | None:
    """Resolve the caller's identity hash, same precedence as /social/me:
    explicit ?mh= → R3 WG peer (wg-peers.json) → captive ARP. Returns None when
    unresolvable. Used to bake ?mh= into the landing links so they never hit the
    'identity unresolved' 400 (the page already knows who you are)."""
    mh_qp = (request.query_params.get("mh") or "").strip().lower()
    if mh_qp and all(c in "0123456789abcdef" for c in mh_qp) and 8 <= len(mh_qp) <= 64:
        return mh_qp
    ip = _client_ip(request)
    if ip and ip.startswith("10.99.1."):
        try:
            import hashlib as _h
            import json as _j
            from pathlib import Path as _P
            _db = _P("/var/lib/secubox/toolbox/wg-peers.json")
            if _db.exists():
                for pubkey, meta in _j.loads(_db.read_text()).get("peers", {}).items():
                    if meta.get("ip") == ip:
                        return _h.sha256(pubkey.encode()).hexdigest()[:16]
        except Exception:
            pass
    try:
        _ip, mac = _resolve(request)
        if mac:
            return macmod.hash_mac(mac, salt)
    except Exception:
        pass
    return None


# ───────────────── Public routes ─────────────────

@router.get("/", response_class=HTMLResponse)
@router.get("/hotspot-detect.html", response_class=HTMLResponse)
@router.get("/generate_204", response_class=HTMLResponse)
@router.get("/connecttest.txt", response_class=HTMLResponse)
async def splash(request: Request):
    ip, mac = _resolve(request)
    cfg = _get_cfg()
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt) if mac else None

    # Phase 6.I (#496) : if request comes from a WG peer (10.99.1.x), the
    # client is by construction R3 — bypass MAC/ARP resolution and use
    # the WG peer hash so the splash shows R3 status, masks R0/R1/R2
    # switch (useless when already in tunnel), and links to /report?mh=.
    # Phase 7 (#498) : prefer XFF / X-R3-Peer sentinel because the FastAPI
    # runs behind nginx + mitm-wg, so request.client.host is the proxy peer.
    client_ip = _client_ip(request)
    is_wg_r3 = bool(client_ip and client_ip.startswith("10.99.1."))
    if is_wg_r3:
        try:
            from . import wg as _wg
            peers = _wg._load_peers().get("peers", {})
            import hashlib as _h
            for pk, m in peers.items():
                if m.get("ip") == client_ip:
                    mac_hash = _h.sha256(pk.encode()).hexdigest()[:16]
                    break
        except Exception:
            pass

    no_cache_headers = {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }

    # Phase 3 (#492) : ALWAYS render splash on GET /. Even validated users
    # benefit from seeing the cert install buttons + level switcher + dashboard
    # link. Auto-redirect was hiding the cert links from users who already
    # validated — they had no path back to the install buttons.
    # Phase 6 (#496) : wg_enabled = server.pubkey exists = R3 ready
    wg_enabled = Path("/etc/secubox/toolbox/wg/server.pubkey").exists()
    current_level = "r3" if is_wg_r3 else (store.get_client_level(mac_hash) if mac_hash else None)
    html = _env.get_template("splash.html.j2").render(
        mac_hash=mac_hash or "??",
        ssid=cfg.ap.ssid,
        r2_enabled=cfg.r2.enabled,
        wg_enabled=wg_enabled,
        already_validated=bool(mac and nft.is_validated(mac)) or is_wg_r3,
        current_level=current_level,
        is_wg_r3=is_wg_r3,
        client_ip=client_ip,
    )
    return HTMLResponse(html, headers=no_cache_headers)


@router.post("/accept")
async def accept(request: Request):
    """Phase 3 (#492) : 3-level explicit opt-in.

    Form field 'level' = 'r0' | 'r1' | 'r2' (default 'r1' for backward compat
    with bare-button submission). Each level adds the MAC to incremental nft
    sets and persists the level in the clients table.
      r0 = validated only (net access, no inspection)
      r1 = r0 + consented_r2_macs (MITM enabled, passive analysis only)
      r2 = r1 + r2_banner_macs (banner injection + QUIC drop)
    """
    ip, mac = _resolve(request)
    if not ip or not mac:
        raise HTTPException(400, "client mac unknown")
    cfg = _get_cfg()
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt)

    # Parse level from POST body — accept form-urlencoded or fallback to r1
    try:
        form = await request.form()
        level = (form.get("level") or "r1").lower()
    except Exception:
        level = "r1"
    if level not in ("r0", "r1", "r2", "r3", "r4"):
        level = "r1"
    # R2 only allowed if config enables it
    if level == "r2" and not cfg.r2.enabled:
        level = "r1"
    # R3 only allowed if WG container provisioned (presence of server.pubkey)
    # R3 + R4 (the analyst/reverse-catcher tier, #736) are wg-path tiers.
    if level in ("r3", "r4") and not Path("/etc/secubox/toolbox/wg/server.pubkey").exists():
        level = "r1"

    # All levels get validated (net access)
    if not nft.add_validated(mac, ttl="24h"):
        raise HTTPException(500, "nft add validated failed")

    r2_ok = False
    if level in ("r1", "r2") and nft.add_consented(mac, ttl="24h"):
        r2_ok = True
    # R2-only : banner injection (separate nft set)
    if level == "r2":
        nft.add_r2_banner(mac, ttl="24h")
    # Phase 6 (#496) R3-only : WireGuard consent set
    if level == "r3":
        nft.add_r3_wg(mac, ttl="24h")

    ua = request.headers.get("user-agent", "")
    store.record_consent(mac_hash, ip, ua, ttl_seconds=86400)
    store.upsert_client(mac_hash, ip, level=level)
    log.info("consent recorded mac_hash=%s level=%s r2=%s", mac_hash, level, r2_ok)
    # Phase 3 (#492) : detect form-vs-API.
    # Browser : 303 redirect straight to the dashboard with welcome state.
    # API     : JSON AcceptResp for programmatic clients.
    accept_hdr = request.headers.get("accept", "")
    wants_json = "application/json" in accept_hdr and "text/html" not in accept_hdr
    if wants_json:
        return AcceptResp(ok=True, mac_hash=mac_hash, r2=r2_ok)
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/report/me/html?welcome=1&level={level}",
                             status_code=303)


@router.post("/change-level")
async def change_level(request: Request):
    """Phase 3 (#492) : change opt-in level from the dashboard.

    Adds/removes the MAC from the appropriate nft sets and updates the
    persisted level. Redirects back to /report/me/html.
    """
    ip, mac = _resolve(request)
    if not ip or not mac:
        raise HTTPException(400, "client mac unknown")
    cfg = _get_cfg()
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt)

    try:
        form = await request.form()
        level = (form.get("level") or "r1").lower()
    except Exception:
        level = "r1"
    if level not in ("r0", "r1", "r2", "r3", "r4"):
        level = "r1"
    if level == "r2" and not cfg.r2.enabled:
        level = "r1"
    # R3 + R4 (the analyst/reverse-catcher tier, #736) are wg-path tiers.
    if level in ("r3", "r4") and not Path("/etc/secubox/toolbox/wg/server.pubkey").exists():
        level = "r1"

    # Re-validate (idempotent extend)
    v_ok = nft.add_validated(mac, ttl="24h")
    # Membership in consented_r2_macs : add for r1/r2, remove for r0/r3
    if level in ("r1", "r2"):
        c_ok = nft.add_consented(mac, ttl="24h")
    else:
        c_ok = nft.del_consented(mac)
    # Membership in r2_banner_macs : add for r2, remove otherwise
    if level == "r2":
        b_ok = nft.add_r2_banner(mac, ttl="24h")
    else:
        b_ok = nft.del_r2_banner(mac)
    # Phase 6 (#496) : r3 WireGuard set
    if level == "r3":
        wg_ok = nft.add_r3_wg(mac, ttl="24h")
    else:
        wg_ok = nft.del_r3_wg(mac)

    store.upsert_client(mac_hash, ip, level=level)
    log.info("level switched mac_hash=%s -> %s (nft: validated=%s consented=%s banner=%s wg=%s)",
             mac_hash, level, v_ok, c_ok, b_ok, wg_ok)
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/report/me/html?switched=1&level={level}",
                             status_code=303)


@router.get("/wg/tor-status")
async def wg_tor_status() -> dict:
    """kbin Tor egress status for the clients (#683). Public + read-only, so it
    is reachable on the kbin vhost (unlike the admin-gated /admin/tor/*). The
    webext popup + Android app poll this to show the 🧅 indicator + exit IP."""
    from .filters import get_filters
    from . import tor_ctl
    f = get_filters(force=False)
    st = tor_ctl.status()
    return {
        "tor_mode": bool(f.get("tor_mode", False)),
        "running": bool(st.get("running", False)),
        "bootstrap": int(st.get("bootstrap", 0) or 0),
        "exit_ip": _tor_exit_ip_cached(),
    }


@router.get("/wg/r3-check")
async def wg_r3_check(request: Request):
    """Phase 7 (#498) — same-origin HTTPS probe for the R3 verification
    landing card. iOS Safari blocks mixed content, so the previous
    `<img src='http://10.99.0.1:8088/qr/splash.png'>` cross-origin HTTP
    probe never fires from an HTTPS-served page (and the JS concluded
    "off tunnel" no matter what).

    This endpoint is reachable on every secubox vhost (including the
    public kbin one) and reads `_client_ip(request)` which honours
    `X-R3-Peer` / XFF set by mitm-wg's inject_xff addon. A 10.99.1.x
    source means R3 ; anything else means the request did not come
    through the WireGuard tunnel.
    """
    ip = _client_ip(request)
    in_tunnel = bool(ip and ip.startswith("10.99.1."))
    return {
        "tunnel": in_tunnel,
        "peer_ip": ip if in_tunnel else None,
    }


@router.get("/status", response_model=StatusResp)
async def status(request: Request) -> StatusResp:
    ip, mac = _resolve(request)
    if not mac:
        return StatusResp(ip=ip)
    salt = _get_salt()
    return StatusResp(
        ip=ip,
        mac_hash=macmod.hash_mac(mac, salt),
        validated=nft.is_validated(mac),
        r2_consented=nft.is_consented(mac),
    )


# ───────────────── CA distribution ─────────────────

@router.get("/ca/mobileconfig")
async def ca_mobileconfig() -> Response:
    body = ca.render_mobileconfig()
    return Response(
        content=body,
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox.mobileconfig"},
    )


@router.get("/ca/android.crt")
async def ca_android_crt() -> Response:
    """Serve CA cert as PEM (Android-friendly).
    Chrome on Android prompts to install when MIME = application/x-x509-ca-cert."""
    return Response(
        content=ca.ca_pem(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox.crt"},
    )


@router.get("/ca/android.der")
async def ca_android_der() -> Response:
    """Fallback DER binary for older Android versions / manual install."""
    return Response(
        content=ca.ca_der(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox.der"},
    )


@router.get("/ca/android-help", response_class=HTMLResponse)
async def ca_android_help() -> HTMLResponse:
    """Step-by-step CA install guide for Android (Chrome + Settings flow)."""
    html = """<!DOCTYPE html><html lang=fr><head><meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Installer le certificat Gondwana ToolBoX — Android</title>
<style>body{font-family:sans-serif;background:#0a0a0f;color:#00ff55;padding:1.5rem;max-width:560px;margin:auto;line-height:1.6}
h1{color:#00ff55;text-shadow:0 0 4px #00dd44}h2{color:#cbb6ff;margin-top:1.5rem;font-size:1.1rem}
ol{padding-left:1.4rem}a.btn{display:block;text-align:center;padding:0.8rem;background:#9e76ff;color:#0a0a0f;
text-decoration:none;border-radius:4px;font-weight:bold;margin:1rem 0}code{background:#222;padding:0.1rem 0.4rem;border-radius:2px}</style>
</head><body>
<h1>🤖 Installer le certificat — Android</h1>
<p>Android &le; 13 et certaines apps (banques, gov) refusent les CAs utilisateur.
Le navigateur Chrome lui le respecte. R1/R2 fonctionnent dans Chrome ; les apps natives
peuvent rester en clear-text ou échouer.</p>

<a href="/ca/android.crt" class=btn>📥 Télécharger le certificat (.crt)</a>

<h2>Étape 1 — Télécharger</h2>
<p>Tap le bouton ci-dessus. Chrome demande où enregistrer le fichier
<code>gondwana-toolbox.crt</code> (Downloads).</p>

<h2>Étape 2 — Installer dans Réglages</h2>
<ol>
<li>Ouvre <b>Réglages</b> → <b>Sécurité</b> (ou <b>Sécurité et confidentialité</b>)</li>
<li>Cherche <b>Chiffrement et authentifiants</b> → <b>Installer un certificat</b></li>
<li>Choisis <b>Certificat CA</b></li>
<li>Sélectionne <code>gondwana-toolbox.crt</code> dans Downloads</li>
<li>Confirme l'avertissement (oui, c'est un CA tiers ; il vit le temps de ta session)</li>
</ol>

<h2>Étape 3 — Vérifier l'empreinte</h2>
<p>Après installation, retourne dans <b>Sécurité → Authentifiants de confiance →
Utilisateur</b> et compare l'empreinte SHA-1 affichée avec celle de la cabine :</p>
<p><code id=fp>chargement…</code></p>

<h2>⚠ Limite Android</h2>
<p>Depuis Android 7, les apps doivent <b>opt-in</b> aux CAs utilisateur via
<code>network_security_config.xml</code>. La plupart des apps banques/gov/streaming
NE LE FONT PAS — résultat : R1/R2 cassent leur connexion. Solution : utilise R0
pour ces apps, OU passe en R3 (WireGuard).</p>

<a href="/" class=btn style="background:transparent;color:#00ff55;border:1px solid #00ff55">← Retour splash</a>
<script>
fetch('/ca/fingerprint').then(r=>r.json()).then(d=>{document.getElementById('fp').textContent=d.sha1||'?';});
</script>
</body></html>"""
    return HTMLResponse(html)


@router.get("/cumulative-stats.json")
async def cumulative_stats_json() -> dict:
    """Public anonymous cumulative stats — fed by landing page + dashboards."""
    return _cumulative_stats()


def _ua_platform(ua: str) -> str:
    """Cheap UA sniff. Same logic as /wg/onboard so the auto-open panel
    matches between the two pages."""
    ua = (ua or "").lower()
    if "iphone" in ua or "ipad" in ua or "ios" in ua:
        return "ios"
    if "android" in ua:
        return "android"
    if "macintosh" in ua or "mac os x" in ua:
        return "macos"
    if "windows" in ua:
        return "windows"
    if "linux" in ua:
        return "linux"
    return "other"


def _install_panels_html(platform: str) -> str:
    """Reusable platform-detected install panels for both
    /wg/onboard and the landing page.  Same content, same CSS classes
    so styling stays consistent (the landing page injects matching
    classes via its own style block)."""
    panels = {
        "ios":     ("🍎 iPhone / iPad", "ios"),
        "android": ("🤖 Android", "android"),
        "linux":   ("🐧 Linux", "linux"),
        "macos":   ("🍏 macOS", "macos"),
        "windows": ("🪟 Windows", "windows"),
    }
    order = [platform] + [k for k in panels if k != platform]
    order = [k for i, k in enumerate(order) if k in panels and k not in order[:i]]
    sections = []
    for key in order:
        title, slug = panels[key]
        body = _ONBOARD_BODY[slug]
        open_attr = " open" if key == order[0] else ""
        sections.append(
            f'<details class="install-panel" id="install-{slug}"{open_attr}>'
            f'<summary><span class="emoji">{title.split()[0]}</span> '
            f'<b>{title}</b></summary>{body}</details>'
        )
    return "\n".join(sections)


@router.get("/landing", response_class=HTMLResponse)
@router.get("/cabine", response_class=HTMLResponse)
async def landing(request: Request) -> HTMLResponse:
    """Public landing page for the cabine — shown on kbin.gk2.secubox.in.

    Visitor-facing demo of the project : pitch + 4 levels + install + live
    cumulative anonymous stats + open source license + contact.

    Phase 8.2 (#500) — embeds the same platform-detected install
    panels as /wg/onboard so visitors get a one-click flow matching
    their device right on the landing page.
    """
    stats = _cumulative_stats()
    platform = _ua_platform(request.headers.get("user-agent") or "")
    install_panels = _install_panels_html(platform)
    # Resolve identity now (the page knows who you are) so the report/carto links
    # carry ?mh= and never hit the /social/me "identity unresolved" 400.
    mac_hash = _client_mac_hash(request, _get_salt()) or ""
    return HTMLResponse(
        _env.get_template("landing.html.j2").render(
            stats=stats,
            install_panels=install_panels,
            install_platform=platform,
            mac_hash=mac_hash,
        ),
        headers={"Cache-Control": "private, max-age=60, no-transform"},
    )


@router.get("/ca/webclip-cabine.mobileconfig")
async def webclip_cabine() -> Response:
    """Phase 3 (#492) : iOS Add-to-Home-Screen profile that drops a 'ToolBoX
    Cabine' icon pointing at /report/me/html. User can then check the live
    session report in 1 tap, surviving Safari cache misses + native-app gaps."""
    import uuid as _uuid
    cfg = _get_cfg()
    body = _env.get_template("webclip.mobileconfig.j2").render(
        payload_uuid=str(_uuid.uuid4()),
        webclip_uuid=str(_uuid.uuid4()),
        report_url=f"http://{cfg.dhcp.gateway}/report/me/html",
    )
    return Response(
        content=body,
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": "attachment; filename=toolbox-cabine-icon.mobileconfig"},
    )


@router.get("/ca/install-help", response_class=HTMLResponse)
async def ca_install_help() -> HTMLResponse:
    return HTMLResponse(_env.get_template("ca-help.html.j2").render())


# Phase 6 (#496) : Android PWA manifest + R3 install page
# Android Chrome reads manifest.json + offers 'Add to Home Screen' = PWA
# (Android's equivalent of iOS WebClip).

@router.get("/manifest.json")
async def webapp_manifest(request: Request) -> dict:
    """Web App Manifest for Android Chrome 'Add to Home Screen' PWA install."""
    return {
        "name": "ToolBoX Cabine VILLAGE3B",
        "short_name": "ToolBoX",
        "description": "Cabine numérique Gondwana — diagnostic compromission iPhone/Android",
        "start_url": "/report/me/html",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait",
        "background_color": "#0a0a0f",
        "theme_color": "#00dd44",
        "icons": [
            {
                "src": "/qr/splash.png",
                "sizes": "232x232",
                "type": "image/png",
                "purpose": "any maskable"
            }
        ],
        "categories": ["security", "utilities"],
        "lang": "fr-FR"
    }


@router.get("/wg/r3-install", response_class=HTMLResponse)
async def wg_r3_install(request: Request) -> HTMLResponse:
    """R3 install page — 3-step install with per-OS instructions tabs.

    Optimized for first-time portable setup from anywhere (kbin.gk2.secubox.in).
    Step 1 = WG profile, Step 2 = CA install (per-OS), Step 3 = GO.
    """
    html = """<!DOCTYPE html><html lang=fr><head><meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta name=apple-mobile-web-app-capable content=yes>
<link rel=manifest href=/manifest.json>
<title>R3 — Tunnel portable Gondwana (install all-OS)</title>
<style>:root{--bg:#0a0a0f;--gold:#c9a84c;--phos:#00dd44;--phos-hot:#00ff55;--dim:#006622;--text:#e8e6d9;--purple:#9e76ff;--orange:#ffb347;--err:#e63946;--blue:#5fa8ff}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:'Courier New',Menlo,monospace;line-height:1.5}
body{padding:1.2rem;max-width:720px;margin:auto}
h1{color:var(--gold);text-align:center;font-size:1.4rem;margin-bottom:0.2rem;letter-spacing:2px}
.lead{color:var(--phos);text-align:center;font-size:0.8rem;margin-bottom:1.4rem;opacity:0.85}
.lead b{color:var(--phos-hot)}
.step{border:1px solid #2a2a3f;border-left:4px solid var(--purple);padding:1rem 1.2rem;margin-bottom:1rem;background:linear-gradient(135deg,rgba(110,64,201,0.04),rgba(110,64,201,0.10));border-radius:6px;box-shadow:0 1px 8px rgba(0,0,0,0.25)}
.step h2{color:var(--purple);font-size:1rem;margin-bottom:0.6rem;display:flex;align-items:center;gap:8px}
.num{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;background:var(--purple);color:#0a0a0f;border-radius:50%;font-weight:bold;font-size:0.95rem}
.qr{text-align:center;background:white;padding:14px;border-radius:8px;margin:0.6rem 0;box-shadow:0 2px 10px rgba(158,118,255,0.25)}
.qr img{max-width:300px;width:100%;height:auto}
.btn{display:block;text-align:center;padding:0.85rem 1rem;color:#0a0a0f;text-decoration:none;border-radius:6px;font-weight:bold;margin:0.5rem 0;font-size:0.95rem;transition:all 0.15s}
.btn-go{background:linear-gradient(90deg,var(--phos),var(--phos-hot));color:#0a0a0f;font-size:1.1rem;padding:1rem;letter-spacing:1px;text-shadow:0 0 6px rgba(0,255,85,0.5)}
.btn-warn{background:linear-gradient(90deg,var(--orange),#dd7e0a)}
.btn-small{display:inline-block;padding:0.4rem 0.8rem;background:var(--orange);color:#0a0a0f;border-radius:4px;font-weight:bold;font-size:0.78rem;text-decoration:none;margin:0.2rem 0.3rem 0.2rem 0}
.btn-small.blue{background:var(--blue)}
.btn:hover,.btn-small:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,0.4)}
.alt{font-size:0.72rem;color:#909090;text-align:center;margin-top:0.4rem}
.alt a{color:var(--orange);text-decoration:underline}
.tip{font-size:0.72rem;color:#a0d8a8;background:rgba(0,221,68,0.05);border-left:2px solid var(--phos);padding:0.5rem 0.7rem;margin-top:0.5rem;border-radius:0 3px 3px 0}
.warn{font-size:0.78rem;color:#ffd6a0;background:rgba(255,179,71,0.08);border-left:3px solid var(--orange);padding:0.7rem;margin:0.4rem 0;border-radius:0 4px 4px 0}
.back{display:block;text-align:center;margin-top:1.5rem;color:#666;text-decoration:none;font-size:0.85rem}
.back:hover{color:var(--phos)}
.tabs{display:flex;gap:2px;border-bottom:1px solid #2a2a3f;margin-bottom:0.6rem;flex-wrap:wrap}
.tab{background:transparent;border:0;color:#888;padding:0.5rem 0.9rem;font-family:inherit;font-size:0.82rem;cursor:pointer;border-bottom:2px solid transparent;transition:all 0.15s}
.tab.active{color:var(--purple);border-bottom-color:var(--purple);background:rgba(158,118,255,0.06)}
.tab:hover{color:var(--text)}
.tab-content{display:none;padding:0.4rem 0.2rem}
.tab-content.active{display:block}
.tab-content h3{color:var(--gold);font-size:0.85rem;margin-bottom:0.3rem}
.tab-content ol{padding-left:1.4rem;font-size:0.82rem;line-height:1.7}
.tab-content code{background:#1a1a25;color:var(--phos-hot);padding:0.15rem 0.4rem;border-radius:3px;font-size:0.78rem;display:inline-block;word-break:break-all}
pre{background:#1a1a25;color:var(--phos-hot);padding:0.6rem 0.8rem;border-radius:4px;font-size:0.75rem;overflow-x:auto;margin:0.4rem 0;line-height:1.5}
</style></head><body>

<h1>🌐 R3 — TUNNEL PORTABLE</h1>
<p class=lead>3 étapes · install <b>multi-OS</b> · marche partout (4G / WiFi tiers)</p>

<div class=step>
<h2><span class=num>1</span> 📲 Profil WireGuard</h2>
<p style="font-size:0.85rem;margin-bottom:0.4rem">Installe l'app <b>WireGuard</b> (gratuite, tous OS) puis scanne ce QR :</p>
<div class=qr><img src="/wg/qr.png" alt="QR profil WireGuard"/></div>
<p class=alt>📥 Pas de scanner ? <a href="/wg/profile/new">Télécharger village3b-toolbox.conf</a></p>
<div class=tip>
🌐 <b>WireGuard download :</b>
<a class=btn-small href="https://apps.apple.com/app/wireguard/id1441195209">iOS</a>
<a class=btn-small href="https://play.google.com/store/apps/details?id=com.wireguard.android">Android</a>
<a class=btn-small href="https://www.wireguard.com/install/">Linux/Win/Mac</a>
</div>
</div>

<div class=step>
<h2><span class=num>2</span> 🔐 Certificat R3 (par OS)</h2>
<p style="font-size:0.85rem;margin-bottom:0.5rem">Le CA <b>« Gondwana ToolBoX R3 CA »</b> doit être ajouté à la racine de confiance.</p>

<div class=tabs>
<button class="tab active" data-tab=ios>🍎 iOS / iPad</button>
<button class="tab" data-tab=android>🤖 Android</button>
<button class="tab" data-tab=linux>🐧 Linux</button>
<button class="tab" data-tab=mac>💻 macOS</button>
<button class="tab" data-tab=win>🪟 Windows</button>
</div>

<div class="tab-content active" data-content=ios>
<a href="/wg/ca.mobileconfig" class="btn btn-warn">📲 Installer .mobileconfig (1-tap)</a>
<h3>Puis :</h3>
<ol>
<li>Réglages → Général → <b>VPN et gestion d'appareils</b> → installer le profil</li>
<li>Réglages → Général → Information → <b>Réglages de confiance des certificats</b></li>
<li>Activer le toggle <b>« Gondwana ToolBoX R3 CA »</b> 🟢</li>
</ol>
</div>

<div class="tab-content" data-content=android>
<a href="/wg/toolbox.apk" class="btn btn-go">📱 Installer l'app ToolBoX (1-tap)</a>
<a href="/wg/toolbox.xpi" class="btn">🧩 Extension navigateur (cartographie)</a>
<div class=warn style="margin-top:0.5rem">
✨ <b>Le plus simple</b> : l'app fait tout (CA + tunnel + vérif) en 5 étapes.
Active « sources inconnues » à l'installation. Sinon, méthode manuelle ci-dessous :
</div>
<a href="/wg/ca.crt" class="btn btn-warn">📥 Télécharger CA (.crt format Android)</a>
<div class=warn>
⚠ Chrome ne peut PAS installer un CA directement (sécurité Android 11+).
Tu DOIS passer par les <b>Paramètres système</b>.
<br><br>
🆕 Si tu as déjà un essai raté avec « émis par null » : <b>supprime l'ancien fichier</b>
dans Téléchargements + relance le téléchargement (le CA a été régénéré).
</div>
<h3>Procédure (toutes versions Android 7+) :</h3>
<ol>
<li>Tap <b>📥 Télécharger CA</b> ci-dessus → sauvé dans Téléchargements
   sous <code>gondwana-toolbox-r3-ca.crt</code></li>
<li>Ouvre <b>Paramètres système</b> (pas Chrome / pas Firefox)</li>
<li>→ <b>Sécurité et confidentialité</b> (ou « Sécurité »)</li>
<li>→ <b>Plus de paramètres de sécurité</b> → <b>Chiffrement et authentifiants</b>
   (ou « Identifiants » selon constructeur)</li>
<li>→ <b>Installer un certificat</b> → <b>Certificat d'autorité (CA)</b></li>
<li>Accepter l'avertissement de sécurité</li>
<li>Sélectionne <code>gondwana-toolbox-r3-ca.crt</code> dans Téléchargements</li>
<li>Confirme le PIN/empreinte si demandé</li>
</ol>
<h3>Fallback PEM :</h3>
<a href="/wg/ca.pem" style="color:var(--orange);font-size:0.85rem">📥 Télécharger en .pem</a>
si le .crt ne s'ouvre pas (rare).
<h3>Vérification :</h3>
<pre>Paramètres → Sécurité → Identifiants
de confiance → onglet UTILISATEUR
→ « Gondwana ToolBoX R3 CA » présent ✓</pre>
</div>

<div class="tab-content" data-content=linux>
<a href="/wg/ca.pem" class="btn btn-warn">📥 Télécharger ca.pem</a>
<h3>Debian / Ubuntu :</h3>
<pre>sudo cp ca.pem /usr/local/share/ca-certificates/gondwana-toolbox-r3.crt
sudo update-ca-certificates</pre>
<h3>Fedora / RHEL :</h3>
<pre>sudo cp ca.pem /etc/pki/ca-trust/source/anchors/gondwana-toolbox-r3.crt
sudo update-ca-trust</pre>
<h3>Arch :</h3>
<pre>sudo trust anchor --store ca.pem</pre>
<h3>Vérif Firefox / Chrome :</h3>
<pre># Firefox utilise son propre store
# Chrome utilise NSS :
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," \\
    -n "Gondwana ToolBoX R3 CA" -i ca.pem</pre>
<h3>Tunnel rapide (Linux) :</h3>
<pre>wget /wg/profile/new -O village3b.conf
sudo wg-quick up ./village3b.conf
# stop :
sudo wg-quick down ./village3b.conf</pre>
</div>

<div class="tab-content" data-content=mac>
<a href="/wg/ca.pem" class="btn btn-warn">📥 Télécharger ca.pem</a>
<h3>Install (Keychain Access) :</h3>
<ol>
<li>Double-clic <code>ca.pem</code> → s'ouvre dans <b>Trousseaux d'accès</b></li>
<li>Choisir trousseau <b>Système</b> (pas Login)</li>
<li>Authentifier avec ton mot de passe macOS</li>
<li>Double-clic le cert installé → <b>Approuver</b> → « Toujours approuver »</li>
</ol>
<h3>Ou en CLI :</h3>
<pre>sudo security add-trusted-cert -d -r trustRoot \\
    -k /Library/Keychains/System.keychain ca.pem</pre>
</div>

<div class="tab-content" data-content=win>
<a href="/wg/ca.pem" class="btn btn-warn">📥 Télécharger ca.pem</a>
<h3>Install (PowerShell admin) :</h3>
<pre>Import-Certificate -FilePath .\\ca.pem `
    -CertStoreLocation Cert:\\LocalMachine\\Root</pre>
<h3>Ou GUI :</h3>
<ol>
<li>Double-clic <code>ca.pem</code> → <b>Installer le certificat</b></li>
<li>Emplacement : <b>Ordinateur local</b> (pas Utilisateur courant)</li>
<li>Magasin : <b>Autorités de certification racines de confiance</b></li>
</ol>
</div>
</div>

<div class=step>
<h2><span class=num>3</span> 🚀 Activer le tunnel</h2>
<p style="font-size:0.85rem;margin-bottom:0.5rem">App WireGuard → toggle <b>ON</b> sur le profil <code>village3b-toolbox</code>. L'icône VPN apparaît dans la barre d'état.</p>
<a href="/report/me/html" class="btn btn-go">📊 GO — Voir mon rapport live</a>
<div class=tip>
✓ Trafic chiffré entre device et cabine (jamais en clair sur Internet)<br>
✓ Bandeau apparaît sur toutes les pages HTTPS<br>
✓ Signal / WhatsApp / Telegram / iCloud / banques → <b>passthrough</b> (jamais déchiffrés)
</div>
</div>

<p style="text-align:center;font-size:0.78rem;color:#666;margin-top:1.5rem">
📖 Wiki complet : <a href="https://github.com/CyberMind-FR/secubox-deb/wiki/R3-WireGuard-install" style="color:var(--purple)">github.com/CyberMind-FR/secubox-deb/wiki/R3-WireGuard-install</a>
</p>

<a href="/landing" class=back>← Retour landing</a>

<script>
document.querySelectorAll('.tab').forEach(function(t){
  t.addEventListener('click', function(){
    var tn = this.dataset.tab;
    document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active');});
    this.classList.add('active');
    document.querySelectorAll('.tab-content').forEach(function(x){x.classList.remove('active');});
    document.querySelector('[data-content='+tn+']').classList.add('active');
  });
});
</script>
</body></html>"""
    return HTMLResponse(html)


# ── Phase 6.F (#496) : MITM filtering whitelist ─────────────────────
# Some apps use cert-pinning / E2E protocols that BREAK if mitm decrypts
# their TLS (Signal, WhatsApp, Telegram, Apple Push, banking apps with
# pinned certs). They MUST be bypassed at the mitm layer (ignore_hosts).
# The whitelist file is the single source of truth — admin UI edits it,
# mitm reads it via --set ignore_hosts on (re)start.

MITM_BYPASS_FILE = Path("/var/lib/secubox/toolbox/mitm-bypass.conf")
MITM_BYPASS_SEED_FILE = Path(os.environ.get(
    "SECUBOX_BYPASS_SEED", "/usr/lib/secubox/toolbox/conf/mitm-bypass-seed.conf"))
MITM_BYPASS_DYNAMIC_FILE = Path(os.environ.get(
    "SECUBOX_BYPASS_DYNAMIC", "/var/lib/secubox/toolbox/mitm-bypass-dynamic.conf"))
# TLS-splice lists (host SUFFIX, inline # comments) — the OTHER half of the
# exclusion set: what the R3 engine actually splices. Surfaced in the Filtres
# MITM list so ALL explicit splicing is displayed + known (#803).
TLS_SPLICE_SEED_FILE = Path(os.environ.get(
    "SECUBOX_SPLICE_SEED", "/usr/lib/secubox/toolbox/conf/tls-splice-seed.conf"))
SPLICE_LEARNED_FILE = Path(os.environ.get(
    "SECUBOX_SPLICE_LEARNED", "/var/lib/secubox/toolbox/splice-learned.txt"))
# #806 — federated (mesh-union) lists the R3 engine also reads; surfaced in the
# Filtres MITM list tagged mesh-* (edit on the origin node).
FED_SPLICE_FILE = Path(os.environ.get("SECUBOX_FED_SPLICE", "/var/lib/secubox/toolbox/mitm-exclusion-fed-splice.txt"))
FED_BYPASS_FILE = Path(os.environ.get("SECUBOX_FED_BYPASS", "/var/lib/secubox/toolbox/mitm-exclusion-fed-bypass.txt"))
FED_DISABLED_FILE = Path(os.environ.get("SECUBOX_FED_DISABLED", "/var/lib/secubox/toolbox/mitm-exclusion-fed-disabled.txt"))
# #809 — operator-disabled filter patterns (Filtres MITM uncheck). The R3 engine
# reads this SAME file and suppresses matching per-pattern, so unchecking has
# real effect on ALL sources incl. the package seed.
MITM_FILTER_DISABLED_FILE = Path(os.environ.get(
    "SECUBOX_FILTER_DISABLED", "/var/lib/secubox/toolbox/mitm-filter-disabled.txt"))


def _read_disabled_file(path) -> set:
    try:
        return {ln.split("#", 1)[0].strip()
                for ln in path.read_text().splitlines()
                if ln.split("#", 1)[0].strip()}
    except OSError:
        return set()


def _load_disabled() -> set:
    """Set of operator-disabled patterns (exact strings; # comments stripped).

    #806 fix — union of the LOCAL disabled file with the FEDERATED (mesh-union)
    disabled file: a pattern disabled elsewhere in the fleet must also show
    enabled=false here, matching the R3 engine's disabledLocal ∪ disabledFed."""
    return _read_disabled_file(MITM_FILTER_DISABLED_FILE) | _read_disabled_file(FED_DISABLED_FILE)


def _read_splice(path) -> list:
    """Splice list lines — strips INLINE # comments (the seed uses them)."""
    try:
        out = []
        for ln in path.read_text().splitlines():
            s = ln.split("#", 1)[0].strip()
            if s:
                out.append(s)
        return out
    except OSError:
        return []


def _ensure_bypass_file() -> None:
    if not MITM_BYPASS_FILE.exists():
        MITM_BYPASS_FILE.parent.mkdir(parents=True, exist_ok=True)
        MITM_BYPASS_FILE.write_text(
            "# SecuBox ToolBoX :: operator bypass additions (regex, one per line).\n"
            "# Package cert-pinned defaults live in the read-only seed file;\n"
            "# auto-learned hosts in mitm-bypass-dynamic.conf. Edit via "
            "/admin/filter-control.\n")


def _load_bypass_entries() -> list[str]:
    _ensure_bypass_file()
    try:
        lines = MITM_BYPASS_FILE.read_text().splitlines()
        return [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    except Exception:
        return []


def _read_patterns(path) -> list:
    try:
        return [ln.strip() for ln in path.read_text().splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError:
        return []


def _load_bypass_tagged() -> list:
    """All bypass patterns across the three sources, one row per pattern, tagged
    with the most authoritative source (seed > static > learned)."""
    seen: dict = {}
    for source, path in (("seed", MITM_BYPASS_SEED_FILE),
                         ("static", MITM_BYPASS_FILE),
                         ("learned", MITM_BYPASS_DYNAMIC_FILE)):
        for pat in _read_patterns(path):
            if pat not in seen:        # first wins → seed > static > learned
                seen[pat] = source
    # ALSO surface the TLS-splice list (the R3 engine's actual passthrough set) so
    # every explicitly-spliced host is displayed + known (#803). Bypass wins the
    # tag if a pattern somehow appears in both.
    for source, path in (("splice-seed", TLS_SPLICE_SEED_FILE),
                         ("splice-learned", SPLICE_LEARNED_FILE)):
        for pat in _read_splice(path):
            if pat not in seen:
                seen[pat] = source
    # #806 — surface federated (mesh-union) filter entries from the 3 fed files
    # that the R3 engine also reads; tagged mesh-* so the operator knows they're
    # federation-sourced (edit on the origin node, not here).
    for source, path in (("mesh-splice", FED_SPLICE_FILE),
                         ("mesh-bypass", FED_BYPASS_FILE),
                         ("mesh-disabled", FED_DISABLED_FILE)):
        for pat in _read_splice(path):
            if pat not in seen:
                seen[pat] = source
    # #809 — tag each row: enabled (not operator-disabled) + editable (in a
    # writable file, so 🗑 delete can remove the line; package seeds can only be
    # disabled, not deleted).
    disabled = _load_disabled()
    editable = {"static", "learned", "splice-learned"}
    return [{"pattern": p, "source": s, "enabled": p not in disabled,
             "editable": s in editable}
            for p, s in sorted(seen.items())]


def _is_public_kbin(request: Request) -> bool:
    """Phase 6.J : detect if request comes via the public kbin vhost.
    Public traffic must be READ-ONLY on /admin/filter-control endpoints —
    editing happens only via the auth-gated admin.gk2.secubox.in/toolbox/."""
    host = (request.headers.get("host", "") or "").lower()
    return host.startswith("kbin.")


@router.get("/admin/filter-control", response_class=HTMLResponse)
async def admin_filter_control(request: Request) -> HTMLResponse:
    """Whitelist control panel — VIEW always, EDIT only when reached via
    admin.gk2.secubox.in (auth-gated). Kbin public hits get a read-only
    page with a link to the private editor."""
    entries = _load_bypass_entries()
    readonly = _is_public_kbin(request)
    if readonly:
        # No remove button per row, no add form
        rows = "\n".join(
            f'<tr><td><code>{e}</code></td></tr>'
            for e in entries
        )
    else:
        rows = "\n".join(
            f'<tr><td><code>{e}</code></td><td><form method=POST action=/admin/filter-control/remove style=display:inline><input type=hidden name=entry value="{e}"/><button class=del>✕</button></form></td></tr>'
            for e in entries
        )

    readonly_banner = (
        '<div style="background:rgba(255,179,71,0.08);border-left:3px solid #ffb347;padding:0.7rem;margin-bottom:1rem;border-radius:0 4px 4px 0;font-size:0.85rem;color:#ffd6a0">'
        '🔒 <b>Lecture seule (vhost public kbin).</b> Pour éditer la liste, utilise '
        '<a href="https://admin.gk2.secubox.in/toolbox/" style="color:#ffb347;text-decoration:underline">'
        'admin.gk2.secubox.in/toolbox/</a> (authentifié SSO).'
        '</div>'
    )
    editor_form = (
        '<form method=POST action=/admin/filter-control/add class=add>'
        '<input type=text name=entry placeholder="ex: (.+\\.)?example\\.com" required>'
        '<button class=add type=submit>➕ Ajouter</button></form>'
    )
    readonly_th = '<th>Pattern (regex)</th>'
    editor_th = '<th>Pattern (regex)</th><th></th>'
    html = f"""<!DOCTYPE html><html lang=fr><head><meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Admin :: Filter Control</title>
<style>:root{{--bg:#0a0a0f;--gold:#c9a84c;--phos:#00dd44;--purple:#9e76ff;--text:#e8e6d9;--err:#e63946}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;background:var(--bg);color:var(--text);padding:1.2rem;max-width:780px;margin:auto;line-height:1.5}}
h1{{color:var(--gold);font-size:1.3rem;margin-bottom:0.4rem}}
.lead{{color:var(--purple);font-size:0.85rem;margin-bottom:1.2rem}}
table{{width:100%;border-collapse:collapse;margin-bottom:1rem;background:rgba(110,64,201,0.03);border:1px solid #2a2a3f;border-radius:4px}}
td,th{{padding:0.4rem 0.7rem;border-bottom:1px solid #2a2a3f;font-size:0.8rem;text-align:left}}
th{{background:rgba(110,64,201,0.15);color:var(--purple);font-weight:bold}}
code{{color:var(--phos);background:#111;padding:0.1rem 0.3rem;border-radius:2px}}
.del{{background:var(--err);color:white;border:0;padding:0.2rem 0.5rem;border-radius:3px;cursor:pointer;font-weight:bold}}
input[type=text]{{flex:1;background:#111;color:var(--text);border:1px solid #2a2a3f;padding:0.5rem;border-radius:4px;font-family:monospace;font-size:0.85rem}}
.add{{display:flex;gap:0.5rem;margin:0.5rem 0 1rem}}
button.add{{background:var(--phos);color:#0a0a0f;border:0;padding:0.5rem 1rem;border-radius:4px;cursor:pointer;font-weight:bold}}
.note{{font-size:0.75rem;color:#a0a0a0;background:rgba(255,179,71,0.06);border-left:2px solid #ffb347;padding:0.6rem 0.8rem;margin-top:1rem;border-radius:0 3px 3px 0}}
a.back{{color:var(--purple);text-decoration:underline;font-size:0.85rem}}
</style></head><body>
<h1>🛡️ Mitm Filter Control{" (lecture seule)" if readonly else ""}</h1>
<p class=lead>Hosts bypass — TLS passthrough, jamais déchiffrés. Apps avec cert-pinning ou E2E.</p>

{readonly_banner if readonly else editor_form}

<table>
<tr>{readonly_th if readonly else editor_th}</tr>
{rows or '<tr><td colspan=2 style="color:#666;text-align:center;padding:1rem">Aucune entrée.</td></tr>'}
</table>

<div class=note>
ℹ Les modifications nécessitent un redémarrage de <code>secubox-toolbox-mitm-wg.service</code> + <code>secubox-mitmproxy</code> pour prendre effet.
<br><b>Source de vérité :</b> <code>{MITM_BYPASS_FILE}</code> ({len(entries)} pattern{'s' if len(entries)>1 else ''})
</div>

<p style=margin-top:1.5rem><a href=/admin/ class=back>← Admin home</a></p>
</body></html>"""
    return HTMLResponse(html)


@router.post("/admin/filter-control/add")
async def admin_filter_add(request: Request) -> Response:
    if _is_public_kbin(request):
        raise HTTPException(403, "filter editing disabled on public vhost — use admin.gk2.secubox.in/toolbox/")
    form = await request.form()
    entry = (form.get("entry") or "").strip()
    if entry and "\n" not in entry:
        _ensure_bypass_file()
        with MITM_BYPASS_FILE.open("a") as f:
            f.write(entry + "\n")
    return RedirectResponse("/admin/filter-control", status_code=303)


@router.post("/admin/filter-control/remove")
async def admin_filter_remove(request: Request) -> Response:
    if _is_public_kbin(request):
        raise HTTPException(403, "filter editing disabled on public vhost — use admin.gk2.secubox.in/toolbox/")
    form = await request.form()
    entry = (form.get("entry") or "").strip()
    if entry and MITM_BYPASS_FILE.exists():
        lines = MITM_BYPASS_FILE.read_text().splitlines()
        new_lines = [ln for ln in lines if ln.strip() != entry]
        MITM_BYPASS_FILE.write_text("\n".join(new_lines) + "\n")
    return RedirectResponse("/admin/filter-control", status_code=303)


def _write_disabled(patterns: set) -> None:
    MITM_FILTER_DISABLED_FILE.parent.mkdir(parents=True, exist_ok=True)
    MITM_FILTER_DISABLED_FILE.write_text(
        "# SecuBox ToolBoX :: operator-disabled filter patterns (#809).\n"
        "# Managed via the Filtres MITM webui checkbox. One pattern per line.\n"
        "# The R3 engine reads this file and suppresses matching per-pattern.\n"
        + "".join(sorted(p + "\n" for p in patterns)))


@router.post("/admin/filter-control/toggle")
async def admin_filter_toggle(request: Request) -> dict:
    """#809 — enable/disable a filter pattern (webui checkbox). Toggling adds/
    removes it from the disabled file; the engine hot-reloads and suppresses it.
    Works for ANY source (incl. package seed)."""
    if _is_public_kbin(request):
        raise HTTPException(403, "filter editing disabled on public vhost — use admin.gk2.secubox.in/toolbox/")
    body = await request.json()
    pat = (body.get("pattern") or "").strip()
    if not pat or "\n" in pat:
        raise HTTPException(400, "invalid pattern")
    disabled = _load_disabled()
    if pat in disabled:
        disabled.discard(pat)
        enabled = True
    else:
        disabled.add(pat)
        enabled = False
    _write_disabled(disabled)
    return {"pattern": pat, "enabled": enabled}


@router.post("/admin/filter-control/delete")
async def admin_filter_delete(request: Request) -> dict:
    """#809 — delete a filter entry. Removes the line from any EDITABLE file
    (static/dynamic/splice-learned); a package-seed entry can't be deleted (file
    is read-only) → it is disabled instead."""
    if _is_public_kbin(request):
        raise HTTPException(403, "filter editing disabled on public vhost — use admin.gk2.secubox.in/toolbox/")
    body = await request.json()
    pat = (body.get("pattern") or "").strip()
    if not pat:
        raise HTTPException(400, "invalid pattern")
    removed = False
    for f in (MITM_BYPASS_FILE, MITM_BYPASS_DYNAMIC_FILE, SPLICE_LEARNED_FILE):
        try:
            lines = f.read_text().splitlines()
        except OSError:
            continue
        new = [ln for ln in lines if ln.split("#", 1)[0].strip() != pat]
        if len(new) != len(lines):
            f.write_text("\n".join(new) + ("\n" if new else ""))
            removed = True
    disabled_fallback = False
    if not removed:
        d = _load_disabled()
        d.add(pat)
        _write_disabled(d)
        disabled_fallback = True
    return {"pattern": pat, "deleted": removed, "disabled": disabled_fallback}


@router.get("/admin/filter-control/regex")
async def admin_filter_regex() -> dict:
    """Returns the alternation regex consumable by mitmproxy --set ignore_hosts.
    Used by the mitm-wg/mitm services startup scripts."""
    entries = _load_bypass_entries()
    if not entries:
        return {"regex": "", "count": 0}
    # mitmproxy ignore_hosts wants a single regex; join with | wrapped in non-capture group
    regex = "(" + "|".join(entries) + ")"
    return {"regex": regex, "count": len(entries)}


@router.get("/admin/filter-control/list")
async def admin_filter_list() -> dict:
    """JSON for the #filtres panel — tagged bypass patterns (seed/static/learned)."""
    tagged = _load_bypass_tagged()
    return {"hosts": tagged, "count": len(tagged)}


def _ca_fp(ca_pem) -> dict:
    """SHA1/SHA256/subject of a CA pem via openssl. '?' on any failure."""
    import subprocess
    out = {"sha1": "?", "sha256": "?", "subject": "?"}
    if not ca_pem.exists():
        return out
    try:
        for key, flag in (("sha1", "-sha1"), ("sha256", "-sha256")):
            out[key] = subprocess.run(
                ["openssl", "x509", "-in", str(ca_pem), "-noout", "-fingerprint", flag],
                capture_output=True, text=True, timeout=2, check=False,
            ).stdout.split("=", 1)[-1].strip()
        out["subject"] = subprocess.run(
            ["openssl", "x509", "-in", str(ca_pem), "-noout", "-subject"],
            capture_output=True, text=True, timeout=2, check=False,
        ).stdout.split("=", 1)[-1].strip()
    except Exception:
        pass
    return out


@router.get("/ca/fingerprint")
async def ca_fingerprint(request: Request, ca: str = "auto") -> dict:
    """Expose CA SHA1/SHA256 fingerprints so the user can verify against
    their device's Cert Trust UI. CSPN R2/R3 transparency requirement.

    ?ca=wg → the R3 WireGuard CA ; ?ca=default → the R1/R2 captive CA ;
    auto (default) → R3 when the request arrives over the R3 tunnel
    (X-R3-Peer / 10.99.1.x), else R1/R2. Fixes the landing cert-probe
    showing the wrong (R1/R2) fingerprint to R3 users.
    """
    from pathlib import Path
    r3 = Path("/etc/secubox/toolbox/ca-wg/mitmproxy-ca-cert.pem")
    default = Path("/etc/secubox/toolbox/ca/ca.pem")
    want_wg = False
    if ca == "wg":
        want_wg = True
    elif ca == "auto":
        peer = request.headers.get("x-r3-peer", "") or ""
        xff = request.headers.get("x-forwarded-for", "") or ""
        if peer.startswith("10.99.1.") or "10.99.1." in xff:
            want_wg = True
    path = r3 if (want_wg and r3.exists()) else default
    out = _ca_fp(path)
    out["ca"] = "r3" if path == r3 else "default"
    return out


# Phase 3.x (#497) : 3 QR code endpoints — splash, cert install, webclip
# Used by the splash page + reports + the public poster (POSTER-grand-public).

def _qr_png(payload: str, size: int = 8, border: int = 2) -> bytes:
    """Generate a PNG QR code for the given payload. Returns bytes."""
    import qrcode
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=size,
        border=border,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _portal_url(request: "Request", path: str = "/") -> str:
    """Build absolute URL based on request Host header — works regardless of
    whether the portal is reached via 10.99.0.1, village3b, or external."""
    host = request.headers.get("host", "10.99.0.1:8088")
    scheme = "http"  # captive portal is HTTP-only by design
    return f"{scheme}://{host.rstrip('/')}{path}"


@router.get("/qr/splash.png")
async def qr_splash(request: Request) -> Response:
    """QR encodes the splash URL — scannable from another device to join VILLAGE3B."""
    return Response(content=_qr_png(_portal_url(request, "/")),
                     media_type="image/png",
                     headers={"Cache-Control": "public, max-age=3600"})


@router.get("/qr/cert.png")
async def qr_cert(request: Request) -> Response:
    """QR encodes the CA install URL (.mobileconfig)."""
    return Response(content=_qr_png(_portal_url(request, "/ca/mobileconfig")),
                     media_type="image/png",
                     headers={"Cache-Control": "public, max-age=3600"})


@router.get("/qr/webclip.png")
async def qr_webclip(request: Request) -> Response:
    """QR encodes the webclip URL (Add-to-Home-Screen profile)."""
    return Response(content=_qr_png(_portal_url(request, "/ca/webclip-cabine.mobileconfig")),
                     media_type="image/png",
                     headers={"Cache-Control": "public, max-age=3600"})


# Phase 6 (#496) : WireGuard endpoints — R3 mode

@router.get("/wg/profile/new")
async def wg_profile_new(request: Request) -> Response:
    """Generate a fresh WG profile for this client. Returns .conf content
    suitable for direct import in WireGuard app (iOS + macOS + Linux).

    Phase 6.H (#496) : also registers the new peer in store.clients
    with level=r3 so reports, level lookups, and admin webui all show
    the WG client correctly (otherwise mac_hash is unknown to DB).
    """
    try:
        from . import wg as _wg
    except ImportError:
        raise HTTPException(503, "WG module not available (Phase 6 not provisioned)")
    profile = _wg.generate_client_profile(client_label=request.headers.get("user-agent", "")[:60])

    # Register the freshly generated peer in the clients table so all
    # downstream consumers (store.get_client_level, _aggregate_session,
    # /admin/clients/rich) know about it. mac_hash = sha256(pubkey)[:16].
    import hashlib as _h
    wg_hash = _h.sha256(profile["client_pubkey"].encode()).hexdigest()[:16]
    try:
        store.upsert_client(wg_hash, profile["client_ip"], level="r3")
    except Exception as e:
        log.warning("wg peer upsert failed for %s: %s", wg_hash, e)

    return Response(
        content=profile["conf_text"],
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=village3b-toolbox.conf",
            "X-Client-PubKey": profile["client_pubkey"],
            "X-Client-IP": profile["client_ip"],
            "X-Client-Hash": wg_hash,
        },
    )


@router.get("/wg/onboard", response_class=HTMLResponse)
async def wg_onboard(request: Request) -> HTMLResponse:
    """Phase 7 follow-up (#498) — auto-detect onboarding page.

    Single URL the operator can hand to anyone : detects the visitor's
    OS from the User-Agent and renders the right one-click install
    flow. iPhone → QR + Safari CA mobileconfig button. Android →
    QR + CA .crt link + step-by-step. Linux → .nmconnection download
    + one-line cp command. Windows / macOS → .conf + CA + install
    hint. No device-specific URLs to remember.

    The artefacts themselves stay at the existing endpoints :
        /wg/profile/new                  → wg-quick .conf
        /wg/profile/new.nmconnection     → NetworkManager keyfile
        /wg/ca.mobileconfig              → iOS profile
        /wg/ca.pem                       → CA root cert
        /wg/qr.png                       → QR of the .conf
    """
    ua = (request.headers.get("user-agent") or "").lower()
    # Cheap UA sniffing — good enough for "show the right button first".
    if "iphone" in ua or "ipad" in ua or "ios" in ua:
        platform = "ios"
    elif "android" in ua:
        platform = "android"
    elif "macintosh" in ua or "mac os x" in ua:
        platform = "macos"
    elif "windows" in ua:
        platform = "windows"
    elif "linux" in ua:
        platform = "linux"
    else:
        platform = "other"

    return HTMLResponse(_render_onboard(platform))


def _render_onboard(platform: str) -> str:
    """Plain HTML : minimal CSS, no JS framework. iOS Safari + Android
    Chrome + desktop browsers all render the same markup. Each platform
    gets its dedicated panel expanded by default ; the others are
    collapsed details elements so a user on the wrong device can still
    follow the right flow."""
    panels = {
        "ios":     ("🍎 iPhone / iPad", "ios"),
        "android": ("🤖 Android", "android"),
        "linux":   ("🐧 Linux", "linux"),
        "macos":   ("🍏 macOS", "macos"),
        "windows": ("🪟 Windows", "windows"),
    }
    order = [platform] + [k for k in panels if k != platform]
    # de-dup if platform was "other"
    order = [k for i, k in enumerate(order) if k in panels and k not in order[:i]]

    sections = []
    for key in order:
        title, slug = panels[key]
        body = _ONBOARD_BODY[slug]
        open_attr = " open" if key == order[0] else ""
        sections.append(
            f'<details class="step" id="step-{slug}"{open_attr}>'
            f'<summary><span class="emoji">{title.split()[0]}</span> '
            f'<b>{title}</b></summary>{body}</details>'
        )
    body_html = "\n".join(sections)
    return f"""<!doctype html><html lang=fr><head>
<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Activer SecuBox R3 — Tunnel + Audit</title>
<style>
:root{{--cosmos-black:#0a0a0f;--gold-hermetic:#c9a84c;--matrix-green:#00ff41;
--void-purple:#6e40c9;--text-primary:#e8e6d9;--text-muted:#6b6b7a;
--cinnabar:#e63946;--card:rgba(110,64,201,0.08);--border:rgba(110,64,201,0.4)}}
*{{box-sizing:border-box}}
html,body{{margin:0;padding:0;background:var(--cosmos-black);color:var(--text-primary);
font-family:'JetBrains Mono',ui-monospace,monospace;min-height:100vh}}
header{{padding:1.5rem 1rem 0;text-align:center}}
header h1{{color:var(--matrix-green);font-size:1.4rem;margin:0 0 0.3rem;letter-spacing:0.5px}}
header p{{color:var(--text-muted);margin:0;font-size:0.92rem}}
main{{max-width:560px;margin:1rem auto;padding:0 1rem 4rem}}
.step{{background:var(--card);border:1px solid var(--border);border-radius:10px;
padding:0.9rem 1.1rem;margin:0.75rem 0}}
.step summary{{cursor:pointer;font-size:1.05rem;list-style:none;color:var(--gold-hermetic)}}
.step summary::-webkit-details-marker{{display:none}}
.step[open] summary{{margin-bottom:0.75rem}}
.emoji{{font-size:1.2rem;margin-right:0.35rem}}
.btn{{display:inline-block;padding:0.6rem 1rem;margin:0.35rem 0.25rem 0.35rem 0;
background:var(--void-purple);color:#fff;text-decoration:none;border-radius:8px;
font-weight:bold;font-size:0.92rem}}
.btn.alt{{background:transparent;border:1px solid var(--void-purple);color:var(--void-purple)}}
ol{{padding-left:1.2rem;line-height:1.55}}
code{{background:rgba(0,0,0,0.4);padding:0.12rem 0.4rem;border-radius:4px;
font-size:0.85rem;color:var(--matrix-green)}}
.note{{color:var(--text-muted);font-size:0.85rem;margin-top:0.8rem;
border-left:2px solid var(--gold-hermetic);padding-left:0.7rem}}
footer{{text-align:center;color:var(--text-muted);font-size:0.8rem;padding:1rem}}
footer a{{color:var(--gold-hermetic)}}
</style></head><body>
<header><h1>🛰 SecuBox R3 — Activation</h1>
<p>Choisis ton appareil. La méthode adaptée s'ouvre en premier.</p></header>
<main>{body_html}
<details class=step><summary><span class=emoji>📡</span><b>Comment ça marche</b></summary>
<p>R3 fait passer ton trafic dans un tunnel WireGuard chiffré jusqu'à
ton SecuBox personnel. Une fois le tunnel actif, l'analyseur affiche
un bandeau sur chaque page web visitée — tu peux voir en temps réel
quels services tiers chargent quoi, quels cookies sont posés, quel
fournisseur héberge la requête, etc.</p>
<p class=note>Le certificat racine R3 est généré localement par
<b>ton</b> SecuBox. Il n'est utilisé que pour les flux du tunnel ;
révocable à tout moment depuis Réglages.</p>
</details></main>
<footer>SecuBox-Deb · CyberMind / Gérald Kerma · <a href=https://cybermind.fr>cybermind.fr</a></footer>
</body></html>"""


# Per-platform body fragments — kept in module scope so they're parsed once.
_ONBOARD_BODY = {
    "ios": """
<ol>
<li>Installe l'app <a class=btn href="https://apps.apple.com/app/wireguard/id1441195209" target=_blank rel=noopener>WireGuard</a> depuis l'App Store.</li>
<li>Scanne ton QR :<br><img src="/wg/qr.png" alt="QR code" style="width:240px;max-width:100%;margin:0.5rem 0;border-radius:6px"></li>
<li>Active le tunnel dans WireGuard (bouton vert).</li>
<li>Installe le certificat :<br><a class=btn href="/wg/ca.mobileconfig">📥 Profil iOS (CA R3)</a></li>
<li>Réglages → Profil téléchargé → Installer.</li>
<li>Réglages → Général → Informations → <b>Confiance des certificats racines</b> → active le profil <i>Gondwana ToolBoX</i>.</li>
<li>Ouvre n'importe quel site — le bandeau orange doit apparaître en haut.</li>
</ol>
<p class=note>Si rien ne se passe : Réglages → Batterie → désactive le mode économie (il coupe parfois les VPN).</p>
""",
    "android": """
<p><b>✨ Le plus simple — l'app ToolBoX fait tout :</b></p>
<a class=btn href="/wg/toolbox.apk">📱 Installer l'app ToolBoX (.apk, 1-tap)</a>
<a class=btn href="/wg/toolbox.xpi">🧩 Extension navigateur (cartographie live)</a>
<p class=note>Active « sources inconnues » à l'installation. L'app installe le CA, importe le tunnel et vérifie le R3 en 5 étapes. Sinon, méthode manuelle :</p>
<ol>
<li>Installe l'app <a class=btn href="https://play.google.com/store/apps/details?id=com.wireguard.android" target=_blank rel=noopener>WireGuard</a> depuis le Play Store.</li>
<li>Dans l'app, tap "+" → "Scan from QR code" → scanne ton QR :<br><img src="/wg/qr.png" alt="QR code" style="width:240px;max-width:100%;margin:0.5rem 0;border-radius:6px"></li>
<li>Active le tunnel (interrupteur).</li>
<li>Installe le certificat racine : <a class=btn href="/wg/ca.pem">📥 ca.pem</a> ou <a class=btn alt href="/wg/ca.cer">.cer (DER)</a></li>
<li>Paramètres → Sécurité → Chiffrement et identifiants → Installer un certif depuis le stockage → CA → choisis le fichier.</li>
<li>Ouvre Chrome — le bandeau orange doit apparaître.</li>
</ol>
<p class=note>Sur Android 14+, certains constructeurs (Samsung, Xiaomi) demandent en plus d'autoriser les CA utilisateur dans <i>Paramètres → Sécurité supplémentaire</i>.</p>
""",
    "linux": """
<p>Choisis ton format :</p>
<a class=btn href="/wg/profile/new.nmconnection">📥 NetworkManager keyfile</a>
<a class=btn alt href="/wg/profile/new">📥 wg-quick .conf</a>
<a class=btn alt href="/wg/ca.pem">🔐 CA root .pem</a>
<p><b>NetworkManager (Cosmic / GNOME / KDE) :</b></p>
<pre><code>sudo install -m 0600 village3b-toolbox.nmconnection \\
     /etc/NetworkManager/system-connections/
sudo nmcli connection reload
nmcli connection up village3b-toolbox</code></pre>
<p><b>Ou wg-quick (sans NetworkManager) :</b></p>
<pre><code>sudo cp village3b-toolbox.conf /etc/wireguard/village3b.conf
sudo wg-quick up village3b</code></pre>
<p><b>Faire confiance au CA :</b></p>
<pre><code>sudo cp ca.pem /usr/local/share/ca-certificates/secubox-r3.crt
sudo update-ca-certificates</code></pre>
<p class=note>Pour Firefox : about:preferences#privacy → Voir les certificats → Importer ca.pem dans "Autorités".</p>
""",
    "macos": """
<ol>
<li>Installe <a class=btn href="https://apps.apple.com/app/wireguard/id1451685025" target=_blank rel=noopener>WireGuard</a> depuis le Mac App Store.</li>
<li>Télécharge ton profil :<br><a class=btn href="/wg/profile/new">📥 village3b-toolbox.conf</a></li>
<li>Glisse le .conf sur l'icône WireGuard dans la barre de menu → Active.</li>
<li>Télécharge le CA : <a class=btn alt href="/wg/ca.pem">🔐 ca.pem</a></li>
<li>Ouvre <i>Trousseau d'accès</i> → glisse le ca.pem dans "Système" → double-clique → <b>Toujours approuver</b>.</li>
</ol>
""",
    "windows": """
<ol>
<li>Installe <a class=btn href="https://download.wireguard.com/windows-client/" target=_blank rel=noopener>WireGuard for Windows</a>.</li>
<li>Télécharge ton profil :<br><a class=btn href="/wg/profile/new">📥 village3b-toolbox.conf</a></li>
<li>Dans WireGuard : "Add Tunnel" → "Add Tunnel from file..." → sélectionne le .conf → <b>Activate</b>.</li>
<li>Télécharge le CA : <a class=btn alt href="/wg/ca.pem">🔐 ca.pem</a></li>
<li>Double-clique le .pem → <b>Installer le certificat</b> → Magasin local "Autorités principales de confiance".</li>
</ol>
<p class=note>Sous Edge / Chrome, le bandeau apparaît une fois le tunnel actif. Firefox utilise son propre magasin — importe ca.pem dans Paramètres → Confidentialité → Certificats.</p>
""",
}


@router.get("/wg/profile/new.nmconnection")
async def wg_profile_new_nmconnection(request: Request) -> Response:
    """Phase 7 (#498) — same fresh WG profile but in NetworkManager
    keyfile format. Cosmic / GNOME / KDE's nmcli GUI fail to import
    a plain wg-quick .conf because they store private-key as an
    "agent-owned" secret (`private-key-flags=1`) and refuse to bring
    up the tunnel without --ask.

    This endpoint emits a native .nmconnection : drop it into
    /etc/NetworkManager/system-connections/, chmod 0600, then
    `nmcli connection reload` — the profile is ready to click in the
    Network panel.

        sudo install -m 0600 village3b-toolbox.nmconnection \
             /etc/NetworkManager/system-connections/
        sudo nmcli connection reload
        nmcli connection up village3b-toolbox
    """
    try:
        from . import wg as _wg
    except ImportError:
        raise HTTPException(503, "WG module not available (Phase 6 not provisioned)")
    profile = _wg.generate_client_profile(client_label=request.headers.get("user-agent", "")[:60])

    import hashlib as _h
    wg_hash = _h.sha256(profile["client_pubkey"].encode()).hexdigest()[:16]
    try:
        store.upsert_client(wg_hash, profile["client_ip"], level="r3")
    except Exception as e:
        log.warning("wg peer upsert failed for %s: %s", wg_hash, e)

    return Response(
        content=profile["nm_text"],
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=village3b-toolbox.nmconnection",
            "X-Client-PubKey": profile["client_pubkey"],
            "X-Client-IP": profile["client_ip"],
            "X-Client-Hash": wg_hash,
        },
    )


@router.get("/wg/qr.png")
async def wg_qr(request: Request) -> Response:
    """QR code encoding the WG profile .conf — scannable by the iOS WG app."""
    try:
        from . import wg as _wg
    except ImportError:
        raise HTTPException(503, "WG module not available")
    profile = _wg.generate_client_profile(client_label=request.headers.get("user-agent", "")[:60])
    return Response(
        content=_qr_png(profile["conf_text"], size=6, border=2),
        media_type="image/png",
        headers={"Cache-Control": "no-store"},
    )


@router.get("/wg/ca.pem")
async def wg_ca_pem() -> Response:
    """The mitm-wg-specific CA — REQUIRED for R3 HTTPS interception.

    Separate from the R1/R2 CA at /ca/mobileconfig. iPhone in R3 mode must
    install BOTH the WG profile (tunnel) AND this CA (trust mitm certs).
    """
    p = Path("/etc/secubox/toolbox/ca-wg/mitmproxy-ca-cert.pem")
    if not p.exists():
        raise HTTPException(404, "mitm-wg CA not yet generated")
    return Response(
        content=p.read_bytes(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox-wg.crt"},
    )


@router.get("/wg/ca.der")
@router.get("/wg/ca.crt")
async def wg_ca_der() -> Response:
    """DER (binary) version of the mitm-wg CA. Some Android installers
    (especially Android 11+ Settings → CA certificate) prefer DER over PEM
    and reject the .pem extension. Same cert, just binary-encoded."""
    p = Path("/etc/secubox/toolbox/ca-wg/mitmproxy-ca-cert.cer")
    if not p.exists():
        raise HTTPException(404, "mitm-wg CA DER not yet generated")
    return Response(
        content=p.read_bytes(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox-r3-ca.crt"},
    )


# Android ToolBox app (#531/#536). CI publishes the APK as a GitHub
# release asset on `android-v*` tags ; secubox-toolbox-fetch-apk pulls it
# into the serve path below.  If absent, we redirect to the public
# release so the button always works.
_ANDROID_APK = Path("/var/lib/secubox/toolbox/android/village3b-toolbox.apk")
_ANDROID_APK_RELEASE = (
    "https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/"
    "secubox-toolbox-android.apk"
)


@router.get("/wg/toolbox.apk")
async def wg_toolbox_apk() -> Response:
    """Serve the Android ToolBox installer APK (#536).

    Local file first (sideload from the cabine, works offline) ; if it
    hasn't been fetched yet, 302 to the latest public GitHub release
    asset so the onboard button never dead-ends.
    """
    if _ANDROID_APK.exists() and _ANDROID_APK.stat().st_size > 0:
        return Response(
            content=_ANDROID_APK.read_bytes(),
            media_type="application/vnd.android.package-archive",
            headers={
                "Content-Disposition": "attachment; filename=village3b-toolbox.apk",
                "Cache-Control": "public, max-age=300",
            },
        )
    return RedirectResponse(url=_ANDROID_APK_RELEASE, status_code=302)


# Browser extension (Firefox .xpi), same serve pattern as the APK (#532).
# Tag-pinned URL (not /latest/): the webext release is published with
# make_latest:false so it does not steal "latest" from the Android APK
# release. Bump the tag here when a new webext-v* release is cut.
_WEBEXT_XPI = Path("/var/lib/secubox/toolbox/webext/secubox-toolbox-webext.xpi")
_WEBEXT_XPI_RELEASE = (
    "https://github.com/CyberMind-FR/secubox-deb/releases/download/"
    "webext-v0.1.5/secubox-toolbox-webext.xpi"
)


@router.get("/wg/toolbox.xpi")
async def wg_toolbox_xpi() -> Response:
    """Serve the browser ToolBoX extension .xpi (#532).

    Local file first (install from the cabine, works offline) ; if it
    hasn't been fetched yet, 302 to the latest public GitHub release
    asset so the onboard button never dead-ends.
    """
    if _WEBEXT_XPI.exists() and _WEBEXT_XPI.stat().st_size > 0:
        return Response(
            content=_WEBEXT_XPI.read_bytes(),
            media_type="application/x-xpinstall",
            headers={
                "Content-Disposition": "attachment; filename=secubox-toolbox-webext.xpi",
                "Cache-Control": "public, max-age=300",
            },
        )
    return RedirectResponse(url=_WEBEXT_XPI_RELEASE, status_code=302)


@router.get("/wg/ca.mobileconfig")
async def wg_ca_mobileconfig() -> Response:
    """iOS profile that installs the mitm-wg CA in trust store."""
    import uuid as _uuid
    p = Path("/etc/secubox/toolbox/ca-wg/mitmproxy-ca-cert.pem")
    if not p.exists():
        raise HTTPException(404, "mitm-wg CA not yet generated")
    pem = p.read_text()
    # Strip headers + base64 body
    body_lines = [ln for ln in pem.splitlines() if ln and not ln.startswith("-----")]
    ca_b64 = "\n".join(body_lines)
    payload_uuid = str(_uuid.uuid4()).upper()
    cert_uuid = str(_uuid.uuid4()).upper()
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>fr.cybermind.gondwana.toolbox.wg-ca</string>
<key>PayloadUUID</key><string>{payload_uuid}</string>
<key>PayloadDisplayName</key><string>Gondwana ToolBoX WG CA (R3)</string>
<key>PayloadDescription</key><string>Certificat racine WireGuard mitm pour analyse R3.</string>
<key>PayloadOrganization</key><string>CyberMind / Gondwana</string>
<key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>fr.cybermind.gondwana.toolbox.wg-ca.cert</string>
<key>PayloadUUID</key><string>{cert_uuid}</string>
<key>PayloadDisplayName</key><string>Gondwana ToolBoX WG Root CA</string>
<key>PayloadCertificateFileName</key><string>gondwana-toolbox-wg-ca.pem</string>
<key>PayloadContent</key><data>{ca_b64}</data>
</dict></array></dict></plist>"""
    return Response(
        content=xml,
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox-wg.mobileconfig"},
    )


@router.get("/wg/status")
async def wg_status() -> dict:
    """Running wg-toolbox interface state (peer count, handshakes)."""
    import subprocess
    try:
        out = subprocess.run(
            ["wg", "show", "wg-toolbox"],
            capture_output=True, text=True, timeout=2, check=False,
        ).stdout
        return {"interface": "wg-toolbox", "active": "peer:" in out,
                "peer_count": out.count("peer:"),
                "endpoint": "kbin.gk2.secubox.in:51820"}
    except Exception as e:
        return {"interface": "wg-toolbox", "active": False, "error": str(e)[:80]}


@router.get("/qr/{target}")
async def qr_generic(target: str, request: Request) -> Response:
    """Generic fallback : ?target=splash|cert|webclip|fingerprint maps to fixed
    URLs ; anything else encodes the literal target string."""
    targets = {
        "splash": _portal_url(request, "/"),
        "cert": _portal_url(request, "/ca/mobileconfig"),
        "webclip": _portal_url(request, "/ca/webclip-cabine.mobileconfig"),
        "report": _portal_url(request, "/report/me/html"),
        "fingerprint": _portal_url(request, "/ca/fingerprint"),
    }
    payload = targets.get(target.removesuffix(".png"), target)
    return Response(content=_qr_png(payload),
                     media_type="image/png",
                     headers={"Cache-Control": "public, max-age=3600"})


@router.get("/client-status")
async def client_status(request: Request) -> dict:
    """Health-banner-friendly endpoint : detect captive subnet + R2 consent +
    expose CA fingerprint so the user's browser banner can show MITM presence."""
    ip, mac = _resolve(request)
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt) if mac else None
    # captive_subnet : true if client IP is in the configured DHCP range
    cfg = _get_cfg()
    captive = bool(ip and ip.startswith("10.99.0."))
    # Read CA fingerprint
    import subprocess
    from pathlib import Path
    ca_pem = Path("/etc/secubox/toolbox/ca/ca.pem")
    sha1 = "?"
    if ca_pem.exists():
        try:
            sha1 = subprocess.run(
                ["openssl", "x509", "-in", str(ca_pem), "-noout", "-fingerprint", "-sha1"],
                capture_output=True, text=True, timeout=2, check=False,
            ).stdout.split("=", 1)[-1].strip()
        except Exception:
            pass
    return {
        "captive_subnet": captive,
        "r2_consented": bool(mac and nft.is_consented(mac)),
        "validated": bool(mac and nft.is_validated(mac)),
        "ca_fingerprint_sha1": sha1,
        "ca_subject": "CN = Gondwana ToolBoX CA, O = CyberMind Gondwana, C = FR",
        "mac_hash": mac_hash,
        "session_url": f"http://{cfg.portal.listen_host}:{cfg.portal.listen_port}",
    }


# ───────────────── Report (ephemeral HMAC) ─────────────────

def _aggregate_session(mac_hash: str) -> dict:
    """Aggregate session data from journald (mitmproxy logs) + SQLite events.
    Phase 1.5 :
      - global metrics + apps from journalctl
      - per-MAC DPI / cookies / JA4 / SOC events from SQLite (via local_store addon)
    """
    import json as _json
    import sqlite3 as _sq3
    import subprocess as _sp

    # ── 1. Global metrics from journalctl ──
    # Phase 6.L (#496) : merge BOTH mitm units (captive R2 + WG R3) so the
    # report shows connections/successful/tls_pinned for R3 clients too.
    # Without -u for both, R3 clients always saw 0 connections in metrics.
    try:
        out = _sp.run(
            # #593 — glob matches the live R3 workers (…-mitm-wg-worker@N).
            ["journalctl", "-u", "secubox-toolbox-mitm*",
             "--since", "-30min", "--no-pager"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except Exception:
        out = ""
    connections = out.count("server connect")
    successful = out.count("<< 2") + out.count("<< 30")
    tls_pinned = out.count("Client TLS handshake failed")
    hosts: set[str] = set()
    for line in out.splitlines():
        if " server connect " in line:
            parts = line.rsplit(" ", 1)
            if len(parts) == 2:
                hosts.add(parts[1])

    # ── 2. Per-MAC events from SQLite (local_store addon) ──
    dpi_hosts: dict[str, int] = {}
    dpi_methods: dict[str, int] = {}
    user_agents: set[str] = set()
    cookies_urls: list[dict] = []
    cookies_hosts: dict[str, int] = {}
    cookies_total_set = 0
    cookies_total_sent = 0
    soc_indicators: list[dict] = []
    ja4_snis: set[str] = set()
    ja4_alpns: set[str] = set()
    # Phase 3 (#492) : transparency layer state
    analysis_breakdown: dict[str, int] = {}
    host_analysis: dict[str, dict] = {}
    try:
        with _sq3.connect("/var/lib/secubox/toolbox/toolbox.db", timeout=2) as c:
            cur = c.execute(
                "SELECT source, payload FROM events WHERE mac_hash=? AND ts > ? "
                "ORDER BY ts DESC LIMIT 500",
                (mac_hash, int(time.time()) - 86400),
            )
            for source, payload_json in cur.fetchall():
                try:
                    p = _json.loads(payload_json)
                except Exception:
                    continue
                if source == "dpi":
                    host = p.get("host", "?")
                    dpi_hosts[host] = dpi_hosts.get(host, 0) + 1
                    m = p.get("method", "")
                    if m:
                        dpi_methods[m] = dpi_methods.get(m, 0) + 1
                    ua = p.get("user_agent")
                    if ua:
                        user_agents.add(ua[:80])
                    # Phase 3 (#492) : analysis_status breakdown
                    status = p.get("analysis_status")
                    if status:
                        analysis_breakdown[status] = analysis_breakdown.get(status, 0) + 1
                        # Keep a per-host status for the quality table
                        host_analysis[host] = {
                            "status": status,
                            "reason": p.get("analysis_reason", ""),
                        }
                elif source == "cookies":
                    cookies_total_set += p.get("set_cookie_count", 0)
                    cookies_total_sent += p.get("cookie_count", 0)
                    # Phase 6.L : extract host from URL for classifier merge
                    # (independent of the cookies_urls 15-cap which is just for
                    # the report's bypass detail table)
                    _url = p.get("url", "")
                    if "://" in _url:
                        _h = _url.split("://", 1)[1].split("/", 1)[0]
                        if _h:
                            cookies_hosts[_h] = cookies_hosts.get(_h, 0) + 1
                    if len(cookies_urls) < 15:
                        cookies_urls.append({
                            "url": p.get("url", "?")[:120],
                            "set": p.get("set_cookie_count", 0),
                            "sent": p.get("cookie_count", 0),
                            "set_cookie_names": p.get("set_cookie_names", []),
                            "cookie_names": p.get("cookie_names", []),
                            "status": p.get("status"),
                        })
                elif source == "soc":
                    if len(soc_indicators) < 15:
                        soc_indicators.append({
                            "host": p.get("host", "?"),
                            "kind": p.get("kind", "?"),
                            "weight": p.get("weight", 0),
                        })
                elif source == "ja4":
                    if p.get("sni"):
                        ja4_snis.add(p["sni"])
                    for alpn in p.get("alpn_protocols", []) or []:
                        if isinstance(alpn, str):
                            ja4_alpns.add(alpn)
                        elif isinstance(alpn, bytes):
                            ja4_alpns.add(alpn.decode("ascii", errors="ignore"))
    except Exception:
        pass

    # Phase 6.L (#496) : drop IP-only entries before classification
    def _looks_like_ip(s: str) -> bool:
        if not s:
            return False
        # IPv4 : 4 numeric segments
        parts = s.split(":")[0].split(".")
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    # Phase 2a+ : combine DPI hosts (HTTP host or IP) with JA4 SNIs to get
    # real hostnames for classification. iOS captive probes + cert-pinned apps
    # only expose SNIs ; we lose ~80% of classification data without this merge.
    # Phase 6.L (#496) : also merge cookies URL hosts. R3 Chrome on Android
    # records mostly raw IPs in dpi events (Chrome IP-direct + ECH hides SNI),
    # so cookies URLs are the only reliable source of hostnames.
    classifiable_hosts: dict[str, int] = {}
    for h, n in dpi_hosts.items():
        # Skip IP-only entries (no dot or all-numeric segments)
        if h and not _looks_like_ip(h):
            classifiable_hosts[h] = classifiable_hosts.get(h, 0) + n
    for sni in ja4_snis:
        classifiable_hosts[sni] = classifiable_hosts.get(sni, 0) + 1
    # Cookies hosts : full coverage (not capped at 15 like cookies_urls)
    for host, n in cookies_hosts.items():
        if not _looks_like_ip(host):
            classifiable_hosts[host] = classifiable_hosts.get(host, 0) + n

    # ── 3. Phase 2a SOC scoring : threat-intel + DGA + beaconing ──
    # Threat-intel : match IPs in feeds (resolve hosts isn't done here — match domains
    # directly). On DPI hosts (which are domain names from SNI/Host) we check both.
    ti_matches: list[dict] = []
    unique_hosts_list = list(classifiable_hosts.keys())
    for host in unique_hosts_list:
        for m in threat_intel.is_malicious_domain(host):
            m["ioc"] = host
            ti_matches.append(m)
    # Also check raw IPs seen in mitm logs
    for h in hosts:
        ip = h.split(":")[0]
        # crude IP detection : has dot + all digits
        if ip.replace(".", "").isdigit():
            for m in threat_intel.is_malicious_ip(ip):
                m["ioc"] = ip
                ti_matches.append(m)

    # DGA heuristic on domains
    dga_candidates = dga.analyze_hosts(unique_hosts_list)

    # Beaconing analysis from SQLite cadence
    beacon_candidates = beaconing.analyze_beaconing(mac_hash)

    # Multi-signal score
    score_result = scoring.compute_score(
        threat_intel_matches=ti_matches,
        dga_candidates=dga_candidates,
        beaconing_candidates=beacon_candidates,
        raw_soc_events=soc_indicators,
    )
    risk_score = score_result["score"]

    # ── 4. Top DPI hosts (Phase 1.5 = simple ranking) ──
    # Use combined (DPI + SNI) so classification works on FQDNs not IPs
    top_dpi = sorted(classifiable_hosts.items(), key=lambda x: -x[1])[:15]

    return {
        "device_type": "Smartphone (auto-detected)",
        "metrics": {
            "connections": connections,
            "unique_hosts": len(hosts),
            "successful": successful,
            "tls_pinned": tls_pinned,
        },
        "apps_detected": _classify_apps(hosts),
        "risk_score": risk_score,
        "risk_label": score_result["label"],
        "risk_explanation": score_result["explanation"],
        "indicators": score_result["indicators_summary"] or [
            "Aucun signal de compromission détecté.",
        ],
        "pinned_apps": [
            "Signal Messenger : E2E chiffre - ToolBox NE PEUT PAS lire tes messages",
            "Banking apps : cert pinned - tes apps banque sont protegees",
            "Apple iCloud : cert pinned - tes donnees Apple sont protegees",
            "GitHub : cert pinned - ton code source est protege",
        ],
        "inspected_urls": [u["url"] for u in cookies_urls][:15] if cookies_urls else [],
        "recommendations": [
            "Continue d'utiliser Signal pour les conversations sensibles",
            "Active la 2FA sur tes comptes Google/Apple/GitHub",
            "Verifie periodiquement les profils installes sur ton iPhone",
            "Retire le profil Gondwana ToolBoX CA a la fin de ta session",
        ],
        # ── Phase 1.5 dpi/cookies/soc/ja4 ──
        "dpi": {
            "top_hosts": [{"host": h, "count": n} for h, n in top_dpi],
            "methods": dpi_methods,
            "user_agents": list(user_agents)[:5],
        },
        "cookies": {
            "total_set": cookies_total_set,
            "total_sent": cookies_total_sent,
            "details": cookies_urls,
        },
        "soc": {
            "indicators": soc_indicators,
            "score": risk_score,
        },
        "ja4": {
            "snis_seen": list(ja4_snis)[:10],
            "alpns_seen": list(ja4_alpns),
        },
        # ── Phase 2a SOC scoring ──
        "scoring": {
            "score": score_result["score"],
            "label": score_result["label"],
            "explanation": score_result["explanation"],
            "breakdown": score_result["breakdown"],
        },
        "threat_intel_matches": _enrich_with_geo(ti_matches[:10]),
        "dga_candidates": _enrich_dga_with_geo(dga_candidates[:10]),
        "beaconing_candidates": _enrich_beacon_with_geo(beacon_candidates[:10]),
        # ── Phase 2a+ (#486) geo + app classification + UA analyzer ──
        "dpi_classified": dpi_class.analyze_hosts(unique_hosts_list[:50]),
        "geo_top_hosts": _enrich_top_dpi_with_geo(top_dpi),
        "avatar_analysis": avatar_analysis.analyze_user_agents(user_agents),
        "cookies_providers": cookie_analysis.top_providers(cookies_urls, limit=10),
        # ── Phase 2b (#488) : pull events from receiving modules ──
        "mitm_modules": _pull_mitm_module_events(mac_hash),
        # ── Phase 3 (#492) : transparency layer ──
        "transparency": _build_transparency(
            analysis_breakdown, host_analysis, dpi_hosts, ja4_snis,
        ),
    }


def _build_transparency(
    breakdown: dict[str, int],
    host_analysis: dict[str, dict],
    dpi_hosts: dict[str, int],
    ja4_snis: set,
) -> dict:  # noqa: C901
    """Phase 3 (#492) : pack the inspection breakdown + per-host quality table.

    The breakdown shows what % of traffic was inspected / bypassed / pinned /
    e2e. The per-host quality table grades each destination via passive or
    active signals (currently passive, since header capture is not yet wired).
    """
    total = sum(breakdown.values()) or 1
    pct = {k: round(100 * v / total, 1) for k, v in breakdown.items()}

    # Backfill any host without explicit analysis_status (legacy events)
    for h in dpi_hosts:
        if h not in host_analysis:
            # Best-effort post-hoc tag : whitelist match → bypass, else inspected
            target = h.lower()
            if _HAS_TRANSPARENCY and _whitelist_mod.is_whitelisted(target):
                host_analysis[h] = {
                    "status": "bypassed-whitelist",
                    "reason": (_whitelist_mod.match(target) or {}).get("reason", ""),
                }
            else:
                host_analysis[h] = {
                    "status": "inspected",
                    "reason": "MITM decryption (post-hoc tag)",
                }

    # Build per-host quality (passive grading from what we have)
    per_host: list[dict] = []
    if _HAS_TRANSPARENCY:
        for h, info in host_analysis.items():
            status = info.get("status", "inspected")
            is_e2e = status == "e2e-opaque"
            # We don't know tls_version per host without further capture ; assume
            # 13 for whitelisted (cert-pinned apps use modern TLS) and unknown otherwise
            tls_v = "13" if status in ("bypassed-whitelist", "pinned-failed-mitm", "e2e-opaque") else None
            g = _sec_quality.grade_passive(
                tls_version=tls_v,
                sni=h if h in ja4_snis else None,
                is_e2e_messaging=is_e2e,
            )
            per_host.append({
                "host": h,
                "grade": g["grade"],
                "score": g["score"],
                "status": status,
                "reason": info.get("reason", ""),
            })
        # Sort : worst quality first (catches user attention)
        per_host.sort(key=lambda x: (x["score"], x["host"]))

    # Whitelist sanity stats
    wl_stats = _whitelist_mod.stats() if _HAS_TRANSPARENCY else {"count": 0}

    # Phase 3 (#492) : count whitelist hits per pattern + per category.
    # iPhone usage stores IPs in dpi_hosts (cert-pinning bypasses) but SNIs
    # in ja4_snis (TLS clienthello visible). Iterate BOTH so apple.com etc.
    # actually match patterns like *.apple.com.
    wl_hits_by_pattern: dict[str, int] = {}
    wl_hits_by_category: dict[str, int] = {}
    wl_hits_total = 0
    if _HAS_TRANSPARENCY:
        # Merge dpi_hosts (IP-tagged counts) and ja4_snis (FQDN tags with count 1)
        all_hosts: dict[str, int] = dict(dpi_hosts)
        for sni in ja4_snis:
            all_hosts[sni] = all_hosts.get(sni, 0) + 1
        for h, count in all_hosts.items():
            entry = _whitelist_mod.match(h)
            if entry:
                pat = entry.get("pattern", h)
                cat = entry.get("category", "other")
                wl_hits_by_pattern[pat] = wl_hits_by_pattern.get(pat, 0) + count
                wl_hits_by_category[cat] = wl_hits_by_category.get(cat, 0) + count
                wl_hits_total += count

    # Phase 3 (#492) : attempt counters — full transparency including failures
    attempts = {
        "total": sum(breakdown.values()),
        "inspected": breakdown.get("inspected", 0),
        "bypassed_whitelist": breakdown.get("bypassed-whitelist", 0),
        "pinned_failed": breakdown.get("pinned-failed-mitm", 0),
        "e2e_opaque": breakdown.get("e2e-opaque", 0),
        "blocked": breakdown.get("blocked", 0),  # Phase 4 placeholder
    }

    # Sensitivity profile info (rule engine)
    sensitivity = None
    try:
        from secubox_core import rule_engine as _re
        sensitivity = _re.get_sensitivity()
    except Exception:
        pass

    return {
        "breakdown": breakdown,
        "breakdown_pct": pct,
        "total_events": total,
        "per_host": per_host[:50],
        "whitelist_stats": wl_stats,
        "has_transparency": _HAS_TRANSPARENCY,
        # Phase 3 metrics for richer reporting
        "attempts": attempts,
        "whitelist_hits": {
            "total": wl_hits_total,
            "top_patterns": sorted(
                [{"pattern": k, "count": v} for k, v in wl_hits_by_pattern.items()],
                key=lambda x: -x["count"],
            )[:15],
            "by_category": wl_hits_by_category,
        },
        "sensitivity": sensitivity,
    }


# ── Phase 2b (#488) : cross-module mitm events pull ──

_MITM_MODULES = [
    ("dpi", "/run/secubox/dpi.sock"),
    ("cookies", "/run/secubox/cookies.sock"),
    ("avatar", "/run/secubox/avatar.sock"),
    ("soc", "/run/secubox/soc.sock"),
    ("threat-analyst", "/run/secubox/threat-analyst.sock"),
]


def _pull_mitm_module_events(mac_hash: str, limit: int = 50) -> dict:
    """Query each receiving module's GET /mitm-events for this client.

    Returns a dict {module: {count, sample_events, enriched_summary}} for the
    report. Errors per module are non-fatal — if a module is down, it just
    shows count=0.

    Phase 2c (#490) : also build an enriched_summary per module aggregating
    the enrich_hook output (top apps from dpi, top providers from cookies,
    devices from avatar, JA4 fingerprints from threat-analyst, score band
    from soc).
    """
    import socket as _sock
    import urllib.parse as _up
    import http.client as _hc

    out: dict[str, dict] = {}
    for kind, sock_path in _MITM_MODULES:
        try:
            class UDSConnection(_hc.HTTPConnection):
                def connect(self):
                    self.sock = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
                    self.sock.settimeout(self.timeout)
                    self.sock.connect(sock_path)

            conn = UDSConnection("localhost", timeout=2)
            qs = _up.urlencode({"mac_hash": mac_hash, "limit": limit})
            conn.request("GET", f"/mitm-events?{qs}")
            resp = conn.getresponse()
            if resp.status == 200:
                import json as _json
                data = _json.loads(resp.read().decode("utf-8", errors="ignore")[:200000])
                events = data.get("events", [])
                out[kind] = {
                    "count": data.get("count", 0),
                    "sample": events[:5],
                    "enriched_summary": _summarize_enriched(kind, events),
                }
            else:
                out[kind] = {"count": 0, "error": f"HTTP {resp.status}"}
            conn.close()
        except FileNotFoundError:
            out[kind] = {"count": 0, "error": "socket-missing"}
        except Exception as e:
            out[kind] = {"count": 0, "error": str(e)[:60]}
    return out


def _summarize_enriched(kind: str, events: list[dict]) -> dict:
    """Phase 2c (#490) : per-module aggregation of enrich_hook output.

    Each receiving module attaches its enrich_hook result under 'enriched'
    inside the event payload. This function consolidates them into a
    compact summary suitable for the /report display.
    """
    if not events:
        return {}
    if kind == "dpi":
        apps: dict[str, dict] = {}
        for ev in events:
            e = (ev.get("payload") or {}).get("enriched") or {}
            app = e.get("app")
            if not app or app == "?":
                continue
            if app not in apps:
                apps[app] = {"count": 0, "category": e.get("category"), "emoji": e.get("emoji")}
            apps[app]["count"] += 1
        top = sorted([{"app": k, **v} for k, v in apps.items()], key=lambda x: -x["count"])[:15]
        return {"top_apps": top, "classified_events": sum(v["count"] for v in apps.values())}
    if kind == "cookies":
        providers: dict[str, dict] = {}
        total_trackers = 0
        for ev in events:
            e = (ev.get("payload") or {}).get("enriched") or {}
            for p, info in (e.get("providers") or {}).items():
                if p not in providers:
                    providers[p] = {"count": 0, "category": info.get("category"), "emoji": info.get("emoji")}
                providers[p]["count"] += info.get("count", 1)
                total_trackers += info.get("count", 1)
        top = sorted([{"provider": k, **v} for k, v in providers.items()], key=lambda x: -x["count"])[:10]
        return {"top_providers": top, "tracker_total": total_trackers}
    if kind == "avatar":
        devices: dict[str, dict] = {}
        browsers: dict[str, dict] = {}
        for ev in events:
            e = (ev.get("payload") or {}).get("enriched") or {}
            d = e.get("device")
            if d and d != "unknown":
                if d not in devices:
                    devices[d] = {"count": 0, "emoji": e.get("device_emoji"), "os_label": e.get("os_label")}
                devices[d]["count"] += 1
            b = e.get("browser")
            if b and b != "unknown":
                if b not in browsers:
                    browsers[b] = {"count": 0, "emoji": e.get("browser_emoji"), "label": e.get("browser_label")}
                browsers[b]["count"] += 1
        return {"devices": devices, "browsers": browsers}
    if kind == "threat-analyst":
        fps: dict[str, dict] = {}
        for ev in events:
            e = (ev.get("payload") or {}).get("enriched") or {}
            fp = e.get("ja4_fingerprint")
            if not fp:
                continue
            if fp not in fps:
                fps[fp] = {
                    "count": 0,
                    "known_client": e.get("known_client"),
                    "raw_repr": e.get("ja4_raw_repr"),
                }
            fps[fp]["count"] += 1
        top = sorted([{"fingerprint": k, **v} for k, v in fps.items()], key=lambda x: -x["count"])[:10]
        return {"top_fingerprints": top, "unique_count": len(fps)}
    if kind == "soc":
        total_w = 0
        kinds_seen: dict[str, int] = {}
        max_band = "low"
        band_order = ["low", "medium", "high"]
        for ev in events:
            e = (ev.get("payload") or {}).get("enriched") or {}
            total_w += e.get("total_weight") or 0
            for k in e.get("indicator_kinds") or []:
                kinds_seen[k] = kinds_seen.get(k, 0) + 1
            b = e.get("band") or "low"
            if band_order.index(b) > band_order.index(max_band):
                max_band = b
        return {"total_weight": total_w, "max_band": max_band, "indicator_kinds": kinds_seen}
    return {}


def _enrich_with_geo(matches: list[dict]) -> list[dict]:
    """Add geo info to threat_intel matches."""
    out = []
    for m in matches:
        ioc = m.get("ioc") or ""
        info = geo.lookup(ioc) if ioc else {}
        out.append({**m, "flag": info.get("flag", ""), "country": info.get("country_iso", ""), "asn_org": info.get("asn_org", "")})
    return out


def _enrich_dga_with_geo(candidates: list[dict]) -> list[dict]:
    out = []
    for c in candidates:
        info = geo.lookup(c.get("host", ""))
        out.append({**c, "flag": info.get("flag", ""), "country": info.get("country_iso", ""), "asn_org": info.get("asn_org", "")})
    return out


def _enrich_beacon_with_geo(candidates: list[dict]) -> list[dict]:
    out = []
    for c in candidates:
        info = geo.lookup(c.get("host", ""))
        out.append({**c, "flag": info.get("flag", ""), "country": info.get("country_iso", ""), "asn_org": info.get("asn_org", "")})
    return out


def _enrich_top_dpi_with_geo(top_dpi: list[tuple]) -> list[dict]:
    """Enrich top_dpi with geo + dpi_class + emoji."""
    out = []
    for host, count in top_dpi:
        info = geo.lookup(host)
        cls = dpi_class.classify_host(host)
        out.append({
            "host": host,
            "count": count,
            "flag": info.get("flag", ""),
            "country": info.get("country_iso", ""),
            "asn": info.get("asn", 0),
            "asn_org": info.get("asn_org", ""),
            "app": cls["app"],
            "category": cls["category"],
            "emoji": cls["emoji"],
        })
    return out


def _classify_apps(hosts: set[str]) -> list[str]:
    """Quick IP-based app classification (Phase 1.5 heuristic)."""
    apps = []
    by_prefix = {
        "17.": "Apple Services (iCloud, App Store, Apple Push)",
        "76.223.": "AWS-hosted services (Signal, etc.)",
        "140.82.": "GitHub",
        "172.217.": "Google services",
        "142.251.": "Google services",
        "151.101.": "Fastly CDN (multiple apps)",
    }
    seen_categories: set[str] = set()
    for host in hosts:
        ip = host.split(":")[0]
        for prefix, label in by_prefix.items():
            if ip.startswith(prefix) and label not in seen_categories:
                apps.append(label)
                seen_categories.add(label)
                break
    if not apps:
        apps.append("Trafic generique - pas d'app pre-classifiee")
    return apps


def _build_report_charts(graph: dict) -> dict:
    """Graph-ready aggregates for the report, from the LIVE social graph
    (social.fetch_graph). The events table froze at the #662 cutover, so the
    report reads the SAME source as /social + the webext (was the bug: it read
    the dead events → all zeros). Returns trackers donut + countries bars + sites
    bars; trackers also carry cumulative start/end for the CSS conic-gradient."""
    def _top_pct(items: list, n: int = 6) -> list:
        items = [it for it in items if it.get("count")]
        items.sort(key=lambda x: x["count"], reverse=True)
        items = items[:n]
        total = sum(x["count"] for x in items) or 1
        for it in items:
            it["pct"] = round(100 * it["count"] / total)
        return items

    g = graph or {}
    nodes = g.get("nodes") or []

    trackers = _top_pct([
        {"label": (n.get("domain") or n.get("id") or "?"), "emoji": "🍪",
         "count": int(n.get("hits", 0) or 0)} for n in nodes])
    cum = 0
    for it in trackers:
        it["start"] = cum
        cum += it["pct"]
        it["end"] = cum

    countries = _top_pct([
        {"flag": c.get("flag") or "🏴", "label": (c.get("country_iso") or "?"),
         "count": int(c.get("hits", 0) or 0)} for c in (g.get("by_country") or [])])

    # top tracked sites = number of DISTINCT trackers reaching each first-party
    # site (from each node's sites list) — "where you're tracked most".
    site_trk: dict = {}
    for n in nodes:
        for s in (n.get("sites") or []):
            if s:
                site_trk[s] = site_trk.get(s, 0) + 1
    sites = _top_pct([{"label": s, "emoji": "🌐", "count": c}
                      for s, c in site_trk.items()])

    return {"trackers": trackers, "countries": countries, "sites": sites}


# #699 — DPI exfil donuts for the kbin report (Pistage / DPI-Exfil / Overall
# tabs). Read straight from the secubox-dpi collector state (same wg-hash
# identity as the report's mac_hash). Fail-empty so the report renders before the
# first capture window.
_DPI_STATE_PATH = Path("/var/lib/secubox/dpi/state.json")
# #705 — prefer the 7d cumulative rollup (so the report shows history, not just
# the last 60s window); fall back to the live state.json.
_DPI_CUMUL_PATH = Path("/var/lib/secubox/dpi/cumulative.json")
_DPI_CAT_EMOJI = {
    "cloud": "☁️", "filehost": "📦", "messaging": "💬", "ai": "🤖",
    "media": "🎬", "game": "🎮", "social": "👥", "adult": "🔞",
}
_DPI_ALERT_EMOJI = {
    "exfil_volume": "⬆️", "new_cloud": "☁️", "beaconing": "📡",
    "unclassified_external": "❔",
}


def _dpi_donut(items: list, n: int = 6) -> list:
    """top-N + pct + cumulative start/end for a CSS conic-gradient donut."""
    items = [it for it in items if it.get("count")]
    items.sort(key=lambda x: x["count"], reverse=True)
    items = items[:n]
    total = sum(x["count"] for x in items) or 1
    cum = 0
    for it in items:
        it["pct"] = round(100 * it["count"] / total)
        it["start"] = cum
        cum += it["pct"]
        it["end"] = cum
    return items


def _dpi_stats(mac_hash: str | None) -> dict:
    """Build DPI donut data for THIS device (me) and board-wide (overall) from
    the secubox-dpi collector state. Returns {me, all}, each with categories /
    protocols / alerts / destinations donuts (+ summary counters)."""
    import json
    st = {}
    for p in (_DPI_CUMUL_PATH, _DPI_STATE_PATH):  # #705 cumulative first, live fallback
        try:
            if p.exists():
                st = json.loads(p.read_text())
                break
        except Exception:
            continue
    devices = st.get("devices") or []

    def cats(bycat: dict) -> list:
        return _dpi_donut([{"label": k, "emoji": _DPI_CAT_EMOJI.get(k, "🌐"),
                            "count": v} for k, v in (bycat or {}).items()])

    def alerts(alist: list) -> list:
        by: dict = {}
        for a in alist or []:
            k = a.get("kind") or "?"
            by[k] = by.get(k, 0) + 1
        return _dpi_donut([{"label": k.replace("_", " "),
                            "emoji": _DPI_ALERT_EMOJI.get(k, "⚠️"), "count": c}
                           for k, c in by.items()])

    # ── this device ──
    me = next((d for d in devices if d.get("device") == mac_hash), None) or {}
    me_protos: dict = {}
    me_dests: list = []
    for s in (me.get("services") or []):
        p = s.get("proto") or "unknown"
        me_protos[p] = me_protos.get(p, 0) + int(s.get("up_bytes", 0) or 0) + int(s.get("down_bytes", 0) or 0)
        me_dests.append({"label": s.get("service") or s.get("dst") or "?",
                         "emoji": _DPI_CAT_EMOJI.get(s.get("category"), "🌐"),
                         "count": int(s.get("up_bytes", 0) or 0)})
    me_stats = {
        "present": bool(me),
        "flows": me.get("flows", 0), "up": me.get("up_bytes", 0), "down": me.get("down_bytes", 0),
        "alert_count": len(me.get("alerts") or []),
        "categories": cats(me.get("by_category")),
        "protocols": _dpi_donut([{"label": k, "emoji": "📡", "count": v} for k, v in me_protos.items()]),
        "alerts": alerts(me.get("alerts")),
        # #792 — donut 'alerts' loses the per-alert fields; keep the RAW collector
        # alerts (kind/service/dst/detail) for the persona Quêtes section.
        "alerts_raw": me.get("alerts") or [],
        "destinations": _dpi_donut(me_dests),
    }

    # ── overall (board) ──
    all_cats: dict = {}
    for d in devices:
        for k, v in (d.get("by_category") or {}).items():
            all_cats[k] = all_cats.get(k, 0) + v
    all_stats = {
        "devices": len(devices),
        "flows": sum(int(d.get("flows", 0) or 0) for d in devices),
        "alert_count": st.get("alert_count", 0),
        "categories": cats(all_cats),
        "protocols": _dpi_donut([{"label": p.get("name"), "emoji": "📡",
                                  "count": int(p.get("bytes", 0) or 0)} for p in (st.get("top_protocols") or [])]),
        "alerts": alerts(st.get("alerts")),
        "destinations": _dpi_donut([{"label": a.get("name"), "emoji": "🌐",
                                     "count": int(a.get("bytes", 0) or 0)} for a in (st.get("top_apps") or [])]),
    }
    return {"me": me_stats, "all": all_stats}


def _media_stats(mac_hash: str | None) -> dict:
    """#785 — media-type donut data (MIME captured by sbxmitm R4) for THIS
    device (me) and board-wide (all). Reuses _dpi_donut for pct/start/end so the
    donuts render identically to the DPI-exfil ones. Fail-empty."""
    try:
        from secubox_core import media_catch
        agg = media_catch.aggregate(path=media_catch.MEDIA_CATCH_PATH, mac_hash=mac_hash)
    except Exception:  # pragma: no cover — helper is fail-empty, this is belt+braces
        agg = {"me": {}, "all": {}}

    def _shape(view: dict) -> dict:
        view = view or {}
        return {
            "present": bool(view.get("present")),
            "flows": view.get("flows", 0),
            "bytes": view.get("bytes", 0),
            "kinds": _dpi_donut(list(view.get("kinds") or [])),
            "ctypes": _dpi_donut(list(view.get("ctypes") or [])),
            "top_hosts": view.get("top_hosts") or [],
        }

    return {"me": _shape(agg.get("me")), "all": _shape(agg.get("all"))}


def _build_pdf_donuts(mac_hash: str | None, data: dict) -> list:
    """#703 — assemble the 4 device-stat donuts for the PDF (mitm/certs/ads/dpi)
    from LIVE sources (DPI collector + ad-block SQLite); the events table is
    frozen post-#662 so we never read it. Each donut's segments carry pct +
    cumulative start/end (via _dpi_donut)."""
    me = (data.get("dpi_exfil") or {}).get("me") or {}
    # ads — per-device blocked ad hosts (Go adstats → SQLite)
    try:
        ads = store.ad_client_stats(mac_hash, hours=24, top=6)
    except Exception:
        ads = {"total": 0, "top_hosts": []}
    ads_segs = _dpi_donut([{"label": h.get("host", "?"), "emoji": "🚫",
                            "count": int(h.get("hits", 0) or 0)} for h in ads.get("top_hosts", [])])
    # certs — TLS-trust split from the protocol mix (what we could decrypt)
    tls = quic = other = 0
    for p in (me.get("protocols") or []):
        nm = (p.get("label") or "").lower()
        c = int(p.get("count", 0) or 0)
        if "quic" in nm or "http3" in nm:
            quic += c
        elif "tls" in nm or "ssl" in nm or "https" in nm:
            tls += c
        else:
            other += c
    certs_segs = _dpi_donut([
        {"label": "Inspecté (TLS)", "count": tls},
        {"label": "Opaque (QUIC)", "count": quic},
        {"label": "Autre", "count": other},
    ])
    return [
        {"title": "🛰️ DPI — catégories", "hole": "DPI", "segments": me.get("categories") or []},
        {"title": "🔍 MITM — protocoles", "hole": "proto", "segments": me.get("protocols") or []},
        {"title": "🔒 Certs — confiance TLS", "hole": "certs", "segments": certs_segs},
        {"title": "🚫 Pubs bloquées", "hole": str(ads.get("total", 0)), "segments": ads_segs},
    ]


def _ua_class(ua: str) -> tuple:
    """(emoji, label) device class from a User-Agent. Order matters: Android UAs
    also contain 'linux', iPad desktop-mode contains 'macintosh'."""
    u = (ua or "").lower()
    if "android" in u:
        return ("🤖", "Android")
    if "iphone" in u or "ipad" in u or "ipod" in u:
        return ("📱", "iPhone/iPad")
    if "cros" in u:
        return ("💻", "ChromeOS")
    if "windows" in u:
        return ("🪟", "PC Windows")
    if "macintosh" in u or "mac os" in u:
        return ("💻", "Mac")
    if "linux" in u or "x11" in u or "ubuntu" in u or "fedora" in u:
        return ("🐧", "Ordinateur Linux")
    return ("🧑‍💻", "Runner")


def _is_wg_r3_peer(mac_hash: str) -> bool:
    """True if mac_hash == sha256(wg_pubkey)[:16] of a wg-toolbox peer → the
    device is physically on the R3 tunnel, regardless of the stored client-level
    preference (which can lag at r1)."""
    import json
    import hashlib
    try:
        doc = json.loads(Path("/var/lib/secubox/toolbox/wg-peers.json").read_text())
    except Exception:
        return False
    for pk in (doc.get("peers") or {}):
        if hashlib.sha256(pk.encode()).hexdigest()[:16] == mac_hash:
            return True
    return False


# #707 — Cyberpunk-Netrunner character sheet. Maps the LIVE telemetry (exposure,
# trackers, DPI cumulative, ads blocked, active protections) onto RPG stats.
def _persona_sheet(mac_hash: str, current_level: str, gs: dict,
                   exposure: int, dpi_e: dict, device_type: str = "",
                   ua: str = "") -> dict:
    me = (dpi_e or {}).get("me") or {}
    emoji, klass = _ua_class(ua)  # live device from the request's User-Agent
    try:
        ads_total = int((store.ad_client_stats(mac_hash, hours=7 * 24, top=1) or {}).get("total", 0) or 0)
    except Exception:
        ads_total = 0
    try:
        from .filters import get_filters as _gf
        tor_on = bool((_gf() or {}).get("tor_mode"))
    except Exception:
        tor_on = False

    level = (current_level or "r1").lower()
    if _is_wg_r3_peer(mac_hash):  # on the R3 tunnel → effective R3 regardless of stored pref
        level = "r3"
    lvl_bonus = {"r0": 0, "r1": 1, "r2": 3, "r3": 6}.get(level, 1)
    inventory = [
        {"icon": "🧅", "name": "Tunnel Tor", "on": tor_on},
        {"icon": "🔒", "name": "Cert MITM", "on": level in ("r2", "r3")},
        {"icon": "🛰️", "name": "WireGuard R3", "on": level == "r3"},
        {"icon": "🚫", "name": "Ad-blocker", "on": level in ("r1", "r2", "r3")},
    ]
    n_prot = sum(1 for p in inventory if p["on"])

    trackers = int(gs.get("total_trackers", 0) or 0)
    n_cats = len(me.get("categories") or [])
    n_protos = len(me.get("protocols") or [])
    flows = int(me.get("flows", 0) or 0)
    data_kb = int(((me.get("up", 0) or 0) + (me.get("down", 0) or 0)) / 1024)

    def _clamp(v):
        return max(3, min(20, int(v)))

    defense = _clamp(6 + n_prot * 2 + lvl_bonus)
    discretion = _clamp(20 - min(16, trackers // 2) - (0 if tor_on else 2))
    riposte = _clamp(4 + int(ads_total ** 0.38)) if ads_total > 0 else 4
    intel = _clamp(4 + n_cats * 2 + n_protos)

    def _attr(icon, name, v, note=""):
        return {"icon": icon, "name": name, "v": v,
                "pips": max(0, min(6, round(v / 20 * 6))), "note": note}

    hp = max(0, 100 - int(exposure or 0))
    align = ("🛡️ Protégé" if exposure < 30 else
             "⚖️ Exposé" if exposure < 70 else "☣️ Vulnérable")
    return {
        "tag": f"VILLAGE3B·#{mac_hash[:4].upper()}",
        "id": mac_hash[:8],
        "klass": klass,
        "emoji": emoji,
        "level": level.upper(),
        "exposure": int(exposure or 0),
        "hp": hp,
        "xp": data_kb,
        "align": align,
        "attrs": [
            _attr("🛡️", "DÉFENSE", defense),
            _attr("👁️", "DISCRÉTION", discretion),
            _attr("⚔️", "RIPOSTE", riposte, f"{ads_total} pubs tuées"),
            _attr("🧠", "INTEL", intel, f"{n_cats} cat · {flows} flux"),
        ],
        "inventory": inventory,
        "ads_total": ads_total,
        "flows": flows,
    }


# NOTE: route order matters in FastAPI — specific routes (/report/me,
# /report/me/html) MUST be declared BEFORE the catch-all /report/{token},
# otherwise FastAPI matches /report/me with token="me" and returns 404.


@router.get("/report/me/html", response_class=HTMLResponse)
async def report_me_html(request: Request) -> HTMLResponse:
    """HTML version of the live report — embedded in the captive portal.
    Auto-refresh every 15s. Same content as the PDF but stylé P31.

    Phase 6 (#496) : accepts ?mh=<hash> query param so R3 WG clients (no
    ARP entry on captive subnet) and remote viewers via kbin can fetch
    their own report. The hash for R3 = sha256(wg_pubkey)[:16] derived
    by inject_banner.py and embedded in the banner 'Mon rapport' link.
    """
    # Resolve identity the same way everywhere: ?mh → R3 WG peer (wg-peers.json)
    # → captive ARP. R3 clients hitting this directly (no ?mh) now resolve too.
    mac_hash = _client_mac_hash(request, _get_salt())
    if not mac_hash:
        raise HTTPException(
            400,
            "client identity unresolved (not on R3 tunnel and not in captive "
            "subnet) — append ?mh=<hash> from your banner's report link",
        )
    ip = _client_ip(request) or (request.client.host if request.client else "?")
    session = _aggregate_session(mac_hash)
    # #686 — the events table froze at the #662 cutover, so the report's numbers
    # came out all-zero. The LIVE per-client data is the social graph (same source
    # /social + the webext use). Pull it (7d) and drive the summary + graphs off it.
    try:
        from . import social as _social
        graph = _social.fetch_graph(mac_hash, since_seconds=7 * 86400)
    except Exception:
        graph = {"stats": {}, "nodes": [], "by_country": []}
    gs = graph.get("stats") or {}
    # Honest exposure indicator (0-100) from the live graph: tracker breadth +
    # operator-grade / anti-bot presence. Not a "compromise" score (events dead).
    exposure_score = min(100, int(
        (gs.get("total_trackers", 0) or 0) * 1.5
        + (gs.get("opgrade_sites", 0) or 0) * 12
        + (gs.get("antibot_sites", 0) or 0) * 8))
    # Phase 3 (#492) : pass query args + force no-cache so iPhone Safari
    # actually fetches the new template.
    # Phase 6 (#496) : also pass wg_enabled so dashboard R3 link renders
    wg_enabled = Path("/etc/secubox/toolbox/wg/server.pubkey").exists()
    # Phase 6.D (#497) : cumulative anonymous stats for visual context
    cumulative = _cumulative_stats()
    _level = store.get_client_level(mac_hash) if mac_hash else "r1"
    _dpi_e = _dpi_stats(mac_hash)
    # #823 — fold in the per-device Sentinel compromission assessment (same
    # data source the PDF routes already use via build_report_data) so the
    # "🛡️ Compromission" tab (report.sentinel) is fed instead of Undefined.
    report_data = reports.build_report_data(mac_hash, session)
    html = _env.get_template("report-live.html.j2").render(
        mac_hash=mac_hash, ip=ip,
        request_args=dict(request.query_params),
        current_level=_level,
        wg_enabled=wg_enabled,
        cumulative=cumulative,
        graph=graph, graph_stats=gs, exposure_score=exposure_score,
        charts=_build_report_charts(graph),
        dpi_exfil=_dpi_e,
        media_exfil=_media_stats(mac_hash),
        persona=_persona_sheet(mac_hash, _level, gs, exposure_score, _dpi_e,
                               session.get("device_type", ""),
                               request.headers.get("user-agent", "")),
        report=report_data,
        **session,
    )
    return HTMLResponse(html, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    })


def _enrich_report_data(mac_hash: str, data: dict, ua: str = "") -> dict:
    """#790 — attach the live enrichment (DPI, media, persona, charts, carto) to
    a report `data` dict. Factored out of report_me so /report/{token} and the
    admin route produce the SAME rich PDF. `ua` drives the persona device class;
    "" is fine for non-HTTP callers (falls back to a generic Runner class)."""
    data["dpi_exfil"] = _dpi_stats(mac_hash)          # #701 DPI parity
    data["media_exfil"] = _media_stats(mac_hash)      # #785 media-type donuts
    data["pdf_donuts"] = _build_pdf_donuts(mac_hash, data)  # #703 visual donuts
    try:
        from . import social as _social
        _graph = _social.fetch_graph(mac_hash, since_seconds=7 * 86400)
    except Exception:
        _graph = {"stats": {}, "nodes": [], "by_country": []}
    _gs = _graph.get("stats") or {}
    _exp = min(100, int((_gs.get("total_trackers", 0) or 0) * 1.5
                        + (_gs.get("opgrade_sites", 0) or 0) * 12
                        + (_gs.get("antibot_sites", 0) or 0) * 8))
    _lvl = store.get_client_level(mac_hash) if mac_hash else "r1"
    data["persona"] = _persona_sheet(mac_hash, _lvl, _gs, _exp, data["dpi_exfil"],
                                     data.get("device_type", ""), ua)
    _charts = _build_report_charts(_graph)
    data["charts"] = _charts                          # #711 "En un coup d'œil"
    data["graph_stats"] = _gs
    data["bestiary"] = (_charts.get("trackers") or [])[:5]
    data["carto_nodes"] = _graph.get("nodes") or []   # #709 carto + tables
    data["carto_country"] = _graph.get("by_country") or []
    return data


@router.get("/report/me")
async def report_me(request: Request) -> Response:
    """Generate + serve PDF report for the CURRENT requesting client.

    Phase 6 (#496) : same ?mh=<hash> bypass as /report/me/html — R3 WG
    clients (no captive ARP entry) and remote viewers via kbin can
    download their PDF report.
    """
    mh_qp = (request.query_params.get("mh") or "").strip().lower()
    if mh_qp and all(c in "0123456789abcdef" for c in mh_qp) and 8 <= len(mh_qp) <= 64:
        mac_hash = mh_qp
    else:
        ip, mac = _resolve(request)
        if not mac:
            raise HTTPException(400, "client MAC unknown (not in captive subnet?) — use ?mh=<hash>")
        salt = _get_salt()
        mac_hash = macmod.hash_mac(mac, salt)
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    _enrich_report_data(mac_hash, data, ua=request.headers.get("user-agent", ""))
    pdf_bytes = await _render_pdf_offloaded(reports.render_pdf, data, cache_key=f"me:{mac_hash}")
    fname = f"gondwana-toolbox-{mac_hash[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/report/{token}")
async def report(token: str) -> Response:
    """Returns PDF report for a given session token. HMAC-signed, expires after TTL.
    Declared LAST so that /report/me and /report/me/html match first."""
    salt = _get_salt()
    ok, mac_hash = reports.verify_token(token, salt)
    if not ok:
        raise HTTPException(404, "report not found or expired")
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    _enrich_report_data(mac_hash, data)  # #790 — same rich content as /report/me
    pdf_bytes = await _render_pdf_offloaded(reports.render_pdf, data, cache_key=f"tok:{mac_hash}")
    fname = f"gondwana-toolbox-{mac_hash[:8]}-{int(time.time())}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ───────────────── Admin (Phase 1 minimal) ─────────────────

@router.get("/admin/utiq-events")
async def admin_utiq_events(hours: int = 24, limit: int = 200) -> dict:
    """Phase 8 (#500) — silenced-but-tracked Utiq detections.

    Lists every event the mitm-wg `utiq_defense` addon recorded within
    the window (default 24 h, max 31 d).  Operator dashboard uses this
    to surface the per-client + per-publisher views.
    """
    from . import utiq as _u
    return {
        "events": _u.recent(hours=hours, limit=limit),
        "aggregates": _u.aggregates(hours=hours),
    }


# ───────────────── Phase 11.A — Social Mapping (#505, parent #502) ─────────────────

@router.get("/social/graph/{token}")
async def social_graph_client(token: str, since: int = 86400) -> dict:
    """Per-client cross-cookie tracker graph.

    `token` is the same HMAC-signed report token used by /report/{token}
    (see reports.verify_token).  Same TTL semantics : 24 h then the
    salt rotation invalidates further access.

    The returned shape is the JSON contract consumed by the d3 view in
    Phase 11.B and by the bilingual PDF in Phase 11.C.
    """
    from . import social as _s
    salt = _get_salt()
    ok, mac_hash = reports.verify_token(token, salt)
    if not ok:
        raise HTTPException(404, "graph not found or expired")
    # Clamp the window between 1 h and 7 d so a bad query can't
    # walk the entire retention period.
    since = max(3600, min(int(since or 86400), 7 * 86400))
    return _s.fetch_graph(mac_hash, since_seconds=since)


@router.post("/social/wipe/{token}")
async def social_wipe_client(token: str) -> dict:
    """RGPD art. 17 — droit à l'effacement.

    HMAC-token-gated to the same identity as the per-client view.
    Deletes every row across social_edges + social_nodes + social_links
    for the resolved mac_hash.
    """
    from . import social as _s
    salt = _get_salt()
    ok, mac_hash = reports.verify_token(token, salt)
    if not ok:
        raise HTTPException(404, "graph not found or expired")
    rows = _s.wipe_mac(mac_hash)
    return {"wiped": True, "rows_deleted": rows, "mac_hash_prefix": mac_hash[:8]}


@router.get("/admin/social-aggregate")
async def admin_social_aggregate(hours: int = 24) -> dict:
    """Operator dashboard view : KPI tiles + tracker-domain histogram +
    anonymized client table.  No per-client graph at this endpoint
    (that lives behind the HMAC-token route above).
    """
    from . import social as _s
    return _s.aggregate(hours=hours)


@router.get("/admin/cookie-crosssite")
async def admin_cookie_crosssite(hours: int = 24, top: int = 50) -> dict:
    """Operator view : cross-site tracker cookies (a cookie id reused across
    >= 2 first-party sites) with per-tracker site/client/cookie counts. Read-only
    over social_edges; same admin gating as the sibling /admin/* routes.
    """
    from . import social as _s
    return _s.cookie_xsite_detail(hours=hours, top_n=top)


@router.get("/admin/blacklist")
async def admin_blacklist() -> dict:
    """Phase 13.A (#521) + 13.B (#522) — enforcement-spine status :
    element counts + drop counters of the unified nft blacklist sets,
    plus the DoH/DoT detection counters and the last-sync state.
    Read-only ; parses `nft -j list table inet secubox_blacklist`.
    """
    import json as _json
    import subprocess as _sp
    from pathlib import Path as _P
    out: dict = {
        "active": False,
        "v4_count": 0,
        "v6_count": 0,
        "drops": 0,
        "doh_detect_v4": 0,
        "doh_detect_v6": 0,
        "doh_hits": 0,
        "resolved_domains": 0,
        "doh_block": False,
        "sources": ["crowdsec", "threat-intel", "dns-guard"],
    }
    try:
        r = _sp.run(
            ["/usr/sbin/nft", "-j", "list", "table", "inet", "secubox_blacklist"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            data = _json.loads(r.stdout or "{}")
            for item in data.get("nftables", []):
                if "set" in item:
                    s = item["set"]
                    n = len(s.get("elem", []) or [])
                    name = s.get("name")
                    if name == "blacklist_v4":
                        out["v4_count"] = n
                    elif name == "blacklist_v6":
                        out["v6_count"] = n
                    elif name == "doh_detect_v4":
                        out["doh_detect_v4"] = n
                    elif name == "doh_detect_v6":
                        out["doh_detect_v6"] = n
                if "counter" in item and isinstance(item["counter"], dict):
                    cobj = item["counter"]
                    cname = cobj.get("name", "")
                    pk = int(cobj.get("packets", 0) or 0)
                    if cname.startswith("sbx_doh_detect"):
                        out["doh_hits"] += pk
                    elif cname.startswith(("sbx_drop_blacklist", "sbx_drop_quarantine")):
                        out["drops"] += pk
            out["active"] = True
    except Exception as e:  # noqa: BLE001
        log.warning("admin_blacklist nft parse failed: %s", e)
    # Last-sync state file (resolved-domain count + doh_block flag).
    try:
        st = _P("/run/secubox/blacklist-sync.json")
        if st.exists():
            j = _json.loads(st.read_text())
            out["resolved_domains"] = int(j.get("resolved_domains", 0) or 0)
            out["doh_block"] = str(j.get("doh_block", "0")) == "1"
    except Exception:
        pass
    return out


@router.get("/admin/device-blocks")
async def admin_device_blocks(hours: int = 24) -> dict:
    """Phase 13.C (#524) — per-device blocked-attempts attribution :
    which anonymous device hit blacklisted IPs / DoH endpoints, how often.
    """
    from . import device_blocks as _db
    return _db.aggregate(hours=hours)


def _quarantine_ip(ip: str, add: bool, ttl: str = "6h") -> dict:
    """Add/remove a device source IP to the nft quarantine set."""
    import ipaddress as _ip
    import subprocess as _sp
    try:
        addr = _ip.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"invalid IP {ip!r}")
    setname = "quarantine_v6" if addr.version == 6 else "quarantine_v4"
    op = "add" if add else "delete"
    elem = f"{ip} timeout {ttl}" if add else ip
    try:
        r = _sp.run(
            ["/usr/sbin/nft", op, "element", "inet", "secubox_blacklist",
             setname, "{ " + elem + " }"],
            capture_output=True, text=True, timeout=5,
        )
        ok = r.returncode == 0
        if not ok and not add and "No such file" in (r.stderr or ""):
            ok = True  # already absent → treat as success
        log.info("quarantine %s %s -> %s", op, ip, "ok" if ok else r.stderr.strip())
        return {"ok": ok, "ip": ip, "action": op, "set": setname,
                "error": None if ok else (r.stderr or "").strip()}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"nft {op} failed: {e}")


@router.post("/admin/quarantine/{ip}")
async def admin_quarantine_add(ip: str, ttl: str = "6h") -> dict:
    """Quarantine a device : drop ALL its forward traffic for `ttl`."""
    return _quarantine_ip(ip, add=True, ttl=ttl)


@router.post("/admin/unquarantine/{ip}")
async def admin_quarantine_remove(ip: str) -> dict:
    """Lift a device's quarantine."""
    return _quarantine_ip(ip, add=False)


@router.get("/admin/escalate")
async def admin_escalate() -> dict:
    """Phase 13.D (#527) — escalation policy + last cycle summary.
    Read-only : the policy flags (all default OFF) come from the
    evaluator's env, the last-run summary from its state file.
    """
    import json as _json
    from pathlib import Path as _P
    from . import escalate as _esc
    out: dict = {"policy": _esc.load_policy(), "last_run": None}
    try:
        st = _P("/run/secubox/escalate.json")
        if st.exists():
            out["last_run"] = _json.loads(st.read_text())
    except Exception:
        pass
    return out


@router.get("/admin/protective")
async def admin_protective() -> dict:
    """#560 — protective-mode status + counters. Read-only.
    mode comes from SECUBOX_PROTECTIVE_MODE (default off) ; the live
    alert/spoof counts from the addon's state file.
    """
    import json as _json
    import os as _os
    from pathlib import Path as _P
    out: dict = {
        "mode": (_os.environ.get("SECUBOX_PROTECTIVE_MODE") or "off").lower(),
        "alerts": 0, "spoofs": 0, "since": None, "updated": None,
    }
    try:
        st = _P("/run/secubox/protective.json")
        if st.exists():
            out.update(_json.loads(st.read_text()))
    except Exception:
        pass
    try:
        from .filters import get_filters as _gf
        out["mode"] = _gf().get("protective", out["mode"])
    except Exception:
        pass
    return out


@router.get("/admin/ad-stats")
async def admin_ad_stats(hours: int = 24) -> dict:
    """Contextual ad-block metrics for the #ads tab (read-only, kbin-safe)."""
    h = max(1, min(int(hours if hours is not None else 24), 168))
    out = store.ad_stats(hours=h)
    # #758 — real network-layer drops from the hub netstats collector snapshot.
    # Fall back to the legacy blacklist nft parse when the snapshot is absent.
    nd = None
    try:
        import json as _json
        snap = _json.loads(NETSTATS_SNAPSHOT.read_text())
        nd = int(snap.get("network_drops", 0) or 0)
    except Exception:
        nd = None
    if nd is None:
        try:
            bl = await admin_blacklist()
            nd = int(bl.get("drops", 0) or 0)
        except Exception:
            nd = 0
    out["network_drops"] = nd
    # DNS-layer ad-blocking (secubox-adblock-sync #740): the Unbound sinkhole
    # kills most ads BEFORE they reach the engine, so total_blocked (204s) reads
    # low/0. Surface the real DNS blocking so the tab isn't misleading — "0
    # engine blocks" ≠ "no ad-blocking".
    try:
        import json as _json
        s = _json.loads(Path("/var/lib/secubox/ad-guard/sinkhole-status.json").read_text())
        comp = s.get("compile", {}) or {}
        out["dns_sinkhole"] = {
            "enabled": bool(s.get("enabled")),
            "domains": int(s.get("blocked", 0) or 0),
            "net_rules": int(comp.get("net_rules", 0) or 0),
            "cosmetic_domains": int(comp.get("cosmetic_domains", 0) or 0),
            "sources": sorted((comp.get("sources") or {}).keys()),
        }
    except Exception:
        out["dns_sinkhole"] = {"enabled": None}
    return out


@router.get("/admin/ad-stats/client/{mac_hash}")
async def admin_ad_stats_client(mac_hash: str, hours: int = 24) -> dict:
    """#659 — one visitor's ad-block drill-down (read-only)."""
    h = max(1, min(int(hours if hours is not None else 24), 168))
    return store.ad_client_stats(mac_hash, hours=h)


@router.get("/admin/ghost")
async def admin_ghost() -> dict:
    """#566 — ad/banner ghoster savings (R3+/R4). Read-only counters."""
    import json as _json
    from pathlib import Path as _P
    out: dict = {"blocked_requests": 0, "bytes_saved_est": 0,
                 "pages_cleaned": 0, "since": None, "updated": None}
    try:
        st = _P("/run/secubox/ghost.json")
        if st.exists():
            out.update(_json.loads(st.read_text()))
    except Exception:
        pass
    out["mb_saved_est"] = round(out.get("bytes_saved_est", 0) / 1048576, 1)
    return out


_MEDIA_EMOJI = {
    "page": "\U0001F4C4", "image": "\U0001F5BC", "video": "\U0001F3AC",
    "audio": "\U0001F3B5", "script": "\U0001F9E9", "style": "\U0001F3A8",
    "font": "\U0001F524", "api": "\U0001F4E6", "text": "\U0001F4DD",
    "other": "❓",
}


@router.get("/admin/cache")
async def admin_cache() -> dict:
    """#577 — shared media cache stats (hits/misses/bytes served/size)."""
    import json as _json
    from pathlib import Path as _P
    out: dict = {"hits": 0, "misses": 0, "stored": 0, "evicted": 0,
                 "bytes_served": 0, "objects": 0, "bytes_cached": 0,
                 "since": None, "updated": None}
    try:
        st = _P("/run/secubox/media_cache.json")
        if st.exists():
            out.update(_json.loads(st.read_text()))
    except Exception:
        pass
    tot = (out.get("hits", 0) + out.get("misses", 0)) or 1
    out["hit_rate"] = round(100 * out.get("hits", 0) / tot, 1)
    out["mb_served"] = round(out.get("bytes_served", 0) / 1048576, 1)
    out["mb_cached"] = round(out.get("bytes_cached", 0) / 1048576, 1)
    try:
        from .filters import get_filters as _gf
        out["enabled"] = bool(_gf().get("media_cache"))
    except Exception:
        out["enabled"] = False
    return out


_PIN_PATH = "/run/secubox/pin.json"


@router.get("/admin/pin")
async def admin_pin() -> dict:
    """#578 — the shared broadcast pin shown in every client's banner."""
    import json as _json
    from pathlib import Path as _P
    cur = {"text": "", "url": "", "ts": 0, "by": ""}
    try:
        p = _P(_PIN_PATH)
        if p.exists():
            cur.update(_json.loads(p.read_text()))
    except Exception:
        pass
    return cur


@router.post("/admin/pin")
async def admin_pin_set(request: Request) -> dict:
    """#578 — set/clear the shared pin (broadcast to all banners). Empty
    text clears it."""
    import json as _json
    import time as _time
    from pathlib import Path as _P
    try:
        body = await request.json()
    except Exception:
        body = {}
    text = (str(body.get("text", "")) if isinstance(body, dict) else "")[:80].strip()
    url = (str(body.get("url", "")) if isinstance(body, dict) else "")[:300].strip()
    rec = {"text": text, "url": url, "ts": int(_time.time()) if text else 0, "by": "admin"}
    try:
        _P(_PIN_PATH).parent.mkdir(parents=True, exist_ok=True)
        _P(_PIN_PATH).write_text(_json.dumps(rec))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return rec


@router.get("/admin/pin/ui", response_class=HTMLResponse)
async def admin_pin_ui() -> HTMLResponse:
    """#578 — minimal pin setter; can auto-fill the current top-1 tracker."""
    html = """<!doctype html><html lang=fr><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Pin partagé — ToolBoX</title>
<style>
 body{background:#0a0a0f;color:#e8e6d9;font:14px system-ui,sans-serif;max-width:520px;margin:30px auto;padding:0 18px}
 h1{color:#c9a84c;font-size:18px} label{display:block;color:#6b6b7a;font-size:12px;margin:12px 0 4px}
 input{width:100%;padding:8px;border-radius:6px;border:1px solid #333;background:#14141c;color:#e8e6d9}
 button{margin:14px 8px 0 0;padding:9px 14px;border-radius:6px;border:1px solid #c9a84c;background:#c9a84c;color:#0a0a0f;font-weight:700;cursor:pointer}
 button.alt{background:transparent;color:#00d4ff;border-color:#00d4ff}
 button.danger{background:transparent;color:#e63946;border-color:#e63946}
 #msg{color:#00ff41;min-height:18px;margin-top:10px} .muted{color:#6b6b7a;font-size:12px}
</style>
<h1>📌 Pin partagé (toutes les bannières)</h1>
<p class=muted>Un message épinglé, diffusé dans la bannière de TOUS les clients R2/R3 (24 h).</p>
<label>Texte du pin <input id=text maxlength=80 placeholder="ex: traceur #1 du jour — doubleclick.net"></label>
<label>Lien (optionnel) <input id=url maxlength=300 placeholder="https://…"></label>
<button id=save>📌 Épingler</button>
<button class=alt id=top>⬆ Utiliser le traceur #1</button>
<button class=danger id=clear>Retirer</button>
<p id=msg></p>
<script>
const $=s=>document.querySelector(s);
fetch('/admin/pin').then(r=>r.json()).then(p=>{$('#text').value=p.text||'';$('#url').value=p.url||'';});
function post(t,u){return fetch('/admin/pin',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({text:t,url:u})}).then(r=>r.json()).then(()=>{$('#msg').textContent='✓ diffusé';setTimeout(()=>$('#msg').textContent='',1500);});}
$('#save').onclick=()=>post($('#text').value,$('#url').value);
$('#clear').onclick=()=>{$('#text').value='';$('#url').value='';post('','');};
$('#top').onclick=()=>fetch('/admin/social-aggregate?hours=24').then(r=>r.json()).then(d=>{const t=(d.by_tracker_domain||[])[0];if(t){$('#text').value='Traceur #1 : '+t.tracker_domain+' ('+t.hits+' hits)';}else{$('#msg').textContent='aucun traceur';}});
</script></html>"""
    return HTMLResponse(content=html)


@router.get("/admin/media")
async def admin_media() -> dict:
    """#570 — DPI media/content-type statistics for the donut UI."""
    import json as _json
    from pathlib import Path as _P
    raw: dict = {"categories": {}, "providers": {}, "total": {"bytes": 0, "count": 0}}
    try:
        st = _P("/run/secubox/media.json")
        if st.exists():
            raw.update(_json.loads(st.read_text()))
    except Exception:
        pass
    tot_b = max(int(raw.get("total", {}).get("bytes", 0)), 1)
    cats = []
    for cat, v in (raw.get("categories") or {}).items():
        b = int(v.get("bytes", 0))
        cats.append({"cat": cat, "emoji": _MEDIA_EMOJI.get(cat, "❓"),
                     "bytes": b, "count": int(v.get("count", 0)),
                     "mb": round(b / 1048576, 1), "pct": round(100 * b / tot_b, 1)})
    cats.sort(key=lambda x: -x["bytes"])
    provs = sorted(
        ({"provider": p, "bytes": int(v.get("bytes", 0)),
          "count": int(v.get("count", 0)), "mb": round(int(v.get("bytes", 0)) / 1048576, 1)}
         for p, v in (raw.get("providers") or {}).items()),
        key=lambda x: -x["bytes"])[:5]
    return {"categories": cats, "top_providers": provs,
            "total_mb": round(raw.get("total", {}).get("bytes", 0) / 1048576, 1),
            "total_count": raw.get("total", {}).get("count", 0),
            "updated": raw.get("updated")}


@router.get("/admin/media/ui", response_class=HTMLResponse)
async def admin_media_ui() -> HTMLResponse:
    """#570 — donut + emoji legend + top-5 providers."""
    html = """<!doctype html><html lang=fr><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>DPI Médias — ToolBoX</title>
<style>
 body{background:#0a0a0f;color:#e8e6d9;font:14px system-ui,sans-serif;max-width:560px;margin:24px auto;padding:0 18px;text-align:center}
 h1{color:#c9a84c;font-size:18px} .muted{color:#6b6b7a;font-size:12px}
 #legend{display:flex;flex-wrap:wrap;gap:6px;justify-content:center;margin:10px 0}
 .lg{background:#12121a;border:1px solid #222;border-radius:14px;padding:4px 9px;font-size:12px}
 table{width:100%;border-collapse:collapse;margin-top:14px;font-size:13px}
 td{padding:5px 4px;border-bottom:1px solid #1a1a22;text-align:left} td.r{text-align:right;color:#6b6b7a}
 .fav{width:16px;height:16px;border-radius:3px;vertical-align:middle;margin-right:6px;background:#1a1a22}
 h2{color:#6e40c9;font-size:13px;margin:18px 0 4px;text-align:left}
</style>
<h1>📊 DPI — types de contenus</h1>
<p class=muted id=tot>…</p>
<svg id=donut viewBox="0 0 200 200" width=200 height=200></svg>
<div id=legend></div>
<h2>Top 5 fournisseurs</h2>
<table id=provs></table>
<script>
const PAL=['#c9a84c','#00d4ff','#e63946','#6e40c9','#00ff41','#ff9900','#9aa0a6','#ff5a9e','#4285f4','#888'];
const SVGNS='http://www.w3.org/2000/svg';
function arc(cx,cy,r,a0,a1){const p=(a,rr)=>[cx+rr*Math.cos(a),cy+rr*Math.sin(a)];const[x0,y0]=p(a0,r),[x1,y1]=p(a1,r),[xi1,yi1]=p(a1,r*0.58),[xi0,yi0]=p(a0,r*0.58);const big=a1-a0>Math.PI?1:0;return`M${x0} ${y0}A${r} ${r} 0 ${big} 1 ${x1} ${y1}L${xi1} ${yi1}A${r*0.58} ${r*0.58} 0 ${big} 0 ${xi0} ${yi0}Z`;}
fetch('/admin/media').then(r=>r.json()).then(d=>{
 document.getElementById('tot').textContent=`${d.total_mb||0} Mo · ${d.total_count||0} flux`;
 const svg=document.getElementById('donut');const cats=d.categories||[];
 let a=-Math.PI/2;const tot=cats.reduce((s,c)=>s+c.bytes,0)||1;
 cats.forEach((c,i)=>{const a1=a+2*Math.PI*c.bytes/tot;const path=document.createElementNS(SVGNS,'path');path.setAttribute('d',arc(100,100,92,a,a1));path.setAttribute('fill',PAL[i%PAL.length]);const t=document.createElementNS(SVGNS,'title');t.textContent=`${c.emoji} ${c.cat} ${c.pct}% (${c.mb} Mo)`;path.appendChild(t);svg.appendChild(path);a=a1;});
 const lg=document.getElementById('legend');
 cats.forEach((c,i)=>{const s=document.createElement('span');s.className='lg';s.innerHTML=`<b style="color:${PAL[i%PAL.length]}">●</b> ${c.emoji} ${c.cat} ${c.pct}%`;lg.appendChild(s);});
 const tb=document.getElementById('provs');
 (d.top_providers||[]).forEach(p=>{const tr=document.createElement('tr');tr.innerHTML=`<td><img class=fav loading=lazy src="/social/favicon/${encodeURIComponent(p.provider)}" onerror="this.style.visibility='hidden'">${p.provider}</td><td class=r>${p.mb} Mo · ${p.count}</td>`;tb.appendChild(tr);});
});
</script></html>"""
    return HTMLResponse(content=html)


@router.get("/admin/filters")
async def admin_filters_get() -> dict:
    """#566 — modular mitm filter config (read)."""
    from .filters import get_filters
    return get_filters(force=True)


@router.post("/admin/filters")
async def admin_filters_set(request: Request) -> dict:
    """#566 — toggle mitm filters from the toolbox WebUI (write)."""
    from .filters import set_filters
    try:
        patch = await request.json()
    except Exception:
        patch = {}
    if not isinstance(patch, dict):
        raise HTTPException(status_code=400, detail="json object expected")
    return set_filters(patch)


# ── kbin Tor egress switch (#683) — reuses the secubox-tor control plane ──
_TOR_EXIT_IP_CACHE = "/tmp/tor_exit_ip"  # shared with secubox-tor


def _tor_exit_ip_cached():
    try:
        if os.path.exists(_TOR_EXIT_IP_CACHE):
            return (open(_TOR_EXIT_IP_CACHE).read().strip() or None)
    except Exception:
        pass
    return None


def _require_tor_admin(request: Request) -> None:
    """Tor on/off/newnym/leak-check are operator actions — blocked on the
    public kbin vhost (defense-in-depth, mirrors /admin/filter-control)."""
    if _is_public_kbin(request):
        raise HTTPException(status_code=403,
                            detail="Tor controls are admin-only (use admin.gk2.secubox.in)")


@router.get("/admin/tor/state")
async def admin_tor_state() -> dict:
    """kbin Tor mode status: the flag + live daemon bootstrap/circuits/exit IP.
    Read-only — safe to expose on the public kbin vhost (no secrets)."""
    from .filters import get_filters
    from . import tor_ctl
    f = get_filters(force=True)
    st = tor_ctl.status()
    st.update({
        "tor_mode": bool(f.get("tor_mode", False)),
        "tor_preset": f.get("tor_preset", "anonymous"),
        "exit_ip": _tor_exit_ip_cached(),
    })
    return st


@router.post("/admin/tor/on")
async def admin_tor_on(request: Request) -> dict:
    """Arm kbin Tor mode. Flips the flag only; the privileged tunnel arm runs
    async via secubox-toolbox-tor.path → reconcile (portal stays unprivileged)."""
    _require_tor_admin(request)
    from .filters import set_filters
    try:
        body = await request.json()
    except Exception:
        body = {}
    patch = {"tor_mode": True}
    if isinstance(body, dict) and body.get("tor_preset"):
        patch["tor_preset"] = body["tor_preset"]
    out = set_filters(patch)
    return {"tor_mode": out["tor_mode"], "tor_preset": out["tor_preset"], "armed_async": True}


@router.post("/admin/tor/off")
async def admin_tor_off(request: Request) -> dict:
    """Disarm kbin Tor mode (flag flip; reconciler tears the tunnel down)."""
    _require_tor_admin(request)
    from .filters import set_filters
    out = set_filters({"tor_mode": False})
    return {"tor_mode": out["tor_mode"], "disarmed_async": True}


@router.post("/admin/tor/newnym")
async def admin_tor_newnym(request: Request) -> dict:
    """Request a fresh Tor circuit (new exit IP) — SIGNAL NEWNYM via control port."""
    _require_tor_admin(request)
    from . import tor_ctl
    ok = tor_ctl.new_identity()
    try:
        if os.path.exists(_TOR_EXIT_IP_CACHE):
            os.unlink(_TOR_EXIT_IP_CACHE)
    except Exception:
        pass
    return {"success": ok}


@router.post("/admin/tor/check-leaks")
async def admin_tor_check_leaks(request: Request) -> dict:
    """Probe the egress IP via Tor SOCKS (9050) and cache it for the badge.
    A real off-board leak test is still the source of truth; this confirms the
    SOCKS path resolves and surfaces the current exit IP."""
    _require_tor_admin(request)
    from . import tor_ctl
    if not tor_ctl.tor_running():
        return {"ok": False, "error": "tor not running"}
    import httpx
    result: dict = {"ok": True}
    # httpx renamed proxies= → proxy= (0.26+, removed proxies in 0.28); board
    # ships bookworm's 0.23 (proxies=). Support both.
    try:
        _client = httpx.AsyncClient(timeout=15.0, proxy="socks5://127.0.0.1:9050")
    except TypeError:
        _client = httpx.AsyncClient(timeout=15.0, proxies="socks5://127.0.0.1:9050")
    try:
        async with _client as c:
            tor_ip = (await c.get("https://api.ipify.org")).text.strip()
        result["tor_ip"] = tor_ip
        try:
            with open(_TOR_EXIT_IP_CACHE, "w") as fh:
                fh.write(tor_ip)
        except Exception:
            pass
    except Exception:
        result["ok"] = False
        result["tor_ip"] = None
        result["error"] = "SOCKS probe failed (python3-socksio installed? tor bootstrapped?)"
    return result



# ── Tor exit-country / VPN-client / obfs4-bridge CRUD (#683 follow-up) ──
# Validated, audited state files consumed by
# sbin/secubox-toolbox-tor-reconcile (root, path-triggered). This layer
# never escalates privilege — it only writes /etc/secubox/toolbox/tor-*.txt
# and re-triggers the SAME secubox-toolbox-tor.path watcher that
# admin_tor_on/off use (touch filters.json), so the privileged reconciler
# picks up the change exactly like a tor_mode flip (#683).
import ipaddress as _ipaddress
import re as _re

TOR_EXIT_CC = Path(os.environ.get(
    "SECUBOX_TOR_EXIT_CC_PATH", "/etc/secubox/toolbox/tor-exit-country.txt"))
TOR_VPN_CLIENTS = Path(os.environ.get(
    "SECUBOX_TOR_VPN_CLIENTS_PATH", "/etc/secubox/toolbox/tor-vpn-clients.txt"))
TOR_BRIDGES = Path(os.environ.get(
    "SECUBOX_TOR_BRIDGES_PATH", "/etc/secubox/toolbox/tor-bridges.txt"))
_TOR_AUDIT_LOG = Path("/var/log/secubox/audit.log")

_CC_RE = _re.compile(r"^[A-Za-z]{2}$")
_MAC_RE = _re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
_BRIDGE_RE = _re.compile(r"^Bridge obfs4 [][A-Za-z0-9:._=+/, -]+$")


def _valid_cc(c: str) -> bool:
    return bool(_CC_RE.fullmatch(c or ""))


def _valid_selector(kind: str, sel: str) -> bool:
    # IPv4-only: the backend tor_vpn_src nft set is `type ipv4_addr` and
    # populate_vpn_clients silently skips non-v4, so accepting an IPv6
    # selector would be a false success (200 + audit, nothing enforced).
    try:
        if kind == "ip":
            return _ipaddress.ip_address(sel).version == 4
        if kind == "cidr":
            return _ipaddress.ip_network(sel, strict=False).version == 4
        if kind == "mac":
            return bool(_MAC_RE.fullmatch(sel))
    except ValueError:
        return False
    return False


def _valid_bridge(line: str) -> bool:
    return bool(_BRIDGE_RE.fullmatch(line or ""))


def _tor_audit(action: str, target: str, request: Request | None = None) -> None:
    """Append-only CSPN audit trail (mirrors escalate.py's _audit)."""
    try:
        _TOR_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        operator = (request.client.host if request and request.client else "admin")
        with _TOR_AUDIT_LOG.open("a") as f:
            f.write(f"{ts} secubox-toolbox operator={operator} action={action} target={target}\n")
    except Exception as e:  # pragma: no cover
        log.warning("tor audit write failed: %s", e)


def _trigger_reconcile() -> None:
    """Fire the privileged reconciler the same way tor_mode on/off does
    (#683): touch filters.json so secubox-toolbox-tor.path re-runs
    secubox-toolbox-tor-reconcile. The portal itself never escalates."""
    try:
        from .filters import set_filters
        set_filters({})
    except Exception as e:  # pragma: no cover
        log.warning("tor reconcile trigger failed: %s", e)


def _read_state_lines(path: Path) -> list[str]:
    try:
        return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except Exception:
        return []


def _write_state_lines(path: Path, lines: list[str]) -> None:
    """Same atomic-tmp-then-fallback-in-place write as filters.set_filters,
    since /etc/secubox/toolbox is 0750 and the serving user may not be able
    to create a tmp file in the parent dir."""
    data = "\n".join(lines) + ("\n" if lines else "")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    try:
        tmp = str(path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, path)
    except OSError:
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)


@router.get("/exit_country")
async def get_exit_country(request: Request) -> dict:
    _require_tor_admin(request)
    return {"countries": [c.upper() for c in _read_state_lines(TOR_EXIT_CC)]}


@router.post("/exit_country")
async def set_exit_country(request: Request) -> dict:
    """Replaces the WHOLE exit-country list. One validated ISO cc per line."""
    _require_tor_admin(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    countries = (body or {}).get("countries")
    if not isinstance(countries, list):
        raise HTTPException(status_code=400, detail="countries: list expected")
    clean: list[str] = []
    for c in countries:
        if not isinstance(c, str) or not _valid_cc(c):
            raise HTTPException(status_code=400, detail=f"invalid country code: {c!r}")
        cc = c.upper()
        if cc not in clean:
            clean.append(cc)
    _write_state_lines(TOR_EXIT_CC, clean)
    _tor_audit("exit_country_set", ",".join(clean) or "(cleared)", request)
    _trigger_reconcile()
    return {"countries": clean}


@router.get("/vpn/clients")
async def get_vpn_clients(request: Request) -> dict:
    _require_tor_admin(request)
    out = []
    for ln in _read_state_lines(TOR_VPN_CLIENTS):
        kind, _, sel = ln.partition(":")
        out.append({"kind": kind, "selector": sel})
    return {"clients": out}


@router.post("/vpn/client")
async def add_vpn_client(request: Request) -> dict:
    _require_tor_admin(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    kind = (body or {}).get("kind")
    sel = (body or {}).get("selector")
    if not isinstance(kind, str) or not isinstance(sel, str) or not _valid_selector(kind, sel):
        raise HTTPException(status_code=400, detail="invalid kind/selector")
    entry = f"{kind}:{sel}"
    lines = _read_state_lines(TOR_VPN_CLIENTS)
    if entry not in lines:
        lines.append(entry)
        _write_state_lines(TOR_VPN_CLIENTS, lines)
        _tor_audit("vpn_client_add", entry, request)
        _trigger_reconcile()
    return {"clients": [{"kind": k, "selector": s} for k, _, s in
                         (ln.partition(":") for ln in lines)]}


@router.delete("/vpn/client")
async def remove_vpn_client(request: Request) -> dict:
    _require_tor_admin(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    kind = (body or {}).get("kind")
    sel = (body or {}).get("selector")
    if not isinstance(kind, str) or not isinstance(sel, str) or not _valid_selector(kind, sel):
        raise HTTPException(status_code=400, detail="invalid kind/selector")
    entry = f"{kind}:{sel}"
    lines = _read_state_lines(TOR_VPN_CLIENTS)
    if entry in lines:
        lines = [ln for ln in lines if ln != entry]
        _write_state_lines(TOR_VPN_CLIENTS, lines)
        _tor_audit("vpn_client_remove", entry, request)
        _trigger_reconcile()
    return {"clients": [{"kind": k, "selector": s} for k, _, s in
                         (ln.partition(":") for ln in lines)]}


@router.get("/tor/bridges")
async def get_tor_bridges(request: Request) -> dict:
    _require_tor_admin(request)
    return {"bridges": _read_state_lines(TOR_BRIDGES)}


@router.post("/tor/bridge")
async def add_tor_bridge(request: Request) -> dict:
    _require_tor_admin(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    line = (body or {}).get("line")
    if not isinstance(line, str) or not _valid_bridge(line):
        raise HTTPException(status_code=400, detail="invalid bridge line")
    lines = _read_state_lines(TOR_BRIDGES)
    if line not in lines:
        lines.append(line)
        _write_state_lines(TOR_BRIDGES, lines)
        _tor_audit("tor_bridge_add", line, request)
        _trigger_reconcile()
    return {"bridges": lines}


@router.delete("/tor/bridge")
async def remove_tor_bridge(request: Request) -> dict:
    _require_tor_admin(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    line = (body or {}).get("line")
    if not isinstance(line, str) or not _valid_bridge(line):
        raise HTTPException(status_code=400, detail="invalid bridge line")
    lines = _read_state_lines(TOR_BRIDGES)
    if line in lines:
        lines = [ln for ln in lines if ln != line]
        _write_state_lines(TOR_BRIDGES, lines)
        _tor_audit("tor_bridge_remove", line, request)
        _trigger_reconcile()
    return {"bridges": lines}


@router.get("/admin/sentinel/stats")
async def admin_sentinel_stats() -> dict:
    """Fleet Sentinel counters for the WebUI tab. Fail-safe: a dark daemon
    yields active=false with zeroed counters (HTTP 200), never a 5xx."""
    stats = sentinel_link.fetch_stats()
    if not stats:
        return {"active": False, "detections": 0, "blocked": 0, "spyware": 0}
    return {
        "active": True,
        "detections": sentinel_link._safe_int(stats.get("detections", 0)),
        "blocked": sentinel_link._safe_int(stats.get("blocked", 0)),
        "spyware": sentinel_link._safe_int(stats.get("spyware", 0)),
    }


@router.get("/admin/sentinel/verdicts")
async def admin_sentinel_verdicts(limit: int = 50) -> dict:
    """Recent fleet detections + the compromise assessment for the WebUI tab."""
    dets = sentinel_link.fetch_verdicts(limit)
    return {
        "active": bool(dets),
        "assess": sentinel_link.assess(dets),
        "detections": dets,
    }


def _c2_signals(s):
    """Normalize Signals to a list: Go map[string]bool -> JSON object; []string -> JSON array."""
    if isinstance(s, dict):
        return sorted(k for k, v in s.items() if v)
    if isinstance(s, list):
        return s
    return []


def _c2_norm_learned(h):
    return {"host": h.get("host", ""), "signals": _c2_signals(h.get("signals")),
            "interval_s": h.get("interval_s"), "devices": h.get("devices")}


def _c2_norm_cand(c):
    return {"host": c.get("host", ""), "signals": _c2_signals(c.get("signals")),
            "interval_s": c.get("interval_s"), "windows": c.get("windows")}


@router.get("/admin/sentinel/c2")
async def admin_sentinel_c2() -> dict:
    """Learned + candidate C2 hosts for the WebUI 'C2 appris' view. Fail-safe."""
    data = sentinel_link.fetch_c2()
    if not data:
        return {"active": False, "learned": [], "candidates": []}
    return {"active": True,
            "learned": [_c2_norm_learned(h) for h in data.get("learned", [])],
            "candidates": [_c2_norm_cand(c) for c in data.get("candidates", [])]}


@router.post("/admin/sentinel/c2/allow")
async def admin_sentinel_c2_allow(host: str = Form(...)) -> dict:
    """Operator 'Ignorer' — allowlist a host so it is never learned as C2."""
    return {"ok": sentinel_link.c2_allow(host)}


# ───────────────── /rlevel — per-peer wg-toolbox MITM R-level (#rlevel-per-peer, task 6) ─────────────────
#
# Modes, increasing intrusion: off(0) < passive(1) < active(2) < reel(3).
# Effective = forced ?? clamp(chosen, floor, reel) — mirrors cmd/sbxmitm/rlevel.go
# effective() and sbxmitm-policyctl's bash re-implementation, kept in lockstep
# here so the admin/self-service list can compute it WITHOUT asking the ctl a
# second time. No in-process root: every mutation is delegated to
# `sudo -n /usr/sbin/sbxmitm-policyctl` (mirrors the proxypac API's `_ctl`
# pattern) — this module only ever READS peer-rlevel.json (via `ctl list`)
# and wg-peers.json.
_RLEVEL_MODES = ("off", "passive", "active", "reel")
_RLEVEL_RANK = {m: i for i, m in enumerate(_RLEVEL_MODES)}
_RLEVEL_POLICYCTL = "/usr/sbin/sbxmitm-policyctl"
_RLEVEL_WG_PEERS = Path("/var/lib/secubox/toolbox/wg-peers.json")


def _rlevel_valid_mode(mode: str) -> bool:
    return mode in _RLEVEL_RANK


def _rlevel_clamp(value: str, floor: str, ceiling: str = "reel") -> str:
    r = _RLEVEL_RANK.get(value, _RLEVEL_RANK["passive"])
    lo = _RLEVEL_RANK.get(floor, _RLEVEL_RANK["passive"])
    hi = _RLEVEL_RANK.get(ceiling, _RLEVEL_RANK["reel"])
    r = max(lo, min(hi, r))
    return _RLEVEL_MODES[r]


def _rlevel_effective(chosen: str, forced: str | None, floor: str) -> str:
    if forced:
        return forced
    return _rlevel_clamp(chosen, floor)


def _rlevel_ctl(args: list[str], timeout: int = 15):
    """Delegate a privileged rlevel action to sbxmitm-policyctl via `sudo -n`.
    Never raises — returns (returncode, stdout, stderr); a transport failure
    (sudo missing, timeout, ctl absent) yields rc=1 so callers fail closed."""
    import subprocess
    try:
        p = subprocess.run(
            ["sudo", "-n", _RLEVEL_POLICYCTL, *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return 1, "", str(e)[:200]


def _rlevel_load_wg_peers() -> dict:
    """{pubkey: {ip, label, ...}} from wg-peers.json — best-effort, {} on error."""
    import json as _json
    try:
        return (_json.loads(_RLEVEL_WG_PEERS.read_text()).get("peers") or {})
    except Exception:
        return {}


def _rlevel_load_policy() -> dict:
    """Whole peer-rlevel.json document via `sbxmitm-policyctl list` (read-only —
    the ctl owns the file; this module never touches it directly)."""
    import json as _json
    rc, out, _err = _rlevel_ctl(["list"])
    if rc != 0 or not out:
        return {"defaults": {"mode": "passive", "floor": "passive"}, "peers": {}}
    try:
        doc = _json.loads(out)
    except Exception:
        return {"defaults": {"mode": "passive", "floor": "passive"}, "peers": {}}
    doc.setdefault("defaults", {"mode": "passive", "floor": "passive"})
    doc.setdefault("peers", {})
    return doc


def _rlevel_wg_live(pubkeys: set) -> dict:
    """Best-effort {pubkey: bool} — True if wg-toolbox reports a handshake in
    the last 180s for that peer. Never raises; unavailable wg → {} (UI treats
    missing as unknown, never as a false 'live')."""
    import subprocess
    live: dict = {}
    if not pubkeys:
        return live
    try:
        out = subprocess.run(
            ["wg", "show", "wg-toolbox", "dump"],
            capture_output=True, text=True, timeout=2, check=False,
        ).stdout
    except Exception:
        return live
    now = time.time()
    for line in out.splitlines()[1:]:  # skip the interface header line
        cols = line.split("\t")
        if len(cols) < 5:
            continue
        pk = cols[0]
        if pk not in pubkeys:
            continue
        try:
            hs = int(cols[4])
        except (ValueError, IndexError):
            hs = 0
        live[pk] = bool(hs) and (now - hs) < 180
    return live


def _rlevel_peer_entry(doc: dict, pubkey: str) -> tuple[str, str | None, str]:
    """(chosen, forced, floor) for pubkey, falling back to doc['defaults']."""
    defaults = doc.get("defaults") or {}
    def_mode = defaults.get("mode", "passive")
    def_floor = defaults.get("floor", "passive")
    p = (doc.get("peers") or {}).get(pubkey) or {}
    chosen = p.get("chosen") or def_mode
    forced = p.get("forced")
    floor = p.get("floor") or def_floor
    return chosen, forced, floor


def _rlevel_peer_for_ip(ip: str | None) -> str | None:
    """Resolve a wg-toolbox tunnel source IP to its pubkey — the self-service
    auth identity. None if the IP is not a known wg-toolbox peer."""
    if not ip:
        return None
    for pk, meta in _rlevel_load_wg_peers().items():
        if meta.get("ip") == ip:
            return pk
    return None


def _is_wg_peer_source(request: Request) -> bool:
    """True if the request's source IP is itself a known wg-toolbox tunnel
    peer. uvicorn binds 0.0.0.0:8088 and the wg-toolbox nft DNAT forwards a
    peer's tunnel traffic straight to it at L3/L4 — bypassing nginx/SSO
    entirely — so a peer can otherwise reach the ADMIN routes directly with
    nothing but its own tunnel IP. A peer cannot spoof this source (the DNAT
    preserves the real 10.99.1.x address), so "source is a known peer" is a
    sound negative test for "this is NOT an admin call"."""
    return _rlevel_peer_for_ip(_client_ip(request)) is not None


def _require_admin_source(request: Request) -> None:
    """Gate for the admin rlevel routes. Rejects 403 when the caller's source
    IP is a wg-toolbox tunnel peer: an admin acts through the admin vhost
    (nginx-proxied, so the source is loopback / a non-peer address), while a
    tunnel connection IS a peer connection by construction — never an admin
    one. Keeps the self-service /rlevel/me routes untouched (they require the
    OPPOSITE : the caller MUST be a tunnel peer)."""
    if _is_wg_peer_source(request):
        raise HTTPException(status_code=403, detail="tunnel-peer source cannot call admin rlevel routes")


@router.get("/rlevel/peers")
async def rlevel_peers(request: Request) -> dict:
    """Admin — every wg-toolbox peer's rlevel status (chosen/forced/floor/
    effective + best-effort live handshake). Read-only: sourced from
    wg-peers.json (identity) + `sbxmitm-policyctl list` (policy)."""
    if _is_public_kbin(request):
        raise HTTPException(status_code=403, detail="rlevel admin disabled on public vhost — use admin.gk2.secubox.in/toolbox/")
    _require_admin_source(request)
    wg_peers = _rlevel_load_wg_peers()
    doc = _rlevel_load_policy()
    live = _rlevel_wg_live(set(wg_peers.keys()))
    peers = []
    for pk, meta in wg_peers.items():
        chosen, forced, floor = _rlevel_peer_entry(doc, pk)
        peers.append({
            "pubkey": pk,
            "label": meta.get("label"),
            "chosen": chosen,
            "forced": forced,
            "floor": floor,
            "effective": _rlevel_effective(chosen, forced, floor),
            "live": live.get(pk),
        })
    return {"peers": peers, "defaults": doc.get("defaults")}


@router.post("/rlevel/peer")
async def rlevel_peer_set(request: Request) -> dict:
    """Admin — set a peer's floor and/or forced mode. Body: {"pubkey": str,
    "floor"?: mode, "forced"?: mode|null}. Every write is delegated to
    sbxmitm-policyctl (no in-process root).

    The pubkey travels in the JSON body, not the URL path : WireGuard
    pubkeys are standard base64 and routinely contain '/' (and '+'), which
    Starlette rejects in a path segment (even %2F-encoded) — a path param
    made roughly half of real pubkeys unaddressable."""
    if _is_public_kbin(request):
        raise HTTPException(status_code=403, detail="rlevel admin disabled on public vhost — use admin.gk2.secubox.in/toolbox/")
    _require_admin_source(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    pubkey = body.get("pubkey")
    if not pubkey or not isinstance(pubkey, str):
        raise HTTPException(status_code=400, detail="pubkey required")
    if pubkey not in _rlevel_load_wg_peers():
        raise HTTPException(status_code=404, detail="unknown wg-toolbox pubkey")
    floor = body.get("floor")
    forced_present = "forced" in body
    forced = body.get("forced")

    if floor is not None and not _rlevel_valid_mode(floor):
        raise HTTPException(status_code=400, detail=f"invalid floor mode: {floor}")
    if forced_present and forced is not None and not _rlevel_valid_mode(forced):
        raise HTTPException(status_code=400, detail=f"invalid forced mode: {forced}")

    results = {}
    if floor is not None:
        rc, out, err = _rlevel_ctl(["set-floor", pubkey, floor])
        if rc != 0:
            raise HTTPException(status_code=502, detail=err or "set-floor failed")
        results["floor"] = floor
    if forced_present:
        mode = forced if forced is not None else "none"
        rc, out, err = _rlevel_ctl(["force", pubkey, mode])
        if rc != 0:
            raise HTTPException(status_code=502, detail=err or "force failed")
        results["forced"] = forced

    if not results:
        raise HTTPException(status_code=400, detail="nothing to set (expected floor and/or forced)")
    return {"ok": True, "pubkey": pubkey, **results}


@router.get("/rlevel/me")
async def rlevel_me(request: Request) -> dict:
    """Peer self-service — identity is the wg-toolbox tunnel source IP itself
    (10.99.1.x), resolved to a pubkey via wg-peers.json. 403 if the source IP
    is not a known wg-toolbox peer (tunnel-auth, no token/JWT involved)."""
    ip = _client_ip(request)
    pubkey = _rlevel_peer_for_ip(ip)
    if not pubkey:
        raise HTTPException(status_code=403, detail="source IP is not a known wg-toolbox peer")
    doc = _rlevel_load_policy()
    chosen, forced, floor = _rlevel_peer_entry(doc, pubkey)
    return {
        "chosen": chosen,
        "forced": forced,
        "floor": floor,
        "effective": _rlevel_effective(chosen, forced, floor),
    }


@router.post("/rlevel/me")
async def rlevel_me_set(request: Request) -> dict:
    """Peer self-service — set own `chosen` mode, bounded: a peer can never
    descend below its own floor nor lift a `forced` (409 either way). Delegates
    to `sbxmitm-policyctl set-chosen` (which re-clamps server-side too)."""
    ip = _client_ip(request)
    pubkey = _rlevel_peer_for_ip(ip)
    if not pubkey:
        raise HTTPException(status_code=403, detail="source IP is not a known wg-toolbox peer")

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    chosen = body.get("chosen")
    if not chosen or not _rlevel_valid_mode(chosen):
        raise HTTPException(status_code=400, detail=f"invalid chosen mode: {chosen}")

    doc = _rlevel_load_policy()
    _cur_chosen, forced, floor = _rlevel_peer_entry(doc, pubkey)
    if forced:
        raise HTTPException(status_code=409, detail=f"mode is forced to '{forced}' by admin")
    if _RLEVEL_RANK[chosen] < _RLEVEL_RANK[floor]:
        raise HTTPException(status_code=409, detail=f"below floor '{floor}'")

    rc, out, err = _rlevel_ctl(["set-chosen", pubkey, chosen])
    if rc != 0:
        raise HTTPException(status_code=502, detail=err or "set-chosen failed")
    return {"ok": True, "chosen": chosen, "floor": floor,
            "effective": _rlevel_effective(chosen, None, floor)}


@router.get("/admin/filters/ui", response_class=HTMLResponse)
async def admin_filters_ui() -> HTMLResponse:
    """#566 — minimal filter toggle panel for the toolbox WebUI."""
    html = """<!doctype html><html lang=fr><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Filtres ToolBoX</title>
<style>
 body{background:#0a0a0f;color:#e8e6d9;font:14px system-ui,sans-serif;max-width:560px;margin:30px auto;padding:0 18px}
 h1{color:#c9a84c;font-size:18px} h2{color:#6e40c9;font-size:13px;margin:18px 0 6px}
 label{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #1a1a22}
 select,input{accent-color:#6e40c9} .muted{color:#6b6b7a;font-size:12px}
 .stat{display:inline-block;background:#12121a;border:1px solid #222;border-radius:6px;padding:6px 10px;margin:4px 4px 0 0}
 #msg{color:#00ff41;min-height:18px;margin-top:10px}
</style>
<h1>🛡 Filtres ToolBoX</h1>
<p class=muted>Activation/désactivation à chaud des filtres mitm (R2/R3+). Prend effet en quelques secondes, sans redémarrage.</p>
<div id=stats></div>
<h2>Bannière & inspection</h2>
<label><input type=checkbox data-k=banner> Bannière de transparence (R2/R3)</label>
<label>Mode protecteur (spoof traceurs)
  <select data-k=protective><option value=off>off</option><option value=alert>alert</option><option value=spoof>spoof</option></select></label>
<h2>Ghosting pub (R3+/R4)</h2>
<label><input type=checkbox data-k=ad_ghost> Masquer pubs/bannières/widgets (cosmétique)</label>
<label><input type=checkbox data-k=ad_ghost_block> Bloquer les hôtes pub/traceurs (économise la bande passante)</label>
<h2>Cache média partagé (#577)</h2>
<label><input type=checkbox data-k=media_cache> Cache média/photo/vidéo partagé (2 Go, 1 fetch → tous les clients)</label>
<h2>Catégories ghosting</h2>
<label><input type=checkbox data-c=ads> · catégorie : publicités</label>
<label><input type=checkbox data-c=consent_nag> · catégorie : bandeaux cookies/consentement</label>
<label><input type=checkbox data-c=newsletter> · catégorie : pop-ups newsletter</label>
<label><input type=checkbox data-c=social_widgets> · catégorie : widgets sociaux</label>
<p id=msg></p>
<script>
const $=s=>document.querySelector(s);
function post(p){fetch('/admin/filters',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(p)}).then(r=>r.json()).then(load).then(()=>{$('#msg').textContent='Enregistré ✓';setTimeout(()=>$('#msg').textContent='',1200)});}
function load(f){
 document.querySelectorAll('[data-k]').forEach(el=>{const k=el.dataset.k;if(el.type==='checkbox')el.checked=!!f[k];else el.value=f[k];});
 const c=f.ad_ghost_categories||{};document.querySelectorAll('[data-c]').forEach(el=>el.checked=!!c[el.dataset.c]);
}
function wire(){
 document.querySelectorAll('[data-k]').forEach(el=>el.addEventListener('change',()=>{const v=el.type==='checkbox'?el.checked:el.value;post({[el.dataset.k]:v});}));
 document.querySelectorAll('[data-c]').forEach(el=>el.addEventListener('change',()=>post({ad_ghost_categories:{[el.dataset.c]:el.checked}})));
}
function stats(){fetch('/admin/ghost').then(r=>r.json()).then(g=>{$('#stats').innerHTML=`<span class=stat>🛡 ${g.blocked_requests||0} bloqués</span><span class=stat>💾 ~${g.mb_saved_est||0} Mo économisés</span><span class=stat>🧹 ${g.pages_cleaned||0} pages nettoyées</span>`;});}
fetch('/admin/filters').then(r=>r.json()).then(f=>{load(f);wire();stats();});
</script></html>"""
    return HTMLResponse(content=html)


@router.get("/social/report/{token}.pdf")
async def social_report_pdf(token: str) -> Response:
    """Phase 11.C (#508) — bilingual FR/EN evidence PDF for a peer.

    Same HMAC-token gate as /social/graph/{token}.  Fact-only report :
    cross-site tracker reuse, trackers fired before consent (RGPD art.
    6.1.a + 7), extra-EU transfers (art. 44+).
    """
    from . import social_report as _sr
    salt = _get_salt()
    ok, mac_hash = reports.verify_token(token, salt)
    if not ok:
        raise HTTPException(404, "report not found or expired")
    data = _sr.build_social_report(mac_hash, since_seconds=7 * 86400)
    data["generated_at"] = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    pdf_bytes = await _render_pdf_offloaded(_sr.render_social_pdf, data, cache_key=f"soc:{mac_hash}")
    fname = f"village3b-carto-{mac_hash[:8]}-{int(time.time())}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ───────────────── Phase 11.B — per-client view + favicon proxy (#507) ─────────────────

import json as _json_b


def _load_social_i18n(lang: str) -> dict:
    """Pick the FR or EN dictionary.  FR is the source-of-truth."""
    lang = (lang or "").lower().split(",", 1)[0].split("-", 1)[0]
    if lang not in ("en", "fr"):
        lang = "fr"
    path = TEMPLATE_DIR / "i18n" / f"social.{lang}.json"
    try:
        return _json_b.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("social i18n load failed (%s): %s", lang, e)
        return {}


@router.get("/social/me")
async def social_view_me(request: Request) -> RedirectResponse:
    """Self-resolving entry point used by the kbin splash menu.

    Resolution chain (matches /report/me/html):
      1. ?mh=<hash>             explicit R3 hash in URL (e.g. from banner)
      2. X-R3-Peer header       mitm-wg's inject_xff sentinel for transparent
                                R3 flows (peer IP in 10.99.1.0/24)
      3. _resolve() ARP lookup  R2 captive subnet clients only

    Mints a short-TTL (1 h) HMAC token bound to the resolved mac_hash and
    redirects to /social/{token}.  Keeps a single HMAC-token-gated code
    path for the graph view + wipe endpoint.
    """
    salt = _get_salt()
    mac_hash = None

    # 1) ?mh= overrides everything (used by inject_banner.py links + the
    # report flow + manual curl).
    mh_qp = (request.query_params.get("mh") or "").strip().lower()
    if mh_qp and all(c in "0123456789abcdef" for c in mh_qp) and 8 <= len(mh_qp) <= 64:
        mac_hash = mh_qp

    # 2) X-R3-Peer (transparent R3 — the iPhone hits kbin via the R3
    # tunnel, mitm-wg adds the sentinel, HAProxy passes it through).
    # We derive the same mac_hash the local_store addon uses :
    # sha256(wg_pubkey)[:16] looked up from /var/lib/secubox/toolbox/
    # wg-peers.json keyed by peer IP.
    if not mac_hash:
        peer_ip = _client_ip(request)
        if peer_ip and peer_ip.startswith("10.99.1."):
            try:
                import hashlib as _h
                import json as _j
                from pathlib import Path as _P
                _DB = _P("/var/lib/secubox/toolbox/wg-peers.json")
                if _DB.exists():
                    peers = _j.loads(_DB.read_text()).get("peers", {})
                    for pubkey, meta in peers.items():
                        if meta.get("ip") == peer_ip:
                            mac_hash = _h.sha256(pubkey.encode()).hexdigest()[:16]
                            break
            except Exception as e:
                log.warning("/social/me wg-peer lookup failed: %s", e)

    # 3) R2 captive — ARP _resolve().
    if not mac_hash:
        _ip, mac = _resolve(request)
        if mac:
            mac_hash = macmod.hash_mac(mac, salt)

    if not mac_hash:
        raise HTTPException(
            400,
            "client identity unresolved (not on R3 tunnel and not in "
            "captive subnet) — append ?mh=<hash> from your banner's "
            "report link",
        )

    tok = reports.mint_token(mac_hash, salt, ttl_seconds=3600)
    lang = request.query_params.get("lang") or ""
    suffix = f"?lang={lang}" if lang else ""
    return RedirectResponse(url=f"/social/{tok.token}{suffix}", status_code=303)


@router.get("/social/{token}", response_class=HTMLResponse)
async def social_view(token: str, request: Request) -> HTMLResponse:
    """Per-client social mapping HTML page.

    HMAC-token-gated identically to /report/{token} so the same kbin
    splash + R3 onboard flow can issue a link.  The page itself
    contains no per-client data — the d3 layer fetches it via
    GET /social/graph/{token} after page-load (so a forwarded link
    that's been TTL-expired surfaces an empty graph + error message
    in the page rather than a 404 at HTTP layer).
    """
    salt = _get_salt()
    ok, _mac_hash = reports.verify_token(token, salt)
    if not ok:
        raise HTTPException(404, "page not found or expired")

    # Language pick : query string `?lang=` wins, else Accept-Language.
    lang = request.query_params.get("lang") or request.headers.get("accept-language", "fr")
    lang = "fr" if "fr" in lang.lower() else "en"
    i18n = _load_social_i18n(lang)
    html = _env.get_template("social_view.html.j2").render(
        token=token,
        lang=lang,
        t=i18n,
        t_json=_json_b.dumps(i18n, ensure_ascii=False),
    )
    return HTMLResponse(content=html)


# Favicon cache (Phase 11.B) — server-side cache so the per-client
# view never makes a client-side request to a tracker domain just to
# show its icon.  Default TTL 7 d.
_FAVICON_CACHE_DIR = Path("/var/lib/secubox/toolbox/favicons")
_FAVICON_TTL_SECONDS = 7 * 86400


@router.get("/social/favicon/{domain}")
async def social_favicon(domain: str) -> Response:
    """Server-side favicon proxy with 7 d disk cache.

    Path traversal is impossible because `domain` is whitelisted to
    a strict charset and the cache file is sha256-keyed.  We fetch
    over HTTPS only, time out hard at 5 s, and fall back to a 1×1
    transparent gif on any failure.
    """
    import hashlib as _h
    import re as _re
    import time as _time

    if not _re.match(r"^[a-z0-9.-]{1,253}$", domain.lower()):
        raise HTTPException(400, "invalid domain")

    _FAVICON_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _h.sha256(domain.lower().encode()).hexdigest()[:24]
    cache_file = _FAVICON_CACHE_DIR / f"{key}.ico"
    now = _time.time()

    if cache_file.exists() and now - cache_file.stat().st_mtime < _FAVICON_TTL_SECONDS:
        return Response(
            content=cache_file.read_bytes(),
            media_type="image/x-icon",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    # Best-effort fetch.  No cross-host redirects, no JS, no cookies.
    try:
        import httpx
        url = f"https://{domain.lower()}/favicon.ico"
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as c:
            r = await c.get(
                url,
                headers={"User-Agent": "SecuBox-ToolBox-Favicon-Cache/1.0"},
            )
            if r.status_code == 200 and r.content and len(r.content) < 65536:
                cache_file.write_bytes(r.content)
                return Response(
                    content=r.content,
                    media_type="image/x-icon",
                    headers={"Cache-Control": "public, max-age=86400"},
                )
    except Exception as e:  # noqa: BLE001
        log.warning("favicon fetch failed for %s: %s", domain, e)

    # Fallback : 1×1 transparent gif.
    GIF = (
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
        b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02L\x01\x00;"
    )
    return Response(
        content=GIF,
        media_type="image/gif",
        headers={"Cache-Control": "public, max-age=300"},
    )


@router.get("/admin/config")
async def admin_config() -> dict:
    return _get_cfg().model_dump()


@router.get("/admin/clients", response_model=list[ClientRow])
async def admin_clients() -> list[ClientRow]:
    rows = store.list_clients()
    return [ClientRow(**r) for r in rows]


@router.get("/admin/clients/rich")
async def admin_clients_rich() -> dict:
    """Phase 6.D : enriched client list with pseudo icons + statuses + levels.

    Returns each client decorated with device emoji, status emoji, level chip,
    last activity, real device classification (from UA), and geo data (country,
    flag, ASN org).  Designed for the admin webui table.
    """
    import time as _t
    # Use module-level imports so monkeypatching in tests works correctly.
    _av = avatar_analysis
    _geo = geo
    # Phase 6 (#662) : map each WG client to its REAL external (pre-tunnel)
    # endpoint IP so the flag reflects the client's true origin country, not
    # the internal 10.99.1.x (which GeoIPs to nothing). Best-effort, cached.
    try:
        from . import wg as _wg
        _wg_eps = _wg.wg_endpoints()
    except Exception:
        _wg_eps = {}
    rows = store.list_clients()
    rows = sorted(rows, key=lambda r: (r.get("last_seen") or 0), reverse=True)
    now = _t.time()
    enriched = []
    for idx, r in enumerate(rows):
        age_min = (now - (r.get("last_seen") or 0)) / 60.0
        if age_min < 5:
            status_emoji = "🟢"
            status_label = "actif"
        elif age_min < 60:
            status_emoji = "🟡"
            status_label = "idle"
        else:
            status_emoji = "⚪"
            status_label = "expiré"
        if r.get("state") == "quarantine":
            status_emoji = "🔴"
            status_label = "quarantine"
        level = r.get("level") or "r1"
        level_emoji = {"r0": "🌐", "r1": "🛡", "r2": "🔍", "r3": "🌐"}.get(level, "❔")
        score = r.get("score", 0)
        risk_emoji = "🟢" if score < 30 else "🟡" if score < 70 else "🔴"

        # Device + geo enrichment only for the displayed rows (ENRICH_LIMIT).
        dev_emoji, dev_label = "📱", ""
        flag = country_iso = asn_org = ""
        if idx < ENRICH_LIMIT:
            try:
                ua = store.latest_user_agent(r.get("mac_hash") or "")
                if ua:
                    cl = _av.classify_user_agent(ua)
                    dev_emoji = cl.get("device_emoji") or dev_emoji
                    dev_label = cl.get("device") or ""
            except Exception:
                pass
            try:
                # PRIVACY : the external endpoint IP is used transiently for the
                # GeoIP lookup ONLY — it is NEVER stored or returned in the API
                # response. The appliance is privacy-focused: country-granularity
                # only (flag / ISO), never the raw client origin IP. Fall back to
                # the stored (internal) IP for non-WG / captive clients.
                geo_key = _wg_eps.get(r.get("mac_hash") or "") or (r.get("ip") or "")
                gi = _geo.lookup(geo_key)
                flag = gi.get("flag", "") or ""
                country_iso = gi.get("country_iso", "") or ""
                asn_org = gi.get("asn_org", "") or ""
            except Exception:
                pass

        enriched.append({
            "mac_hash": r.get("mac_hash"),
            "ip": r.get("ip"),
            "state": r.get("state"),
            "level": level,
            "level_emoji": level_emoji,
            "score": score,
            "risk_emoji": risk_emoji,
            "status_emoji": status_emoji,
            "status_label": status_label,
            "first_seen": r.get("first_seen"),
            "last_seen": r.get("last_seen"),
            "device_emoji": dev_emoji,
            "device": dev_label,
            "flag": flag,
            "country_iso": country_iso,
            "asn_org": asn_org,
        })
    return {"clients": enriched, "count": len(enriched)}


@router.post("/admin/clients/{mac_hash}/level")
async def admin_override_level(mac_hash: str, request: Request) -> dict:
    """Phase 6.D : admin override of a client's level (operator-only).

    Allows the operator to force-change a client's R0/R1/R2/R3 level from
    the admin webUI without requiring the client to navigate the dashboard.

    Phase 6.J : refused on public kbin vhost — editing happens only via
    auth-gated admin.gk2.secubox.in/toolbox/.
    """
    if _is_public_kbin(request):
        raise HTTPException(403, "level override disabled on public vhost — use admin.gk2.secubox.in/toolbox/")
    try:
        form = await request.form()
        new_level = (form.get("level") or "").lower()
    except Exception:
        new_level = ""
    if new_level not in ("r0", "r1", "r2", "r3"):
        raise HTTPException(400, f"invalid level '{new_level}', expected r0|r1|r2|r3")
    # Need to know the client's current MAC ; the store keeps mac_hash only.
    # Without raw MAC we can't update nft sets — operator must trigger the
    # client's own /change-level to push to nft. We update the store level
    # which the inject_banner addon reads.
    row = next((c for c in store.list_clients() if c.get("mac_hash") == mac_hash), None)
    if not row:
        raise HTTPException(404, "client not found")
    store.upsert_client(mac_hash, row.get("ip") or "?", level=new_level)
    log.info("admin override mac_hash=%s -> level=%s", mac_hash, new_level)
    return {"ok": True, "mac_hash": mac_hash, "new_level": new_level,
            "note": "nft sets not auto-updated; client must reload or operator manually adjusts nft"}


# Phase 11.B+ (#513) — the inline kbin /admin/ HTML admin UI was removed.
# The canonical operator dashboard is admin.gk2.secubox.in/toolbox/ (sub-tab
# WebUI in www/toolbox/index.html).  All /admin/* JSON API routes below stay.


@router.get("/admin/metrics")
async def admin_metrics() -> dict:
    """Live metrics for the admin WebUI : per-source event counts (DPI, cookies,
    SOC, JA4), recent clients, mitmproxy flow stats."""
    import sqlite3 as _sq3
    import subprocess as _sp
    metrics = {
        "events_by_source": {},
        "clients_active": 0,
        "events_24h_total": 0,
        "mitm": {"connections": 0, "tls_pinned": 0, "unique_hosts": 0},
    }
    # Per-source event counts. The legacy toolbox.db `events` table was fed by the
    # OLD Python mitmproxy addons; the current R3 path is Go sbxmitm → relay →
    # sidecars → cumulative stats, so that table is now empty. Read the cumulative
    # per-source totals (cookies/ja4/…) when the events table has nothing, so the
    # Live-metrics panel shows real activity instead of zeros.
    since = int(time.time()) - 86400
    try:
        with _sq3.connect("/var/lib/secubox/toolbox/toolbox.db", timeout=2) as c:
            rows = c.execute(
                "SELECT source, COUNT(*) FROM events WHERE ts > ? GROUP BY source",
                (since,),
            ).fetchall()
            metrics["events_by_source"] = {r[0]: r[1] for r in rows}
            metrics["events_24h_total"] = sum(metrics["events_by_source"].values())
            metrics["clients_active"] = c.execute(
                "SELECT COUNT(*) FROM clients WHERE last_seen > ?",
                (since,),
            ).fetchone()[0]
    except Exception as e:
        metrics["sqlite_error"] = str(e)
    if not metrics["events_by_source"]:
        try:
            ev = (cumulative.get_cached() or {}).get("events", {}) or {}
            src = {k: int(v) for k, v in ev.items()
                   if k != "total_7d" and isinstance(v, (int, float))}
            if src:
                metrics["events_by_source"] = src
                metrics["events_24h_total"] = int(ev.get("total_7d") or sum(src.values()))
                metrics["events_window"] = "7d"  # cumulative fallback, not strictly 24h
        except Exception:
            pass
    # Live MITM activity. NOTE: the old journal-scrape for "server connect"
    # NEVER worked — the workers run at --log-level warning, so those INFO lines
    # are never emitted → the trio was permanently 0. Derive from real data: the
    # cumulative stats (same source the landing page uses) + the auto-learned
    # cert-pin bypass list.
    try:
        cs = cumulative.get_cached() or {}
        ev = cs.get("events", {}) or {}
        # "connections analysées" — each JA4 observation is one inspected TLS
        # handshake/upstream connection. The cumulative stats expose ja4 (and
        # cookies), not a `dpi` key, so the old ev.get("dpi") was always 0.
        metrics["mitm"]["connections"] = int(ev.get("ja4") or ev.get("dpi") or 0)
        metrics["mitm"]["unique_hosts"] = len(cs.get("top_hosts_7d", []) or [])
    except Exception:
        pass
    # Cert-pinned hosts that had to be bypassed (auto-learned by cert_pin_detect).
    try:
        if MITM_BYPASS_DYNAMIC_FILE.exists():
            metrics["mitm"]["tls_pinned"] = sum(
                1 for ln in MITM_BYPASS_DYNAMIC_FILE.read_text().splitlines()
                if ln.strip() and not ln.strip().startswith("#"))
    except Exception:
        pass
    return metrics


@router.get("/admin/clients/{mac_hash}/report")
async def admin_client_report(mac_hash: str) -> Response:
    """Admin endpoint : download PDF for a specific client by mac_hash."""
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    _enrich_report_data(mac_hash, data)  # #790 — same rich content as /report/me
    pdf_bytes = await _render_pdf_offloaded(reports.render_pdf, data, cache_key=f"adm:{mac_hash}")
    fname = f"gondwana-toolbox-{mac_hash[:8]}-admin.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/admin/clients/{mac_hash}/social")
async def admin_client_social(mac_hash: str, request: Request) -> RedirectResponse:
    """Phase 12.B (#516) — operator entry to a client's social mapping
    graph from the toolbox WebUI Clients tab.  Mints a short-TTL (1 h)
    HMAC token for the mac_hash and 303-redirects to the per-client view.

    The /social/ route is ONLY served on the kbin vhost (HAProxy → the
    toolbox uvicorn).  When the operator triggers this from
    admin.gk2.secubox.in, a relative redirect would land on the
    aggregator's "missing module" page — so we build an ABSOLUTE kbin
    URL by swapping the leading `admin.` host label for `kbin.`.
    """
    salt = _get_salt()
    tok = reports.mint_token(mac_hash, salt, ttl_seconds=3600)
    host = (request.headers.get("host") or "").strip()
    if host.startswith("admin."):
        kbin_host = "kbin." + host[len("admin."):]
        target = f"https://{kbin_host}/social/{tok.token}"
    elif host.startswith("kbin."):
        target = f"/social/{tok.token}"  # already on kbin, relative is fine
    else:
        # Fallback : same-origin relative (dev / direct uvicorn).
        target = f"/social/{tok.token}"
    return RedirectResponse(url=target, status_code=303)


@router.post("/admin/clients/{mac_hash}/reset")
async def admin_client_reset(mac_hash: str) -> dict:
    """Phase 12.B (#516) — RAZ a specific client's accumulated statistics
    from the operator WebUI.  Wipes the social-mapping graph + the
    toolbox events/consents/reports and zeroes the client score.
    """
    from . import social as _s
    rows = store.reset_client(mac_hash)
    rows += _s.wipe_mac(mac_hash)
    log.info("admin reset client %s: %d rows", mac_hash[:8], rows)
    return {"ok": True, "rows_deleted": rows, "mac_hash_prefix": mac_hash[:8]}


def _reset_all_clients() -> dict:
    """Apply the per-client reset to every client (events/consents/reports +
    social graph wiped, score zeroed, client row kept). One client's failure is
    logged and skipped. Returns counts."""
    from . import social as _s
    clients_reset = 0
    rows_deleted = 0
    for c in store.list_clients():
        mh = c.get("mac_hash")
        if not mh:
            continue
        try:
            rows_deleted += store.reset_client(mh)
            rows_deleted += _s.wipe_mac(mh)
            clients_reset += 1
        except Exception as e:
            log.warning("reset-all: client %s failed: %s", str(mh)[:8], e)
    log.info("admin reset-all: %d clients, %d rows", clients_reset, rows_deleted)
    return {"ok": True, "clients_reset": clients_reset, "rows_deleted": rows_deleted}


@router.post("/admin/clients/reset-all")
async def admin_clients_reset_all(request: Request) -> dict:
    """RAZ ALL clients (bulk per-client reset). Blocked on the public kbin vhost."""
    if _is_public_kbin(request):
        raise HTTPException(403, "reset-all disabled on public vhost — use admin.gk2.secubox.in/toolbox/")
    return _reset_all_clients()


@router.get("/admin/clients/{mac_hash}/events")
async def admin_client_events(mac_hash: str) -> dict:
    """Admin endpoint : per-source event summary for a specific client."""
    import json as _json
    import sqlite3 as _sq3
    res = {"mac_hash": mac_hash, "events_by_source": {}, "recent": []}
    try:
        with _sq3.connect("/var/lib/secubox/toolbox/toolbox.db", timeout=2) as c:
            rows = c.execute(
                "SELECT source, COUNT(*) FROM events WHERE mac_hash=? GROUP BY source",
                (mac_hash,),
            ).fetchall()
            res["events_by_source"] = {r[0]: r[1] for r in rows}
            recent = c.execute(
                "SELECT source, ts, payload FROM events WHERE mac_hash=? "
                "ORDER BY ts DESC LIMIT 30",
                (mac_hash,),
            ).fetchall()
            for src, ts, payload in recent:
                try:
                    p = _json.loads(payload)
                except Exception:
                    p = {}
                res["recent"].append({"source": src, "ts": ts, **{
                    k: v for k, v in p.items()
                    if k in ("host", "url", "method", "kind", "weight", "sni", "status")
                }})
    except Exception as e:
        res["error"] = str(e)
    return res


@router.get("/health")
async def health() -> dict:
    return {"status": "ok", "module": "toolbox", "version": "1.0.0"}
