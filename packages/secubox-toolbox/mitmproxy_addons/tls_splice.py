# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: toolbox :: selective SNI-splice (#649, Lever A).

At the TLS ClientHello, splice (raw passthrough, no forge/decrypt/parse/addons)
pure-asset flows decided from the SNI. Modes (filters.tls_splice):
  off     — never splice (legacy: MITM everything)
  observe — classify + log/count "would-splice", but still MITM (dark-launch)
  on      — actually splice
Also records per-host content-type observations (MITM'd flows) to feed the
autolearn never-HTML promotion. Registered FIRST in the mitm-wg addon chain.
"""
from __future__ import annotations

import concurrent.futures as _futures
import json
import logging
import os
import sys
import time

if "/usr/lib/secubox/toolbox" not in sys.path:
    sys.path.insert(0, "/usr/lib/secubox/toolbox")

from secubox_toolbox import splice as _splice          # noqa: E402
from secubox_toolbox.filters import get_filters as _gf  # noqa: E402
try:
    from secubox_toolbox import store as _store          # noqa: E402
except Exception:  # pragma: no cover
    _store = None

log = logging.getLogger("secubox.toolbox.addons")

SEED_PATH = os.environ.get("SECUBOX_SPLICE_SEED",
                           "/usr/lib/secubox/toolbox/conf/tls-splice-seed.conf")
LEARNED_PATH = os.environ.get("SECUBOX_SPLICE_LEARNED",
                              "/var/lib/secubox/toolbox/splice-learned.txt")
PURE_PATH = os.environ.get("SECUBOX_PURE_TRACKERS",
                           "/var/lib/secubox/toolbox/pure-trackers.txt")
STATS = "/run/secubox/splice.json"

_counts = {"spliced": 0, "would_splice": 0, "mitm": 0, "since": int(time.time())}
_last_flush = 0.0

# Learning observations are written off the proxy event loop (mirror
# local_store): the response hook must return instantly. Single worker thread
# serialises writes to the shared SQLite.
_obs_executor = _futures.ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="sbx_splice_obs")


class TlsSplice:
    def __init__(self) -> None:
        self._seed: set = set()
        self._learned: set = set()
        self._never: set = set()
        self._mtimes: tuple = ()
        self._refresh_sets()

    def _refresh_sets(self) -> None:
        """Reload seed/learned/never sets when any backing file changes."""
        try:
            mtimes = tuple(
                os.stat(p).st_mtime if os.path.exists(p) else 0.0
                for p in (SEED_PATH, LEARNED_PATH, PURE_PATH))
        except Exception:
            mtimes = ()
        if mtimes == self._mtimes and self._seed:
            return
        self._seed = _splice.load_splice_seed(SEED_PATH)
        self._learned = _splice.load_learned_splice(LEARNED_PATH)
        never = _splice.load_learned_splice(PURE_PATH)   # pure trackers
        try:
            for s in _gf().get("fortknox_sites", []) or []:
                never.add(str(s).lower().strip("."))
        except Exception:
            pass
        self._never = never
        self._mtimes = mtimes

    def tls_clienthello(self, data) -> None:
        try:
            mode = _gf().get("tls_splice", "observe")
            if mode == "off":
                return
            # media_cache wants to see asset flows → don't splice when it's on
            if _gf().get("media_cache"):
                return
            sni = getattr(data.client_hello, "sni", None)
            if not sni:
                return
            self._refresh_sets()
            if not _splice.should_splice(sni, self._seed, self._learned, self._never):
                return
            if mode == "on":
                data.ignore_connection = True
                _counts["spliced"] += 1
            else:  # observe
                _counts["would_splice"] += 1
                log.info("tls-splice would-splice %s", sni)
            self._flush()
        except Exception as e:  # never break a connection
            log.debug("tls_splice clienthello error: %s", e)

    def response(self, flow) -> None:
        """Record host content-type on MITM'd flows (learning signal).

        Off the event loop (bg thread) so the hook returns instantly. Skips
        hosts already decided (seed/learned/never) — they need no more signal —
        so the DB is touched only for the still-unclassified long tail.
        """
        if _store is None:
            return
        try:
            if _gf().get("tls_splice", "observe") == "off":
                return
            host = (flow.request.pretty_host or "").lower().strip(".")
            if not host:
                return
            # Already-decided hosts gain nothing from more observations.
            if (_splice.host_matches(host, self._seed)
                    or _splice.host_matches(host, self._learned)
                    or _splice.host_matches(host, self._never)):
                return
            ct = (flow.response.headers.get("content-type", "") or "").lower()
            _obs_executor.submit(_store.record_splice_obs, host, "text/html" in ct)
        except Exception:
            pass

    def _flush(self) -> None:
        global _last_flush
        now = time.time()
        if (now - _last_flush) < 5:
            return
        _last_flush = now
        try:
            os.makedirs(os.path.dirname(STATS), exist_ok=True)
            with open(STATS, "w", encoding="utf-8") as f:
                json.dump({**_counts, "updated": int(now)}, f)
        except Exception:
            pass


addons = [TlsSplice()]
