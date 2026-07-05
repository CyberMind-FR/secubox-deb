# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tiered presence alert engine (Project B, #820,
Task 6).

`load_config()` parses `/etc/secubox/presence-alerts.toml` (stdlib
`tomllib`). Its ABSENCE is the feature's off-switch, per the plan's "no
mail storms" constraint: a missing file returns `None` and `evaluate()`
then does nothing at all — no alert is computed, recorded, or emailed.
Config shape (all keys optional; a plane section with no keys disables
that plane's checks)::

    recipient = "admin@example.com"   # required for email; alerts still
                                       # record without it
    window_seconds = 3600             # both the lookback window used by
                                       # the checks AND the email dedup
                                       # coalescing window

    [wan]
    bot_surge = 50      # > N bot/crawler wan presences last-seen within
                        # `window_seconds` -> tier "warn"
    new_country = true  # a geo_cc never seen before (this process's
                        # lifetime, tracked in `state`) -> tier "notice"

    [wg]
    rogue_router = true # a wg/lan presence linked to a device A scored
                        # risk_level=="high" (the rogue-AP signal, #817) ->
                        # tier "warn"

`evaluate(store, config, mailer_send, *, now, state)` is the tiered engine:
each check below independently computes zero or more "conditions"
(`{plane, tier, detail}`). Every fired condition is UNCONDITIONALLY passed
to `store.record_alert(plane, tier, detail)` (so the alert log/webui always
reflects reality even when config is present but no recipient is set, or
sendmail is down) — only the EMAIL is deduped/rate-limited, coalesced per
`(tier, plane)` per `window_seconds` via `state["last_sent"]` (a caller-held
dict; the collector/Task 7 loop is expected to keep the SAME `state` dict
across cycles so the dedup actually spans process lifetime rather than
resetting every call).

`state["seen_countries"]` is the `new_country` check's own novelty memory
(distinct from the generic per-`(tier,plane)` email dedup): a country is
"new" only once, ever (per `state`'s lifetime) — after the first sighting
it's remembered and never re-fires, independent of the email window.

FAIL-SAFE throughout: a malformed/unreadable config resolves to `None`
(same as "absent" -> no alerts). Any exception raised by an individual
check function, by `store.record_alert`, or by `mailer_send` is caught
locally and never propagates out of `evaluate()` — one broken input source
degrades that check to "no conditions fired", not a crashed loop.

Pure stdlib (`tomllib`, `json`, `time`). No I/O at import time — only
`load_config()` touches the filesystem.
"""
from __future__ import annotations

import json
import tomllib

DEFAULT_CONFIG_PATH = "/etc/secubox/presence-alerts.toml"
DEFAULT_WINDOW_SECONDS = 3600

# client_type values counted as "bot traffic" by the wan.bot_surge check
# (mirrors presence.wan.classify_ua's bot/crawler buckets).
_BOT_CLIENT_TYPES = ("bot", "crawler")


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict | None:
    """Parse the presence-alerts TOML config. Never raises.

    Returns `None` when the file is absent, unreadable, or fails to parse
    as TOML — this IS the feature's off-switch: no config -> `evaluate()`
    computes/records/emails nothing.
    """
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        # OSError (missing/unreadable file), tomllib.TOMLDecodeError
        # (malformed TOML), or anything else — all mean "no config".
        return None
    if not isinstance(data, dict):
        return None
    return data


def _extra_risk_level(pres: dict) -> str | None:
    """Best-effort pull of `extra.risk_level` (JSON) off a presence row."""
    extra = pres.get("extra")
    if not extra:
        return None
    try:
        parsed = json.loads(extra)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed.get("risk_level")


def _check_bot_surge(store, config, *, now, window, state) -> list:
    """`[wan] bot_surge = N` — > N bot/crawler wan presences in `window`."""
    threshold = config.get("wan", {}).get("bot_surge")
    if not threshold:
        return []
    try:
        presences = store.list(plane="wan")
    except Exception:
        return []
    if not presences:
        return []

    count = 0
    for pres in presences:
        if pres.get("client_type") not in _BOT_CLIENT_TYPES:
            continue
        last_seen = pres.get("last_seen") or 0
        if (now - last_seen) <= window:
            count += 1

    if count > threshold:
        return [{
            "plane": "wan",
            "tier": "warn",
            "detail": f"bot surge: {count} bot/crawler wan presences in the last {window}s (threshold {threshold})",
        }]
    return []


def _check_new_country(store, config, *, now, window, state) -> list:
    """`[wan] new_country = true` — a geo_cc never seen before -> notice.

    Novelty is tracked in `state["seen_countries"]`, NOT the generic
    per-`(tier,plane)` email dedup window — a country alerts once ever
    (per `state`'s lifetime), not once per window.
    """
    if not config.get("wan", {}).get("new_country"):
        return []
    try:
        presences = store.list(plane="wan")
    except Exception:
        return []
    if not presences:
        return []

    seen = state.setdefault("seen_countries", set())
    fired = []
    for pres in presences:
        cc = pres.get("geo_cc")
        if not cc or cc in seen:
            continue
        seen.add(cc)
        fired.append({
            "plane": "wan",
            "tier": "notice",
            "detail": f"new country seen on wan: {cc}",
        })
    return fired


def _check_rogue_router(store, config, *, now, window, state) -> list:
    """`[wg] rogue_router = true` — a wg/lan presence linked to a device A
    scored `risk_level == "high"` (#817's rogue-AP signal: an unknown
    router)."""
    if not config.get("wg", {}).get("rogue_router"):
        return []

    fired = []
    for plane in ("wg", "lan"):
        try:
            presences = store.list(plane=plane)
        except Exception:
            continue
        for pres in presences:
            if _extra_risk_level(pres) != "high":
                continue
            fired.append({
                "plane": plane,
                "tier": "warn",
                "detail": f"rogue router signal on {plane}: {pres.get('identity')}",
            })
    return fired


# Extensible: append additional `(store, config, *, now, window, state) ->
# list[dict]` check functions here to add more tiers/conditions without
# touching `evaluate()`.
_CHECKS = (
    _check_bot_surge,
    _check_new_country,
    _check_rogue_router,
)


def _should_send(state: dict, tier: str, plane: str, now: float, window: float) -> bool:
    """Per-`(tier, plane)` email dedup/rate-limit. Records `now` on send."""
    last_sent = state.setdefault("last_sent", {})
    key = (tier, plane)
    last = last_sent.get(key)
    if last is not None and (now - last) < window:
        return False
    last_sent[key] = now
    return True


def evaluate(store, config, mailer_send, *, now, state: dict) -> list:
    """Run every check, record every fired condition, email deduped/rate-limited.

    Returns the list of fired alert dicts (`{plane, tier, detail}`), in
    check-order. `config is None` (absent/malformed config file) -> `[]`,
    no recording, no email — the feature's off-switch.

    FAIL-SAFE: an exception from any single check, from
    `store.record_alert`, or from `mailer_send` is swallowed locally —
    `evaluate()` itself never raises.
    """
    if not isinstance(config, dict):
        return []

    recipient = config.get("recipient")
    window = config.get("window_seconds", DEFAULT_WINDOW_SECONDS)
    state.setdefault("seen_countries", set())
    state.setdefault("last_sent", {})

    fired: list = []
    for check in _CHECKS:
        try:
            conditions = check(store, config, now=now, window=window, state=state)
        except Exception:
            conditions = []
        if not conditions:
            continue

        for cond in conditions:
            plane = cond.get("plane")
            tier = cond.get("tier")
            detail = cond.get("detail", "")

            try:
                store.record_alert(plane, tier, detail)
            except Exception:
                # Fail-safe: the store misbehaving must not stop other
                # conditions from being evaluated/recorded/emailed.
                pass

            fired.append(cond)

            if not recipient:
                continue
            if not _should_send(state, tier, plane, now, window):
                continue
            try:
                subject = f"[SecuBox Presence] {tier.upper()} — {plane}"
                mailer_send(subject, detail, to=recipient)
            except Exception:
                # Fail-safe: a raising/failing mailer must never prevent
                # the alert from having been recorded above, nor crash
                # the evaluate loop.
                pass

    return fired
