# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — presence report builder + scheduler (Project B,
#820, Task 7).

`build_report(store, *, fmt="html", now=None)` renders a self-contained
cross-plane presence report: per-plane counts, top-N geo/ASN, and the most
recent presences + recorded tiered alerts (Task 6). No external template
engine and no dependency on `packages/secubox-reporter` — that module's
HTML/PDF helpers are wired to its own `Report`/`ReportType` pydantic models
and its own on-disk report store, which would drag FastAPI + a second
persistence layer into a module that only ever needs to hand a byte string
to `presence.mailer.send_alert`/an HTTP response. Building a small
self-contained HTML string here is far more cohesive with the Task 6
mailer contract (a plain `str` body). `fmt="text"` renders the same
sections as plain text (no HTML escaping needed there — no markup is ever
interpreted).

ALL values interpolated into the HTML report are `html.escape()`d: `geo_cc`/
`geo_org`, `identity`, `provenance`, `client_type`, and the `host`/`ua`
fields folded out of a presence's `extra` JSON blob are every one of them
attacker-influenceable (a WAN visitor's `Host`/User-Agent header, a crafted
reverse-DNS/ASN string, ...). Fail-safe: `build_report` NEVER raises — a
`store=None`, an empty store, a `store.list()`/`store.alerts()` that raises,
or a malformed `extra` JSON blob on any one row all degrade to "0 rows"/
"no host" for that row, never abort the whole report render.

`run_scheduled(store, *, schedule_path=..., recipient=None,
mailer_send=None, now=None, state=None)` is the piece that actually
*executes* what `packages/secubox-reporter`'s `POST /schedule` only ever
persists (`/etc/secubox/reporter-schedule.json`) — reporter's own endpoint
writes a schedule but nothing on the board ever reads it back and acts on
it. `run_scheduled` reads that SAME file (default path) so a
`secubox-presence-report.timer` (shipped in Task 9's packaging, out of
scope here — see the module-level note below) can tick it, but it treats
the schedule as an ADDITIVE, read-modify-write document: it looks for two
keys reporter's own `{"enabled": ..., "schedules": [...]}` shape never
sets — `frequency` (`"daily"` or `"weekly"`) and `recipient` — and, on a due
run, adds/updates only its own `last_run` key back into the SAME dict
before writing the whole thing back out. Reporter's `schedules`/`enabled`
keys (if present) are read, kept, and rewritten untouched; a file that is
purely reporter's own shape (no `frequency` key) simply has no valid
frequency to act on, so `run_scheduled` treats it exactly like "no
schedule configured" — a shape mismatch fails safe, it never crashes and
never corrupts the file the reporter module owns.

Schedule file shape (all keys optional; ONLY `frequency` makes a run
possible)::

    {
      "frequency": "daily",              # or "weekly"; anything else = off
      "recipient": "admin@example.com",  # overridden by run_scheduled()'s
                                          # own `recipient=` kwarg if given
      "last_run": 1751600000              # epoch seconds; written back here
                                          # after a SUCCESSFUL send
    }

Design choice — a failed send does NOT advance `last_run`: if
`mailer_send(...)` returns falsy (sendmail down, no MTA configured, ...),
the schedule file is left untouched so the NEXT tick (the following day/
week's timer fire, or an operator-triggered retry) sees the same overdue
`last_run` and tries again, rather than silently skipping a whole period
because one send happened to fail. `run_scheduled` returns `True` only for
a tick that actually ran AND successfully emailed (i.e. `last_run` was
persisted); every other outcome (not due, no config, missing recipient,
failed send, failed persist) returns `False` — a caller that only cares
"did today's report go out" gets a single boolean answer, and a systemd
timer's oneshot exit code stays meaningful without needing to inspect logs.

Packaging note: this task deliberately ships ONLY `reports.py` + the
`/presence/report/now` endpoint (`api/main.py`) + tests. The
`secubox-presence-report.{service,timer}` unit files the plan sketches are
left to Task 9 (packaging) per the plan's own "prefer... leave the actual
.timer/.service unit files to Task 9" guidance — that keeps this task's
diff to the library + the on-demand endpoint, and lets Task 9 own every
systemd unit + `debian/control`/postinst wiring in one place, consistent
with how Task 6's mailer shipped without its own unit either.

Pure stdlib (`html`, `json`, `time`, `collections.Counter`). No I/O at
import time — only `build_report()` (store I/O, all delegated to the
passed-in `store`) and `run_scheduled()` (the schedule JSON file) touch
anything.
"""
from __future__ import annotations

import html
import json
import time
from collections import Counter
from datetime import datetime, timezone

DEFAULT_SCHEDULE_PATH = "/etc/secubox/reporter-schedule.json"
DEFAULT_TOP_N = 5
DEFAULT_RECENT_LIMIT = 20
DEFAULT_ALERTS_LIMIT = 20
DEFAULT_LIST_LIMIT = 100_000

# Reporter-style schedule -> seconds since `last_run` required to be "due"
# again. Any other/missing `frequency` value means "not configured".
_FREQUENCY_SECONDS = {
    "daily": 86_400,
    "weekly": 7 * 86_400,
}


def _esc(value) -> str:
    """`html.escape` a value, tolerating `None`/non-str inputs. Never raises."""
    if value is None:
        return ""
    try:
        return html.escape(str(value))
    except Exception:
        return ""


def _safe_list(store, **kwargs) -> list:
    if not store:
        return []
    try:
        result = store.list(**kwargs)
    except Exception:
        return []
    return result if isinstance(result, list) else []


def _safe_alerts(store, limit: int) -> list:
    if not store:
        return []
    try:
        result = store.alerts(limit=limit)
    except Exception:
        return []
    return result if isinstance(result, list) else []


def _extra_host(pres: dict) -> str:
    """Best-effort pull of `extra.host` (JSON) off a presence row. Never raises."""
    extra = pres.get("extra")
    if not extra:
        return ""
    try:
        parsed = json.loads(extra)
    except (ValueError, TypeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    host = parsed.get("host")
    return host if isinstance(host, str) else ""


def _aggregate(presences: list) -> tuple[Counter, Counter, Counter]:
    by_plane: Counter = Counter()
    by_country: Counter = Counter()
    by_asn: Counter = Counter()
    for pres in presences:
        by_plane[pres.get("plane") or "unknown"] += 1
        cc = pres.get("geo_cc")
        if cc:
            by_country[cc] += 1
        asn = pres.get("geo_asn")
        if asn:
            by_asn[asn] += 1
    return by_plane, by_country, by_asn


def _render_html(
    *, generated_at: str, by_plane: Counter, top_countries, top_asns,
    recent: list, alerts: list,
) -> str:
    plane_rows = "".join(
        f"<tr><td>{_esc(plane)}</td><td>{count}</td></tr>"
        for plane, count in sorted(by_plane.items())
    ) or "<tr><td colspan=\"2\">No presences recorded</td></tr>"

    country_rows = "".join(
        f"<tr><td>{_esc(cc)}</td><td>{n}</td></tr>" for cc, n in top_countries
    ) or "<tr><td colspan=\"2\">No geo data</td></tr>"

    asn_rows = "".join(
        f"<tr><td>{_esc(asn)}</td><td>{n}</td></tr>" for asn, n in top_asns
    ) or "<tr><td colspan=\"2\">No ASN data</td></tr>"

    recent_rows = "".join(
        "<tr>"
        f"<td>{_esc(p.get('plane'))}</td>"
        f"<td>{_esc(p.get('identity'))}</td>"
        f"<td>{_esc(p.get('provenance'))}</td>"
        f"<td>{_esc(p.get('client_type'))}</td>"
        f"<td>{_esc(p.get('geo_cc'))}</td>"
        f"<td>{_esc(_extra_host(p))}</td>"
        "</tr>"
        for p in recent
    ) or "<tr><td colspan=\"6\">No presences recorded</td></tr>"

    alert_rows = "".join(
        "<tr>"
        f"<td>{_esc(a.get('ts'))}</td>"
        f"<td>{_esc(a.get('plane'))}</td>"
        f"<td>{_esc(a.get('tier'))}</td>"
        f"<td>{_esc(a.get('detail'))}</td>"
        "</tr>"
        for a in alerts
    ) or "<tr><td colspan=\"4\">No alerts recorded</td></tr>"

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>SecuBox Presence Report</title>
<style>
body {{ font-family: monospace; background:#0a0a0f; color:#e8e6d9; }}
table {{ border-collapse: collapse; margin-bottom: 1.5em; width: 100%; }}
th, td {{ border: 1px solid #6b6b7a; padding: 4px 8px; text-align: left; }}
th {{ background:#1a1a24; color:#c9a84c; }}
h1, h2 {{ color:#c9a84c; }}
</style>
</head><body>
<h1>SecuBox Presence Report</h1>
<p>Generated: {_esc(generated_at)}</p>

<h2>Presences by plane</h2>
<table><tr><th>Plane</th><th>Count</th></tr>{plane_rows}</table>

<h2>Top countries</h2>
<table><tr><th>Country</th><th>Count</th></tr>{country_rows}</table>

<h2>Top ASNs</h2>
<table><tr><th>ASN</th><th>Count</th></tr>{asn_rows}</table>

<h2>Recent presences</h2>
<table><tr><th>Plane</th><th>Identity</th><th>Provenance</th><th>Client type</th><th>Country</th><th>Host</th></tr>{recent_rows}</table>

<h2>Recent alerts</h2>
<table><tr><th>Time</th><th>Plane</th><th>Tier</th><th>Detail</th></tr>{alert_rows}</table>
</body></html>
"""


def _render_text(
    *, generated_at: str, by_plane: Counter, top_countries, top_asns,
    recent: list, alerts: list,
) -> str:
    lines = [
        "SecuBox Presence Report",
        f"Generated: {generated_at}",
        "",
        "Presences by plane:",
    ]
    if by_plane:
        for plane, count in sorted(by_plane.items()):
            lines.append(f"  {plane}: {count}")
    else:
        lines.append("  (no presences recorded)")

    lines.append("")
    lines.append("Top countries:")
    if top_countries:
        for cc, n in top_countries:
            lines.append(f"  {cc}: {n}")
    else:
        lines.append("  (no geo data)")

    lines.append("")
    lines.append("Top ASNs:")
    if top_asns:
        for asn, n in top_asns:
            lines.append(f"  {asn}: {n}")
    else:
        lines.append("  (no ASN data)")

    lines.append("")
    lines.append("Recent presences:")
    if recent:
        for p in recent:
            lines.append(
                f"  {p.get('plane')}:{p.get('identity')} "
                f"provenance={p.get('provenance')} "
                f"client_type={p.get('client_type')} "
                f"geo_cc={p.get('geo_cc')} host={_extra_host(p)}"
            )
    else:
        lines.append("  (no presences recorded)")

    lines.append("")
    lines.append("Recent alerts:")
    if alerts:
        for a in alerts:
            lines.append(f"  [{a.get('ts')}] {a.get('plane')}/{a.get('tier')}: {a.get('detail')}")
    else:
        lines.append("  (no alerts recorded)")

    return "\n".join(lines) + "\n"


def build_report(
    store,
    *,
    fmt: str = "html",
    now: float | None = None,
    top_n: int = DEFAULT_TOP_N,
    recent_limit: int = DEFAULT_RECENT_LIMIT,
    alerts_limit: int = DEFAULT_ALERTS_LIMIT,
) -> bytes:
    """Render a cross-plane presence report as bytes. NEVER raises.

    `fmt="html"` (default) -> a self-contained HTML document, every
    interpolated value `html.escape()`d. `fmt="text"` -> the same sections
    rendered as plain text. An empty/`None` store, or a store whose
    `list()`/`alerts()` raise, degrades to a valid "no presences recorded"
    report rather than aborting — this function is called from both an
    authenticated HTTP handler and an unattended systemd timer tick, and
    neither call site should ever see an exception out of it.
    """
    try:
        ts = now if now is not None else time.time()
        generated_at = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        presences = _safe_list(store, limit=DEFAULT_LIST_LIMIT)
        alerts = _safe_alerts(store, alerts_limit)

        by_plane, by_country, by_asn = _aggregate(presences)
        top_countries = by_country.most_common(top_n)
        top_asns = by_asn.most_common(top_n)
        recent = presences[:recent_limit]

        renderer = _render_text if fmt == "text" else _render_html
        text = renderer(
            generated_at=generated_at,
            by_plane=by_plane,
            top_countries=top_countries,
            top_asns=top_asns,
            recent=recent,
            alerts=alerts,
        )
        return text.encode("utf-8")
    except Exception:
        # Fail-safe: never let a rendering bug (or a store misbehaving in
        # some way `_safe_list`/`_safe_alerts` didn't anticipate) raise out
        # of build_report — hand back a minimal, always-valid report.
        fallback = (
            "SecuBox Presence Report\n(report generation failed; no data available)\n"
            if fmt == "text"
            else (
                "<!doctype html><html><body><h1>SecuBox Presence Report</h1>"
                "<p>Report generation failed; no data available.</p></body></html>"
            )
        )
        return fallback.encode("utf-8")


def _load_schedule(path: str) -> dict | None:
    """Read+parse the schedule JSON. `None` on any missing/malformed file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _save_schedule(path: str, data: dict) -> bool:
    """Write the (whole, read-modify-write) schedule dict back. `False` on failure."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception:
        return False


def run_scheduled(
    store,
    *,
    schedule_path: str = DEFAULT_SCHEDULE_PATH,
    recipient: str | None = None,
    mailer_send=None,
    now: float | None = None,
    state: dict | None = None,
) -> bool:
    """Run the presence report scheduler ONE tick. Returns `True` only for
    a tick that ran AND successfully emailed; `False` for every other
    outcome (not due, no/invalid schedule, no recipient, failed send).
    Never raises — see the module docstring for the schedule shape, the
    additive read-modify-write contract with `reporter-schedule.json`, and
    the "don't advance `last_run` on a failed send" rationale.

    `mailer_send` defaults to `presence.mailer.send_alert` (imported here,
    not at module scope, so `build_report`'s pure-stdlib import stays free
    of the mailer's `subprocess`/`email` imports for callers that only
    ever need report rendering, e.g. the `/report/now` HTTP handler).
    `state` is accepted for interface symmetry with `alerts.evaluate` (a
    caller-held dict a future revision could use for finer per-recipient
    dedup) but is not required by the current daily/weekly-only logic.
    """
    try:
        ts = now if now is not None else time.time()

        schedule = _load_schedule(schedule_path)
        if schedule is None:
            return False

        frequency = schedule.get("frequency")
        interval = _FREQUENCY_SECONDS.get(frequency)
        if interval is None:
            # Missing/invalid/unset frequency — including a file that is
            # purely reporter's own {"enabled"/"schedules"} shape — means
            # "not configured for this scheduler". Fail safe, not an error.
            return False

        last_run = schedule.get("last_run")
        if isinstance(last_run, (int, float)) and (ts - last_run) < interval:
            return False  # not due yet

        effective_recipient = recipient or schedule.get("recipient")
        if not effective_recipient:
            return False  # nothing to send to

        if mailer_send is None:
            from .mailer import send_alert as mailer_send

        report_bytes = build_report(store, fmt="html", now=ts)
        body = report_bytes.decode("utf-8", errors="replace")
        subject = f"SecuBox Presence Report ({frequency}) — {datetime.fromtimestamp(ts, tz=timezone.utc).date().isoformat()}"

        try:
            # #820 whole-branch fix M1: this body is always an HTML
            # document (`build_report(..., fmt="html", ...)` above) — tell
            # the mailer so it sends `text/html`, not `text/plain` raw
            # markup source.
            sent = bool(mailer_send(subject, body, to=effective_recipient, html=True))
        except Exception:
            sent = False

        if not sent:
            # Design choice (see module docstring): do NOT advance
            # `last_run` on a failed send, so the next tick retries
            # instead of silently skipping a whole period.
            return False

        schedule["last_run"] = ts
        if not _save_schedule(schedule_path, schedule):
            # The email went out but persisting last_run failed — the next
            # tick will see a stale last_run and (harmlessly) re-send. That
            # is preferable to reporting success while the on-disk state is
            # inconsistent, so this is still reported as a non-clean run.
            return False

        return True
    except Exception:
        # Belt-and-braces: run_scheduled must never raise regardless of
        # what a caller-supplied `store`/`mailer_send`/`state` does.
        return False
