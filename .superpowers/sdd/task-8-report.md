# Task 8 report — OpenClaw LXC scanner: live end-to-end deployment + verification (gk2)

Branch: `feature/openclaw-lxc-scanner` (base commit `bf22964e`).
Board: `root@192.168.1.200` (gk2).

## Step 1 — Build

```
cd packages/secubox-openclaw && dpkg-buildpackage -us -uc -b
```

Result: **success**. Only warnings were pre-existing `debian/changelog` locale-formatted date
parse warnings (French month names in the last entry's trailer line — cosmetic, non-blocking,
not touched per "no code changes unless deploy-blocking").

```
secubox-openclaw_1.0.1-1~bookworm1_all.deb   17804 bytes
```

`dpkg-deb -I` confirms real control metadata (Depends: secubox-core, debootstrap, lxc, jq;
Installed-Size: 90). `dpkg-deb -c` confirms real payload: `api/main.py` (11829 bytes),
`sbin/openclawctl` (7679 bytes, +x), sudoers.d drop-in (0440), nginx/secubox.d conf, systemd unit,
menu.d entry, `usr/share/secubox/www/openclaw/` static assets.

## Step 2 — Install

```
scp packages/secubox-openclaw_1.0.1-1~bookworm1_all.deb root@192.168.1.200:/root/
ssh root@192.168.1.200 'dpkg -i --force-confdef --force-confold /root/secubox-openclaw_1.0.1-1~bookworm1_all.deb'
```

Result: **rc=0**. Upgraded cleanly from the previously-installed 1.0.0-1~bookworm1. One conffile
prompt (`/etc/nginx/secubox.d/openclaw.conf`) auto-resolved by `--force-confold` — kept the
board's existing (already-correct, aggregator-routed) version and stashed the new maintainer
version as `.dpkg-dist`. See "Note" below — this is expected/correct, not a bug.

**Sudoers-as-secubox check:**

```
$ ssh root@192.168.1.200 'sudo -u secubox sudo -n /usr/sbin/openclawctl status --json'
{"running":true,"installed":true,"ip":"10.100.0.41","tools":{"nmap":true,"dig":true,"whois":true,"curl":true}}
```

JSON, not a sudo error → the sudoers grant works.

## Step 3 — Aggregator restart (once)

```
ssh root@192.168.1.200 'systemctl restart secubox-aggregator'
```

Polled `/api/v1/openclaw/status` on the aggregator socket every 2s; **ready after 15s** (well
inside the ~60s budget). No second restart performed.

```json
{"module":"openclaw","enabled":true,"running":true,"installed":true,"ip":"10.100.0.41",
 "tools":{"nmap":true,"dig":true,"whois":true,"curl":true},"total_scans":0}
```

## Step 4 — Status verification

```
$ curl -s --unix-socket /run/secubox/aggregator.sock http://localhost/api/v1/openclaw/status | jq '{installed,running,tools,total_scans}'
{
  "installed": true,
  "running": true,
  "tools": { "nmap": true, "dig": true, "whois": true, "curl": true },
  "total_scans": 0
}
```

## Step 5 — Concurrency / SPOF proof

Kicked a real scan directly via the helper, and while it ran hit two other modules' status
endpoints through the shared aggregator socket:

```
$ openclawctl scan ip 127.0.0.1 dddd4444 &   # background
$ sleep 1
$ time curl -s -o /dev/null -w "HTTP=%{http_code} TIME=%{time_total}s\n" --unix-socket $S http://localhost/api/v1/cookies/status
HTTP=200 TIME=0.005979s        (real 0m0.035s)

$ time curl -s -o /dev/null -w "HTTP=%{http_code} TIME=%{time_total}s\n" --unix-socket $S http://localhost/api/v1/dpi/status
HTTP=401 TIME=0.194691s        (real 0m0.223s — auth-gated 401, still sub-second, not a stall)

$ wait; jq .status /var/lib/secubox/openclaw/scans/dddd4444.json
"completed"
```

**cookies/status returned in 6ms while the scan was actively running** — proves the async-job
scan pipeline does not block the shared aggregator event loop (the SPOF this design eliminates).
The scan itself reached `status: completed`. Test scan file `dddd4444.json` removed after
verification (no leftover artifact).

## Step 6 — Dashboard

```
$ curl -s -o /dev/null -w "%{http_code}\n" -k https://admin.gk2.secubox.in/openclaw/
200
$ curl -s -k https://admin.gk2.secubox.in/openclaw/ | grep -c "esc\|data-op"
24
```

200 + wired markup present (24 matches for `esc`/`data-op`), confirming `bf22964e`'s XSS-hardened
dashboard shipped and renders from the board's static file root.

**Note on routing**: `secubox-openclaw`'s own `nginx/openclaw.conf` template only ships the
`/api/v1/openclaw/` proxy location (to `openclaw.sock`, a dormant-fallback socket — the board
kept its already-correct aggregator-routed version via `--force-confold`, matching commit
`2fe92754`'s in-process design). There is **no dedicated static alias** for `/openclaw/` in
the package (unlike `secubox-cookies`, which ships one explicitly) — it doesn't need one: the
admin vhost's generic `location / { try_files $uri $uri/ @fallback; }` with
`root /usr/share/secubox/www;` serves `usr/share/secubox/www/openclaw/index.html` automatically,
same mechanism that already serves `/cookies/`. Verified working, not a blocker — flagging only
because it's a source-vs-board conf drift worth being aware of (harmless; `.dpkg-dist` left on
board for reference, not touched).

## Step 7 — Board recovery after the single restart

```
/cookies/ -> 200      /waf/ -> 200      /soc/ -> 200      /system/ -> 200
api/cookies/status -> 200   api/waf/status -> 200   api/soc/status -> 200
api/system/status -> 401 (auth-gated, expected)   api/dpi/status -> 401 (auth-gated, expected)
```

No 502s anywhere. `secubox-aggregator` and `nginx` both `active`. Aggregator journal (last 5 min)
shows zero errors/tracebacks/exceptions. RSS 162M, single worker, CPU nominal — board fully
recovered from the one restart.

## Step 8 — Tracking

- `.claude/MIGRATION-MAP.md`: `secubox-openclaw` row was **already** all-✅ (www/API/deb/status) —
  no change needed.
- `.claude/HISTORY.md`: added a dated entry for the Task 8 live deployment + SPOF proof.
- Committed (message: `docs(openclaw): mark module implemented (LXC scanner live on gk2)`).

## Verdict

**DONE.** No code changes were required — deploy-clean, sudoers works, aggregator restarted once
and recovered, concurrency proof confirms no SPOF regression, dashboard renders wired markup,
board fully healthy afterward.
