# SecuBox — Branded Error Pages

Branded HTTP error pages in the **C3BOX hermetic** look (cosmos-black, cyber-cyan,
gold-hermetic, matrix-green, cinnabar; Courier Prime / JetBrains Mono; emoji).
Self-contained: inline CSS, no external assets, no CDN, no JS dependency.

| Code | Emoji | Title (FR)              | Meaning                                                         |
|------|-------|-------------------------|----------------------------------------------------------------|
| 421  | 🧭 🚧 | Service non routé       | Host isn't wired at the gateway yet (vhost/route missing).     |
| 500  | 💥    | Erreur interne          | A module hiccuped server-side.                                 |
| 502  | 🔌    | Passerelle injoignable  | Backend is down / restarting.                                  |
| 503  | ⏳    | Service en préparation  | Service is starting up / not ready (first-run) — retry soon.   |

Two artefacts per code:

- `<code>.html` — a complete standalone page (for nginx `error_page`, or any
  server that serves an HTML file directly). ≤ ~3 KB each.
- `<code>.http` — a **raw HTTP response** (status line + headers + blank line +
  body) for HAProxy `errorfile` / `http-error … file`.

---

## Install location

Ship both sets under **`/etc/secubox/errorpages/`**. The `secubox-hub` package
should install them (e.g. `debian/secubox-hub.install`):

```
packages/secubox-hub/errorpages/*.http  etc/secubox/errorpages/
packages/secubox-hub/errorpages/*.html  etc/secubox/errorpages/
```

Permissions: world-readable (`0644`), directory `0755`. HAProxy reads `.http`
at config-load; nginx reads `.html` per-request as the worker user.

---

## CRLF note (read before deploying `.http`)

The `.http` files are generated with **real CRLF** (`\r\n`) on the status line,
each header, and the blank separator — HAProxy requires this. They were verified
with `cat -A` (header lines end `^M$`). If your build/VCS/editor ever strips the
CR (e.g. a `.gitattributes` `text=auto` normalisation, or hand-editing on a
tool that saves LF-only), re-add it at install time on the header block:

```bash
# Safe belt-and-suspenders: ensure CRLF on every line of the .http files
for f in /etc/secubox/errorpages/*.http; do
  sed -i 's/\r$//; s/$/\r/' "$f"   # normalise then re-add CR on all lines
done
```

The `.html` files are plain LF and need **no** conversion.

---

## HAProxy wiring (backend-down, and intercepted 5xx)

HAProxy natively generates 421/500/502/503 in some conditions (503 when a
backend has no available server; 502 on a bad/absent backend response; 500 on
internal errors). Point those at the branded files.

### Option A — classic `errorfile` (per section)

In the relevant `defaults` (or a specific `frontend`/`backend`) section:

```haproxy
defaults
    errorfile 421 /etc/secubox/errorpages/421.http
    errorfile 500 /etc/secubox/errorpages/500.http
    errorfile 502 /etc/secubox/errorpages/502.http
    errorfile 503 /etc/secubox/errorpages/503.http
```

### Option B — `http-errors` group + `errorfiles` (HAProxy ≥ 2.2, reusable)

Define once in `global`/top-level, reference by name:

```haproxy
http-errors secubox
    errorfile 421 /etc/secubox/errorpages/421.http
    errorfile 500 /etc/secubox/errorpages/500.http
    errorfile 502 /etc/secubox/errorpages/502.http
    errorfile 503 /etc/secubox/errorpages/503.http

defaults
    errorfiles secubox            # pull all of the above into this section
```

### Option C — inline `http-error` directive (HAProxy ≥ 2.2)

```haproxy
defaults
    http-error status 503 content-type "text/html" file /etc/secubox/errorpages/503.html
```

Note: with `http-error … file`, HAProxy wants the **body only** — pass the
`.html`, not the `.http`. `errorfile`/`errorfiles` (A/B) want the full raw
response — pass the `.http`.

### Important: what HAProxy actually intercepts

- **503** is the big win: HAProxy synthesises 503 itself when a backend server is
  down / in maintenance / has no server up — this is the common "service asleep
  or crashed" case, and the branded 503 is what the visitor sees.
- **502 / 500** produced *by the backend itself* (nginx, an app, mitmproxy)
  are **passed through unchanged** — HAProxy only substitutes its own generated
  errors, unless you force interception. To brand backend-origin 5xx at the
  HAProxy layer too, add per-backend:

  ```haproxy
  backend some_app
      errorfiles secubox                 # (or errorfile 502 …)
      # force HAProxy to swap the backend's own 5xx for the branded page:
      http-response return status 502 content-type "text/html" \
          file /etc/secubox/errorpages/502.html if { status 502 }
  ```

  In most SecuBox deployments it is cleaner to brand backend-origin 5xx at the
  **origin** (nginx, below) and let HAProxy own the 503/502-no-backend cases.

Reload after editing:

```bash
haproxy -c -f /etc/secubox/haproxy.cfg     # validate first
systemctl reload haproxy
```

---

## nginx wiring (app-origin 500 / 502 / 503)

For services fronted by nginx (the static htdocs + `/api/v1/<module>/*` reverse
proxy), brand the origin 5xx. In the `server { }` block (or `http { }` for a
global default):

```nginx
    error_page 500 502 503 504 /_sbx_err_5xx.html;

    location = /_sbx_err_5xx.html {
        root      /etc/secubox/errorpages;   # serves 500.html? no — see below
        internal;
    }
```

`error_page` serves a **single** page for the listed codes. Two idiomatic
choices:

**1) One shared 5xx page** (simplest) — symlink or copy one of the bodies to the
name nginx serves:

```nginx
    error_page 500 502 503 504 /_sbx_err_5xx.html;
    location = /_sbx_err_5xx.html {
        root /etc/secubox/errorpages;
        internal;
    }
```
```bash
ln -sf 503.html /etc/secubox/errorpages/_sbx_err_5xx.html
```

**2) Distinct page per code** (recommended) — map each code to its own file:

```nginx
    error_page 500 /_sbx_500.html;
    error_page 502 /_sbx_502.html;
    error_page 503 /_sbx_503.html;

    location = /_sbx_500.html { root /etc/secubox/errorpages; internal; }
    location = /_sbx_502.html { root /etc/secubox/errorpages; internal; }
    location = /_sbx_503.html { root /etc/secubox/errorpages; internal; }
```
```bash
ln -sf 500.html /etc/secubox/errorpages/_sbx_500.html
ln -sf 502.html /etc/secubox/errorpages/_sbx_502.html
ln -sf 503.html /etc/secubox/errorpages/_sbx_503.html
```

(The alias names avoid exposing the bare `500.html` path and keep the location
`internal;` so the pages can only be reached via `error_page`, never fetched
directly.)

For a reverse-proxy `location` that must show *nginx's* branded page instead of
the upstream's own error body, add:

```nginx
    location /api/v1/ {
        proxy_pass http://unix:/run/secubox/aggregator.sock;
        proxy_intercept_errors on;     # swap upstream 5xx for error_page
    }
```

Reload after editing:

```bash
nginx -t && systemctl reload nginx
```

---

## Layering summary

| Layer   | Owns / brands                                              | File type used     |
|---------|-----------------------------------------------------------|--------------------|
| HAProxy | 503 (backend down/absent), 502 (no backend), 421, 500     | `.http` (errorfile)|
| nginx   | origin 500/502/503 from app / aggregator upstreams        | `.html` (error_page)|

Brand at both layers for full coverage: HAProxy catches "nothing is listening",
nginx catches "the app answered with an error".

---

*© 2026 CyberMind · Notre-Dame-du-Cruet, Savoie · LicenseRef-CMSD-1.0*
