<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# BBS URL-Snapshot Thumbnails — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A BBS post whose only content is a URL (no attached media) gets a **website-snapshot thumbnail** as its card cover — captured asynchronously, cached, served same-origin — instead of the tinted-glyph placeholder shipped in #1114.

**Architecture:** BBS (Go) records a *pending* row per distinct URL and renders `<img src="/urlshot/<key>">` on the card. The endpoint serves the cached PNG if present, else a placeholder PNG (and ensures the row is pending). A **Python worker** (systemd timer, one capture at a time, load-guarded) drains pending rows: it fetches the page's **og:image** first, and falls back to a **chromium screenshot** (`secubox_core.shotter`) only when there's no og:image. **All outbound fetches route through the toolbox/WAF egress** (sbxmitm proxy + its CA) with SSRF guards. Snapshots inherit the citing post's visibility.

**Tech Stack:** Go (secubox-bbs `internal/store`, `internal/web`, SQLite), Python 3.11 (`httpx`, `secubox_core.screenshots`, `secubox_core.shotter`, chromium via CDP), systemd oneshot service + timer, Debian packaging.

**Spec:** GitHub issue **#1120** (design + decisions + egress finding). This plan is its argument; read both.

## Global Constraints

- **CSP** on BBS is `default-src 'self'` — snapshots MUST be served same-origin (`/urlshot/<key>`, PNG); no inline scripts, no remote image hotlinking.
- **Egress ONLY through the toolbox/WAF** — outbound HTTP (og:image fetch) and chromium both go through the sbxmitm proxy `http://10.99.1.1:8091`, trusting CA `/etc/secubox/toolbox/ca/ca.pem`. NEVER let chromium or httpx reach the internet directly. If the proxy is unreachable, the capture FAILS (recorded as `ok=false`) — it does not fall back to direct.
- **SSRF guards** (applied before any fetch, even through the proxy): `http`/`https` scheme only; reject `localhost`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fc00::/7`, and any host ending in `.secubox.in`, `.gk2.net`, or the board's own domains.
- **Never block a web request on capture.** The `/urlshot` endpoint only reads cache/serves placeholder + upserts a pending row. Capture is the worker's job, off-request.
- **Visibility** (mirrors #1114 `/f/` gating): a URL snapshot is public iff at least one **public** post cites it; otherwise it is member-only. Anonymous requests to `/urlshot/<key>` for a non-public key get the placeholder, never the snapshot.
- **Key is Go-computed and stored** — the worker uses the stored key verbatim (never recomputes), so no cross-language key-agreement bug. Key = lowercase hex of `sha256(normalised_url)`, 32 chars (safe for `secubox_core.screenshots._safe_key`: no `/`, `.`, `\`).
- **Reuse** `secubox_core.screenshots` (keyed PNG cache: `png_path`/`is_stale`/`record`, layout `<base>/<key>/screenshot.png`) and `secubox_core.shotter` (`capture(url, timeout, width, height, wait)`); do NOT write a new capture engine.
- semver bump on `secubox-bbs`; **commit `debian/changelog` with the build**. TDD throughout (Go `testing`, Python `pytest`).
- Cache base: `/var/cache/secubox/bbs/urlshots/`. TTL: re-capture when the row's fingerprint is stale (default 14 days) — via `screenshots.is_stale`.

---

## File Structure

**secubox-bbs (Go core, CSPN perimeter):**
- Create `internal/store/migrations/0023_urlshots.sql` — the `urlshots` table.
- Create `internal/store/urlshots.go` — `CleUrlshot`, `EnfileUrlshot`, `StatutUrlshot`, `ProchainUrlshot`, `MarqueUrlshot` (the last two are for the worker via the same DB, but Go owns the schema + Go-side reads).
- Create `internal/web/urlshot.go` — `GET /urlshot/{key}` handler (`servirUrlshot`).
- Modify `internal/web/routes.go` — register the route; card-render helper `cleApercuURL`.
- Modify `internal/web/templates/newsroom.html` — URL cards use `/urlshot/<key>` cover when the post is a bare-URL post.
- Create `internal/web/static/urlshot-placeholder.png` — a neutral 212×182 placeholder (generated once).

**secubox-bbs (Python worker, ships in the same package):**
- Create `py/urlshot/__init__.py`
- Create `py/urlshot/egress.py` — SSRF guard + proxy/CA httpx client factory.
- Create `py/urlshot/ogimage.py` — fetch + parse `og:image`, resolve + download the image.
- Create `py/urlshot/capture.py` — orchestrator: og:image → shotter fallback → PNG bytes.
- Create `py/urlshot/worker.py` — drain the `urlshots` queue (one row), capture, `screenshots.record`.
- Create `py/urlshot/tests/` — pytest for egress/ogimage/capture/worker.

**Packaging:**
- Create `debian/secubox-bbs-urlshot.service` (oneshot) + `debian/secubox-bbs-urlshot.timer`.
- Modify `debian/rules` / `debian/install` — ship `py/urlshot/` to `/usr/lib/secubox/bbs/urlshot/`, install the units, the tmpfiles for the cache dir.
- Create `debian/secubox-bbs.tmpfiles` entry (or extend) — `/var/cache/secubox/bbs/urlshots` `0750 secubox-bbs secubox`.
- Modify `debian/control` — `Recommends: chromium, python3-httpx` (worker is best-effort; core BBS works without it, cards fall back to placeholder).

---

### Task 1: `urlshots` table + migration

**Files:**
- Create: `packages/secubox-bbs/internal/store/migrations/0023_urlshots.sql`
- Test: `packages/secubox-bbs/internal/store/urlshots_test.go`

**Interfaces:**
- Produces: table `urlshots(cle TEXT PRIMARY KEY, url TEXT NOT NULL, visibility TEXT NOT NULL DEFAULT 'local', statut TEXT NOT NULL DEFAULT 'pending', maj INTEGER NOT NULL DEFAULT 0)`.

- [ ] **Step 1: Write the migration**
```sql
-- 0023_urlshots.sql — file d'attente + état des vignettes-snapshot d'URL (#1120).
-- La CLÉ est calculée côté Go (sha256 de l'URL normalisée) ; le worker Python la
-- réutilise telle quelle. `visibility` recopie la plus haute visibilité d'un post
-- CITANT l'URL (public si au moins un post public la cite) — miroir du gating /f/.
CREATE TABLE IF NOT EXISTS urlshots (
  cle        TEXT PRIMARY KEY,
  url        TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'local',   -- 'public' | 'local'
  statut     TEXT NOT NULL DEFAULT 'pending',  -- 'pending' | 'done' | 'failed'
  maj        INTEGER NOT NULL DEFAULT 0        -- epoch de la dernière transition
);
CREATE INDEX IF NOT EXISTS urlshots_pending ON urlshots(statut) WHERE statut = 'pending';
```

- [ ] **Step 2: Write the failing test** (`urlshots_test.go`)
```go
func TestMigrationUrlshotsCreeLaTable(t *testing.T) {
	s := storeDeTest(t) // helper existant qui applique les migrations
	if _, err := s.db.Exec(`INSERT INTO urlshots(cle,url) VALUES('abc','https://x')`); err != nil {
		t.Fatalf("table urlshots absente : %v", err)
	}
}
```

- [ ] **Step 3: Run it, verify it fails** (`go test ./internal/store/ -run Urlshots`) — FAIL: no such table.
- [ ] **Step 4: Confirm the migration is embedded/applied** (migrations are `//go:embed`ed; the new file is picked up automatically). Re-run — PASS.
- [ ] **Step 5: Commit** `git add internal/store/migrations/0023_urlshots.sql internal/store/urlshots_test.go && git commit -m "feat(bbs): table urlshots (file d'attente des snapshots) (ref #1120)"`

---

### Task 2: Go store — key, enqueue, status

**Files:**
- Create: `packages/secubox-bbs/internal/store/urlshots.go`
- Test: `packages/secubox-bbs/internal/store/urlshots_test.go` (extend)

**Interfaces:**
- Produces:
  - `func CleUrlshot(url string) string` — 32-hex sha256 of the normalised URL; `""` if the URL is not eligible (see normalisation).
  - `func (s *Store) EnfileUrlshot(cle, url, visibility string) error` — upsert: insert pending if absent; **raise** visibility to `public` if this citation is public; never lower it.
  - `func (s *Store) StatutUrlshot(cle string) (statut, visibility string, ok bool)`.

- [ ] **Step 1: Write failing tests**
```go
func TestCleUrlshotStableEtNormalisee(t *testing.T) {
	a := store.CleUrlshot("HTTPS://Example.COM/p?a=1#frag")
	b := store.CleUrlshot("https://example.com/p?a=1")
	if a == "" || a != b {
		t.Fatalf("clé instable/non normalisée : %q vs %q", a, b)
	}
	if len(a) != 32 {
		t.Fatalf("clé de longueur %d, attendu 32", len(a))
	}
	if store.CleUrlshot("ftp://x") != "" || store.CleUrlshot("/relatif") != "" {
		t.Fatal("une URL non http(s) doit donner une clé vide")
	}
}

func TestEnfileMonteLaVisibiliteJamaisNeLaBaisse(t *testing.T) {
	s := storeDeTest(t)
	cle := store.CleUrlshot("https://x.example/a")
	must(s.EnfileUrlshot(cle, "https://x.example/a", "local"))
	must(s.EnfileUrlshot(cle, "https://x.example/a", "public")) // monte
	must(s.EnfileUrlshot(cle, "https://x.example/a", "local"))  // ne redescend pas
	_, vis, ok := s.StatutUrlshot(cle)
	if !ok || vis != "public" {
		t.Fatalf("visibilité = %q (ok=%v), attendu public", vis, ok)
	}
}
```

- [ ] **Step 2: Run, verify fail** — undefined `CleUrlshot`/`EnfileUrlshot`.
- [ ] **Step 3: Implement `urlshots.go`**
```go
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"time"
)

// CleUrlshot : clé de cache d'une URL. Normalise (schéma+hôte en minuscules,
// fragment retiré) puis sha256 tronqué en 32 hexa — sûr pour _safe_key côté
// Python (ni '/', ni '.', ni '\'). Vide si l'URL n'est pas une http(s) absolue.
func CleUrlshot(brut string) string {
	u, err := url.Parse(strings.TrimSpace(brut))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	sum := sha256.Sum256([]byte(u.String()))
	return hex.EncodeToString(sum[:])[:32]
}

// EnfileUrlshot insère une ligne pending si absente, et MONTE la visibilité à
// 'public' si cette citation est publique — jamais l'inverse (une fois public,
// reste public : le fichier a fuité, on ne le reprivatise pas — cf. /f/ #1114).
func (s *Store) EnfileUrlshot(cle, u, visibility string) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO urlshots(cle,url,visibility,statut,maj) VALUES(?,?,?,'pending',?)
		ON CONFLICT(cle) DO UPDATE SET
		  visibility = CASE WHEN excluded.visibility='public' THEN 'public' ELSE urlshots.visibility END`,
		cle, u, visibility, now)
	return err
}

func (s *Store) StatutUrlshot(cle string) (statut, visibility string, ok bool) {
	err := s.db.QueryRow(`SELECT statut, visibility FROM urlshots WHERE cle=?`, cle).
		Scan(&statut, &visibility)
	return statut, visibility, err == nil
}
```

- [ ] **Step 4: Run tests** — PASS.
- [ ] **Step 5: Commit** `feat(bbs): clé + enqueue + statut des urlshots (ref #1120)`

---

### Task 3: Go endpoint `GET /urlshot/{key}`

**Files:**
- Create: `packages/secubox-bbs/internal/web/urlshot.go`
- Modify: `packages/secubox-bbs/internal/web/routes.go` (register route)
- Create: `packages/secubox-bbs/internal/web/static/urlshot-placeholder.png` (generate a 212×182 neutral PNG once, e.g. via `python3 -c` with Pillow or a checked-in asset)
- Test: `packages/secubox-bbs/internal/web/urlshot_test.go`

**Interfaces:**
- Consumes: `store.StatutUrlshot`, the cache base `/var/cache/secubox/bbs/urlshots`, `screenshots` PNG layout `<base>/<key>/screenshot.png`.
- Produces: route `/urlshot/{key}` → PNG (`image/png`), never a capture.

- [ ] **Step 1: Write failing tests**
```go
func TestUrlshotSertLePlaceholderQuandPasDeSnapshot(t *testing.T) {
	srv, s := banc(t)
	cle := store.CleUrlshot("https://x.example/a")
	must(s.EnfileUrlshot(cle, "https://x.example/a", "public"))
	w := demande(t, srv, "GET", "/urlshot/"+cle, "", nil) // anonyme
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("placeholder attendu : code=%d ct=%q", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestUrlshotLocalRefuseAnonyme(t *testing.T) {
	srv, s := banc(t)
	cle := store.CleUrlshot("https://x.example/b")
	must(s.EnfileUrlshot(cle, "https://x.example/b", "local"))
	// dépose un vrai PNG dans le cache pour prouver que c'est la VISIBILITÉ, pas
	// l'absence de fichier, qui protège.
	deposeSnapshotDeTest(t, cle, []byte("\x89PNG..."))
	w := demande(t, srv, "GET", "/urlshot/"+cle, "", nil) // anonyme
	// anonyme + local → placeholder (jamais le snapshot)
	if bytes.Contains(w.Body.Bytes(), []byte("\x89PNG...")) {
		t.Fatal("snapshot d'un post LOCAL servi à un anonyme")
	}
}

func TestUrlshotCleInvalideEst404(t *testing.T) {
	srv, _ := banc(t)
	w := demande(t, srv, "GET", "/urlshot/../etc/passwd", "", nil)
	if w.Code == 200 { t.Fatal("traversée de chemin acceptée") }
}
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement `urlshot.go`**
```go
package web

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var cleUrlshotRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

const urlshotBase = "/var/cache/secubox/bbs/urlshots"

// servirUrlshot rend la vignette-snapshot d'une URL. Ne capture JAMAIS : lecture
// du cache ou placeholder. Gating visibilité miroir de /f/ (#1114) : un anonyme
// n'obtient un snapshot que si l'URL est citée par un post PUBLIC.
func (s *Server) servirUrlshot(w http.ResponseWriter, r *http.Request) {
	cle := strings.TrimPrefix(r.URL.Path, "/urlshot/")
	if !cleUrlshotRe.MatchString(cle) {
		http.NotFound(w, r)
		return
	}
	_, vis, ok := s.st.StatutUrlshot(cle)
	v := s.qui(r)
	autorise := ok && (vis == "public" || v.Connecte)
	png := filepath.Join(urlshotBase, cle, "screenshot.png")
	if autorise {
		if b, err := os.ReadFile(png); err == nil {
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "private, max-age=300")
			w.Write(b)
			return
		}
	}
	// Placeholder embarqué (assets FS) — toujours 200 pour que l'<img> charge.
	if b, err := assets.ReadFile("static/urlshot-placeholder.png"); err == nil {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "private, max-age=60")
		w.Write(b)
		return
	}
	http.NotFound(w, r)
}
```
Register in `routes.go`: `s.mux.HandleFunc("/urlshot/", s.servirUrlshot)`. Add `static/urlshot-placeholder.png` to the `//go:embed static/*` set (already covered by the glob).

- [ ] **Step 4: Generate the placeholder PNG** (212×182, neutral):
```bash
python3 -c "from PIL import Image; Image.new('RGB',(212,182),(20,33,45)).save('internal/web/static/urlshot-placeholder.png')"
```
- [ ] **Step 5: Run tests — PASS. Commit** `feat(bbs): endpoint /urlshot avec gating visibilité (ref #1120)`

---

### Task 4: Card integration — enqueue + `<img>` cover

**Files:**
- Modify: `packages/secubox-bbs/internal/web/routes.go` (in `apercuEtDernier` or the News assembly: compute `CleApercu` for bare-URL posts + enqueue)
- Modify: `packages/secubox-bbs/internal/web/templates/newsroom.html` (URL card cover)
- Test: `packages/secubox-bbs/internal/web/urlshot_test.go` (extend: rendering a URL-only fil enqueues + emits `/urlshot/<key>`)

**Interfaces:**
- Consumes: `store.CleUrlshot`, `store.EnfileUrlshot`, the fil's first-post body (to extract the sole URL) and visibility.

- [ ] **Step 1: Failing test** — assembling News for a fil whose body is a bare URL sets `Fil.CleApercu` non-empty and inserts a pending row; the carousel HTML contains `src="/urlshot/<key>"`.
- [ ] **Step 2: Extract the URL + enqueue.** In the News assembly (where `apercuEtDernier` runs), when the fil has NO media and its cleaned excerpt is essentially one URL, compute `cle := store.CleUrlshot(url)`; if non-empty, `s.st.EnfileUrlshot(cle, url, string(fil.Visibility))` and set `fil.CleApercu = cle`. (Add `CleApercu string` to the fil/News item type.)
- [ ] **Step 3: Template cover.** In `newsroom.html`, in the cover conditional (currently `{{if $cover}}…{{else if …vid}}…{{else}}…ph…{{end}}`), add a branch **before** the `ph` placeholder:
```
{{else if $n.CleApercu}}<span class="cccover"><img src="/urlshot/{{$n.CleApercu}}?v={{$.VCSS}}" alt="" loading="lazy"></span>
```
So a bare-URL card shows the snapshot (or placeholder PNG) instead of the glyph mosaic. Non-URL no-media cards keep the mosaic.
- [ ] **Step 4: Run tests — PASS. Commit** `feat(bbs): couverture snapshot pour les cartes URL (ref #1120)`

---

### Task 5: Python egress client (proxy + CA + SSRF)

**Files:**
- Create: `packages/secubox-bbs/py/urlshot/egress.py`
- Test: `packages/secubox-bbs/py/urlshot/tests/test_egress.py`

**Interfaces:**
- Produces: `def url_interdite(u: str) -> str | None` (raison si SSRF/rejet, sinon None); `def client() -> httpx.Client` (proxy sbxmitm + CA, timeouts).

- [ ] **Step 1: Failing tests**
```python
import egress
def test_ssrf_bloque_interne():
    for u in ["http://127.0.0.1/","http://10.0.0.5/","https://x.gk2.secubox.in/",
              "http://169.254.169.254/","ftp://x/","file:///etc/passwd","http://[::1]/"]:
        assert egress.url_interdite(u), u
def test_ssrf_laisse_passer_externe():
    assert egress.url_interdite("https://example.com/page") is None
```
- [ ] **Step 2: Implement** — parse URL, resolve host, reject non-http(s), private/loopback/link-local ranges (use `ipaddress`; resolve DNS and check EVERY resolved IP), and any host matching `*.secubox.in`/`*.gk2.net`/board domains. `client()` builds `httpx.Client(proxies="http://10.99.1.1:8091", verify="/etc/secubox/toolbox/ca/ca.pem", timeout=15, follow_redirects=True, headers={"User-Agent": "SecuBox-URLShot/1.0"})`. On each redirect hop, re-check `url_interdite` (defence against redirect-to-internal).
- [ ] **Step 3: Run — PASS. Commit** `feat(bbs): egress SSRF-safe via sbxmitm pour urlshot (ref #1120)`

---

### Task 6: og:image fetch + parse

**Files:**
- Create: `packages/secubox-bbs/py/urlshot/ogimage.py`
- Test: `packages/secubox-bbs/py/urlshot/tests/test_ogimage.py`

**Interfaces:**
- Produces: `def cherche_og_image(url: str, cli) -> bytes | None` — fetch HTML (cap 2 MiB), parse `<meta property="og:image">` (fallback `twitter:image`), resolve relative → absolute, SSRF-check the image URL, download it (cap 8 MiB, must be `image/*`), return PNG/JPEG bytes or None.

- [ ] **Step 1: Failing test** — feed a fake `httpx` transport returning HTML with `og:image`, assert the image bytes come back; HTML without og:image → None; og:image pointing to `127.0.0.1` → None (SSRF).
- [ ] **Step 2: Implement** using a regex/`html.parser` for the meta tag (no heavy dep), `urllib.parse.urljoin` for relative, `egress.url_interdite` on the image URL, content-type + size caps.
- [ ] **Step 3: Run — PASS. Commit** `feat(bbs): extraction og:image pour urlshot (ref #1120)`

---

### Task 7: Capture orchestrator (og:image → shotter fallback)

**Files:**
- Create: `packages/secubox-bbs/py/urlshot/capture.py`
- Test: `packages/secubox-bbs/py/urlshot/tests/test_capture.py`

**Interfaces:**
- Consumes: `ogimage.cherche_og_image`, `secubox_core.shotter.capture`, `egress`.
- Produces: `def capture_vignette(url: str) -> tuple[bytes | None, bool]` — `(png, ok)`. og:image first; if None, chromium screenshot **through the proxy + CA** (`shotter.capture(url, wait=shotter.wait_static_ready, ...)` launched with `--proxy-server=http://10.99.1.1:8091` and the CA trusted). Any exception/timeout → `(None, False)`.

- [ ] **Step 1: Failing test** — monkeypatch `cherche_og_image` to return bytes → orchestrator returns those, never calls shotter; monkeypatch it to None + shotter to return bytes → returns shotter's; both raise → `(None, False)`.
- [ ] **Step 2: Implement.** Note: `shotter.capture` launches chromium; pass proxy + CA via its launch options (extend `shotter` with an optional `proxy=`/`ca=` param in a small, backward-compatible sub-task if needed — a shared change, guard existing callers). SSRF-check `url` up front.
- [ ] **Step 3: Run — PASS. Commit** `feat(bbs): orchestrateur de capture og:image+screenshot (ref #1120)`

---

### Task 8: Worker — drain the queue

**Files:**
- Create: `packages/secubox-bbs/py/urlshot/worker.py`
- Test: `packages/secubox-bbs/py/urlshot/tests/test_worker.py`

**Interfaces:**
- Consumes: BBS `index.db` (`urlshots` table, read/update via a read-write connection to `/var/lib/secubox/bbs/index.db`), `capture.capture_vignette`, `secubox_core.screenshots.record` (base `/var/cache/secubox/bbs/urlshots`).
- Produces: `def draine(n: int = 3) -> dict` — process up to `n` pending rows, one at a time; per row: `capture_vignette(url)` → `screenshots.record(base, cle, png, fingerprint, ok)`; `UPDATE urlshots SET statut=?, maj=? WHERE cle=?` (`done`/`failed`). Load-guard: skip if 1-min loadavg > threshold (default 40, like metablog-shotter).

- [ ] **Step 1: Failing test** — seed a temp SQLite `urlshots` with 2 pending rows, monkeypatch `capture_vignette` (one ok, one fail), run `draine`, assert PNG written for the ok row, statuts updated to `done`/`failed`, load-guard honoured.
- [ ] **Step 2: Implement** — `fingerprint` can be the URL itself (recapture governed by `is_stale` TTL); one capture at a time; never raise out of the loop (a bad row must not wedge the worker).
- [ ] **Step 3: Run — PASS. Commit** `feat(bbs): worker de capture urlshot (ref #1120)`

---

### Task 9: systemd units + packaging

**Files:**
- Create: `packages/secubox-bbs/debian/secubox-bbs-urlshot.service`, `.timer`
- Modify: `packages/secubox-bbs/debian/rules` (or `.install`) — ship `py/urlshot/` → `/usr/lib/secubox/bbs/urlshot/`
- Modify: `packages/secubox-bbs/debian/*.tmpfiles` — `d /var/cache/secubox/bbs/urlshots 0750 secubox-bbs secubox -`
- Modify: `packages/secubox-bbs/debian/control` — `Recommends: chromium, python3-httpx` + `secubox-core` (for `secubox_core`)
- Test: `packages/secubox-bbs/debian/tests/` or a smoke check that the unit file is valid.

- [ ] **Step 1: Service** (oneshot, hardened, runs as `secubox-bbs`, load-guarded inside the worker):
```ini
[Unit]
Description=SecuBox BBS — capture des vignettes-snapshot d'URL (#1120)
After=secubox-bbs.service

[Service]
Type=oneshot
User=secubox-bbs
Group=secubox
Environment=PYTHONPATH=/usr/lib/secubox/bbs/urlshot
ExecStart=/usr/bin/python3 -m worker
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/secubox/bbs /var/cache/secubox/bbs
# Egress: seul le proxy sbxmitm est joignable (le worker le configure ; le
# durcissement réseau reste permissif AF_INET pour joindre 10.99.1.1).
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SuccessExitStatus=0 1
```
- [ ] **Step 2: Timer** — `OnBootSec=2min`, `OnUnitInactiveSec=2min` (like metablog-shots).
- [ ] **Step 3: postinst** — `systemctl enable --now secubox-bbs-urlshot.timer` (guard: only if the package installs cleanly; never fail the install on a missing chromium — the timer runs, the worker load-guards/no-ops).
- [ ] **Step 4: Verify** `systemd-analyze verify` on the unit; `dpkg-buildpackage` produces the `.deb` with the worker + units.
- [ ] **Step 5: Commit** `feat(bbs): unité+timer de capture urlshot + packaging (ref #1120)`

---

### Task 10: End-to-end verification on gk2 + docs

**Files:**
- Modify: `packages/secubox-bbs/README.md` (document `/urlshot`, the worker, the cache path, the egress/SSRF model)
- Modify: `.claude/HISTORY.md` (dated entry)

- [ ] **Step 1:** Build + deploy `secubox-bbs` (semver bump, changelog committed). `reprepro includedeb`.
- [ ] **Step 2:** Create a test fil whose body is a single external URL (e.g. `https://example.com/`). Confirm a pending `urlshots` row, then run `systemctl start secubox-bbs-urlshot.service`, confirm a PNG lands in `/var/cache/secubox/bbs/urlshots/<key>/screenshot.png`, and the accueil carousel card serves it via `/urlshot/<key>` (200 `image/png`).
- [ ] **Step 3:** Confirm an anonymous request to a **local**-post URL key returns the placeholder, not the snapshot (visibility gate).
- [ ] **Step 4:** Confirm SSRF: enqueue a `http://127.0.0.1/` URL (via a crafted post) → worker records `failed`, no PNG, no internal fetch (check journal).
- [ ] **Step 5:** README + HISTORY, commit, open PR `Closes #1120` **only after user validation** (no auto-close per project rule).

---

## Self-Review

**Spec coverage (#1120):** og:image-first + screenshot fallback (Tasks 6–7) ✓; egress through toolbox/WAF + CA (Task 5) ✓; SSRF guards (Tasks 5, 10) ✓; async worker + cache reuse `secubox_core` (Tasks 7–8) ✓; visibility gating mirror of #1114 (Tasks 2–3) ✓; card cover + placeholder (Tasks 3–4) ✓; #1049 kept separate (no gateway_contenu touch) ✓; CSP same-origin serving (Task 3) ✓.

**Type consistency:** `CleUrlshot`/`EnfileUrlshot`/`StatutUrlshot` names are used identically in Tasks 2–4; the cache base `/var/cache/secubox/bbs/urlshots` and PNG layout `<base>/<key>/screenshot.png` are consistent between Go endpoint (Task 3) and Python worker (Task 8) via `secubox_core.screenshots`.

**Open risk to resolve during Task 7:** `secubox_core.shotter.capture` currently launches chromium without a proxy/CA option — adding a backward-compatible `proxy=`/`ca=` parameter is a shared-module change; keep existing callers (metablog/streamlit shots) working (default None = direct, as today).

## Execution Handoff

Plan saved. Two execution options:
1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks.
2. **Inline Execution** — batch execution with checkpoints.
