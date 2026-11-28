<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# billets — micro-blog gateway inter-médias sociaux

Self-hosted micro-blog + social-media gateway. Author-published short posts; a
public read feed with comments, emoji reactions and republish share-intents. It
**ingests** links/embeds from social networks (SSRF-guarded oEmbed, sanitized)
and lets each billet be **re-shared** back to them.

Built as a SecuBox module (`secubox-billets`): FastAPI + **aiosqlite (WAL)** +
Jinja2, served on a Unix socket behind nginx.

## Architecture

```
api/
  asgi.py        runtime entrypoint (uvicorn api.asgi:app) — lifespan opens the DB
  main.py        app factory + public feed / permalink / feeds / oEmbed
  db.py          aiosqlite WAL + numbered .sql migrations
  models.py      Pydantic v2 (strict, size-limited, https-only URLs)
  repo.py        billet/comment/reaction/author queries (keyset pagination)
  ids.py         ULID (time-sortable)
  routes/        admin.py (auth + CRUD + moderation), public.py (react/comment)
  services/      render, sanitize, ssrf, oembed, linkcard, eventlog, revisions,
                 antispam, security, feeds
  templates/  static/  migrations/
  manage.py      CLI: create-author / set-password / seed
```

**Invariants.** Every security-relevant action (publish/edit/delete, comment
moderation, login) appends to an **append-only BLAKE2b hash-chained** `event_log`
(`services/eventlog`, `verify_chain`). Every billet's content **and style** are
versioned in a **Gitea repo** (`services/revisions`, one front-matter `.md` per
billet, full `git log --follow` history).

## Install

### Debian package
```
dpkg -i secubox-billets_*.deb
# postinst creates the secubox user, /var/lib/secubox/billets, the signing
# secret, the venv (pip install requirements.txt), and the nginx vhost.
cd /usr/lib/secubox/billets
sudo -u secubox venv/bin/python -m api.manage create-author admin
```
Set the public origin so feeds/oEmbed emit absolute URLs — add to the unit:
`Environment=BILLETS_SITE_URL=https://billets.example.com`.

### Standalone
`sudo deploy/install.sh` (idempotent). In SecuBox, billets is fronted by
HAProxy (TLS 1.3) → sbxwaf → nginx → the socket.

## Configuration (environment)

| Var | Default | Purpose |
|-----|---------|---------|
| `BILLETS_DB` | `/var/lib/secubox/billets/billets.db` | SQLite WAL file |
| `BILLETS_REVISIONS_DIR` | `/var/lib/secubox/billets/revisions` | Gitea revision repo |
| `BILLETS_SECRET_FILE` | `/etc/secubox/secrets/billets` | signing secret (0600 secubox) |
| `BILLETS_SECRET` | — | secret override (takes precedence) |
| `BILLETS_SITE_URL` | derived from request | absolute origin for feeds/oEmbed |
| `BILLETS_MEDIA_DIR` | `/var/lib/secubox/billets/media` | re-encoded media + embed snapshots |
| `BILLETS_PDFPAGES_DIR` | `/var/lib/secubox/billets/pdfpages` | pages des PDF joints rendues en JPEG (cache du diaporama, #4049) |
| `BILLETS_SNAPSHOT_BROWSER` | `1` | set `0` to disable the headless-Chromium capture |

## Diaporama des médias (#4049)

La carte du fil immersif et la vue d'un billet montrent un **diaporama** de tous ses médias : images, vignettes des vidéos
jointes, **pages des PDF joints**, instantané d'un embed non vidéo. Défilement automatique toutes les 5 s (aucun si
`prefers-reduced-motion`), pause au survol, au focus, au toucher et hors écran ; flèches, points, clavier ← →
(`static/diaporama.js`, `static/diaporama.css`, partiel `templates/_diaporama.html`). Un embed vidéo garde son lecteur.

Les PDF sont rendus **par la box** (`pdftoppm`, paquet `poppler-utils`), jamais par le navigateur (pas de PDF.js) :
en tâche de fond à l'envoi, ou paresseusement au premier affichage pour les PDF plus anciens. Bornes : 30 pages,
côté long 1280 px, 2 Mio par page, 120 s au total, `nice -n 19`, sans shell. Cache :
`$BILLETS_PDFPAGES_DIR/<id du média>/p-NNN.jpg` + marqueur `.ok` (ou `.echec` : plus de nouvel essai, la diapositive
reste « document PDF »). Supprimé avec le média.

**`GET /b/{slug}/diapo/{media_id}/{n}`** (public, même garde que le permalien) : page `n` en JPEG si le billet est
publié et non échu **et** que le média est un PDF de ce billet ; sinon 404 (page pas encore rendue : 404 + rendu
planifié). Le cache n'est pas sous `/media/` (servi en direct par nginx) : il ne sort que par cette route.

## Chronologie audio (#4058)

Un billet qui porte un **audio** (mp3…) et une **chronologie** montre, dans sa vue, un diaporama **synchronisé** sur la
lecture : plus de minuteur, la diapositive suit `currentTime` de l'`<audio>` (timeupdate + seeked), la réplique en cours
s'affiche en sous-titre (`aria-live="polite"`), et un point de navigation fait sauter l'audio au début de sa diapo. La
carte du fil garde le minuteur. Sans chronologie (ou sans audio) : comportement inchangé.

Stockage : colonne `billet.chronologie` (TEXT JSON, NULL = aucune, migration `0009`). Format :

```json
[{"debut_s": 0.0, "fin_s": 4.2, "diapo": 0, "replique": "Texte dit"}, …]
```

`diapo` = index 0-based dans l'ordre des médias **image** du billet. Validation (`models.valider_chronologie`) :
`0 ≤ debut_s < fin_s ≤ 21600`, répliques en ordre croissant sans chevauchement, `diapo` entier 0..499, au plus 2000
répliques et 128 Kio, réplique ≤ 500 caractères (contrôles et marques bidirectionnelles retirés), champ inconnu refusé.

Écriture (gardes inchangées) : champ `chronologie` du formulaire `/admin/billets[/{id}]` (session + CSRF, JSON en texte,
vide = effacée) et de `POST`/`PUT /admin/api/billets[/{id}]` (`billets.publish` ; au PUT : absent = inchangé, `null`/`[]`
= effacé). À la mise à jour, chaque `diapo` doit désigner une image existante (422 sinon) ; à la création par l'API les
images arrivent ensuite, le rendu ignore donc une réplique dont l'image manque. `GET /admin/api/billets/{id}` la rend.

## Atelier des émissions : auteur, garde d'espace, rétention MP4 (#4058)

- **Auteur `emissions`** : `sudo secubox-billets-auteur-emissions` (idempotent) crée l'auteur et le jeton
  `/etc/secubox/secrets/billets-emissions.jeton` (0600, `secubox:secubox`). Ce jeton, envoyé en
  `Authorization: Bearer`, ouvre l'**écriture** de `/admin/api/billets` (création, mise à jour, médias, suppression),
  comparé en temps constant ; sans lui, la garde reste la session portant `billets.publish`.
- **Garde d'espace** : `media.espace_suffisant(octets, marge=512 Mio)` sur le volume de `media_dir()`. Faux → **507**
  avant toute écriture (ni billet ni média), au formulaire `/admin/billets[/{id}]` et à `POST /admin/api/billets/{id}/media`.
- **Rétention** : `media.purger_mp4(jours)` purge les `.mp4` plus vieux que `jours` (mtime) ; MP3 et images jamais.
  Réglage `retention_mp4_jours = 14` dans `/etc/secubox/billets.toml` (chemin : `BILLETS_TOML`). Minuterie quotidienne
  `secubox-billets-purge-mp4.timer` → `python -m api.manage purger-mp4 [--jours N]` (retire aussi les lignes média orphelines).

## Communiqué style + embed snapshot

Each billet has a `style`: **`default`** (feed look) or **`communique`** (a
poster/affiche layout — ROOT→MESH→MIND side-band, a framed "TRANSMISSION · CANAL
PUBLIC" embed, stamp/kicker/slogans/footer). Pick it in the editor.

For communiqué billets with an embed, the module captures a still **vignette** of
the embed (stored like any media file, shown in the poster frame as a
click-to-load thumbnail and in the feed as a compact framed image):

1. **Headless Chromium** (a real full-page screenshot) — **OPTIONAL**. Enable it
   with `pip install playwright && playwright install chromium` (or install the
   `snapshot` extra). Any missing package / browser / timeout degrades silently.
2. **og:image fallback** — the page's `og:image` fetched through the same SSRF
   guard (https-only, must resolve to a public IP, redirects re-validated,
   size-capped). This is the default path when Chromium is not installed, so the
   feature works fully without a browser.

The capture runs OFF the shared event loop (`asyncio.to_thread`) and only
re-captures when the `embed_url` changes.

**`GET /admin/billets/{id}/archive.html`** (JWT-gated) exports a portable,
fully self-contained single `.html` of a billet in the communiqué layout: CSS
inlined, system fonts (no network), media + the embed vignette inlined as
`data:` URIs, and the embed rendered as its snapshot image **linking to the
original** (no live iframe, so it opens offline). Button: "💾 Archive HTML".

To push revisions to Gitea, add an `origin` remote in the revisions repo as the
`secubox` user (else commits stay local — still a full history).

## Backup / restore

SQLite is the single source of truth. Take a consistent snapshot:
```
sudo -u secubox sqlite3 /var/lib/secubox/billets/billets.db ".backup '/var/backups/billets-$(date +%F).db'"
```
Restore: stop the service, copy the backup over `billets.db` (and the `-wal`/`-shm`
are rebuilt), start again. The Gitea revision repo and `/etc/secubox/secrets/billets`
should be backed up alongside.

## Tests

```
PYTHONPATH=. python -m pytest -q     # from packages/secubox-billets
```
Covers data layer, feed/pagination, admin auth/CRUD, **SSRF + XSS** (the critical
step), comments/anti-spam, reactions, feeds/oEmbed. `pip-audit` runs in CI.

## Design decisions (documented per the brief)

- **aiosqlite (async), not sync sqlite3.** As a SecuBox module, billets shares
  the aggregator's event loop path; a blocking DB call would stall the box. All
  DB access is awaited off-loop.
- **`api/` layout + Unix socket**, following SecuBox module conventions (rather
  than the standalone `app/` layout).
- **Own author auth** (argon2id + optional TOTP) kept per spec; SecuBox-auth SSO
  is a possible v2.
- **htmx replaced by a tiny vanilla shim** (`static/billets.js`, CSP
  `script-src 'self'`). The reaction endpoint returns an htmx-compatible fragment,
  so dropping in a vendored `htmx.min.js` at deploy works unchanged — this avoids
  an un-fetchable CDN dependency while keeping graceful no-JS degradation.
- **Emails hashed** (BLAKE2b), not encrypted — never displayed, only used to
  detect a returning approved commenter (spec allows "chiffré au repos ou hashé").
- **oEmbed discovery is same-origin only** (Mastodon/PeerTube self-hosted); an
  unknown host with no same-origin oEmbed link falls back to a local OpenGraph card.

### Publication par l'atelier des émissions (#4058)

L'atelier de gk0 (`secubox-ai-agents/emissions/publication.py`) publie par `POST /admin/api/billets` (brouillon),
`POST …/{id}/media` (MP3, PNG dans l'ordre des diapositives, MP4 s'il existe) puis `PUT …/{id}` (chronologie +
`published`), avec `Authorization: Bearer` = `/etc/secubox/secrets/billets-emissions.jeton` (copie 0600 sur gk0 :
`~/.config/secubox-ai-jeton/billets-emissions`). Un échec en route supprime le billet créé.
