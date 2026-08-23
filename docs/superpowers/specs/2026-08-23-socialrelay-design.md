<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# SocialRelay — Design (secubox-socialrelay)

**Goal:** a **social-network relay** — pull posts from fediverse & social sources, **cache their media locally**, and turn each source (or thread) into a **BBS gateway thread** you can discuss — the client never contacts the third party. Same ergonomics as MetaNews Actualités.

**Steer:** this is the **Linkers** layer realized (Peek/Poke, in/out), the fediverse+social evolution of the MetaNews connector. RSS is already a linker; SocialRelay adds the *social* linkers and the **media cache**.

**Trio → quartet:** RADIO *écouter* · METANEWS *observer (news)* · **SOCIALRELAY *suivre (social)*** · BBS *discuter*.

---

## 0. Feasibility — honest per network

Because the operator will ask "why not just Facebook?", the matrix is the first design artifact. **We never scrape or bypass access controls** (SecuBox principle, restated from the MetaNews brief).

| Source | How | Verdict |
|---|---|---|
| **Mastodon / fediverse** | Public account/tag **timeline JSON** + RSS (`/@user.rss`), ActivityPub | ✅ **Clean, open — MVP first.** No auth for public content. |
| **Bluesky** | AT Protocol public XRPC (`getAuthorFeed`) — open, no key for public | ✅ Clean. Good second connector. |
| **PeerTube** | Public API + RSS | ✅ Clean (BBS already ingests it). |
| **YouTube** | Channel RSS (`feeds/videos.xml?channel_id=`) | ✅ Clean (RSS). |
| **RSS/Atom** | Already a linker | ✅ (belongs to MetaNews; shared). |
| **Nitter / X (Twitter)** | Nitter mostly dead; API paywalled | ⚠️ Unreliable. Not shipped. |
| **Facebook group** (e.g. `/groups/473694028670754`) | No RSS since ~2015. Graph API needs **that group's app + admin token + review**. Scraping = ToS breach + brittle. | ❌ **Not a default.** Only via (a) official Graph API **with the group admin's token/consent**, or (b) a **user-run RSS-Bridge** the operator opts into and owns the fragility/risk of. Never a scraper we ship. |
| Instagram / TikTok | Closed, aggressive anti-bot | ❌ Same as Facebook. |

**Design consequence:** a **connector registry** where each connector declares its *access mode* (`open` / `bridge` / `consent`). The UI shows the mode honestly; `bridge`/`consent` connectors are opt-in and carry a warning.

---

## 1. Architecture — Linker + media cache

```
   source (fediverse/…)
        │  PEEK (in)              ← pull public posts as gateway.Contenu
        ▼
   normalisation
        ▼
   MÉDIA : télécharger + CACHER EN LOCAL  ← images/vidéo dans le magasin BBS
        ▼                                    (le navigateur ne touche jamais la source)
   fil passerelle BBS  ── POST /api/v1/bbs/threads (JWT) ──► BBS
        ▼
   Discuter (couche humaine)
        │  POKE (out, plus tard) ← republier/répondre depuis SecuBox
        ▼
   source
```

**Linker interface** (reuse the MetaNews `Linker` verbatim — promote to shared `secubox-linkers` in Phase 2):

```go
type Linker interface {
    ID() string                              // "mastodon", "bluesky", …
    Mode() AccessMode                        // open | bridge | consent
    Peek(depuis int64) ([]gateway.Contenu, error) // IN
    Poke(msg OutMsg) (Ref, error)            // OUT (ErrLectureSeule au MVP)
    Sante() Sante
}
```

`gateway.Contenu` gains `Medias []Media{URL, Kind}` (already present-ish); SocialRelay is the first consumer that **persists** them.

**Media cache (the new core vs MetaNews):** for each pulled post, download every media (SSRF-guarded, size cap, type-checked), store it under `/var/lib/secubox/socialrelay/media/<hash>.<ext>`, and rewrite the thread body/attachment to the **local** ref. This is the "récupérateur de topic et de médias pour cache locaux BBS". The BBS already serves attachments (`/f/NN`) — SocialRelay pushes media into that store (or its own, served via a relay route like `/mn-vignette`).

**Runtime:** Go daemon (radio-shaped) on `/run/secubox/socialrelay.sock`, SQLite, poll loop, nginx `social.gk2` vhost, full hardening + egress. WebUI embedded. Menu `mind`/`wall`.

---

## 2. Data model (SQLite)

```sql
source(id, slug, name, kind TEXT,          -- 'mastodon'|'bluesky'|'peertube'|'youtube'|'bridge'
       handle TEXT, url, enabled, mode TEXT, -- open|bridge|consent
       salon TEXT,                          -- salon BBS cible (slug)
       refresh_sec, last_sync, last_error);

post(id, source_id, ref TEXT,              -- id natif, unique(source_id,ref)
     author, url, text, published_at, fetched_at,
     bbs_thread_id, media TEXT);           -- JSON: [{local_ref, kind, orig}]

media(hash TEXT PRIMARY KEY, kind, bytes, fetched_at, orig_url);
```

---

## 3. API (`/api/v1/socialrelay/`)

```
GET  /sources                       liste + état + mode
POST /sources        (JWT)          {name,kind,handle|url,salon,mode}
PATCH/DELETE /sources/:id (JWT)
POST /sources/:id/test (JWT)        essai de PEEK
GET  /feed?source=&limit=           posts relayés (avec médias locaux)
GET  /media/:hash                   sert un média caché localement
GET  /health /status
```

Poll loop: for each due source → `Peek` → for each new post → cache media → `POST /api/v1/bbs/threads` (author `passerelle`, salon from source, **VisLocal by default**, body = text + local media refs, `source_url` = post URL).

---

## 4. BBS integration

- Reuse the **existing** `POST /api/v1/bbs/threads` (built for MetaNews) — no new BBS write API needed.
- Media: push cached files into the BBS attachment store so threads render them from `/f/NN` (fully local). Alternative: serve from SocialRelay `/media/:hash` via a relayed `<img>` (members-only), like `/mn-vignette`.
- A **BBS newsroom cartouche** "Réseaux" mirroring the MetaNews Actualités cardlet (same style, vignettes, per-source), fed from the SocialRelay socket — one more `vitrine*()` in the BBS, gated to a salon (e.g. `/c/reseaux`).

---

## 5. UI mockup (textual, MetaNews-style)

```
  🌐 SOCIALRELAY · suivre le monde social            ⚙ Sources

  [ carrousel des 10 derniers posts · vignette · auto-rotation ]

  ┌───────────────────────── mastodon · open ─┐
  │ [média local]  @gkerma@piaille.fr          │
  │ « On lance MetaNews… »   🖼×2   il y a 4 min │
  │ [ Ouvrir ]        [ 💬 Discuter ]           │
  └────────────────────────────────────────────┘

  Sources : mastodon(open) · bluesky(open) · peertube(open)
            facebook(consent — jeton admin requis) ⚠
```

---

## 6. MVP plan (TDD, fediverse-first)

1. Scaffold `secubox-socialrelay` from radio/metanews (socket, health, empty UI).
2. `internal/linker` : **Mastodon** connector — public account/tag timeline JSON → `Contenu` (+ media list). Tests on parse.
3. Store (source/post/media) + CRUD sources. Tests.
4. Media cache : download (SSRF-guard, cap, type) → `/var/lib/.../media/<hash>` + `/media/:hash` route. Tests.
5. Poll loop → thread spawn (reuse BBS `POST /threads`) with local media refs.
6. WebUI : feed + carousel + admin sources (mode-aware, warnings).
7. BBS cartouche "Réseaux" (a `vitrineSocial()` + a `/c/reseaux` view).
8. Packaging (service, nginx, tmpfiles, menu, secubox.yaml) → deploy + apt.

**Phase 2:** Bluesky + PeerTube + YouTube connectors; **Poke** (cross-post/reply from SecuBox); promote `Linker`/`gateway` into shared `secubox-linkers`; Facebook via Graph-with-consent or user RSS-Bridge (opt-in).

**Deps:** pure-Go + stdlib only (net/http, encoding/json, modernc/sqlite). No scraping libs, no headless browser, ARM64+amd64 clean.
