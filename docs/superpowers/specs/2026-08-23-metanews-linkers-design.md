<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# MetaNews + Linkers — Design (secubox-metanews)

**Goal:** a local news *radar* — many sources → one event → short factual summary → the original links → a one-click BBS discussion. Never a press portal, never full-article copies.

**Trio:** RADIO *écouter* · **METANEWS *observer*** · BBS *discuter*.

**Steer honoured:** RSS is a **connector, Mastodon-style** (not a parallel module); connectors become bidirectional **Linkers** — *in/out*, `GET/PUT`, **PEEK** (read/observe/in) / **POKE** (write/act/out), named after Zanimalos Peek (Observateur) & Poke (Bricoleur).

---

## 1. Architecture — the Linker model

A **Linker** is a bidirectional connector to an external world (RSS, Atom, Mastodon, later PeerTube/YouTube/other fediverse & social SaaS). Two verbs:

```
        ┌──────────────── LINKER ────────────────┐
  world │  PEEK  (in / read)   → []Contenu        │  normalized
  ◄────►│  POKE  (out / write) ← Post/Thread ref  │  gateway.Contenu
        └─────────────────────────────────────────┘
```

- **PEEK** = pull normalized items (`gateway.Contenu`: title, body, source URL, ref, published_at, entities, hash). This is exactly what BBS `internal/connectors/rss.go` already does (`Tirer(since)`), and what `internal/mastodon` does for toots.
- **POKE** = push out (publish/reply to the source). Not needed for MVP RSS (read-only) but the interface reserves it, so Mastodon/fediverse later gain write (cross-post, reply) without reshaping anything.

```go
type Linker interface {
    ID() string                         // "rss", "mastodon", …
    Peek(since int64) ([]gateway.Contenu, error)   // IN
    Poke(out OutMsg) (Ref, error)                  // OUT (optional; ErrReadOnly for RSS)
    Health() gateway.Sante
}
```

**Where things live (recommended):**

| Layer | Home | Rationale |
|---|---|---|
| `Linker` interface + RSS/Atom + Mastodon connectors | **shared Go module** `packages/secubox-linkers/` (promote BBS `internal/connectors` + `internal/gateway` + `internal/mastodon` out of `internal/`) | user's steer: RSS *is* the Mastodon connector; today they're trapped in BBS `internal/` and un-importable. Promoting them lets BBS **and** MetaNews share one connector fleet. |
| Clustering, MetaNews topics, summary, UI | **`packages/secubox-metanews/`** (Go daemon, radio-shaped) | net-new; needs its own store + UI; Go so it imports the shared linkers directly and reuses the proven radio scaffold. |
| Thread spawn target | **BBS**: new `POST /api/v1/bbs/threads` (JWT) | BBS has no external write API today; MetaNews POKEs it to open a discussion. |

**MVP scope-cut:** to avoid a big BBS refactor on day one, MVP ships the `Linker` interface + a fresh RSS/Atom linker **inside `secubox-metanews`** (small, self-contained, SSRF-guarded — same shape as the BBS one). The *promotion* of BBS connectors into `secubox-linkers` is Phase 2 (then BBS and MetaNews converge on the shared package). This keeps MVP a single new module + one small BBS endpoint.

Runtime: **Go daemon** on `/run/secubox/metanews.sock`, nginx `metanews.gk2` vhost (radio pattern), SQLite at `/var/lib/secubox/metanews/metanews.db`, feed polling via a timer goroutine (double-cache discipline), full systemd hardening + `IPAddressAllow` for outbound fetch (copy radio's egress block). Privacy: local aggregation, no third-party tracker, external calls only to fetch declared feeds, history is wipeable.

---

## 2. Files to create / modify

**New module `packages/secubox-metanews/` (mirrors `secubox-radio/`):**
```
cmd/secubox-metanewsd/main.go          # daemon: socket, db, poll loop
internal/linker/                       # Linker iface + rss.go (Peek), types
internal/store/                        # SQLite: sources, articles, topics, topic_sources; migrations/*.sql
internal/cluster/                      # similarity + clustering + confidence
internal/resume/                       # short factual summary (heuristic; IA-optional)
internal/intel/                        # Intelligence Provider abstraction (heuristic | ollama | mcp)
internal/web/                          # HTTP handlers + //go:embed static/  (radio-style UI)
www/metanews/                          # admin JS (sources mgmt), served by nginx
debian/{control,rules,postinst,prerm,changelog,source}
debian/secubox.yaml                    # generate after control
systemd/secubox-metanews.service
nginx/metanews.conf
tmpfiles/secubox-metanews.conf
menu.d/28-metanews.json                # category: "mind", icon 📡
go.mod / go.sum / vendor/
```

**Modify `packages/secubox-bbs/`:**
- `internal/web/api.go` — add `POST /api/v1/bbs/threads` guarded by `s.jwt`, body `{title, body, category?, source_url?, visibility?}`, resolves author from JWT `sub` (fallback a `metanews` service author), calls `store.NewThread(cat, authorID, title, body, vis)` + `MarquerSourceMedia`, returns `{ok, thread_id, slug}`. Default `visibility=local` ("au doute, local"). Mirrors the existing `apiInvite`/`apiBackup` POST style.

**Phase 2 (not MVP):** `packages/secubox-linkers/` promoted from BBS `internal/{connectors,gateway,mastodon}`; BBS + MetaNews depend on it.

---

## 3. Data model (SQLite)

```sql
-- une source déclarée (flux)
source(id, slug, name, type TEXT,           -- 'rss'|'atom'
       url, enabled INT, category, refresh_sec INT,
       last_sync INT, last_error TEXT);

-- un article normalisé (une entrée d'un flux)
article(id, source_id, ref TEXT,            -- guid/link, unique(source_id,ref)
        title, url, summary, author,
        lang, published_at INT, fetched_at INT,
        fingerprint BLOB,                   -- blake2b(title+summary) → near-dup
        entities TEXT, tags TEXT,           -- JSON arrays
        topic_id);                          -- NULL until clustered

-- un événement MetaNews (cluster d'articles)
topic(id TEXT,                              -- mn_YYYYMMDD_xxxx
      title, summary, lang,
      created_at INT, updated_at INT,
      tags TEXT, entities TEXT,             -- JSON
      sources_count INT, confidence REAL,
      importance REAL,                      -- ranking (see §5)
      bbs_thread_id INT, bbs_slug TEXT);    -- NULL until "Discuter"

-- timeline: comment un sujet s'est construit
topic_event(id, topic_id, at INT, kind TEXT, detail TEXT);  -- 'detected'|'+source'|'resummarized'
```

Article→Topic is many-to-one (`article.topic_id`). `topic.sources` in the API is derived by joining articles.

---

## 4. API (under `/api/v1/metanews/`)

Read (public):
```
GET  /topics?category=&cursor=          → [{id,title,summary,sources_count,tags,updated_at,importance,bbs}]
GET  /topics/:id                        → full topic + timeline
GET  /topics/:id/sources                → [{name,title,url,published_at}]
GET  /categories                        → counts per category
GET  /tags                              → top tags
GET  /search?q=                         → topics matching title/summary/tags/entities
GET  /sources                           → declared feeds + status
GET  /health  /status
```
Write (JWT / sysop):
```
POST   /topics/:id/discuss              → PEEK-less POKE: create/find BBS thread, store bbs_thread_id
POST   /sources    {name,url,type,category,refresh_sec}
PATCH  /sources/:id {enabled?,...}
DELETE /sources/:id
POST   /sources/:id/test                → try a fetch, report count/error
```
Realtime: SSE `GET /stream` for new/updated topics (optional; degrade to poll). Matches SecuBox no-WebSocket-required posture.

`POST /topics/:id/discuss` server-side calls BBS `POST /api/v1/bbs/threads` with a service JWT (signed with fleet `api.jwt_secret`), body:
```
title = topic.title
body  = "MetaNews · {date}\n\nRésumé:\n{summary}\n\nSources:\n• {name} — {url}\n…\n\n#tag #tag"
source_url = lead article url
```
Then persists `bbs_thread_id`/`bbs_slug` on the topic. BBS thread shows a "📰 issu de MetaNews" marker; MetaNews shows "💬 N messages" by polling the thread.

---

## 5. Clustering strategy (the core, IA-optional)

`internal/intel` = **Intelligence Provider** abstraction with two implementations selected by config:

**Heuristic mode (default, no LLM):**
1. **Blocking** by time window (article within ±36 h of a topic) + shared language.
2. **Candidate score** vs each open topic:
   `score = 0.45·title_sim + 0.30·entity_overlap + 0.15·tag_overlap + 0.10·recency`
   - `title_sim` = token-set cosine over TF-IDF (stop-words FR/EN) + trigram Jaccard fallback.
   - `entity_overlap` = shared named entities (capitalised n-grams + a small gazetteer of places/orgs) / union.
3. **Assign** to best topic if `score ≥ 0.62`; else open a new topic. Update `confidence = score`.
4. **Dedup clones**: near-identical `fingerprint` (blake2b of normalized title+summary) or same wire lead ⇒ counted as **one** origin, not N (so 40 clone-sites ≠ 40 sources — §15 of the brief). `sources_count` counts distinct *origins*.

**IA mode (optional, opt-in):** embeddings for similarity, multi-source summary, entity extraction, divergence detection — via the same `intel.Provider` interface (local model / Ollama / SecuBox MCP / explicitly-configured remote). Core never *requires* a cloud API.

**Summary** (`internal/resume`): 2–4 sentences, built from the intersection of sources; when sources diverge on a number/fact, emit "le nombre exact varie selon les sources" rather than inventing certainty. Heuristic mode = extractive (lead sentences shared across sources); IA mode = abstractive.

**Ranking** `importance = source_diversity + freshness + sources_count + emergence_speed + user_relevance` — diversity-weighted so a single dispatch cloned everywhere doesn't dominate.

---

## 6. BBS integration

- One-way for MVP: MetaNews **POKEs** BBS to open the thread (new `POST /api/v1/bbs/threads`).
- Link stored both sides: topic keeps `bbs_thread_id`; the BBS thread carries the source-media tag + a "issu de MetaNews" note. MetaNews shows live reply count by polling `/api/v1/bbs/threads`.
- Idempotent: second "Discuter" on the same topic returns the existing thread.

---

## 7. UI mockup (radio-style, newsroom skin)

```
  📡 METANEWS · observer le monde

  [ À LA UNE ] [ FRANCE ] [ MONDE ] [ TECH ] [ CYBER ]        🔎 recherche

  ┌──────────────────────────────────────────────── PUBLIC ─┐
  │ 🔥 Incendie important près de Marseille                   │
  │ 3 sources · maj il y a 8 min · ▓▓▓▓▓░ confiance 0.91      │
  │                                                          │
  │ Un incendie mobilise plusieurs centaines de pompiers     │
  │ dans les Bouches-du-Rhône. Des évacuations sont          │
  │ signalées ; leur nombre varie selon les sources.         │
  │                                                          │
  │ #Marseille #Incendie #BouchesDuRhône                     │
  │ France Info · RTL · Reuters                               │
  │                                                          │
  │ [ Sources 3 ]        [ 💬 Discuter (17) ]                │
  └──────────────────────────────────────────────────────────┘
```
`[Sources]` expands to the per-source list (title + time + [Lire] → original). No full article text is ever shown. Card = the **event**, never a single RSS row. Admin `www/metanews/` panel = add/remove/toggle/test feeds, per the WEBUI-PANEL guidelines.

---

## 8. MVP plan (bite-sized, TDD)

1. Scaffold `secubox-metanews` Go module from radio (build, socket, empty UI, health). — *deployable skeleton.*
2. `internal/store` + migrations (source/article/topic/topic_event); CRUD sources. — *tests on store.*
3. `internal/linker` RSS/Atom `Peek` (SSRF-guard, 8 MiB cap, RFC dates). — *tests on parse.*
4. Poll loop (timer goroutine) → normalize → upsert articles (idempotent on (source,ref)). — *tests.*
5. `internal/cluster` heuristic (title_sim + entities + dedup) → assign topics + confidence. — *golden-set tests: the 3-fire example → 1 topic.*
6. `internal/resume` extractive short summary. — *tests.*
7. Read API + newsroom UI cards + categories/search. — *deployed, usable radar.*
8. BBS `POST /api/v1/bbs/threads` (JWT) + MetaNews `POST /topics/:id/discuss`. — *end-to-end "Discuter".*
9. secubox.yaml + menu + nginx + tmpfiles + postinst; deploy to gk2 + apt.

Phase 2 (post-MVP): promote BBS connectors → `secubox-linkers`; add Mastodon/fediverse **Peek+Poke**; SSE stream; IA-mode intel provider; angles/divergence view; timeline UI.

**Dependencies:** pure-Go only (`modernc.org/sqlite`, stdlib xml) — no heavy deps, ARM64+amd64 clean. LLM strictly optional.
