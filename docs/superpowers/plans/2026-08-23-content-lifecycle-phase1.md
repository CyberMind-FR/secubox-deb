# Content Lifecycle — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the content spine in the BBS (ContentObject + provenance + representations + events + timeline, with the identity gate) and wire the Radio module as the first adapter, end-to-end: validation → object+topic, broadcast event, member chat → replayable timeline.

**Architecture:** The spine is SQLite tables in `secubox-bbs`, exposed over the existing BBS unix socket + JWT. `secubox-radio` keeps its own DB and calls the BBS content API (like the billets/metanews clients already do). Anonymous radio chat stays volatile in the radio daemon; only BBS-member messages become persistent `TimelineComment`s.

**Tech Stack:** Go 1.22, modernc.org/sqlite (CGO-free), unix-socket HTTP, HS256 fleet JWT. TDD throughout (`go test`, `httptest`).

**Spec:** `docs/superpowers/specs/2026-08-23-content-lifecycle-design.md`

## Global Constraints

- **Règle d'or (données)** : `content_provenance` a toujours ≥1 ligne `is_original=1` et n'est jamais supprimée ; `content_representation.is_cache=1` marque une copie, jamais l'original.
- **Gate d'identité (schéma)** : `content_timeline.author_id` est `INTEGER NOT NULL` et l'insertion **rejette `author_id <= 0`** — les anonymes ne persistent jamais.
- **Migrations additives uniquement**, suivies via la table `_migrations` (une migration `ALTER`/`CREATE` n'est jouée qu'une fois). Ne jamais modifier une migration déjà livrée.
- **Idempotence** : `content_object` (sur la provenance originale), `content_representation` (UNIQUE `content_id,kind,module,ref`), `content_provenance` (UNIQUE `content_id,source_url`) — un re-appel ne duplique rien.
- **Auth** : tout endpoint `/api/v1/bbs/content*` exige le JWT de flotte (`Depends`/middleware existant). `POST /timeline` exige en plus `author_id > 0`.
- **Sockets** : `/run/secubox/bbs.sock` (BBS), `/run/secubox/radio.sock` (radio). Jamais de port TCP direct.
- **Versioning** : bump semver de chaque paquet modifié (bbs patch→mineur, radio idem) ; sync apt après build.
- **Pas d'edit live sur la board** : construire le .deb même pour un essai.

---

## PART A — Content spine in the BBS

### Task A1: Migration `content_*` tables

**Files:**
- Create: `packages/secubox-bbs/internal/store/migrations/00NN_content.sql` (NN = next free number)
- Test: `packages/secubox-bbs/internal/store/content_test.go`

**Interfaces:**
- Produces: five tables `content_object, content_provenance, content_representation, content_event, content_timeline` (schéma exact = spec §Modèle de données).

- [ ] **Step 1: Write the failing test** — the migration must create the tables.

```go
package store

import "testing"

func TestContentMigrationCreeLesTables(t *testing.T) {
	s := banc(t) // helper existant : ouvre un Store neuf en tempdir (migrations jouées)
	for _, tbl := range []string{"content_object", "content_provenance",
		"content_representation", "content_event", "content_timeline"} {
		var n int
		err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n)
		if err != nil || n != 1 {
			t.Fatalf("table %s absente (n=%d, err=%v)", tbl, n, err)
		}
	}
}
```

- [ ] **Step 2: Run it, watch it fail** — `go test ./internal/store/ -run TestContentMigrationCreeLesTables` → FAIL (tables absentes).

- [ ] **Step 3: Write the migration SQL** (exact columns from the spec):

```sql
CREATE TABLE content_object (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, title TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}', bbs_topic_id INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'proposed', visibility TEXT NOT NULL DEFAULT 'community',
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE content_provenance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_id TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE,
  source_url TEXT NOT NULL, source_type TEXT NOT NULL,
  is_original INTEGER NOT NULL DEFAULT 0, noted_at INTEGER NOT NULL,
  UNIQUE(content_id, source_url));
CREATE TABLE content_representation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_id TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, module TEXT NOT NULL, ref TEXT NOT NULL,
  is_cache INTEGER NOT NULL DEFAULT 0, url TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,
  UNIQUE(content_id, kind, module, ref));
CREATE INDEX idx_repr_ref ON content_representation(module, ref);
CREATE TABLE content_event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_id TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, actor TEXT NOT NULL DEFAULT '', payload TEXT NOT NULL DEFAULT '{}', at INTEGER NOT NULL);
CREATE TABLE content_timeline (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_id TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE,
  author TEXT NOT NULL, author_id INTEGER NOT NULL,
  offset_ms INTEGER NOT NULL DEFAULT 0, body TEXT NOT NULL,
  broadcast_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE INDEX idx_timeline_off ON content_timeline(content_id, offset_ms);
```

- [ ] **Step 4: Run test → PASS.**
- [ ] **Step 5: Commit** — `git commit -m "feat(bbs): content_* schema migration (ref #1166)"`.

---

### Task A2: Store — ContentObject types + create/resolve

**Files:**
- Create: `packages/secubox-bbs/internal/store/content.go`
- Test: `packages/secubox-bbs/internal/store/content_test.go` (append)

**Interfaces:**
- Produces:
  - `type ContentObject struct { ID, Type, Title, Metadata string; BBSTopicID int64; Status, Visibility string; CreatedAt, UpdatedAt int64 }`
  - `type Provenance struct { SourceURL, SourceType string; Original bool }`
  - `CreerContenu(o ContentObject, prov []Provenance, now int64) (string, error)` — génère l'ID si vide (`co_<yyyymmdd>_<rand6>`), insère l'objet + provenances (INSERT OR IGNORE), garantit ≥1 `is_original`. Idempotent : si une provenance `original` existe déjà, renvoie l'ID existant sans doublon.
  - `ContenuParID(id string) (ContentObject, error)` ; `ContenuParRef(module, ref string) (string, bool)` (résout via `content_representation`).

- [ ] **Step 1: Write failing tests** — creation returns a stable id, resolves by original provenance (idempotent), and enforces ≥1 original.

```go
func TestCreerContenuIdempotentParProvenanceOriginale(t *testing.T) {
	s := banc(t)
	prov := []Provenance{{SourceURL: "https://youtu.be/X", SourceType: "youtube", Original: true}}
	id1, err := s.CreerContenu(ContentObject{Type: "video", Title: "Clip"}, prov, 1000)
	if err != nil || id1 == "" { t.Fatalf("create 1: id=%q err=%v", id1, err) }
	id2, err := s.CreerContenu(ContentObject{Type: "video", Title: "Clip (revu)"}, prov, 1001)
	if err != nil { t.Fatal(err) }
	if id2 != id1 {
		t.Fatalf("re-création avec la même source originale devrait renvoyer %q, obtenu %q", id1, id2)
	}
}

func TestCreerContenuExigeUneOriginale(t *testing.T) {
	s := banc(t)
	_, err := s.CreerContenu(ContentObject{Type: "video", Title: "X"},
		[]Provenance{{SourceURL: "u", SourceType: "rss", Original: false}}, 1)
	if err == nil { t.Fatal("attendu une erreur : aucune provenance originale") }
}
```

- [ ] **Step 2: Run → FAIL** (undefined: CreerContenu).
- [ ] **Step 3: Implement `content.go`** — id generator (reuse the module's rand helper; if none, `crypto/rand` 3 bytes hex), the idempotent create (resolve by `SELECT content_id FROM content_provenance WHERE source_url=? AND is_original=1`), the getters.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(bbs): content object store — create/resolve (ref #1166)`.

---

### Task A3: Store — representations & events

**Files:**
- Modify: `packages/secubox-bbs/internal/store/content.go`
- Test: `content_test.go` (append)

**Interfaces:**
- Consumes: `CreerContenu` (A2).
- Produces:
  - `AjouterRepresentation(contentID, kind, module, ref string, isCache bool, url string, now int64) error` (INSERT OR IGNORE, UNIQUE).
  - `AjouterEvent(contentID, kind, actor, payloadJSON string, at int64) error` (append-only).
  - `LierTopic(contentID string, topicID int64) error` (UPDATE bbs_topic_id).

- [ ] **Step 1: Write failing tests** — representation idempotent (UNIQUE), event appended, `ContenuParRef` resolves after adding a representation.

```go
func TestRepresentationIdempotenteEtResoluble(t *testing.T) {
	s := banc(t)
	id, _ := s.CreerContenu(ContentObject{Type: "audio", Title: "T"},
		[]Provenance{{SourceURL: "u", SourceType: "youtube", Original: true}}, 1)
	must(t, s.AjouterRepresentation(id, "radio", "secubox-radio", "248", true, "", 2))
	must(t, s.AjouterRepresentation(id, "radio", "secubox-radio", "248", true, "", 3)) // re-appel
	got, ok := s.ContenuParRef("secubox-radio", "248")
	if !ok || got != id { t.Fatalf("ContenuParRef = %q,%v ; attendu %q", got, ok, id) }
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM content_representation WHERE content_id=?`, id).Scan(&n)
	if n != 1 { t.Fatalf("doublon de représentation : n=%d", n) }
}
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the three methods.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(bbs): content representations + events (ref #1166)`.

---

### Task A4: Store — timeline with the identity gate

**Files:**
- Modify: `packages/secubox-bbs/internal/store/content.go`
- Test: `content_test.go` (append)

**Interfaces:**
- Produces:
  - `type TimelineComment struct { ID int64; Author string; AuthorID int64; OffsetMS int64; Body string; BroadcastAt, CreatedAt int64 }`
  - `AjouterTimeline(contentID string, c TimelineComment) (int64, error)` — **rejette `AuthorID <= 0`** avec `ErrAnonymeNonPersiste`.
  - `TimelineDe(contentID string, fromMS, toMS int64) ([]TimelineComment, error)` — `ORDER BY offset_ms` ; `toMS<=0` = pas de borne haute.

- [ ] **Step 1: Write failing tests** — anonymous rejected; member persisted & ordered by offset.

```go
func TestTimelineRejetteAnonyme(t *testing.T) {
	s := banc(t)
	id, _ := s.CreerContenu(ContentObject{Type: "audio", Title: "T"},
		[]Provenance{{SourceURL: "u", SourceType: "youtube", Original: true}}, 1)
	if _, err := s.AjouterTimeline(id, TimelineComment{Author: "anon", AuthorID: 0, OffsetMS: 1000, Body: "hi"}); err == nil {
		t.Fatal("un message anonyme (author_id=0) ne doit JAMAIS être persisté")
	}
}

func TestTimelineMembreOrdreParOffset(t *testing.T) {
	s := banc(t)
	id, _ := s.CreerContenu(ContentObject{Type: "audio", Title: "T"},
		[]Provenance{{SourceURL: "u", SourceType: "youtube", Original: true}}, 1)
	s.AjouterTimeline(id, TimelineComment{Author: "Koda", AuthorID: 7, OffsetMS: 80000, Body: "b"})
	s.AjouterTimeline(id, TimelineComment{Author: "Lyra", AuthorID: 5, OffsetMS: 64000, Body: "a"})
	got, err := s.TimelineDe(id, 0, 0)
	if err != nil || len(got) != 2 { t.Fatalf("len=%d err=%v", len(got), err) }
	if got[0].OffsetMS != 64000 || got[1].OffsetMS != 80000 {
		t.Fatalf("ordre par offset non respecté : %d puis %d", got[0].OffsetMS, got[1].OffsetMS)
	}
}
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — `AjouterTimeline` guards `AuthorID<=0`; `TimelineDe` with optional upper bound.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(bbs): content timeline + identity gate (ref #1166)`.

---

### Task A5: API — content create/representation/event/topic + GET

**Files:**
- Create: `packages/secubox-bbs/internal/web/api_content.go`
- Modify: `packages/secubox-bbs/internal/web/api.go` (route registration, near the existing `/api/v1/bbs/threads`)
- Test: `packages/secubox-bbs/internal/web/api_content_test.go`

**Interfaces:**
- Consumes: store A2–A4; the existing `s.jwt(...)` middleware.
- Produces (all JWT):
  - `POST /api/v1/bbs/content` → `{type,title,metadata,provenance:[{source_url,source_type,original}]}` → `{ok,id}`.
  - `POST /api/v1/bbs/content/{id}/representation` → `{kind,module,ref,is_cache,url}`.
  - `POST /api/v1/bbs/content/{id}/event` → `{kind,actor,payload}`.
  - `POST /api/v1/bbs/content/{id}/topic` → ouvre/associe le fil (réutilise `NewThread` avec l'auteur passerelle) → `{ok,bbs_topic_id}`.
  - `GET /api/v1/bbs/content/{id}` → objet + provenance + representations + derniers events.
  - `GET /api/v1/bbs/content/by-ref?module=&ref=` → `{id}` ou 404.

- [ ] **Step 1: Write failing test** — round-trip create → resolve by-ref (httptest with a valid fleet JWT via the existing test helper).

```go
func TestAPIContentCreeEtResoutParRef(t *testing.T) {
	s := serveurTest(t) // helper existant montant un Server avec JWT de test
	body := `{"type":"video","title":"Clip","provenance":[{"source_url":"https://youtu.be/X","source_type":"youtube","original":true}]}`
	rec := postJWT(t, s, "/api/v1/bbs/content", body)
	if rec.Code != 200 { t.Fatalf("create HTTP %d", rec.Code) }
	id := decode(t, rec)["id"].(string)
	postJWT(t, s, "/api/v1/bbs/content/"+id+"/representation",
		`{"kind":"radio","module":"secubox-radio","ref":"248","is_cache":true}`)
	rec2 := getJWT(t, s, "/api/v1/bbs/content/by-ref?module=secubox-radio&ref=248")
	if rec2.Code != 200 || decode(t, rec2)["id"] != id {
		t.Fatalf("by-ref HTTP %d, id mismatch", rec2.Code)
	}
}
```

*(If `serveurTest/postJWT/getJWT/decode` helpers don't exist, add them to a `helpers_test.go` mirroring `api_creerfil_test.go`'s setup — reuse its JWT minting.)*

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement `api_content.go`** — handlers using Go 1.22 `r.PathValue("id")`, JSON decode with `io.LimitReader`, JSON responses only (never HTML error bodies — panels parse unconditionally).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(bbs): content API — create/representation/event/topic/by-ref (ref #1166)`.

---

### Task A6: API — timeline (member-gated) + GET ordered

**Files:**
- Modify: `packages/secubox-bbs/internal/web/api_content.go`, `api.go` (routes)
- Test: `api_content_test.go` (append)

**Interfaces:**
- Produces:
  - `POST /api/v1/bbs/content/{id}/timeline` → `{author_id,author,offset_ms,body}` → 200 `{ok,id}`; **`author_id<=0` → 400** `{ok:false,erreur:"anonyme non persisté"}`.
  - `GET /api/v1/bbs/content/{id}/timeline?from=&to=` → `{comments:[…]}` ordonnés par offset.

- [ ] **Step 1: Write failing test** — anonymous 400, member 200 then GET returns it.

```go
func TestAPITimelineGateEtRelecture(t *testing.T) {
	s := serveurTest(t)
	id := creerContenuTest(t, s) // helper : POST /content, renvoie l'id
	if postJWT(t, s, "/api/v1/bbs/content/"+id+"/timeline",
		`{"author_id":0,"author":"anon","offset_ms":1000,"body":"x"}`).Code != 400 {
		t.Fatal("anonyme doit être refusé (400)")
	}
	if postJWT(t, s, "/api/v1/bbs/content/"+id+"/timeline",
		`{"author_id":7,"author":"Koda","offset_ms":64000,"body":"excellent"}`).Code != 200 {
		t.Fatal("membre doit passer (200)")
	}
	rec := getJWT(t, s, "/api/v1/bbs/content/"+id+"/timeline")
	if n := len(decode(t, rec)["comments"].([]any)); n != 1 {
		t.Fatalf("relecture timeline : %d commentaires, attendu 1", n)
	}
}
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the two handlers (POST maps `ErrAnonymeNonPersiste`→400).
- [ ] **Step 4: Run → PASS ; full `go test ./...` green ; build the .deb.**
- [ ] **Step 5: Commit + bump** — `feat(bbs): content timeline API (member-gated) (ref #1166)` ; bump `debian/changelog`.

---

## PART B — Radio adapter (the motor case)

### Task B1: Radio → BBS content client

**Files:**
- Create: `packages/secubox-radio/internal/contentbbs/client.go`
- Test: `packages/secubox-radio/internal/contentbbs/client_test.go`

**Interfaces:**
- Produces `type Client struct{…}` over a unix-socket `http.Client` (mirror `internal/ytsas` / the BBS `billets` client) + fleet JWT signer (reuse the radio JWT helper if present, else HS256 sign like socialrelay's `signerJeton`):
  - `Creer(o Objet, prov []Prov) (string, error)` → POST /content.
  - `Representation(id, kind, module, ref string, isCache bool) error`.
  - `Event(id, kind, actor, payloadJSON string) error`.
  - `Topic(id string) (int64, error)`.
  - `Timeline(id string, authorID int64, author string, offsetMS int64, body string) error`.

- [ ] **Step 1: Write failing test** — against an `httptest.NewServer` (unix not required for the client test; inject the base URL) asserting `Creer` POSTs the right JSON and returns the id.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the client (Bearer JWT header, 5s timeout, JSON bodies).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(radio): BBS content client (ref #1166)`.

---

### Task B2: On validation → ContentObject + representation + topic

**Files:**
- Modify: `packages/secubox-radio/internal/web/web.go` (the sysop `Valide` handler path) and/or `internal/store` call site.
- Test: `packages/secubox-radio/internal/web/content_hook_test.go`

**Interfaces:**
- Consumes: B1 client; the existing validation flow (`store.Valide`), the piste (source URL, title, id).
- Produces: on a successful validation, one call chain `Creer(prov=source, original=true)` → `Representation(kind=radio, module=secubox-radio, ref=piste_id, is_cache=true)` → `Topic(id)` ; store the returned `content_id` on the piste (add a nullable `content_id` column via migration, or a side map — **decide: add column**, additive migration, so replay can resolve).

- [ ] **Step 1: Write failing test** — validating a piste triggers the client calls (inject a fake `contentbbs.Client` interface; assert Creer+Representation+Topic called with the piste's source/id).
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — extract a small interface for the client so the handler is testable; call it after `Valide` succeeds; persist `content_id` on the piste. Non-blocking: a client error is logged, never fails the validation (the antenna must not depend on the BBS being up).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(radio): validation opens a ContentObject + topic (ref #1166)`.

---

### Task B3: On broadcast → event

**Files:**
- Modify: `packages/secubox-radio/internal/programme/programme.go` (the `avance`/`NoteLecture` path) — emit a `broadcast` event via a callback, to keep `programme` free of HTTP.
- Test: `programme` test asserting the callback fires with the piste id on track change.

**Interfaces:**
- Produces: a `OnBroadcast func(pisteID int64, at int64)` hook on the Programmateur, invoked in `avance` after `NoteLecture`; wired in `main.go`/web to call `client.Event(content_id, "broadcast", "", payload)` resolving the piste's `content_id`.

- [ ] **Step 1: Write failing test** — `programme_test.go`: set a hook, advance, assert it fired with the played piste id.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — add the hook field + call; wire it in the web/main layer (resolve content_id → Event). Errors logged only.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(radio): broadcast event on track change (ref #1166)`.

---

### Task B4: Radio chat — member → timeline, anonymous → volatile

**Files:**
- Modify: `packages/secubox-radio/internal/web/web.go` (the `/api/v1/radio/chat` POST handler) + `internal/web/static/radio.js` (send the BBS pseudo when logged-in).
- Test: `packages/secubox-radio/internal/web/chat_timeline_test.go`

**Interfaces:**
- Consumes: B1 client, the current media's `content_id` + live offset (from `prog.Actuel`), the requester identity.
- Produces: on a chat POST, **always** push to the existing volatile chat (ambiance) ; **additionally**, if the requester is an identified BBS member (member id > 0 from the session/aggregator), call `client.Timeline(content_id, memberID, pseudo, offsetMS, body)` where `offsetMS = prog.Actuel().OffsetMS`. Anonymous → volatile only.

- [ ] **Step 1: Write failing test** — a member chat POST calls `client.Timeline` with the current offset; an anonymous POST does not (fake client + fake identity).
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — resolve current content_id from the playing piste; gate on member id; compute offset from `prog.Actuel`. Frontend: include the pseudo when known (the webui already reads `sbx_token`).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `feat(radio): member chat persists to content timeline (ref #1166)`.

---

### Task B5: Replay — serve the timeline for a media

**Files:**
- Modify: `packages/secubox-radio/internal/web/web.go` (+ `radio.js` replay view if present)
- Test: `chat_timeline_test.go` (append)

**Interfaces:**
- Produces: `GET /api/v1/radio/replay/{piste}/timeline` → resolves the piste's `content_id` → `client` GET `/content/{id}/timeline` → returns the ordered comments for the replay UI (`offset_ms` → réaffichage au bon instant).

- [ ] **Step 1: Write failing test** — the endpoint resolves content_id and returns the comments the fake client yields.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — thin proxy over the client; 404 if the piste has no content_id yet.
- [ ] **Step 4: Run → PASS ; full `go test ./...` ; build .deb.**
- [ ] **Step 5: Commit + bump** — `feat(radio): replay timeline endpoint (ref #1166)` ; bump changelog.

---

## Deploy & verify (end of Phase 1)

- [ ] Build both .debs, deploy to gk2, sync apt.
- [ ] **Verify E2E**: validate a radio proposition → a `content_object` exists (`by-ref module=secubox-radio ref=<piste>`), a `topic` is opened, a `broadcast` event lands on play; a **member** chat during play creates a `content_timeline` row at the right offset; an **anonymous** chat does **not**; `GET replay/{piste}/timeline` returns the member comment ordered by offset.
- [ ] Update `.claude/HISTORY.md`, comment #1166 "Phase 1 implemented, pending review" (never close).

## Self-Review

- **Spec coverage**: A1–A6 = spine (object/provenance/representation/event/timeline + API + identity gate) ; B1–B5 = Radio adapter (validation→object/topic, broadcast event, member chat→timeline, replay). Lifecycle/visibility = out of Phase 1 (phase 2/3), consistent with the spec.
- **Type consistency**: `content_id` is `string` everywhere; `AuthorID int64` gate matches the `NOT NULL` + `>0` rule at store (A4) and API (A6) and adapter (B4). `ContenuParRef(module,ref)` produced in A3, consumed in A5/B5.
- **Placeholder scan**: no TBDs; the one open call-out ("add `content_id` column on piste") is decided in B2 (additive migration).
- **No live edits**: every task ends by building the package; deploy is a single explicit step at the end.
