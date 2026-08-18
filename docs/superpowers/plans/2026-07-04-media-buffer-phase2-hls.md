<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Media Buffer — Phase 2 Implementation Plan (HLS reassembly)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a captured HLS stream replayable as one independent media: capture its manifest + segments, and at replay time serve a **rewritten local manifest** whose segment URIs point at the captured segments — no live cross-request session state.

**Architecture — read-time URL join (key decision):** Phase 1 already captures each media object (incl. HLS `.m3u8` manifests, `kind="manifest"`) with its original `url` in the metatag. Phase 2 (a) also captures HLS **segments** (`.ts`/`.m4s`), tagging them `kind="segment"` so the gallery hides them, and (b) at replay time, when the requested record is a manifest, parses the stored manifest bytes, resolves each segment URI against the manifest's original URL, finds the captured **segment record whose `url` matches** (still non-expired), and rewrites each URI to `/api/v1/dpi/media/replay/{seg_id}`. The player then fetches the rewritten playlist and pulls each segment through the existing replay endpoint. Grouping is a **join on absolute URL at read time** — sbxmitm stays stateless, the 4 worker processes need no coordination, and segments that hit a different worker than the manifest still join correctly.

**Tech Stack:** Go (sbxmitm — segment classification only), Python 3.11 (DPI — HLS parse/rewrite + replay), vanilla JS (DPI Media tab).

## Global Constraints (inherit Phase 1 + these)

- **HLS media playlists only** in Phase 2: a single-variant `#EXTINF` media playlist. **Master/multivariant (ABR) playlists, AES-128 `#EXT-X-KEY` encrypted segments, and DASH `.mpd`** are OUT of scope — detect and mark them `partial`/unsupported (the manifest card shows "flux non réassemblable — variantes/chiffré" rather than a broken player). Deferred to Phase 2b.
- **Read-time join, never live session state**: do NOT add cross-request or cross-process session grouping in sbxmitm. Segments are captured independently and matched to a manifest only at replay time, by URL.
- **Reuse Phase 1 surface**: segments are ordinary buffer objects served by the existing `GET /media/replay/{id}`; the manifest rewrite is a new branch inside `media_replay`, not a new store. `mediaBufferRecord.Segments` (already in the schema, currently `0`) is populated for manifests at replay time or left as a display hint — do not change the metatag schema.
- **Non-blocking / def / traversal / setgid perms**: all Phase 1 constraints hold. New DPI handlers/branches stay plain `def`; every path built from a validated hex id; captured URLs never interpolated raw into HTML.
- **Feature stays behind `--media-buffer`** (default OFF). No new flag.
- **Bounded work at replay**: a manifest can list thousands of segments — cap the number of segments rewritten/served per manifest (e.g. 5000) and cap manifest parse size (reuse a bounded read), logging when truncated.

---

## File Structure

- Modify `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer.go` (or a new `mediasegment.go`) — classify HLS segments → a `segmentKind()` helper; capture them tagged `kind="segment"`.
- Modify `packages/secubox-toolbox-ng/cmd/sbxmitm/main.go` — the download-tee `Capture(...)` call passes the segment kind when applicable.
- Create `common/secubox_core/hls.py` — pure-stdlib HLS media-playlist parser + URI resolver + rewriter.
- Create `common/secubox_core/tests/test_hls.py`.
- Modify `packages/secubox-dpi/api/main.py` — `media_replay`: manifest branch (parse → join segments by URL → serve rewritten playlist); a `_segment_index()` helper over `media_buffer.read_records()`.
- Modify `packages/secubox-dpi/tests/test_media_buffer_api.py` — manifest-replay tests.
- Modify `packages/secubox-dpi/www/dpi/index.html` — hide `kind=="segment"` cards; manifest card playback (native `<video>` for the rewritten m3u8 + a download link; note non-Safari needs MSE — see Task 5).

---

### Task 1: Classify + capture HLS segments (Go)

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer.go` (+ `main.go` tee call)
- Test: `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer_test.go`

**Interfaces:**
- Produces: a classification such that a captured HLS segment gets `kind="segment"` in its metatag (so the DPI gallery can hide it and the join can find it), while whole-file video/audio keep `kind="video"/"audio"` and manifests keep `kind="manifest"`.
- Add `func segmentKind(path, ctype string) bool` (or extend the kind decision): true for `.ts`, `.m4s`, `.m4v` segment paths and `video/mp2t`/`video/iso.segment` ctypes that are clearly HLS/DASH chunks (NOT whole `.mp4`). A segment is distinguished from a whole file by extension/ctype; when ambiguous (e.g. `application/octet-stream`), only treat as a segment when the path ends in a segment extension.

- [ ] **Step 1: Failing test** — `TestSegmentClassification`: `.ts`+`video/mp2t` → segment; `.m4s` → segment; `.mp4`+`video/mp4` → NOT segment (whole `video`); `.m3u8` → manifest (unchanged). Assert `Capture(...)` for a `.ts` writes a metatag with `kind:"segment"`, and for `.mp4` writes `kind:"video"`.
- [ ] **Step 2: Run — FAIL.** `cd packages/secubox-toolbox-ng && go test ./cmd/sbxmitm/ -run TestSegment`
- [ ] **Step 3: Implement** — add `segmentKind`; in `Capture` (or the tee call site) set `kind="segment"` when `segmentKind` is true (take precedence over the `video/audio` fallback so a `.ts` served `video/mp2t` is a segment, not a whole video). Keep the whole-file `.mp4`/`video/*` path as `video`. Do NOT capture segments served with a Range-partial 206 (Phase 1's `==200` gate already excludes those — good, HLS segments are normally whole 200s).
- [ ] **Step 4: Run — PASS.** Also `go test -race ./cmd/sbxmitm/ -run 'TestSegment|TestMediaBuffer|TestTee'`.
- [ ] **Step 5: Commit** `feat(sbxmitm): capture HLS segments as kind=segment (Phase 2, ref #812)`

---

### Task 2: HLS media-playlist parser/rewriter (Python, `common/secubox_core/hls.py`)

**Files:**
- Create: `common/secubox_core/hls.py`
- Test: `common/secubox_core/tests/test_hls.py`

**Interfaces (consumed by Task 3):**
- `is_master_playlist(text: str) -> bool` — True if it has `#EXT-X-STREAM-INF` (multivariant → unsupported in Phase 2).
- `is_encrypted(text: str) -> bool` — True if it has `#EXT-X-KEY` with a non-`NONE` METHOD.
- `segment_uris(text: str) -> list[str]` — ordered list of the media segment URIs (the non-comment lines following `#EXTINF`, plus `#EXT-X-MAP` init segment `URI="..."` if present). Ignores comment/tag lines.
- `resolve(base_url: str, uri: str) -> str` — absolute-URL resolution of a segment URI against the manifest's URL (stdlib `urllib.parse.urljoin`), normalized the SAME way segment records store their `url` (so the join matches — decide one canonical form and use it both when the Go side records segment URLs and here; document it).
- `rewrite(text: str, mapping: dict[str, str], max_segments: int = 5000) -> tuple[str, int, int]` — returns `(rewritten_text, matched, total)`: replaces each segment URI (and `#EXT-X-MAP` URI) whose resolved absolute URL is a key in `mapping` with `mapping[abs_url]`; leaves unmatched URIs as-is (the player will 404 that segment — acceptable, partial playback) OR drops them per a documented policy; caps at `max_segments`.

- [ ] **Step 1: Failing tests** — a small VOD media playlist fixture (3 `#EXTINF` + relative `seg0.ts`..`seg2.ts`, and an `#EXT-X-MAP:URI="init.mp4"`): `segment_uris` returns `[init.mp4, seg0.ts, seg1.ts, seg2.ts]`; `resolve("https://h/hls/index.m3u8","seg0.ts")=="https://h/hls/seg0.ts"`; `rewrite` with a mapping for 2 of 3 segments returns matched==2,total==4 and the rewritten text points those 2 at the mapped URLs; `is_master_playlist` True on an `#EXT-X-STREAM-INF` fixture; `is_encrypted` True on an `#EXT-X-KEY:METHOD=AES-128` fixture, False on `METHOD=NONE`.
- [ ] **Step 2: Run — FAIL.** `cd common && PYTHONPATH=. python -m pytest secubox_core/tests/test_hls.py -q`
- [ ] **Step 3: Implement** `hls.py` — pure stdlib (`urllib.parse`), line-based parse; fail-safe (never raise on malformed input → treat as unsupported). SPDX header.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(core): HLS media-playlist parser + segment-URI rewriter (Phase 2, ref #812)`

---

### Task 3: DPI replay — manifest reassembly branch (Python)

**Files:**
- Modify: `packages/secubox-dpi/api/main.py`
- Test: `packages/secubox-dpi/tests/test_media_buffer_api.py`

**Interfaces:**
- Consumes: `secubox_core.hls` (Task 2), `media_buffer.read_records/record_by_id` (Phase 1).
- In `media_replay(rec_id, ...)`: after resolving the record (still admin-gated + 410-on-evict + traversal-safe as Phase 1), branch on `rec.get("kind")`:
  - `"manifest"`: read the manifest object bytes; if `hls.is_master_playlist` or `hls.is_encrypted` → return the RAW manifest (unchanged) with a response header `X-SecuBox-Media: unsupported-variant` (frontend shows the "non-réassemblable" note) — do NOT attempt a broken rewrite. Else build `mapping = {seg_abs_url: f"/api/v1/dpi/media/replay/{seg_id}"}` from `_segment_index()` (all non-expired `kind=="segment"` records for the SAME `mac_hash` + host, keyed by their resolved absolute `url`), call `hls.rewrite`, and return the rewritten playlist as `application/vnd.apple.mpegurl` (a `Response`, not FileResponse — it's generated). Audit as a replay.
  - default (video/audio/file/segment): the existing Phase-1 FileResponse path unchanged.
- `_segment_index(mac_hash, host) -> dict[str,str]`: `read_records(mac_hash=mac_hash)` filtered to `kind=="segment"`, not `expired`, same host → `{record_url: record_id}`. Bounded (cap 5000).

- [ ] **Step 1: Failing tests** — seed a temp buffer with: one manifest record (bytes = a 3-segment playlist referencing `seg0.ts`..`seg2.ts`) + 2 matching segment records (`kind="segment"`, same mac/host, live) + 1 expired segment. `media_replay(manifest_id, admin)` returns a rewritten playlist where `seg0.ts`/`seg1.ts` URIs point at `/api/v1/dpi/media/replay/{their_id}` and the expired/missing one is left as-is; content-type is `application/vnd.apple.mpegurl`. A master-playlist manifest returns raw + the `unsupported-variant` header. A `kind="segment"` replay still returns its FileResponse. Traversal/410/403 behavior unchanged.
- [ ] **Step 2: Run — FAIL.** (temp ACL on `/var/lib/secubox` per the Phase-1 note if import mkdir fails.)
- [ ] **Step 3: Implement** the manifest branch + `_segment_index`. Plain `def`. Keep it bounded + fail-safe (a parse failure → serve raw manifest, never 500).
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(dpi): HLS manifest replay — rewrite segment URIs to captured segments (Phase 2, ref #812)`

---

### Task 4: Gallery — hide segments, play/mark manifests (frontend)

**Files:**
- Modify: `packages/secubox-dpi/www/dpi/index.html`

- [ ] **Step 1** In `loadMediaBuffer`/`buildMediaCard`, **skip `item.kind === "segment"`** items entirely (they're join fodder, not gallery entries) — the gallery shows only manifest + whole-file media.
- [ ] **Step 2** For a `kind === "manifest"` card: the Play action targets `/api/v1/dpi/media/replay/{id}` (the rewritten playlist). Native `<video>` plays HLS on Safari; on Chromium/Firefox add a small note "ouvrir dans Safari ou télécharger" + a Download link to the raw manifest — OR (stretch) inline `hls.js` is NOT allowed (no external CDN, self-contained only), so Phase 2 provides the rewritten-manifest link + download, not universal in-page playback. Show the segment count if `item.segments` is set.
- [ ] **Step 3** If the replay response carried `X-SecuBox-Media: unsupported-variant` (master/encrypted), show "flux non réassemblable (ABR/chiffré)" and disable Play, keep metadata. (Detect via a `fetch` HEAD or on the click handler's response.)
- [ ] **Step 4** Keep all Phase-1 escaping (`textContent`/`.title`/`encodeURIComponent`) — segment/manifest URLs are still attacker-influenceable.
- [ ] **Step 5: Commit** `feat(dpi): Media tab — hide HLS segments, manifest playback/download + unsupported-variant note (Phase 2, ref #812)`

---

### Task 5: End-to-end HLS test + docs

**Files:**
- Create: `packages/secubox-dpi/tests/test_hls_e2e.py` (or extend) — a cross-layer test that writes a manifest + segment objects to a temp buffer (mimicking what the Go tee produces), then drives `media_replay` and asserts the rewritten playlist references replayable segment URLs whose ids resolve to real object files. This is the integration coverage Phase 1's whole-branch review noted was missing.
- Modify: `packages/secubox-toolbox-ng/debian/changelog` — bump (e.g. 0.1.28) with a Phase-2 stanza.

- [ ] **Step 1** Write the e2e test (manifest + 3 segments → replay manifest → each rewritten URI's id → `record_by_id` → object file exists + bytes match).
- [ ] **Step 2** Run all suites green: `go test -race ./cmd/sbxmitm/`; `pytest common/secubox_core/tests/test_hls.py`; `pytest packages/secubox-dpi/tests/test_media_buffer_api.py test_hls_e2e.py`.
- [ ] **Step 3** changelog stanza.
- [ ] **Step 4: Commit** `test(#812): HLS reassembly end-to-end + changelog (Phase 2)`

---

## Phase 2 Done-Definition

Capturing a single-variant unencrypted HLS VOD stream through R3 with `--media-buffer` on, the DPI Media tab shows ONE manifest card (segments hidden); its replay serves a rewritten `.m3u8` whose segment URIs resolve to the captured segments and plays/downloads as one media for the retention window, then greys to metatag-only after eviction. Master/ABR + AES-128 + DASH are detected and shown as "non-réassemblable" (not broken) — deferred to **Phase 2b**. Phase 3 (kbin persona links, owner scoping) remains its own plan.

## Risks
- **Segment↔manifest URL canonicalization**: the join only works if the segment record's stored `url` and `hls.resolve(manifest_url, uri)` produce the SAME string. Pin ONE canonical form (scheme+host+path, query included as captured) and use it on both sides; test it explicitly.
- **Live playlists / sliding window**: we only have the segments that flowed during capture; a rewritten live playlist may reference segments already evicted → left unmatched (partial). Acceptable; note it.
- **Segment volume**: cap per-manifest segments (5000) and log truncation; a pathological playlist must not OOM the join.
- **In-page playback**: no external hls.js (self-contained CSP) → non-Safari browsers get download/open, not inline play. Acceptable for Phase 2; revisit with a bundled player later.
