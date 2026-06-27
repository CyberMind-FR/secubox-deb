# #757 — SW revalidation nudge (strip conditional headers for allow-listed hosts)

**Goal:** stale-while-revalidate SWs on the sw-neuter allow-list update their cache
with a banner'd shell WITHOUT being neutered — by forcing a full 200 (not a 304)
on their HTML revalidation fetch so the MITM's existing injection lands.

**Design (approved):** in `mitmPipeline`, BEFORE the upstream proxy (`up.Do(req)`),
for an allow-listed host (`swNeuter.Match`) on an HTML document request, strip
`If-None-Match` + `If-Modified-Since` → upstream returns 200 with body → MITM
injects the banner → the SW caches the banner'd version on next background
revalidation. Gated to the allow-list (bounds the full-200 bandwidth cost).
Limitation: only helps SWs that revalidate; cache-first still needs #753's neuter.

## Task 1 (single)
**Files:** modify `cmd/sbxmitm/swneuter.go` (add `requestWantsHTML`), `cmd/sbxmitm/main.go` (the strip); test `cmd/sbxmitm/swneuter_test.go`.

- requestWantsHTML(req): true if `Sec-Fetch-Dest: document` (case-insensitive) OR `Accept` contains `text/html`; nil-safe false.
- Strip in mitmPipeline before `resp, err := up.Do(req)`:
  `if px.swNeuter != nil && requestWantsHTML(req) && px.swNeuter.Match(host) { req.Header.Del("If-None-Match"); req.Header.Del("If-Modified-Since") }`
- Test: requestWantsHTML true/false cases (Sec-Fetch-Dest document, Accept text/html, neither, nil).
- Verify: go build + vet + go test ./cmd/sbxmitm/.
