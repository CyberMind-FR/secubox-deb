// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: ad-block metrics aggregator + flusher (#662)
//
// The #662 cutover moved the BLOCK decision (204 on ad/tracker hosts) into the
// Go engine but left the METRICS unported: the Python ad_ghost addon tallied
// every block into SQLite (record_ad_blocks / record_ad_client_blocks) feeding
// the #ads dashboard, which has been frozen since the cutover (the Go engine
// blocked but recorded nothing).
//
// This restores the tally IN the engine: an in-memory aggregator accumulates
// per-(adHost,site) and per-(macHash,adHost) hit counts + estimated bytes on the
// block hot path (O(1), lock-guarded for the concurrent workers), and a
// background flusher POSTs the snapshot every 10s to the portal's
// /__toolbox/ad-event ingest, which writes them to the SAME SQLite tables the
// dashboard already reads. Best-effort throughout: a dead/slow portal never
// blocks the block path and can never grow the maps unbounded.
//
// Pure standard library — no external modules.
package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// ── ad-candidate learning feed (#662 auto-learn loop) ─────────────────────────
//
// The STATIC block list never grows on its own; ad_ghost fed autolearn by
// capturing CANDIDATES — 3rd-party requests whose PATH smells like an ad/track
// endpoint — into ad_candidates, which secubox-toolbox-autolearn later promotes
// into learned-trackers.txt at AD_MIN_SITES distinct sites. The Go cutover
// dropped this feed, so new adwares (acotedemoi.com) were never observed. This
// restores it in the engine: the allow/mitm hot path records (host,site) when
// the request is 3rd-party AND adPathRE matches, buffered + flushed with the
// existing ad-event machinery.

// adPathRE ports ad_ghost._AD_PATH (RE2-safe, case-insensitive). Matches a path
// that looks like an ad/track endpoint. Learning only — never a block decision.
//
//	Python: re.compile(r"/ads?/|/adserver|/pagead|/gampad|/doubleclick|/beacon|"
//	                    r"/pixel|/collect|/track(ing)?|/telemetry|/metric", re.I)
var adPathRE = regexp.MustCompile(`(?i)/ads?/|/adserver|/pagead|/gampad|/doubleclick|/beacon|/pixel|/collect|/track(ing)?|/telemetry|/metric`)

// adCandMapCap bounds the candidate buffer (mirrors ad_ghost's `len(_cand) <
// 20000` guard): NEW keys past the cap are dropped until the next flush clears
// it, so a dead portal can never grow memory unbounded.
const adCandMapCap = 20000

// adCandidates is the lock-guarded (host,site)→hits candidate aggregator,
// drained by the ad-stats flusher into the ad-event payload's "candidates" list.
type adCandidates struct {
	mu  sync.Mutex
	hit map[adKey]int64
}

func newAdCandidates() *adCandidates { return &adCandidates{hit: map[adKey]int64{}} }

// record tallies one ad-candidate (host,site). O(1); the cap drops only NEW keys
// (existing keys keep accumulating). Empty host is ignored.
func (a *adCandidates) record(host, site string) {
	if host == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	k := adKey{adHost: host, site: site}
	if _, ok := a.hit[k]; ok {
		a.hit[k]++
	} else if len(a.hit) < adCandMapCap {
		a.hit[k] = 1
	}
}

// snapshot atomically reads-and-clears the buffer, returning the candidate rows.
func (a *adCandidates) snapshot() []adCandidateRow {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.hit) == 0 {
		return nil
	}
	rows := make([]adCandidateRow, 0, len(a.hit))
	for k, n := range a.hit {
		rows = append(rows, adCandidateRow{Host: k.adHost, Site: k.site, Hits: n})
	}
	a.hit = map[adKey]int64{}
	return rows
}

// refererSite ports the ad_ghost _site_of logic: parse the Referer header as a
// URL, take its hostname, and return registrable(hostname). Empty Referer or a
// parse failure → "" (the page that issued the blocked request is unknown).
// Kept here next to the metrics wiring it feeds.
func refererSite(referer string) string {
	if referer == "" {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil {
		return ""
	}
	return registrable(u.Hostname())
}

// adEstBytesPerBlock matches the existing dashboard convention: each blocked
// ad/tracker request is credited a flat 45 KB saved (mirrors the Python
// _EST_BYTES_PER_REQ = 45000 in ad_ghost.py). The #ads "bytes saved" figure
// stays comparable across the engine cutover.
const adEstBytesPerBlock = 45000

// adFlushInterval is how often the flusher drains the maps to the portal.
const adFlushInterval = 10 * time.Second

// adMapCap bounds each aggregator map: once a map holds this many keys, NEW keys
// are dropped (existing keys still accumulate) until the next flush clears it.
// Guards against a dead portal letting the maps grow without bound.
const adMapCap = 5000

// adCounter is the accumulated (hits, bytes) for one aggregation key.
type adCounter struct {
	hits  int64
	bytes int64
}

// adStats is the lock-guarded in-memory aggregator. blocks is keyed by
// (adHost,site); clients by (macHash,adHost). The keys are small structs so the
// maps stay allocation-light and comparable without string concatenation.
// cosmetic counts HTML pages where the cosmetic ad-hide style was injected (#755).
type adStats struct {
	mu       sync.Mutex
	blocks   map[adKey]*adCounter
	clients  map[cliKey]*adCounter
	cosmetic atomic.Int64 // #755 — pages where the cosmetic ad-hide style was injected
}

type adKey struct{ adHost, site string }
type cliKey struct{ macHash, adHost string }

func newAdStats() *adStats {
	return &adStats{
		blocks:  map[adKey]*adCounter{},
		clients: map[cliKey]*adCounter{},
	}
}

// recordAdBlock tallies one blocked ad/tracker request. It increments the
// (adHost,site) global counter by 1 hit + adEstBytesPerBlock, and — only when
// macHash is non-empty — the (macHash,adHost) per-client counter likewise. An
// empty adHost is ignored (nothing to attribute). O(1), never blocks: the only
// contention is the short mutex held across two map ops. The size cap drops only
// NEW keys (existing keys keep accumulating), so a dead portal can't grow memory
// unbounded.
func (a *adStats) recordAdBlock(adHost, site, macHash string) {
	if adHost == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	bk := adKey{adHost: adHost, site: site}
	if c := a.blocks[bk]; c != nil {
		c.hits++
		c.bytes += adEstBytesPerBlock
	} else if len(a.blocks) < adMapCap {
		a.blocks[bk] = &adCounter{hits: 1, bytes: adEstBytesPerBlock}
	}

	if macHash != "" {
		ck := cliKey{macHash: macHash, adHost: adHost}
		if c := a.clients[ck]; c != nil {
			c.hits++
			c.bytes += adEstBytesPerBlock
		} else if len(a.clients) < adMapCap {
			a.clients[ck] = &adCounter{hits: 1, bytes: adEstBytesPerBlock}
		}
	}
}

// recordCosmetic tallies one R3 HTML page that received the cosmetic ad-hide style.
func (a *adStats) recordCosmetic() { a.cosmetic.Add(1) }

// snapshotCosmetic atomically reads-and-clears the cosmetic page counter.
func (a *adStats) snapshotCosmetic() int64 { return a.cosmetic.Swap(0) }

// ── wire payload (mirrors the portal /__toolbox/ad-event JSON contract) ──────

type adBlockRow struct {
	AdHost string `json:"ad_host"`
	Site   string `json:"site"`
	Hits   int64  `json:"hits"`
	Bytes  int64  `json:"bytes"`
}

type adClientRow struct {
	MacHash string `json:"mac_hash"`
	AdHost  string `json:"ad_host"`
	Hits    int64  `json:"hits"`
	Bytes   int64  `json:"bytes"`
}

// adCandidateRow is one learning candidate (host seen issuing ad-path requests
// from a 1st-party site). Mirrors the portal /__toolbox/ad-event "candidates"
// contract → store.record_ad_candidates([(host, site, hits), ...]).
type adCandidateRow struct {
	Host string `json:"host"`
	Site string `json:"site"`
	Hits int64  `json:"hits"`
}

type adEventPayload struct {
	Blocks        []adBlockRow     `json:"blocks"`
	Clients       []adClientRow    `json:"clients"`
	Candidates    []adCandidateRow `json:"candidates,omitempty"`
	CosmeticPages int64            `json:"cosmetic_pages,omitempty"` // #755 — pages cleaned since the last flush
}

// snapshot atomically reads-and-clears both maps, returning the accumulated rows.
// Clearing under the lock means a concurrent recordAdBlock either lands fully in
// this snapshot or fully in the next one — never split. Returns empty slices (not
// nil) only when there was nothing to flush; the caller checks emptiness.
func (a *adStats) snapshot() adEventPayload {
	a.mu.Lock()
	defer a.mu.Unlock()
	var p adEventPayload
	for k, c := range a.blocks {
		p.Blocks = append(p.Blocks, adBlockRow{AdHost: k.adHost, Site: k.site, Hits: c.hits, Bytes: c.bytes})
	}
	for k, c := range a.clients {
		p.Clients = append(p.Clients, adClientRow{MacHash: k.macHash, AdHost: k.adHost, Hits: c.hits, Bytes: c.bytes})
	}
	// Clear by re-allocating: cheaper than ranged delete and drops the cap.
	a.blocks = map[adKey]*adCounter{}
	a.clients = map[cliKey]*adCounter{}
	return p
}

// empty reports whether a payload carries no rows (nothing to POST).
func (p adEventPayload) empty() bool {
	return len(p.Blocks) == 0 && len(p.Clients) == 0 && len(p.Candidates) == 0 && p.CosmeticPages == 0
}

// adEventClient is a short-timeout fire-and-forget client for the ad-event POST.
// Sibling of portalClient (banner.go): the portal is a fixed loopback base, so
// we never follow redirects (SSRF hygiene) and keep the timeout tight so a slow
// portal can't stall the flusher goroutine.
var adEventClient = &http.Client{
	Timeout:       5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// flushOnce snapshots the maps and, if non-empty, POSTs them to the portal's
// /__toolbox/ad-event ingest. Best-effort: any error (marshal, portal down,
// non-2xx) is swallowed with at most a debug log — the metrics are stats, not
// security, and the engine must never block on the portal. Exposed (returns the
// flushed payload) so the test can assert the snapshot/clear + payload shape.
//
// cand may be nil (the CONNECT PoC / tests with no learning feed); when set its
// candidate rows are drained into the SAME payload so the learning feed rides
// the existing ad-event channel (one POST per 10s, not two).
func (a *adStats) flushOnce(portal string, cand *adCandidates) adEventPayload {
	p := a.snapshot()
	if cand != nil {
		p.Candidates = cand.snapshot()
	}
	p.CosmeticPages = a.snapshotCosmetic() // #755 — pages cleaned in this window
	if p.empty() {
		return p
	}
	buf, err := json.Marshal(p)
	if err != nil {
		log.Printf("ad-event marshal failed: %v", err)
		return p
	}
	url := portalTargetURL(portal, "/__toolbox/ad-event")
	resp, err := adEventClient.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		log.Printf("ad-event post failed for %s: %v", url, err)
		return p
	}
	resp.Body.Close()
	return p
}

// runAdStatsFlusher is the background flusher goroutine: every adFlushInterval it
// drains the aggregator to the portal. Start it once from main() (like the
// engine's other startup goroutines). It runs forever (the process lifetime).
func (a *adStats) runAdStatsFlusher(portal string, cand *adCandidates) {
	t := time.NewTicker(adFlushInterval)
	defer t.Stop()
	for range t.C {
		a.flushOnce(portal, cand)
	}
}
