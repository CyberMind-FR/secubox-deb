// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: R-level per-peer core (#rlevel-per-peer)
//
// Pure decision core for the per-peer MITM R-level ladder: the enum, the
// effective-mode resolver (explicit force vs. chosen/floor clamp), and the
// verdict clamp that enforces what each mode is allowed to do to a decision
// already produced upstream by the policy layer (policy.go).
//
// Off      — nft handles bypass upstream; this layer is never consulted.
// Passive  — passthrough only: never decrypts, verdict is always "splice".
// Active   — decrypts+inspects but does not enforce block (block→"mitm");
//
//	a pinned host ("splice") must never be decrypted, so it stays splice.
//
// Reel     — full enforcement: verdict passes through unchanged.
//
// Pure standard library — no external modules, no go.sum.
package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reload"
)

// RLevel is the per-peer MITM depth: how far sbxmitm is allowed to go for
// a given peer, from no interception at all up to full enforcement.
type RLevel int

const (
	Off RLevel = iota
	Passive
	Active
	Reel
)

// parseRLevel parses a case-insensitive, whitespace-trimmed R-level name
// ("off", "passive", "active", "reel") into its RLevel constant. The bool
// result reports whether s was a recognized name.
func parseRLevel(s string) (RLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off":
		return Off, true
	case "passive":
		return Passive, true
	case "active":
		return Active, true
	case "reel":
		return Reel, true
	default:
		return 0, false
	}
}

// effective resolves the R-level actually applied to a peer. An explicit
// forced level (hasForced) always wins outright. Otherwise the chosen level
// is clamped into [floor, Reel]: it can never fall below the configured
// floor, and never exceeds Reel (the ceiling of the ladder).
func effective(chosen, forced, floor RLevel, hasForced bool) RLevel {
	if hasForced {
		return forced
	}
	return clampRLevel(chosen, floor, Reel)
}

// clampRLevel returns v bounded to [lo, hi].
func clampRLevel(v, lo, hi RLevel) RLevel {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// clampVerdict applies the per-mode ceiling to a verdict already computed
// by the policy layer ("allow", "block", "splice", or "mitm"), enforcing
// what each R-level is actually permitted to do:
//
//   - Off:     unchanged — this mode is never reached in practice, since nft
//     performs the bypass upstream of any decision; must not panic.
//   - Passive: always "splice" — passthrough only, never decrypts regardless
//     of the underlying verdict.
//   - Active:  decrypts and inspects but does not enforce blocking, so
//     "block" is downgraded to "mitm" (visibility without enforcement).
//     Every other verdict is left unchanged — in particular "splice" MUST
//     stay "splice": a pinned host must never be decrypted.
//   - Reel:    unchanged — full enforcement, "block" is honored as-is.
func clampVerdict(mode RLevel, verdict string) string {
	switch mode {
	case Passive:
		return "splice"
	case Active:
		if verdict == "block" {
			return "mitm"
		}
		return verdict
	default: // Off, Reel
		return verdict
	}
}

// ── PeerPolicy: per-peer R-level resolver (peer-rlevel.json ⋈ wg-peers.json) ──
//
// Joins the two on-disk stores by WG pubkey to answer, for a given client IP,
// "what R-level applies right now": peer-rlevel.json holds the per-pubkey
// {chosen, forced, floor} tuple (webui self-service + admin override) and
// wg-peers.json (already read by machash.go) maps pubkey → IP. Both files are
// hot-reloaded on mtime change, mirroring the Policy pattern in policy.go.
//
// Fail-safe posture (never fatal, never panics):
//   - either file missing/unreadable/corrupt JSON → treated as empty, which
//     (combined with defaults.mode/floor defaulting to Passive when absent or
//     invalid) makes ModeForIP return Passive for every IP — the safest mode
//     (passthrough only, never decrypts).
//   - an IP with no matching peer entry (unknown client, or a peer present in
//     wg-peers.json but absent from peer-rlevel.json) resolves to the file's
//     declared defaults, clamped the same way effective() clamps a named peer.

// rlevelDefaults mirrors the top-level "defaults" object in peer-rlevel.json.
type rlevelDefaults struct {
	Mode  string `json:"mode"`
	Floor string `json:"floor"`
}

// rlevelPeerRaw mirrors one entry in peer-rlevel.json's "peers" map. Forced is
// a nullable string (JSON `null` or the field's absence both decode to a nil
// pointer) so an explicit force can be distinguished from "not set".
type rlevelPeerRaw struct {
	Chosen string  `json:"chosen"`
	Forced *string `json:"forced"`
	Floor  string  `json:"floor"`
}

// rlevelFile mirrors the whole peer-rlevel.json document.
type rlevelFile struct {
	Defaults rlevelDefaults           `json:"defaults"`
	Peers    map[string]rlevelPeerRaw `json:"peers"`
}

// rlevelLoaded is the value handed from a reload.Target's Load to its Apply
// for the peer-rlevel.json target (defaults + raw per-pubkey entries).
type rlevelLoaded struct {
	defaults rlevelDefaults
	peers    map[string]rlevelPeerRaw
}

// loadRlevelFile reads and parses peer-rlevel.json. ANY error (missing file,
// unreadable, malformed JSON) → fail-safe zero value: defaults{"passive",
// "passive"} and an empty peers map, so every peer resolves to Passive until
// the file is fixed.
func loadRlevelFile(path string) rlevelLoaded {
	failSafe := rlevelLoaded{
		defaults: rlevelDefaults{Mode: "passive", Floor: "passive"},
		peers:    map[string]rlevelPeerRaw{},
	}
	if path == "" {
		return failSafe
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return failSafe
	}
	var f rlevelFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return failSafe
	}
	if f.Peers == nil {
		f.Peers = map[string]rlevelPeerRaw{}
	}
	if strings.TrimSpace(f.Defaults.Mode) == "" {
		f.Defaults.Mode = "passive"
	}
	if strings.TrimSpace(f.Defaults.Floor) == "" {
		f.Defaults.Floor = "passive"
	}
	return rlevelLoaded{defaults: f.Defaults, peers: f.Peers}
}

// loadWgPubkeyIP reads wg-peers.json into a pubkey → ip map, reusing the exact
// shape machash.go already parses ({"peers":{"<pubkey>":{"ip":"..."}}}). Kept
// separate from wgHashOf's own ip-keyed cache (different key direction, and
// PeerPolicy hot-reloads independently on its own throttle). ANY error →
// empty map (best-effort, never fatal).
func loadWgPubkeyIP(path string) map[string]string {
	out := map[string]string{}
	if path == "" {
		return out
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var db wgPeersDB
	if err := json.Unmarshal(raw, &db); err != nil {
		return out
	}
	for pubkey, meta := range db.Peers {
		if meta.IP != "" {
			out[pubkey] = meta.IP
		}
	}
	return out
}

// PeerPolicy resolves the effective R-level for a client IP by joining
// peer-rlevel.json (pubkey → {chosen,forced,floor}) with wg-peers.json
// (pubkey → ip). The joined ip → RLevel map is rebuilt under mu whenever
// either backing file's mtime changes.
type PeerPolicy struct {
	mu sync.RWMutex

	byIP    map[string]RLevel // resolved effective mode, keyed by peer IP
	defMode RLevel            // effective mode for an IP with no matching peer

	// raw cached inputs (guarded by mu), kept so either file's reload can
	// rebuild byIP without re-reading the other file from disk.
	defaults rlevelDefaults
	peers    map[string]rlevelPeerRaw
	wgIP     map[string]string // pubkey -> ip

	watcher *reload.Watcher

	reloadMu       sync.Mutex
	lastReloadID   int64
	reloadThrottle time.Duration
}

// LoadPeerPolicy loads peer-rlevel.json and wg-peers.json and builds the
// joined ip → RLevel map. Never returns an error for a missing/unreadable/
// corrupt file (best-effort, like LoadPolicy) — failure degrades to the
// Passive fail-safe described above, it does not abort startup.
func LoadPeerPolicy(rlevelPath, wgPeersPath string) (*PeerPolicy, error) {
	pp := &PeerPolicy{reloadThrottle: defaultReloadThrottle}

	rl := loadRlevelFile(rlevelPath)
	pp.defaults = rl.defaults
	pp.peers = rl.peers
	pp.wgIP = loadWgPubkeyIP(wgPeersPath)
	pp.rebuildLocked()

	targets := []reload.Target{
		{
			Path:      rlevelPath,
			LastMtime: reload.StatMtime(rlevelPath),
			Load:      func(path string) any { return loadRlevelFile(path) },
			Apply: func(v any) {
				lv := v.(rlevelLoaded)
				pp.mu.Lock()
				pp.defaults = lv.defaults
				pp.peers = lv.peers
				pp.rebuildLocked()
				pp.mu.Unlock()
			},
		},
		{
			Path:      wgPeersPath,
			LastMtime: reload.StatMtime(wgPeersPath),
			Load:      func(path string) any { return loadWgPubkeyIP(path) },
			Apply: func(v any) {
				pp.mu.Lock()
				pp.wgIP = v.(map[string]string)
				pp.rebuildLocked()
				pp.mu.Unlock()
			},
		},
	}
	pp.watcher = reload.NewWatcher(0, targets...)
	return pp, nil
}

// rebuildLocked recomputes byIP and defMode from the current pp.defaults/
// pp.peers/pp.wgIP. Caller must hold pp.mu (write lock), or call it during
// construction before pp is shared across goroutines.
func (pp *PeerPolicy) rebuildLocked() {
	defMode, ok := parseRLevel(pp.defaults.Mode)
	if !ok {
		defMode = Passive
	}
	defFloor, ok := parseRLevel(pp.defaults.Floor)
	if !ok {
		defFloor = Passive
	}
	pp.defMode = effective(defMode, 0, defFloor, false)

	byIP := make(map[string]RLevel, len(pp.wgIP))
	for pubkey, ip := range pp.wgIP {
		chosen, floor := defMode, defFloor
		var forced RLevel
		hasForced := false

		if entry, ok := pp.peers[pubkey]; ok {
			if c, okc := parseRLevel(entry.Chosen); okc {
				chosen = c
			}
			if f, okf := parseRLevel(entry.Floor); okf {
				floor = f
			}
			if entry.Forced != nil {
				if fr, okfr := parseRLevel(*entry.Forced); okfr {
					forced = fr
					hasForced = true
				}
			}
		}
		byIP[ip] = effective(chosen, forced, floor, hasForced)
	}
	pp.byIP = byIP
}

// maybeReload re-stats the two backing files (throttled) and rebuilds byIP if
// either changed. Mirrors Policy.maybeReload exactly.
func (pp *PeerPolicy) maybeReload() {
	now := time.Now()
	pp.reloadMu.Lock()
	if pp.reloadThrottle > 0 && pp.lastReloadID != 0 &&
		now.Sub(time.Unix(0, pp.lastReloadID)) < pp.reloadThrottle {
		pp.reloadMu.Unlock()
		return
	}
	pp.lastReloadID = now.UnixNano()
	pp.reloadMu.Unlock()

	pp.watcher.Maybe()
}

// ModeForIP resolves the effective R-level for a client IP: an IP matching a
// WG peer with a rlevel entry gets that peer's effective() result (forced
// wins outright, else chosen clamped to floor); an unknown IP — no matching
// peer, or the rlevel/wg-peers store unreadable — gets the file's declared
// defaults (or Passive if the store itself is unusable), which is the safe
// fail-closed posture: never decrypt a client sbxmitm cannot positively
// identify a policy for.
func (pp *PeerPolicy) ModeForIP(ip string) RLevel {
	pp.maybeReload()
	pp.mu.RLock()
	defer pp.mu.RUnlock()
	if mode, ok := pp.byIP[ip]; ok {
		return mode
	}
	return pp.defMode
}
