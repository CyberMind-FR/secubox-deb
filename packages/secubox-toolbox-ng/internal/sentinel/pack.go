// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Pack loading: the shipped base IOC/YARA content pack, live-overlay merge,
// and hot-reload — mirroring cmd/sbxmitm/policy.go's LoadPolicy/maybeReload
// mtime-based reload pattern (see internal/reload for the extracted generic
// version of that pattern for fixed file sets).
//
// Unlike policy.go's fixed set of backing files, a pack directory (base or
// overlay) holds a DYNAMIC set of *.json files — feeds/operators add and
// remove packs over time — so Loader globs the directory on each reload
// check rather than watching a fixed Target list.
package sentinel

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Pack is a JSON-encoded bundle of IOCs and (optionally) YARA rule bodies —
// either the shipped base content pack or a live operator/feed overlay.
type Pack struct {
	Version   string   `json:"version"`
	IOCs      []IOC    `json:"iocs"`
	YaraRules []string `json:"yara_rules"`
}

// LoadBasePack reads and unmarshals a single JSON pack file. It returns an
// error for a missing/unreadable file or invalid JSON — the caller decides
// whether that is fatal (a shipped base pack) or skip-and-log (a live
// overlay pack), matching the fail-safe requirement that a corrupt overlay
// never wipes out an otherwise-good merged set.
func LoadBasePack(path string) (*Pack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sentinel: read pack %s: %w", path, err)
	}
	var p Pack
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("sentinel: parse pack %s: %w", path, err)
	}
	return &p, nil
}

// MergePacks builds an IOCSet from base, then applies each overlay's IOCs on
// top in order. An overlay entry sharing the same (Type,Value) as an
// already-added entry overrides it (last-write-wins) — IOCSet.Add's
// per-type maps make this automatic: re-adding the same key just replaces
// the map entry. base and any overlay may be nil (treated as empty).
func MergePacks(base *Pack, overlays ...*Pack) *IOCSet {
	set := NewIOCSet()
	addPackTo(set, base)
	for _, ov := range overlays {
		addPackTo(set, ov)
	}
	return set
}

// addPackTo adds every IOC in p to set, logging (never failing) a per-entry
// error such as an unparsable url_regex — one bad entry must not drop the
// rest of the pack.
func addPackTo(set *IOCSet, p *Pack) {
	if p == nil {
		return
	}
	for _, ioc := range p.IOCs {
		if err := set.Add(ioc); err != nil {
			log.Printf("sentinel: skip invalid IOC %+v: %v", ioc, err)
		}
	}
}

// ── Loader: directory-based live-overlay pack loading + hot-reload ──────────

// loaderState is the atomically-swapped snapshot a Loader serves: the merged
// IOCSet plus the concatenated YARA rule bodies from every loaded pack, kept
// together so a reader never observes a set from one reload paired with
// YARA rules from another.
type loaderState struct {
	set  *IOCSet
	yara []string

	// baseCount is the number of raw IOC entries parsed from base pack files
	// (fs.base) that produced this state — NOT the merged/deduped count, just
	// "did the base pack directory have any content at all". MaybeReload uses
	// it to detect a base-pack disappearance (vanished dir, mount blip,
	// dpkg-upgrade window) and refuse to swap in a degraded/empty base rather
	// than silently losing detection coverage. See MaybeReload.
	baseCount int
}

// defaultReloadThrottle bounds how often MaybeReload actually stats the pack
// directories. Task 3's inline gate calls MaybeReload() on every flow, so
// without a throttle every packet pays a directory-glob + per-file stat;
// mirrors cmd/sbxmitm/policy.go's Policy.reloadThrottle pattern.
const defaultReloadThrottle = 5 * time.Second

// Loader watches a base pack directory and an (optional) live-overlay pack
// directory, merging every *.json pack file found in either into a single
// IOCSet. Call NewLoader once at startup, then Set()/YaraRules() on the hot
// path and MaybeReload() periodically (mirrors Policy.maybeReload).
//
// Zero value is not usable; use NewLoader.
type Loader struct {
	baseDir    string
	overlayDir string

	// mu serialises concurrent MaybeReload passes (mirrors reload.Watcher.mu)
	// and guards mtimes, reloadThrottle and lastCheck. It is NOT held by
	// Set()/YaraRules() — those read the atomic state pointer only, so a
	// reload swap never blocks or torn-reads a concurrent hot-path lookup.
	mu     sync.Mutex
	mtimes map[string]time.Time

	// reloadThrottle/lastCheck gate MaybeReload's disk I/O: a call within
	// reloadThrottle of the last check returns immediately with no glob/stat
	// at all (not even a cheap one) — required because MaybeReload is called
	// per-flow on the inline gate hot path. lastCheck zero means "never
	// checked", so the very first MaybeReload call after NewLoader always
	// runs regardless of reloadThrottle. Tests in this package may lower
	// reloadThrottle directly (unexported field) to avoid a real sleep.
	reloadThrottle time.Duration
	lastCheck      time.Time

	state atomic.Pointer[loaderState]
}

// fileSet is the result of globbing base/overlay pack directories for one
// reload pass: which files exist, split by role (base entries are fatal to
// fail on parse error; overlay entries are skip-and-log), plus every found
// file's current mtime for change detection.
type fileSet struct {
	base    []string
	overlay []string
	mtimes  map[string]time.Time
}

// NewLoader constructs a Loader, performing the initial load synchronously.
// A missing/empty baseDir or overlayDir is best-effort (no error, empty
// contribution) — mirrors LoadPolicy's philosophy of never failing on a
// missing backing file. A base pack file that EXISTS but fails to parse is
// fatal (the shipped base pack is trusted content; a bad base indicates a
// real packaging bug, not a transient live-feed hiccup) and is returned as
// an error here since there is no prior good state yet to fall back on.
func NewLoader(baseDir, overlayDir string) (*Loader, error) {
	l := &Loader{baseDir: baseDir, overlayDir: overlayDir, reloadThrottle: defaultReloadThrottle}

	fs, err := l.scan()
	if err != nil {
		return nil, fmt.Errorf("sentinel: scan pack dirs: %w", err)
	}
	state, err := buildState(fs)
	if err != nil {
		return nil, err
	}
	l.state.Store(state)
	l.mtimes = fs.mtimes
	return l, nil
}

// Set returns the current merged IOCSet, safe for concurrent use while
// MaybeReload swaps it out from another goroutine.
func (l *Loader) Set() *IOCSet {
	if s := l.state.Load(); s != nil {
		return s.set
	}
	return NewIOCSet()
}

// YaraRules returns the concatenated YARA rule bodies from the base pack and
// every currently-loaded overlay pack.
func (l *Loader) YaraRules() []string {
	if s := l.state.Load(); s != nil {
		return s.yara
	}
	return nil
}

// MaybeReload re-globs the base and overlay directories and, ONLY if any
// pack file was added, removed, or its mtime changed, re-parses every pack
// and atomically swaps in the newly merged state. When nothing changed this
// is a cheap no-op: a directory listing plus a stat per file, no JSON
// parsing. Fail-safe: a scan error or a corrupt BASE pack is logged and the
// prior good state is kept.
//
// Throttled: MaybeReload is called per-flow by Task 3's inline gate, so a
// call within l.reloadThrottle of the last check returns immediately without
// touching disk at all — the caller pays no cost on the hot path beyond a
// time comparison under l.mu.
//
// Fail-closed on base-pack disappearance: if the rebuilt state's base pack
// contributed ZERO IOCs while the prior state's base pack had contributed at
// least one, the vanished/degraded base is assumed to be a transient
// problem (deleted dir, mount blip, mid-dpkg-upgrade window) rather than a
// deliberate empty base — the swap is refused, the prior state is kept, and
// a warning is logged. A genuine first-ever empty base (no prior state, or a
// prior state that was already empty) is not blocked. This is a
// security-detection engine: silently emptying the detection set is never
// acceptable, so this case fails CLOSED (keeps the last-known-good set)
// rather than open.
func (l *Loader) MaybeReload() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.reloadThrottle > 0 && !l.lastCheck.IsZero() && time.Since(l.lastCheck) < l.reloadThrottle {
		return
	}
	l.lastCheck = time.Now()

	fs, err := l.scan()
	if err != nil {
		log.Printf("sentinel: pack reload scan failed, keeping prior set: %v", err)
		return
	}
	if mtimesEqual(fs.mtimes, l.mtimes) {
		return
	}

	state, err := buildState(fs)
	if err != nil {
		log.Printf("sentinel: pack reload failed, keeping prior set: %v", err)
		return
	}

	if prior := l.state.Load(); prior != nil && prior.baseCount > 0 && state.baseCount == 0 {
		log.Printf("sentinel: pack reload would drop the base IOC set from %d entries to 0 (baseDir=%q missing or empty — vanished directory, mount blip, or mid-upgrade window?); refusing to swap, keeping prior state", prior.baseCount, l.baseDir)
		return
	}

	l.state.Store(state)
	l.mtimes = fs.mtimes
}

// scan globs baseDir and overlayDir for *.json pack files and stats each.
// An error globbing baseDir is returned (a malformed path is a real
// misconfiguration); an error globbing overlayDir is logged and treated as
// "no overlays this pass" (fail-safe — a broken overlay path must not take
// down the base pack).
func (l *Loader) scan() (fileSet, error) {
	var fs fileSet
	fs.mtimes = make(map[string]time.Time)

	base, err := listPackFiles(l.baseDir)
	if err != nil {
		return fileSet{}, fmt.Errorf("sentinel: list base pack dir %s: %w", l.baseDir, err)
	}
	fs.base = base

	overlay, err := listPackFiles(l.overlayDir)
	if err != nil {
		log.Printf("sentinel: list overlay pack dir %s: %v", l.overlayDir, err)
		overlay = nil
	}
	fs.overlay = overlay

	for _, p := range append(append([]string{}, base...), overlay...) {
		if fi, statErr := os.Stat(p); statErr == nil {
			fs.mtimes[p] = fi.ModTime()
		}
	}
	return fs, nil
}

// buildState loads every pack file in fs (base first, then overlays, both
// in sorted-path order for deterministic override semantics) and merges
// them via MergePacks. A base pack that fails to parse aborts the whole
// build (returned as an error, caller decides fatal-at-startup vs
// keep-prior-state-on-reload). An overlay pack that fails to parse is
// skipped (logged) and does not affect the rest of the merge.
func buildState(fs fileSet) (*loaderState, error) {
	var packs []*Pack
	baseCount := 0

	for _, p := range fs.base {
		pk, err := LoadBasePack(p)
		if err != nil {
			return nil, fmt.Errorf("sentinel: base pack %s: %w", p, err)
		}
		baseCount += len(pk.IOCs)
		packs = append(packs, pk)
	}
	for _, p := range fs.overlay {
		pk, err := LoadBasePack(p)
		if err != nil {
			log.Printf("sentinel: skip unparsable overlay pack %s: %v", p, err)
			continue
		}
		packs = append(packs, pk)
	}

	// Dedup YARA rule bodies by exact string so the same rule shipped in both
	// the base pack and an overlay (or repeated across overlay fragments)
	// isn't emitted twice to the YARA compiler/scanner.
	var yara []string
	seenYara := make(map[string]bool)
	for _, pk := range packs {
		for _, r := range pk.YaraRules {
			if seenYara[r] {
				continue
			}
			seenYara[r] = true
			yara = append(yara, r)
		}
	}

	// MergePacks(nil, packs...) applies every pack in order with the same
	// add/override-by-(Type,Value) semantics MergePacks documents for
	// base+overlays — there is no distinct "base" argument needed here since
	// fs.base's entries were already placed first in packs.
	return &loaderState{set: MergePacks(nil, packs...), yara: yara, baseCount: baseCount}, nil
}

// listPackFiles resolves root to a sorted list of *.json pack file paths.
// root may be:
//   - ""            → no files (overlay directory not configured).
//   - a directory   → every *.json file directly inside it, sorted.
//   - a single file → that file alone (convenience for callers that already
//     have one specific pack file path rather than a directory).
//   - missing path  → no files (best-effort: not yet created is not an
//     error, matching LoadPolicy's treatment of missing backing files).
func listPackFiles(root string) ([]string, error) {
	if root == "" {
		return nil, nil
	}
	fi, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !fi.IsDir() {
		return []string{root}, nil
	}
	matches, err := filepath.Glob(filepath.Join(root, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}

// mtimesEqual reports whether two file→mtime snapshots are identical (same
// set of files, same mtimes) — used to make MaybeReload a cheap no-op when
// nothing on disk changed.
func mtimesEqual(a, b map[string]time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		bv, ok := b[k]
		if !ok || !bv.Equal(v) {
			return false
		}
	}
	return true
}
