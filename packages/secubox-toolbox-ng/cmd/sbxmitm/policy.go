// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: policy layer (#662 Phase 3)
//
// Ports the toolbox BLOCK (ad_ghost) and SPLICE (tls_splice) decision logic
// into the Go core, reading the SAME on-disk config files the Python addons
// use. Python is the source of truth; this mirrors it byte-for-byte on the
// decision surface, proven by the cross-engine parity harness
// (testdata/parity-fixtures.json + policy_test.go ↔ tests/test_engine_parity.py).
//
// Pure standard library — no external modules, no go.sum.
package main

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reload"
)

// ── ad_ghost: static ad/tracker host pattern (port of _AD_HOST) ──────────────
//
// Python (mitmproxy_addons/ad_ghost.py):
//
//	_AD_HOST = re.compile(
//	    r"(?:^|\.)(?:doubleclick|googlesyndication|googleadservices|"
//	    r"googletagservices|adservice\.google|amazon-adsystem|adnxs|adsrvr|"
//	    r"adform|criteo|rubiconproject|taboola|outbrain|smartadserver|moatads|"
//	    r"scorecardresearch|2mdn|adroll|pubmatic|openx|casalemedia|"
//	    r"yieldlove|sharethrough|teads|3lift|adsystem|adserver)",
//	    re.IGNORECASE)
//
// Every construct here — non-capturing groups, `^`, `\.`, alternation, the
// case-insensitive flag — is RE2-safe, so it translates 1:1 to Go regexp via
// the `(?i)` inline flag. No fallback substring split was needed.
const adHostPattern = `(?i)(?:^|\.)(?:doubleclick|googlesyndication|googleadservices|` +
	`googletagservices|adservice\.google|amazon-adsystem|adnxs|adsrvr|` +
	`adform|criteo|rubiconproject|taboola|outbrain|smartadserver|moatads|` +
	`scorecardresearch|2mdn|adroll|pubmatic|openx|casalemedia|` +
	`yieldlove|sharethrough|teads|3lift|adsystem|adserver)`

// _2L_TLD: two-level public suffixes (port of ad_ghost._2L_TLD).
var twoLevelTLD = map[string]bool{
	"co.uk": true, "com.au": true, "co.jp": true, "co.nz": true,
	"com.br": true, "co.za": true, "gouv.fr": true,
}

// ── PolicyOpts: configurable file paths (env-overridable, like Python) ───────

// PolicyOpts holds the on-disk paths the loaders read. Empty fields fall back
// to the real production defaults (or the env override) in LoadPolicy.
type PolicyOpts struct {
	AllowPath        string   // ad-allowlist.txt        (_ALLOW_PATH)
	LearnedPath      string   // learned-trackers.txt    (_LEARNED_PATH)
	SpliceSeedPath   string   // conf/tls-splice-seed.conf (SEED_PATH)
	SpliceLearnPath  string   // splice-learned.txt      (LEARNED_PATH)
	PureTrackersPath string   // pure-trackers.txt       (PURE_PATH)
	// mitm-bypass (ignore_hosts) REGEX lists (#803): cert-pinned apps managed via
	// the Filtres MITM webui + autolearn. A match here also splices (passthrough)
	// so the R3 engine honours the SAME exclusion list the webui shows — else
	// Signal/WhatsApp/banks etc. get MITM'd and break through the tunnel.
	BypassSeedPath    string  // conf/mitm-bypass-seed.conf     (package)
	BypassStaticPath  string  // mitm-bypass.conf               (operator/webui)
	BypassDynamicPath string  // mitm-bypass-dynamic.conf       (autolearn)
	DisabledPath      string  // mitm-filter-disabled.txt       (webui uncheck, #809)
	FortknoxSites    []string // filters.json fortknox_sites
	SelfDomains      []string // _SELF_REGS (default {secubox.in}, env SECUBOX_SELF_DOMAINS)
}

// defaultPolicyOpts returns the production defaults, honoring the same env vars
// the Python addons read.
func defaultPolicyOpts() PolicyOpts {
	o := PolicyOpts{
		AllowPath:        "/var/lib/secubox/toolbox/ad-allowlist.txt",
		LearnedPath:      "/var/lib/secubox/toolbox/learned-trackers.txt",
		SpliceSeedPath:   envOr("SECUBOX_SPLICE_SEED", "/usr/lib/secubox/toolbox/conf/tls-splice-seed.conf"),
		SpliceLearnPath:  envOr("SECUBOX_SPLICE_LEARNED", "/var/lib/secubox/toolbox/splice-learned.txt"),
		PureTrackersPath: envOr("SECUBOX_PURE_TRACKERS", "/var/lib/secubox/toolbox/pure-trackers.txt"),
		BypassSeedPath:    envOr("SECUBOX_BYPASS_SEED", "/usr/lib/secubox/toolbox/conf/mitm-bypass-seed.conf"),
		BypassStaticPath:  envOr("SECUBOX_BYPASS_STATIC", "/var/lib/secubox/toolbox/mitm-bypass.conf"),
		BypassDynamicPath: envOr("SECUBOX_BYPASS_DYNAMIC", "/var/lib/secubox/toolbox/mitm-bypass-dynamic.conf"),
		DisabledPath:      envOr("SECUBOX_FILTER_DISABLED", "/var/lib/secubox/toolbox/mitm-filter-disabled.txt"),
	}
	// _SELF_REGS: env SECUBOX_SELF_DOMAINS (comma-split), default {secubox.in}.
	self := os.Getenv("SECUBOX_SELF_DOMAINS")
	if strings.TrimSpace(self) == "" {
		self = "secubox.in"
	}
	for _, d := range strings.Split(self, ",") {
		if d = strings.TrimSpace(strings.ToLower(d)); d != "" {
			o.SelfDomains = append(o.SelfDomains, d)
		}
	}
	return o
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ── Policy: the loaded decision state ────────────────────────────────────────

// Policy carries the loaded sets/regex and decides per-host actions. It also
// keeps the legacy PoC fields (Inject) so the existing wiring/tests still work.
type Policy struct {
	// mu guards the live-reloadable map fields below. Decide/allowed/blockedByAd/
	// shouldSplice take RLock; the reload Apply callbacks take Lock when a backing
	// file actually changed.
	mu sync.RWMutex

	adHost      *regexp.Regexp
	learned     map[string]bool // learned-trackers (host or registrable, lowercased)
	allow       map[string]bool // ad-allowlist (host or registrable, lowercased)
	spliceSeed  map[string]bool // splice seed patterns
	spliceLearn map[string]bool // splice learned patterns
	// mitm-bypass (ignore_hosts) compiled regexes (#803) — a match splices.
	bypassSeedRe   []bypassEntry
	bypassStaticRe []bypassEntry
	bypassDynRe    []bypassEntry
	// #809 — operator-disabled filter patterns (Filtres MITM webui): an entry
	// whose SOURCE pattern is in this set is suppressed in BOTH the bypass and
	// splice paths, so unchecking it in the webui has real engine effect.
	disabled    map[string]bool
	never       map[string]bool // pure-trackers ∪ fortknox (splice never-set)
	selfRegs    map[string]bool // own-infra registrable domains
	selfDomains []string        // own-infra (for the host==d || host endswith .d guard)

	// ── live-reload state (#662 auto-learn loop) ─────────────────────────────
	//
	// The lists are loaded once at startup, then re-read on-disk when their
	// mtime changes so autolearn promotions / manual edits take effect WITHOUT a
	// worker restart (mirrors ad_ghost._maybe_reload). The hot path (Decide)
	// calls maybeReload(): a throttle check, then — at most every reloadThrottle —
	// the generic reload.Watcher stats each backing file and calls Apply for each
	// changed file. Each Apply swaps the affected map under p.mu.
	//
	// Atomicity note: in the original maybeReload(), ALL changed targets were
	// applied under a SINGLE p.mu.Lock(). With reload.Watcher, the Watcher's
	// internal mu serialises concurrent Maybe() calls, and each Apply callback
	// takes p.mu.Lock() independently. The maps are independent (no cross-map
	// invariant between e.g. learned and allow), so per-map locking is safe.
	// The Watcher's mu ensures no two Maybe() batches interleave: a second
	// goroutine calling Maybe() while a batch is applying will block until
	// the first batch completes. Parity tests confirm Decide semantics are
	// identical.
	watcher        *reload.Watcher
	fortknoxSites  []string       // kept for rebuilding the never-set on pure-trackers reload
	reloadMu       sync.Mutex     // guards lastReloadID (throttle bookkeeping)
	lastReloadID   int64          // unix-nano of the last throttle pass (0 = never)
	reloadThrottle time.Duration  // min interval between stat passes (0 in tests = eager)

	// Legacy PoC fields kept so non-policy behaviour is unchanged.
	Inject []byte // banner / ad-CSS marker injected before </head> or </body>
}

// defaultReloadThrottle is the production stat cadence: a backing-file change
// (autolearn runs hourly; a promotion is rare) is observed within ~15s, and the
// hot path stats at most ~4×/minute regardless of request rate.
const defaultReloadThrottle = 15 * time.Second

// LoadPolicy loads all backing files from opts (defaults applied for empty
// fields) and compiles the ad-host regex. It never returns an error for missing
// files (best-effort, like the Python addons), only for a regex-compile bug.
func LoadPolicy(opts PolicyOpts) (*Policy, error) {
	def := defaultPolicyOpts()
	if opts.AllowPath == "" {
		opts.AllowPath = def.AllowPath
	}
	if opts.LearnedPath == "" {
		opts.LearnedPath = def.LearnedPath
	}
	if opts.SpliceSeedPath == "" {
		opts.SpliceSeedPath = def.SpliceSeedPath
	}
	if opts.SpliceLearnPath == "" {
		opts.SpliceLearnPath = def.SpliceLearnPath
	}
	if opts.PureTrackersPath == "" {
		opts.PureTrackersPath = def.PureTrackersPath
	}
	if len(opts.SelfDomains) == 0 {
		opts.SelfDomains = def.SelfDomains
	}
	if opts.BypassSeedPath == "" {
		opts.BypassSeedPath = def.BypassSeedPath
	}
	if opts.BypassStaticPath == "" {
		opts.BypassStaticPath = def.BypassStaticPath
	}
	if opts.BypassDynamicPath == "" {
		opts.BypassDynamicPath = def.BypassDynamicPath
	}
	if opts.DisabledPath == "" {
		opts.DisabledPath = def.DisabledPath
	}

	re, err := regexp.Compile(adHostPattern)
	if err != nil {
		return nil, err
	}

	// never-set = pure-trackers ∪ fortknox_sites (mirrors TlsSplice._refresh_sets).
	never := reload.LoadLines(opts.PureTrackersPath, true)
	for _, s := range opts.FortknoxSites {
		if s = strings.Trim(strings.ToLower(strings.TrimSpace(s)), "."); s != "" {
			never[s] = true
		}
	}

	selfRegs := map[string]bool{}
	selfDomains := make([]string, 0, len(opts.SelfDomains))
	for _, d := range opts.SelfDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		selfRegs[d] = true
		selfDomains = append(selfDomains, d)
	}

	p := &Policy{
		adHost:         re,
		learned:        reload.LoadLines(opts.LearnedPath, false), // mirrors _learned_set (no comment-strip)
		allow:          reload.LoadLines(opts.AllowPath, true),
		spliceSeed:     reload.LoadLines(opts.SpliceSeedPath, true),
		spliceLearn:    reload.LoadLines(opts.SpliceLearnPath, true),
		bypassSeedRe:   loadBypassRegex(opts.BypassSeedPath),
		bypassStaticRe: loadBypassRegex(opts.BypassStaticPath),
		bypassDynRe:    loadBypassRegex(opts.BypassDynamicPath),
		disabled:       reload.LoadLines(opts.DisabledPath, true),
		never:          never,
		selfRegs:       selfRegs,
		selfDomains:    selfDomains,
		fortknoxSites:  append([]string(nil), opts.FortknoxSites...),
		reloadThrottle: defaultReloadThrottle,
	}

	// ── register the live-reloadable backing files (#662 auto-learn loop) ─────
	//
	// Each reload.Target re-reads its file when its mtime changes and calls Apply
	// to swap the map under p.mu. The Watcher (throttle=0 here; the Policy-level
	// throttle check in maybeReload() controls the rate) handles mtime tracking.
	//
	// learned-trackers uses stripComments=false (loadLinesRaw: machine-generated,
	// one-host-per-line, a '#' is kept verbatim). All other files use
	// stripComments=true (operator-editable, comment lines are ignored).
	targets := []reload.Target{
		{
			Path:      opts.LearnedPath,
			LastMtime: reload.StatMtime(opts.LearnedPath),
			Load:      func(path string) any { return reload.LoadLines(path, false) },
			Apply: func(v any) {
				p.mu.Lock()
				p.learned = v.(map[string]bool)
				p.mu.Unlock()
			},
		},
		{
			Path:      opts.AllowPath,
			LastMtime: reload.StatMtime(opts.AllowPath),
			Load:      func(path string) any { return reload.LoadLines(path, true) },
			Apply: func(v any) {
				p.mu.Lock()
				p.allow = v.(map[string]bool)
				p.mu.Unlock()
			},
		},
		{
			Path:      opts.SpliceSeedPath,
			LastMtime: reload.StatMtime(opts.SpliceSeedPath),
			Load:      func(path string) any { return reload.LoadLines(path, true) },
			Apply: func(v any) {
				p.mu.Lock()
				p.spliceSeed = v.(map[string]bool)
				p.mu.Unlock()
			},
		},
		{
			Path:      opts.SpliceLearnPath,
			LastMtime: reload.StatMtime(opts.SpliceLearnPath),
			Load:      func(path string) any { return reload.LoadLines(path, true) },
			Apply: func(v any) {
				p.mu.Lock()
				p.spliceLearn = v.(map[string]bool)
				p.mu.Unlock()
			},
		},
		{
			Path:      opts.PureTrackersPath,
			LastMtime: reload.StatMtime(opts.PureTrackersPath),
			Load:      func(path string) any { return reload.LoadLines(path, true) },
			Apply: func(v any) {
				// pure-trackers ∪ fortknox → never-set (mirrors LoadPolicy above).
				s := v.(map[string]bool)
				for _, fk := range p.fortknoxSites {
					if fk = strings.Trim(strings.ToLower(strings.TrimSpace(fk)), "."); fk != "" {
						s[fk] = true
					}
				}
				p.mu.Lock()
				p.never = s
				p.mu.Unlock()
			},
		},
		{
			Path:      opts.BypassSeedPath,
			LastMtime: reload.StatMtime(opts.BypassSeedPath),
			Load:      func(path string) any { return loadBypassRegex(path) },
			Apply: func(v any) {
				p.mu.Lock()
				p.bypassSeedRe = v.([]bypassEntry)
				p.mu.Unlock()
			},
		},
		{
			Path:      opts.BypassStaticPath,
			LastMtime: reload.StatMtime(opts.BypassStaticPath),
			Load:      func(path string) any { return loadBypassRegex(path) },
			Apply: func(v any) {
				p.mu.Lock()
				p.bypassStaticRe = v.([]bypassEntry)
				p.mu.Unlock()
			},
		},
		{
			Path:      opts.BypassDynamicPath,
			LastMtime: reload.StatMtime(opts.BypassDynamicPath),
			Load:      func(path string) any { return loadBypassRegex(path) },
			Apply: func(v any) {
				p.mu.Lock()
				p.bypassDynRe = v.([]bypassEntry)
				p.mu.Unlock()
			},
		},
		{
			Path:      opts.DisabledPath,
			LastMtime: reload.StatMtime(opts.DisabledPath),
			Load:      func(path string) any { return reload.LoadLines(path, true) },
			Apply: func(v any) {
				p.mu.Lock()
				p.disabled = v.(map[string]bool)
				p.mu.Unlock()
			},
		},
	}
	// The Watcher is created with throttle=0: the Policy-level reloadThrottle
	// check in maybeReload() gates how often we call w.Maybe().
	p.watcher = reload.NewWatcher(0, targets...)
	return p, nil
}

// maybeReload re-reads any backing list whose on-disk mtime changed since the
// last pass, swapping the affected map(s) under p.mu. Throttled to at most one
// stat pass per p.reloadThrottle (cheap: a time compare + a few stats), so the
// Decide hot path pays almost nothing. Concurrency-safe: the throttle
// bookkeeping is under reloadMu, the watcher handles mtime tracking and calls
// Apply callbacks (each taking p.mu.Lock) — Decide's readers hold mu.RLock, so
// a swap is atomic w.r.t. any in-flight decision.
func (p *Policy) maybeReload() {
	now := time.Now()
	p.reloadMu.Lock()
	if p.reloadThrottle > 0 && p.lastReloadID != 0 &&
		now.Sub(time.Unix(0, p.lastReloadID)) < p.reloadThrottle {
		p.reloadMu.Unlock()
		return
	}
	p.lastReloadID = now.UnixNano()
	p.reloadMu.Unlock()

	p.watcher.Maybe()
}

// ── registrable: port of ad_ghost._registrable ───────────────────────────────
//
//	host = host.split(":")[0].lower().strip(".")
//	if not host or host.replace(".","").isdigit() or ":" in host: return None
//	p = host.split(".")
//	if len(p) <= 2: return host
//	last2 = ".".join(p[-2:])
//	return ".".join(p[-3:]) if (last2 in _2L_TLD and len(p) >= 3) else last2
func registrable(host string) string {
	host = strings.ToLower(host)
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, ".")
	if host == "" {
		return ""
	}
	// host.replace(".","").isdigit() → all-digit IPv4-ish → no registrable.
	if isAllDigits(strings.ReplaceAll(host, ".", "")) {
		return ""
	}
	// The Python checks ":" in host AFTER stripping the port; a residual colon
	// (e.g. an IPv6 literal) yields None. We already split on the first colon,
	// so re-check the remainder for any colon to mirror exactly.
	if strings.IndexByte(host, ':') >= 0 {
		return ""
	}
	p := strings.Split(host, ".")
	if len(p) <= 2 {
		return host
	}
	last2 := strings.Join(p[len(p)-2:], ".")
	if twoLevelTLD[last2] && len(p) >= 3 {
		return strings.Join(p[len(p)-3:], ".")
	}
	return last2
}

func isAllDigits(s string) bool {
	if s == "" {
		return false // Python "".isdigit() is False
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ── splice helpers: port of splice.host_matches / should_splice ──────────────

// hostMatches: True if host == pattern OR host is a dotted-suffix subdomain.
func hostMatches(host string, patterns map[string]bool) bool {
	h := strings.Trim(strings.ToLower(host), ".")
	if h == "" || len(patterns) == 0 {
		return false
	}
	if patterns[h] {
		return true
	}
	for p := range patterns {
		if strings.HasSuffix(h, "."+p) {
			return true
		}
	}
	return false
}

// allowed: port of ad_ghost._allowed. Own-infra ALWAYS wins (reflash-safe),
// then the operator allowlist (host or registrable).
//
// LOCK CONTRACT: reads the reloadable allow map — the caller MUST hold at least
// p.mu.RLock (Decide / shouldPoison do). Lock-free internally so Decide can call
// it alongside shouldSplice/blockedByAd under a single RLock (sync.RWMutex is
// not reentrant).
func (p *Policy) allowed(host string) bool {
	h := strings.ToLower(host)
	reg := registrable(h)
	if reg == "" {
		reg = h
	}
	// own infra: registrable in selfRegs, OR host == d || host endswith "."+d.
	if p.selfRegs[reg] {
		return true
	}
	for _, d := range p.selfDomains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return p.allow[h] || p.allow[reg]
}

// allowedSafe is the lock-taking entry point to allowed() for callers OUTSIDE a
// Decide RLock (e.g. the ad-candidate feed). It also picks up a live-reloaded
// allowlist via maybeReload, so a freshly-allowlisted host stops being learned.
func (p *Policy) allowedSafe(host string) bool {
	p.maybeReload()
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.allowed(host)
}

// shouldSplice: port of splice.should_splice (never wins; then seed ∪ learned).
// LOCK CONTRACT: reads the reloadable never/spliceSeed/spliceLearn maps — the
// caller MUST hold at least p.mu.RLock (Decide does).
func (p *Policy) shouldSplice(sni string) bool {
	s := strings.Trim(strings.ToLower(sni), ".")
	if s == "" {
		return false
	}
	if hostMatches(s, p.never) {
		return false
	}
	// #809 — a splice suffix the operator disabled in the webui must NOT match.
	return hostMatchesEnabled(s, p.spliceSeed, p.disabled) ||
		hostMatchesEnabled(s, p.spliceLearn, p.disabled)
}

// bypassEntry keeps the SOURCE pattern next to its compiled regex so a #809
// operator-disabled entry can be skipped by pattern.
type bypassEntry struct {
	pat string
	re  *regexp.Regexp
}

// matchesBypass reports whether host matches any compiled mitm-bypass regex
// (seed ∪ static ∪ dynamic), skipping operator-disabled patterns (#809).
// Callers hold p.mu.RLock (Decide does).
func (p *Policy) matchesBypass(host string) bool {
	host = strings.Trim(strings.ToLower(host), ".")
	if host == "" {
		return false
	}
	for _, group := range [][]bypassEntry{p.bypassSeedRe, p.bypassStaticRe, p.bypassDynRe} {
		for _, e := range group {
			if p.disabled[e.pat] {
				continue
			}
			if e.re.MatchString(host) {
				return true
			}
		}
	}
	return false
}

// hostMatchesEnabled is hostMatches but skips suffix patterns in `disabled`
// (#809): the exact host or a ".pattern" suffix matches only if the matching
// pattern is not operator-disabled.
func hostMatchesEnabled(host string, patterns, disabled map[string]bool) bool {
	h := strings.Trim(strings.ToLower(host), ".")
	if h == "" || len(patterns) == 0 {
		return false
	}
	if patterns[h] && !disabled[h] {
		return true
	}
	for p := range patterns {
		if !disabled[p] && strings.HasSuffix(h, "."+p) {
			return true
		}
	}
	return false
}

// loadBypassRegex reads a mitm-bypass list (regex, one per line, # comments) and
// compiles each entry FULLY ANCHORED + case-insensitive against the bare host,
// so `(.+\.)?signal\.org` matches signal.org and chat.signal.org but NOT
// evilsignal.org. A malformed entry is skipped, never fatal (best-effort like
// the Python addons). Returns nil on a missing/unreadable file.
func loadBypassRegex(path string) []bypassEntry {
	var out []bypassEntry
	for pat := range reload.LoadLines(path, true) {
		re, err := regexp.Compile("(?i)^(?:" + pat + ")$")
		if err == nil {
			out = append(out, bypassEntry{pat: pat, re: re})
		}
	}
	return out
}

// blockedByAd: port of the ad_ghost requestheaders block decision (sans the
// allowlist guard, which Decide applies first): _AD_HOST match OR
// registrable/host in learned-trackers.
//
// LOCK CONTRACT: reads the reloadable learned map — the caller MUST hold at
// least p.mu.RLock. Decide and shouldPoison (via isTracker) do; the candidate-
// emit path calls it only through those.
func (p *Policy) blockedByAd(host string) bool {
	if p.adHost.MatchString(host) {
		return true
	}
	reg := registrable(host)
	if reg != "" && p.learned[reg] {
		return true
	}
	return p.learned[strings.ToLower(host)]
}

// ── Decide: the unified cross-engine decision ────────────────────────────────
//
// action ∈ {"allow","block","splice","mitm"}. Precedence (mirrors the Python
// across the two addons, documented in the harness):
//
//  1. own-infra / allowlist → "allow"  (ad_ghost._allowed; never block/splice)
//  2. splice never-set check, then seed/learned → "splice"
//     (tls_splice runs FIRST at the TLS layer; should_splice already excludes
//     the never-set = pure-trackers ∪ fortknox, so a tracker that is also a
//     splice candidate fails should_splice here and falls through to block)
//  3. _AD_HOST / learned → "block"     (ad_ghost requestheaders, request layer)
//  4. otherwise → "mitm"
//
// sni defaults to host when empty (the live engine splices on SNI == the TLS
// host; for the parity harness host and sni are the same value).
func (p *Policy) Decide(host, sni string) string {
	// #662 — pick up autolearn promotions / manual edits without a worker
	// restart. Throttled to ~every reloadThrottle and best-effort, so the hot
	// path normally pays only a time compare. Done BEFORE taking the read lock
	// (maybeReload may trigger Apply callbacks that take the write lock).
	p.maybeReload()
	if sni == "" {
		sni = host
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.allowed(host) {
		return "allow"
	}
	if p.shouldSplice(sni) {
		return "splice"
	}
	if p.blockedByAd(host) {
		return "block"
	}
	// #803 — mitm-bypass (ignore_hosts) match splices cert-pinned APPS
	// (Signal/WhatsApp/banks…). Checked AFTER ad-block so ad networks that also
	// appear in the bypass list (adform, amazon-adsystem, rubiconproject…) are
	// still BLOCKED, not passed through — ad-blocking wins over app-bypass.
	if p.matchesBypass(sni) {
		return "splice"
	}
	return "mitm"
}

// action keeps the legacy 3-verb surface (block/splice/mitm) for the PoC
// CONNECT wiring, derived from Decide: "allow" collapses to "mitm" (an
// allowlisted host is intercepted normally, just never short-circuited).
func (p *Policy) action(host string) string {
	switch p.Decide(host, host) {
	case "splice":
		return "splice"
	case "block":
		return "block"
	default: // "allow" and "mitm" both → normal interception
		return "mitm"
	}
}
