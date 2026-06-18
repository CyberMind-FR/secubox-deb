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
	"bufio"
	"os"
	"regexp"
	"strings"
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
	adHost       *regexp.Regexp
	learned      map[string]bool // learned-trackers (host or registrable, lowercased)
	allow        map[string]bool // ad-allowlist (host or registrable, lowercased)
	spliceSeed   map[string]bool // splice seed patterns
	spliceLearn  map[string]bool // splice learned patterns
	never        map[string]bool // pure-trackers ∪ fortknox (splice never-set)
	selfRegs     map[string]bool // own-infra registrable domains
	selfDomains  []string        // own-infra (for the host==d || host endswith .d guard)

	// Legacy PoC fields kept so non-policy behaviour is unchanged.
	Inject []byte // banner / ad-CSS marker injected before </head> or </body>
}

// loadLines mirrors the comment-stripping Python loaders (splice._load_lines,
// ad_ghost._allowed's allowlist read): split on first '#', trim, lowercase,
// skip blanks. Missing/unreadable file → empty set (best-effort).
func loadLines(path string) map[string]bool {
	return scanLines(path, true)
}

// loadLinesRaw mirrors ad_ghost._learned_set, which does NOT comment-strip —
// learned-trackers.txt is a machine-generated one-host-per-line file. It does
// `{ln.strip().lower() for ln in f if ln.strip()}`. Matching this exactly is
// load-bearing for parity (a '#' in this file would be kept verbatim, not a
// comment), so the Go core must mirror the divergent behaviour, not normalise it.
func loadLinesRaw(path string) map[string]bool {
	return scanLines(path, false)
}

func scanLines(path string, stripComments bool) map[string]bool {
	out := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		ln := sc.Text()
		if stripComments {
			if i := strings.IndexByte(ln, '#'); i >= 0 {
				ln = ln[:i]
			}
		}
		ln = strings.ToLower(strings.TrimSpace(ln))
		if ln != "" {
			out[ln] = true
		}
	}
	return out
}

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

	re, err := regexp.Compile(adHostPattern)
	if err != nil {
		return nil, err
	}

	// never-set = pure-trackers ∪ fortknox_sites (mirrors TlsSplice._refresh_sets).
	never := loadLines(opts.PureTrackersPath)
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

	return &Policy{
		adHost:      re,
		learned:     loadLinesRaw(opts.LearnedPath), // mirrors _learned_set (no comment-strip)
		allow:       loadLines(opts.AllowPath),
		spliceSeed:  loadLines(opts.SpliceSeedPath),
		spliceLearn: loadLines(opts.SpliceLearnPath),
		never:       never,
		selfRegs:    selfRegs,
		selfDomains: selfDomains,
	}, nil
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

// shouldSplice: port of splice.should_splice (never wins; then seed ∪ learned).
func (p *Policy) shouldSplice(sni string) bool {
	s := strings.Trim(strings.ToLower(sni), ".")
	if s == "" {
		return false
	}
	if hostMatches(s, p.never) {
		return false
	}
	return hostMatches(s, p.spliceSeed) || hostMatches(s, p.spliceLearn)
}

// blockedByAd: port of the ad_ghost requestheaders block decision (sans the
// allowlist guard, which Decide applies first): _AD_HOST match OR
// registrable/host in learned-trackers.
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
	if sni == "" {
		sni = host
	}
	if p.allowed(host) {
		return "allow"
	}
	if p.shouldSplice(sni) {
		return "splice"
	}
	if p.blockedByAd(host) {
		return "block"
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
