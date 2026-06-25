// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: cosmetic / popup-ad hiding CSS inject (#662)
//
// PORTS the ad_ghost cosmetic-hide <style> (../secubox-toolbox/mitmproxy_addons/
// ad_ghost.py, _COSMETIC groups: ads / consent_nag / newsletter / social_widgets)
// into the Go engine, which the #662 cutover left unported — so the engine was
// injecting only the transparency banner loader, NOT the ad/popup-hiding style.
// The result: newsletter / interstitial / subscribe / consent popups reappeared
// for R3 (wg) clients.
//
// It also EXPANDS the popup coverage ("améliorer le blocage des pubs popup")
// with clearly-ad-related popup / interstitial / overlay token patterns.
//
// CONSERVATISM (deliberate, load-bearing): we ONLY hide selectors whose token is
// ad/popup-SPECIFIC (e.g. "popup-ad", "ad-overlay", "interstitial", "popunder",
// "exit-intent"). We DO NOT add bare generic tokens like [class*="modal"],
// [class*="popup"], [class*="overlay"], or [class*="lightbox"] — those routinely
// match legitimate first-party UI (login modals, image lightboxes, nav overlays)
// and hiding them would break the page. A false-negative ad here is far cheaper
// than a broken site, and host-blocking (204) still saves the bandwidth.
//
// Pure standard library — no external modules.
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// cosmeticGuard is the id on the injected <style>. It makes injectCosmetic
// idempotent (skip if already present) and mirrors the Python addon's _MARK
// ("sbx-ghost-style"), so a page already styled by the Python engine path is not
// double-injected either.
const cosmeticGuard = "sbx-ghost-style"

// cosmeticStyle is the single <style> the engine injects for R3 clients. The
// selector list PORTS the four ad_ghost _COSMETIC groups verbatim (ads /
// consent_nag / newsletter / social_widgets) and EXPANDS the popup/interstitial
// coverage. Every selector targets an ad/popup-SPECIFIC token only (see the
// CONSERVATISM note above). The rule mirrors the Python _style_for:
// display:none + visibility:hidden, both !important, collapsing the slot.
const cosmeticStyle = `<style id="sbx-ghost-style">` + cosmeticBaseSelectors +
	`{display:none!important;visibility:hidden!important;}</style>`

// cosmeticBaseSelectors is the conservative, hand-curated base list (extracted
// so the EasyList loader below can re-use it as the always-valid foundation).
const cosmeticBaseSelectors = `` +
	// ── ads (ported from _COSMETIC["ads"]) ──────────────────────────────────
	`[id^="google_ads"],` +
	`[id^="div-gpt-ad"],` +
	`ins.adsbygoogle,` +
	`iframe[src*="doubleclick"],` +
	`iframe[src*="googlesyndication"],` +
	`iframe[src*="amazon-adsystem"],` +
	`[class*="ad-banner"],` +
	`[class*="advert"],` +
	`[id*="banner-ad"],` +
	`[id*="ad-container"],` +
	`[class*="-ads"],` +
	`[class*="sponsored"],` +
	`aside[aria-label*="publicit"],` +
	// ── consent_nag (ported from _COSMETIC["consent_nag"]) ───────────────────
	`#onetrust-banner-sdk,` +
	`#onetrust-consent-sdk,` +
	`#didomi-host,` +
	`.qc-cmp2-container,` +
	`[id^="sp_message_container"],` +
	`[id*="cookie-consent"],` +
	`[class*="cookie-banner"],` +
	`[class*="cookie-notice"],` +
	`[aria-label*="cookie"],` +
	`.cmpbox,` +
	// ── newsletter (ported from _COSMETIC["newsletter"]) ─────────────────────
	`[class*="newsletter-popup"],` +
	`[class*="signup-modal"],` +
	`[id*="newsletter-modal"],` +
	`[class*="subscribe-overlay"],` +
	// ── social_widgets (ported from _COSMETIC["social_widgets"]) ─────────────
	`.fb-like,` +
	`.twitter-share-button,` +
	`[class*="social-share"],` +
	`iframe[src*="facebook.com/plugins"],` +
	`iframe[src*="platform.twitter"],` +
	// ── EXPANDED popup / interstitial / overlay (ad-SPECIFIC tokens only) ────
	`[class*="interstitial"],` +
	`[id*="interstitial"],` +
	`[class*="ad-overlay"],` +
	`[class*="ad-modal"],` +
	`[class*="modal-ad"],` +
	`[class*="popup-ad"],` +
	`[id*="popup-ad"],` +
	`[class*="popunder"],` +
	`[class*="exit-intent"],` +
	`[class*="-paywall-ad"]`

// ── EasyList loader (#740) ──────────────────────────────────────────────────
// The modular filter resource compiles EasyList/EasyPrivacy element-hide rules
// to /var/lib/secubox/filterlists/cosmetic.json ({domain|"*": [selectors]}). We
// fold the GENERIC ("*") selectors into the injected <style>, on top of the
// conservative base. Selectors using uBlock/ABP *procedural* pseudo-classes
// (:has, :matches-css, :xpath, :style, :-abp-…) are NOT valid CSS — a single one
// in a comma list makes the browser drop the WHOLE rule, so they are filtered
// out. mtime-cached; falls back to the base when the file is absent.
const (
	cosmeticFilterPath = "/var/lib/secubox/filterlists/cosmetic.json"
	cosmeticGlobalCap  = 2000
)

// cosmeticProtect force-shows SecuBox's OWN injected UI so a broad EasyList
// generic (e.g. [class*="banner"] matching `sbx-banner`) can never hide our
// transparency banner. It is appended AFTER the hide rule (later cascade) with
// !important, so it wins for any sbx-/__toolbox element.
// `#sbx-banner` (an ID selector, specificity 1,0,0) leads so it out-ranks any
// class/attribute hide rule; z-index:max keeps the banner ABOVE everything and
// opacity/visibility/display force it visible whatever the cosmetic tried.
const cosmeticProtect = `#sbx-banner,[id*="sbx-banner"],[class*="sbx-banner"],` +
	`[id*="sbx-toolbox"],[class*="sbx-toolbox"],` +
	`[id*="sbx-ghost"],[id*="__toolbox"],[class*="__toolbox"]` +
	`{display:revert!important;visibility:visible!important;opacity:1!important;` +
	`z-index:2147483647!important;}`

var (
	cosmeticMu      sync.RWMutex
	cosmeticPrefix  string              // "<style…>" + base + capped generic (no closing)
	cosmeticData    map[string][]string // full cosmetic.json (for per-domain lookup)
	cosmeticMtime   int64
	cosmeticChecked time.Time
)

// procedural pseudo-classes / extended syntax that are NOT plain CSS.
var cosmeticBadTokens = []string{
	":has(", ":has-text(", ":matches-css", ":matches-media", ":matches-path",
	":xpath(", ":style(", ":-abp-", ":upward(", ":remove(", ":watch-attr(",
	":min-text-length(", ":nth-ancestor(", ":contains(", ":if(", ":if-not(",
}

func cosmeticSelectorOK(s string) bool {
	if s == "" || len(s) > 200 || strings.ContainsAny(s, "{}<>") {
		return false
	}
	for _, b := range cosmeticBadTokens {
		if strings.Contains(s, b) {
			return false
		}
	}
	return true
}

// buildCosmeticPrefix rebuilds the cached global prefix (style-open + base +
// capped generic selectors, NO closing brace) and stores the full parsed map
// for per-domain lookup. Caller holds cosmeticMu.
func buildCosmeticPrefix() {
	cosmeticData = nil
	data, err := os.ReadFile(cosmeticFilterPath)
	if err != nil {
		cosmeticPrefix = `<style id="sbx-ghost-style">` + cosmeticBaseSelectors
		return
	}
	var m map[string][]string
	if json.Unmarshal(data, &m) != nil {
		cosmeticPrefix = `<style id="sbx-ghost-style">` + cosmeticBaseSelectors
		return
	}
	cosmeticData = m
	var sb strings.Builder
	sb.WriteString(`<style id="sbx-ghost-style">`)
	sb.WriteString(cosmeticBaseSelectors)
	n := 0
	for _, s := range m["*"] {
		if n >= cosmeticGlobalCap {
			break
		}
		if cosmeticSelectorOK(s) {
			sb.WriteByte(',')
			sb.WriteString(s)
			n++
		}
	}
	cosmeticPrefix = sb.String()
}

// cosmeticRegistrableParents yields host and its parent domains (www.x.com →
// www.x.com, x.com) so both host- and registrable-scoped rules apply.
func cosmeticParents(host string) []string {
	host = strings.ToLower(strings.Trim(host, "."))
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i] // strip :port
	}
	parts := strings.Split(host, ".")
	out := make([]string, 0, len(parts))
	for i := 0; i+1 < len(parts); i++ {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}

// cosmeticStyleFor returns the <style> to inject for `host`: the cached global
// prefix + that host's per-domain EasyList selectors + hide rule + banner
// protection. Refreshes the cache from cosmetic.json at most once a minute.
func cosmeticStyleFor(host string) []byte {
	cosmeticMu.RLock()
	stale := cosmeticPrefix == "" || time.Since(cosmeticChecked) >= time.Minute
	cosmeticMu.RUnlock()
	if stale {
		cosmeticMu.Lock()
		cosmeticChecked = time.Now()
		if fi, err := os.Stat(cosmeticFilterPath); err == nil {
			if cosmeticPrefix == "" || fi.ModTime().Unix() != cosmeticMtime {
				cosmeticMtime = fi.ModTime().Unix()
				buildCosmeticPrefix()
			}
		} else if cosmeticPrefix == "" {
			cosmeticPrefix = `<style id="sbx-ghost-style">` + cosmeticBaseSelectors
		}
		cosmeticMu.Unlock()
	}

	cosmeticMu.RLock()
	defer cosmeticMu.RUnlock()
	var sb strings.Builder
	sb.WriteString(cosmeticPrefix)
	// per-domain rules for this host (and its parents).
	if cosmeticData != nil && host != "" {
		seen := map[string]bool{}
		for _, d := range cosmeticParents(host) {
			for _, s := range cosmeticData[d] {
				if cosmeticSelectorOK(s) && !seen[s] {
					seen[s] = true
					sb.WriteByte(',')
					sb.WriteString(s)
				}
			}
		}
	}
	sb.WriteString(`{display:none!important;visibility:hidden!important;}`)
	sb.WriteString(cosmeticProtect)
	sb.WriteString(`</style>`)
	return []byte(sb.String())
}

// injectCosmetic inserts the cosmetic <style> into an HTML body once. Placement mirrors
// injectLoader (and the Python addon, which prefers </head>):
//   - idempotency: if the body already contains cosmeticGuard → unchanged.
//   - insert right BEFORE the first (case-insensitive) "</head>".
//   - else insert right AFTER the first "<head ...>"'s closing '>'.
//   - else insert right BEFORE the first "<body".
//   - else return the body unchanged (no inject).
// ── Master ad-guard switch (#740) ───────────────────────────────────────────
// Orthogonal to the R0–R4 exposure level: a single `ad_guard` flag in
// filters.json gates the whole R3 ad-blocking layer (cosmetic here + the 204
// host-block, see main.go). Default ON; mtime-cached (5s) so the toolbox UI
// toggle takes effect within seconds without a worker restart.
const adGuardFiltersPath = "/etc/secubox/toolbox/filters.json"

var (
	adgMu      sync.RWMutex
	adgOn      = true
	adgMtime   int64
	adgChecked time.Time
)

func adGuardEnabled() bool {
	adgMu.RLock()
	if !adgChecked.IsZero() && time.Since(adgChecked) < 5*time.Second {
		v := adgOn
		adgMu.RUnlock()
		return v
	}
	adgMu.RUnlock()

	adgMu.Lock()
	defer adgMu.Unlock()
	adgChecked = time.Now()
	fi, err := os.Stat(adGuardFiltersPath)
	if err != nil {
		return adgOn
	}
	if fi.ModTime().Unix() == adgMtime {
		return adgOn
	}
	adgMtime = fi.ModTime().Unix()
	adgOn = true // default ON when key absent
	if data, e := os.ReadFile(adGuardFiltersPath); e == nil {
		var m map[string]interface{}
		if json.Unmarshal(data, &m) == nil {
			if v, ok := m["ad_guard"]; ok {
				if b, ok := v.(bool); ok {
					adgOn = b
				}
			}
		}
	}
	return adgOn
}

func injectCosmetic(body []byte, host string) []byte {
	if !adGuardEnabled() {
		return body
	}
	if bytes.Contains(body, []byte(cosmeticGuard)) {
		return body
	}
	style := cosmeticStyleFor(host)
	low := bytes.ToLower(body)

	// Prefer right before </head> (the Python _RE_HEAD.sub anchor).
	if i := bytes.Index(low, []byte("</head>")); i >= 0 {
		return spliceAt(body, style, i)
	}
	// Else right after the first <head ...>'s closing '>'.
	if h := bytes.Index(low, []byte("<head")); h >= 0 {
		if j := bytes.IndexByte(body[h:], '>'); j >= 0 {
			return spliceAt(body, style, h+j+1)
		}
	}
	// Else right before <body.
	if b := bytes.Index(low, []byte("<body")); b >= 0 {
		return spliceAt(body, style, b)
	}
	return body
}

// spliceAt returns body with ins inserted at byte offset at. Shared by the
// cosmetic placement logic (and available to the loader path) so the two inject
// helpers compose the same insertion semantics.
func spliceAt(body, ins []byte, at int) []byte {
	out := make([]byte, 0, len(body)+len(ins))
	out = append(out, body[:at]...)
	out = append(out, ins...)
	out = append(out, body[at:]...)
	return out
}
