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

var (
	cosmeticMu      sync.RWMutex
	cosmeticCached  []byte
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

func buildCosmetic() []byte {
	base := `<style id="sbx-ghost-style">` + cosmeticBaseSelectors
	data, err := os.ReadFile(cosmeticFilterPath)
	if err != nil {
		return []byte(base + `{display:none!important;visibility:hidden!important;}</style>`)
	}
	var m map[string][]string
	if json.Unmarshal(data, &m) != nil {
		return []byte(base + `{display:none!important;visibility:hidden!important;}</style>`)
	}
	var sb strings.Builder
	sb.WriteString(base)
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
	sb.WriteString(`{display:none!important;visibility:hidden!important;}</style>`)
	return []byte(sb.String())
}

// cosmeticStyleBytes returns the style to inject, refreshing from cosmetic.json
// at most once per minute (and only when its mtime changed).
func cosmeticStyleBytes() []byte {
	cosmeticMu.RLock()
	if cosmeticCached != nil && time.Since(cosmeticChecked) < time.Minute {
		b := cosmeticCached
		cosmeticMu.RUnlock()
		return b
	}
	cosmeticMu.RUnlock()

	cosmeticMu.Lock()
	defer cosmeticMu.Unlock()
	cosmeticChecked = time.Now()
	if fi, err := os.Stat(cosmeticFilterPath); err == nil {
		if cosmeticCached == nil || fi.ModTime().Unix() != cosmeticMtime {
			cosmeticMtime = fi.ModTime().Unix()
			cosmeticCached = buildCosmetic()
		}
	} else if cosmeticCached == nil {
		cosmeticCached = []byte(cosmeticStyle)
	}
	return cosmeticCached
}

// injectCosmetic inserts the cosmetic <style> into an HTML body once. Placement mirrors
// injectLoader (and the Python addon, which prefers </head>):
//   - idempotency: if the body already contains cosmeticGuard → unchanged.
//   - insert right BEFORE the first (case-insensitive) "</head>".
//   - else insert right AFTER the first "<head ...>"'s closing '>'.
//   - else insert right BEFORE the first "<body".
//   - else return the body unchanged (no inject).
func injectCosmetic(body []byte) []byte {
	if bytes.Contains(body, []byte(cosmeticGuard)) {
		return body
	}
	style := cosmeticStyleBytes()
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
