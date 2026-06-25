// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: cosmetic / popup-ad hiding CSS inject tests (#662)
package main

import (
	"strings"
	"testing"
)

// representativeSelectors covers each ported group + an EXPANDED popup token,
// asserting the cosmeticStyle carries the full surface (not a truncated port).
var representativeSelectors = []string{
	`ins.adsbygoogle`,             // ads
	`[class*="ad-banner"]`,        // ads
	`#onetrust-banner-sdk`,        // consent_nag
	`[class*="cookie-banner"]`,    // consent_nag
	`[class*="newsletter-popup"]`, // newsletter
	`.fb-like`,                    // social_widgets
	`[class*="interstitial"]`,     // EXPANDED popup
	`[class*="popup-ad"]`,         // EXPANDED popup
	`[class*="popunder"]`,         // EXPANDED popup
	`[class*="exit-intent"]`,      // EXPANDED popup
}

// forbiddenSelectors are the bare generic tokens we DELIBERATELY do not hide
// (they break legitimate first-party UI). Their absence is load-bearing.
var forbiddenSelectors = []string{
	`[class*="modal"]`,
	`[class*="popup"]`,
	`[class*="overlay"]`,
	`[class*="lightbox"]`,
}

func TestCosmeticStyleHasRepresentativeSelectors(t *testing.T) {
	for _, sel := range representativeSelectors {
		if !strings.Contains(cosmeticStyle, sel) {
			t.Errorf("cosmeticStyle missing representative selector %q", sel)
		}
	}
	if !strings.Contains(cosmeticStyle, `display:none!important`) {
		t.Errorf("cosmeticStyle missing display:none!important rule")
	}
	if !strings.Contains(cosmeticStyle, cosmeticGuard) {
		t.Errorf("cosmeticStyle missing guard id %q", cosmeticGuard)
	}
}

func TestCosmeticStyleNoGenericTokens(t *testing.T) {
	// Conservatism guard: bare generic popup/modal/overlay/lightbox tokens must
	// never appear (they would hide legitimate UI).
	for _, sel := range forbiddenSelectors {
		if strings.Contains(cosmeticStyle, sel) {
			t.Errorf("cosmeticStyle contains forbidden generic selector %q", sel)
		}
	}
}

func TestInjectCosmeticIdempotent(t *testing.T) {
	body := []byte(`<html><head><style id="sbx-ghost-style">x</style></head><body>hi</body></html>`)
	out := injectCosmetic(body, "")
	if string(out) != string(body) {
		t.Fatalf("guarded body must be unchanged.\n got: %s", out)
	}
	// Double-inject from clean must also be a no-op the second time.
	clean := []byte(`<html><head></head><body>hi</body></html>`)
	once := injectCosmetic(clean, "")
	twice := injectCosmetic(once, "")
	if string(once) != string(twice) {
		t.Fatalf("second injectCosmetic must be a no-op.\n once:  %s\n twice: %s", once, twice)
	}
	if strings.Count(string(twice), cosmeticGuard) != 1 {
		t.Fatalf("guard must appear exactly once after double inject: %s", twice)
	}
}

func TestInjectCosmeticBeforeHeadClose(t *testing.T) {
	body := []byte(`<html><head><title>x</title></head><body>hi</body></html>`)
	out := string(injectCosmetic(body, ""))
	// The <style> must land right BEFORE </head>.
	if !strings.Contains(out, `</style></head>`) {
		t.Fatalf("cosmetic style not placed before </head>: %s", out)
	}
	if !strings.Contains(out, `<title>x</title><style id="sbx-ghost-style">`) {
		t.Fatalf("original head content displaced: %s", out)
	}
}

func TestInjectCosmeticAfterHeadOpenNoClose(t *testing.T) {
	// <head ...> present, no </head> → insert right after the open tag's '>'.
	body := []byte(`<html><head lang="en"><body>hi`)
	out := string(injectCosmetic(body, ""))
	if !strings.Contains(out, `<head lang="en"><style id="sbx-ghost-style">`) {
		t.Fatalf("cosmetic style not placed after <head>'s '>': %s", out)
	}
}

func TestInjectCosmeticBodyFallback(t *testing.T) {
	body := []byte(`<html><body class="x">hi</body></html>`)
	out := string(injectCosmetic(body, ""))
	if !strings.Contains(out, `<style id="sbx-ghost-style">`) {
		t.Fatalf("cosmetic style not injected: %s", out)
	}
	// Inserted right before <body.
	i := strings.Index(out, `<style id="sbx-ghost-style">`)
	j := strings.Index(out, `<body class="x">`)
	if i < 0 || j < 0 || i > j {
		t.Fatalf("cosmetic style not placed before <body>: %s", out)
	}
}

func TestInjectCosmeticNoHeadNoBody(t *testing.T) {
	body := []byte(`<p>just a fragment</p>`)
	out := injectCosmetic(body, "")
	if string(out) != string(body) {
		t.Fatalf("no head/body → must be unchanged.\n got: %s", out)
	}
}

func TestInjectCosmeticCaseInsensitive(t *testing.T) {
	body := []byte(`<HTML><HEAD></HEAD><BODY>hi</BODY></HTML>`)
	out := string(injectCosmetic(body, ""))
	if !strings.Contains(out, `<style id="sbx-ghost-style">`) {
		t.Fatalf("case-insensitive </HEAD> match failed: %s", out)
	}
	// Must be before </HEAD> (case-insensitive anchor).
	i := strings.Index(out, `<style id="sbx-ghost-style">`)
	j := strings.Index(strings.ToLower(out), `</head>`)
	if i < 0 || j < 0 || i > j {
		t.Fatalf("cosmetic style not placed before </HEAD>: %s", out)
	}
}

func TestInjectInlineBannerAndCosmeticCompose(t *testing.T) {
	// Both markers must be present after composing the two injects (wg client).
	// #662 — the banner is now the INLINE script (not a <script src> tag).
	body := []byte(`<html><head></head><body>hi</body></html>`)
	out := string(injectHTML(body, inlineTestScript, true, ""))
	if !strings.Contains(out, bannerGuard) {
		t.Fatalf("banner marker missing after compose: %s", out)
	}
	if !strings.Contains(out, cosmeticGuard) {
		t.Fatalf("cosmetic marker missing after compose: %s", out)
	}
	// The inline banner is an inline <script> carrying the baked body, NOT a src.
	if !strings.Contains(out, "<script>"+inlineTestScript+"</script>") {
		t.Fatalf("inline banner body missing after compose: %s", out)
	}
	if strings.Contains(out, "<script src=") {
		t.Fatalf("inline path must NOT emit a <script src> tag: %s", out)
	}
}

func TestInjectHTMLNonWGSkipsCosmetic(t *testing.T) {
	// Non-WG (non-R3) clients get the banner but NOT the cosmetic style.
	body := []byte(`<html><head></head><body>hi</body></html>`)
	out := string(injectHTML(body, inlineTestScript, false, ""))
	if !strings.Contains(out, bannerGuard) {
		t.Fatalf("banner marker missing for non-wg: %s", out)
	}
	if strings.Contains(out, cosmeticGuard) {
		t.Fatalf("cosmetic style must NOT be injected for non-wg client: %s", out)
	}
}

func TestInjectIntoBodyGzipCarriesCosmetic(t *testing.T) {
	// The gzip decompress→inject→recompress path must carry BOTH injects for wg.
	body := []byte(`<html><head></head><body>hi</body></html>`)
	gz := gzipBytes(body)
	out, ok := injectIntoBody(gz, "gzip", inlineTestScript, true, "")
	if !ok {
		t.Fatalf("injectIntoBody(gzip) returned ok=false")
	}
	plain, err := gunzipBytes(out)
	if err != nil {
		t.Fatalf("re-gzip output not gunzippable: %v", err)
	}
	if !strings.Contains(string(plain), bannerGuard) || !strings.Contains(string(plain), cosmeticGuard) {
		t.Fatalf("gzip path lost a marker: %s", plain)
	}
	// The inline banner script body survives the gzip round-trip.
	if !strings.Contains(string(plain), "<script>"+inlineTestScript+"</script>") {
		t.Fatalf("inline banner body lost on gzip path: %s", plain)
	}
}
