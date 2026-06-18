// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Unit tests for the always-on anonymize hygiene + the Set-Cookie poison
// emission wired into the MITM response path (#662 Phase 5-prep, Part A).
//
// These exercise the PURE helpers (anonymizeRequest / poisonSetCookies /
// isTrackingCookieName) so the wiring is testable without standing up a full
// proxy. The behaviour mirrors the Python privacy_guard._anonymize and the
// privacy.fake_id poison intent (see comments in privacy.go) — best-effort
// hygiene, not byte-identical to the request-Cookie path.
package main

import (
	"net/http"
	"testing"
)

// TestAnonymizeRequestStripsOperatorHeaders: the operator/carrier + re-id
// headers are dropped, and DNT:1 + Sec-GPC:1 are pinned (mirrors
// privacy_guard._anonymize / protective_mode spoof header hygiene).
func TestAnonymizeRequestStripsOperatorHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-MSISDN", "33612345678")
	h.Set("X-ACR", "carrier-acr-token")
	h.Set("X-Up-Calling-Line-Id", "33612345678")
	h.Set("X-Wap-Profile", "http://wap.example/ua.xml")
	h.Set("X-Forwarded-For", "10.0.0.7")
	h.Set("Via", "1.1 carrier-proxy")
	h.Set("User-Agent", "Mozilla/5.0") // must survive

	anonymizeRequest(h)

	for _, k := range []string{
		"X-Msisdn", "X-Acr", "X-Up-Calling-Line-Id", "X-Wap-Profile",
		"X-Forwarded-For", "Via",
	} {
		if v := h.Get(k); v != "" {
			t.Errorf("anonymizeRequest left %s=%q (should be stripped)", k, v)
		}
	}
	if h.Get("User-Agent") != "Mozilla/5.0" {
		t.Errorf("anonymizeRequest clobbered a benign header: User-Agent=%q", h.Get("User-Agent"))
	}
	if h.Get("DNT") != "1" {
		t.Errorf("DNT not pinned: %q", h.Get("DNT"))
	}
	if h.Get("Sec-GPC") != "1" {
		t.Errorf("Sec-GPC not pinned: %q", h.Get("Sec-GPC"))
	}
}

// TestAnonymizeRequestPinsSignalsWhenAbsent: DNT/Sec-GPC are asserted even when
// no operator headers were present (always-on hygiene).
func TestAnonymizeRequestPinsSignalsWhenAbsent(t *testing.T) {
	h := http.Header{}
	anonymizeRequest(h)
	if h.Get("DNT") != "1" || h.Get("Sec-GPC") != "1" {
		t.Fatalf("opt-out signals not pinned on a clean request: DNT=%q GPC=%q",
			h.Get("DNT"), h.Get("Sec-GPC"))
	}
}

// TestIsTrackingCookieName: known tracking-id cookie names are recognised;
// benign session/CSRF cookies are not.
func TestIsTrackingCookieName(t *testing.T) {
	track := []string{"_ga", "_GA_ABC123", "_fbp", "_gid", "uid", "uuid", "_pk_id", "__qca", "_gcl_au"}
	for _, n := range track {
		if !isTrackingCookieName(n) {
			t.Errorf("isTrackingCookieName(%q)=false, want true", n)
		}
	}
	benign := []string{"sessionid", "csrftoken", "XSRF-TOKEN", "PHPSESSID", "cart", "lang"}
	for _, n := range benign {
		if isTrackingCookieName(n) {
			t.Errorf("isTrackingCookieName(%q)=true, want false", n)
		}
	}
}

// TestPoisonSetCookiesReplacesTrackingValue: a tracking Set-Cookie has its value
// replaced by the jar fakeID (attributes preserved), while a non-tracking cookie
// is left byte-identical.
func TestPoisonSetCookiesReplacesTrackingValue(t *testing.T) {
	key := []byte("test-jar-seed-key-0123456789abcdef")
	const ch = "203.0.113.9"
	const host = "ads.doubleclick.net"

	in := []string{
		"_ga=GA1.2.111.222; Path=/; Domain=.doubleclick.net; Max-Age=63072000",
		"sessionid=abc123; Path=/; HttpOnly",
	}
	out := poisonSetCookies(in, ch, host, key)
	if len(out) != 2 {
		t.Fatalf("poisonSetCookies returned %d cookies, want 2", len(out))
	}

	// The _ga value must be the jar fakeID and the attributes preserved.
	want, ok := fakeID(ch, host, "_ga", key)
	if !ok {
		t.Fatal("fakeID returned !ok for _ga")
	}
	wantCookie := "_ga=" + want + "; Path=/; Domain=.doubleclick.net; Max-Age=63072000"
	if out[0] != wantCookie {
		t.Errorf("poisoned _ga = %q\n want %q", out[0], wantCookie)
	}
	if out[0] == in[0] {
		t.Error("tracking cookie value was NOT changed")
	}

	// The benign cookie must be untouched.
	if out[1] != in[1] {
		t.Errorf("non-tracking cookie altered: %q != %q", out[1], in[1])
	}
}

// TestPoisonSetCookiesNoKeyLeavesUnchanged: with no jar key (key present-gate),
// nothing is poisoned (fail-closed-to-clean: we never emit a broken cookie).
func TestPoisonSetCookiesNoKeyLeavesUnchanged(t *testing.T) {
	in := []string{"_ga=GA1.2.1.2; Path=/"}
	out := poisonSetCookies(in, "1.2.3.4", "ads.doubleclick.net", nil)
	if len(out) != 1 || out[0] != in[0] {
		t.Fatalf("poisonSetCookies with nil key altered output: %v", out)
	}
}

// TestPoisonSetCookiesNoClientHashLeavesUnchanged: empty clientHash → fakeID !ok
// → cookie left as-is.
func TestPoisonSetCookiesNoClientHashLeavesUnchanged(t *testing.T) {
	key := []byte("test-jar-seed-key-0123456789abcdef")
	in := []string{"_ga=GA1.2.1.2; Path=/"}
	out := poisonSetCookies(in, "", "ads.doubleclick.net", key)
	if len(out) != 1 || out[0] != in[0] {
		t.Fatalf("poisonSetCookies with empty clientHash altered output: %v", out)
	}
}

// TestPoisonSetCookiesDeterministic: same (client,host,name) → same fake value
// across calls ('rémanent' jar — proven byte-exact in jar_test.go; here we just
// assert the wiring keeps it stable).
func TestPoisonSetCookiesDeterministic(t *testing.T) {
	key := []byte("test-jar-seed-key-0123456789abcdef")
	in := []string{"uid=real-user-7; Path=/"}
	a := poisonSetCookies(in, "9.9.9.9", "adnxs.com", key)
	b := poisonSetCookies(in, "9.9.9.9", "adnxs.com", key)
	if a[0] != b[0] {
		t.Fatalf("poison not deterministic: %q != %q", a[0], b[0])
	}
	if a[0] == in[0] {
		t.Fatal("uid (tracking) cookie not poisoned")
	}
}
