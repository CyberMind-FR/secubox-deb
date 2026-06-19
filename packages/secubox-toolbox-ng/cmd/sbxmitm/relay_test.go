// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Unit tests for the per-flow analysis relay payload builders + emit wiring
// (#662 — restoring the dpi/cookies/ja4 events that feed "Qui te piste?").
package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── dpi payload ──────────────────────────────────────────────────────────────

func TestBuildDPIPayload(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://tracker.example.com/pixel?x=1", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11)")
	p := buildDPIPayload("203.0.113.7", "abcd1234", "tracker.example.com", req)

	var m map[string]any
	if err := json.Unmarshal(p, &m); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, p)
	}
	if m["client_ip"] != "203.0.113.7" {
		t.Errorf("client_ip = %v", m["client_ip"])
	}
	if m["client_mac_hash"] != "abcd1234" {
		t.Errorf("client_mac_hash = %v", m["client_mac_hash"])
	}
	if m["host"] != "tracker.example.com" {
		t.Errorf("host = %v", m["host"])
	}
	if m["scheme"] != "https" {
		t.Errorf("scheme = %v", m["scheme"])
	}
	if m["method"] != "GET" {
		t.Errorf("method = %v", m["method"])
	}
	if m["user_agent"] != "Mozilla/5.0 (X11)" {
		t.Errorf("user_agent = %v", m["user_agent"])
	}
	if m["sni"] != "tracker.example.com" {
		t.Errorf("sni = %v", m["sni"])
	}
	// ts_ms present and plausible (a recent unix-millis value).
	ts, ok := m["ts_ms"].(float64)
	if !ok || ts < 1_600_000_000_000 {
		t.Errorf("ts_ms = %v (want recent unix millis)", m["ts_ms"])
	}
}

// Absent User-Agent → JSON null (not "" and not omitted), mirroring the Python
// addon's headers.get("user-agent") → None.
func TestBuildDPIPayloadNullUserAgent(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://h.example/", nil)
	p := buildDPIPayload("1.2.3.4", "h", "h.example", req)
	if !strings.Contains(string(p), `"user_agent":null`) {
		t.Errorf("expected user_agent null, got: %s", p)
	}
}

// ── cookies payload ──────────────────────────────────────────────────────────

func TestBuildCookiesPayloadNamesOnly(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://shop.example.com/cart", nil)
	req.Header.Add("Cookie", "sessionid=SECRET_VALUE; csrftoken=ANOTHER_SECRET")
	req.Header.Add("Cookie", "_ga=GA1.2.deadbeef")
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "_fbp=fb.1.SECRET; Path=/; HttpOnly; SameSite=Lax")
	resp.Header.Add("Set-Cookie", "uid=PRIVATE; Domain=.example.com")

	p := buildCookiesPayload("10.99.1.5", "wgpersona", req, resp)
	var m map[string]any
	if err := json.Unmarshal(p, &m); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, p)
	}
	if m["url"] != "https://shop.example.com/cart" {
		t.Errorf("url = %v", m["url"])
	}
	if m["method"] != "POST" {
		t.Errorf("method = %v", m["method"])
	}
	if int(m["status"].(float64)) != 200 {
		t.Errorf("status = %v", m["status"])
	}
	if int(m["set_cookie_count"].(float64)) != 2 {
		t.Errorf("set_cookie_count = %v", m["set_cookie_count"])
	}
	if int(m["cookie_count"].(float64)) != 2 {
		t.Errorf("cookie_count (header lines) = %v", m["cookie_count"])
	}
	setNames := toStrings(m["set_cookie_names"])
	if !equalStrSet(setNames, []string{"_fbp", "uid"}) {
		t.Errorf("set_cookie_names = %v", setNames)
	}
	cookieNames := toStrings(m["cookie_names"])
	if !equalStrSet(cookieNames, []string{"sessionid", "csrftoken", "_ga"}) {
		t.Errorf("cookie_names = %v", cookieNames)
	}
	// Hard privacy guarantee: NO value leaked anywhere in the payload.
	raw := string(p)
	for _, secret := range []string{"SECRET_VALUE", "ANOTHER_SECRET", "deadbeef", "fb.1.SECRET", "PRIVATE", "GA1.2"} {
		if strings.Contains(raw, secret) {
			t.Errorf("payload leaked cookie value %q: %s", secret, raw)
		}
	}
}

// Set-Cookie name parse: text before the first '='. Cookie header split on ';'.
func TestCookieNameParsing(t *testing.T) {
	if got := setCookieName("name=val; Path=/; Secure"); got != "name" {
		t.Errorf("setCookieName = %q", got)
	}
	if got := setCookieName("  spaced = v"); got != "spaced" {
		t.Errorf("setCookieName trim = %q", got)
	}
	if got := setCookieName("=novalue"); got != "" {
		t.Errorf("setCookieName empty name = %q", got)
	}
	if got := setCookieName("attributeonly"); got != "" {
		t.Errorf("setCookieName no eq = %q", got)
	}

	names := parseCookieHeaderNames("a=1; b=2;c=3")
	if !equalStrSet(names, []string{"a", "b", "c"}) {
		t.Errorf("parseCookieHeaderNames = %v", names)
	}
}

// Caps: ≤30 Set-Cookie names, ≤50 sent cookie names.
func TestCookiesPayloadCaps(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://e.example/", nil)
	var bigCookie strings.Builder
	for i := 0; i < 80; i++ {
		if i > 0 {
			bigCookie.WriteString("; ")
		}
		bigCookie.WriteString("c")
		bigCookie.WriteByte(byte('0' + i%10))
		bigCookie.WriteString("_")
		bigCookie.WriteByte(byte('a' + i%26))
		bigCookie.WriteString("=v")
	}
	req.Header.Add("Cookie", bigCookie.String())
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	for i := 0; i < 45; i++ {
		resp.Header.Add("Set-Cookie", "sc"+string(rune('A'+i%26))+string(rune('0'+i%10))+"=v")
	}
	p := buildCookiesPayload("1.1.1.1", "h", req, resp)
	var m map[string]any
	json.Unmarshal(p, &m)
	if n := len(toStrings(m["set_cookie_names"])); n > 30 {
		t.Errorf("set_cookie_names not capped at 30: %d", n)
	}
	if n := len(toStrings(m["cookie_names"])); n > 50 {
		t.Errorf("cookie_names not capped at 50: %d", n)
	}
	// raw counts still reflect the real totals.
	if int(m["set_cookie_count"].(float64)) != 45 {
		t.Errorf("set_cookie_count = %v", m["set_cookie_count"])
	}
}

// URL truncated to ≤300 chars.
func TestCookiesPayloadURLTruncation(t *testing.T) {
	long := "https://e.example/" + strings.Repeat("a", 500)
	u, _ := url.Parse(long)
	req := &http.Request{Method: "GET", URL: u, Header: http.Header{}}
	req.Header.Add("Cookie", "x=1")
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	p := buildCookiesPayload("1.1.1.1", "h", req, resp)
	var m map[string]any
	json.Unmarshal(p, &m)
	if len(m["url"].(string)) > 300 {
		t.Errorf("url not truncated: %d chars", len(m["url"].(string)))
	}
}

// cookiesRelevant gates emission: only when ≥1 Set-Cookie OR ≥1 Cookie.
func TestCookiesRelevant(t *testing.T) {
	mk := func(setC, reqC bool) (*http.Request, *http.Response) {
		req, _ := http.NewRequest("GET", "https://e/", nil)
		if reqC {
			req.Header.Add("Cookie", "a=1")
		}
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		if setC {
			resp.Header.Add("Set-Cookie", "x=1")
		}
		return req, resp
	}
	if r, p := mk(false, false); cookiesRelevant(r, p) {
		t.Error("no cookies → should not be relevant")
	}
	if r, p := mk(true, false); !cookiesRelevant(r, p) {
		t.Error("set-cookie present → relevant")
	}
	if r, p := mk(false, true); !cookiesRelevant(r, p) {
		t.Error("request cookie present → relevant")
	}
}

// ── ja4 payload ──────────────────────────────────────────────────────────────

func TestBuildJA4Payload(t *testing.T) {
	p := buildJA4Payload("198.51.100.9", "tlspersona", "secure.example.com",
		[]string{"h2", "http/1.1"}, []uint16{4865, 4866, 49195})
	var m map[string]any
	if err := json.Unmarshal(p, &m); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, p)
	}
	if m["sni"] != "secure.example.com" {
		t.Errorf("sni = %v", m["sni"])
	}
	if m["client_ip"] != "198.51.100.9" {
		t.Errorf("client_ip = %v", m["client_ip"])
	}
	if m["client_mac_hash"] != "tlspersona" {
		t.Errorf("client_mac_hash = %v", m["client_mac_hash"])
	}
	alpn := toStrings(m["alpn_protocols"])
	if !equalStrSet(alpn, []string{"h2", "http/1.1"}) {
		t.Errorf("alpn = %v", alpn)
	}
	cs := m["cipher_suites"].([]any)
	if len(cs) != 3 || int(cs[0].(float64)) != 4865 {
		t.Errorf("cipher_suites = %v", cs)
	}
	// extensions: always null (stdlib doesn't expose them).
	if !strings.Contains(string(p), `"extensions":null`) {
		t.Errorf("expected extensions null, got: %s", p)
	}
}

// Empty ALPN / ciphers → JSON empty arrays (mirrors list(... or [])), not null.
func TestBuildJA4PayloadEmptySlices(t *testing.T) {
	p := buildJA4Payload("1.1.1.1", "h", "", nil, nil)
	raw := string(p)
	if !strings.Contains(raw, `"alpn_protocols":[]`) {
		t.Errorf("alpn should be [] not null: %s", raw)
	}
	if !strings.Contains(raw, `"cipher_suites":[]`) {
		t.Errorf("cipher_suites should be [] not null: %s", raw)
	}
}

// ── gate wiring ──────────────────────────────────────────────────────────────

// The flag wires into Proxy.analysisRelay and gates emission.
func TestAnalysisRelayGate(t *testing.T) {
	on := &Proxy{analysisRelay: true}
	off := &Proxy{analysisRelay: false}
	if !on.relayEnabled() {
		t.Error("analysisRelay=true → relayEnabled() should be true")
	}
	if off.relayEnabled() {
		t.Error("analysisRelay=false → relayEnabled() should be false")
	}
}

// emitDPI/emitCookies/emitJA4 respect the gate: with analysisRelay=false they
// deliver nothing to a live socket; with it true they deliver.
func TestEmitGateRespected(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dpi.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	hits := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 1024)
			c.Read(buf)
			c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			c.Close()
			hits <- struct{}{}
		}
	}()

	// Gate off → nothing delivered.
	off := &Proxy{analysisRelay: false}
	off.relayEmit(sock, "/classify", []byte(`{"k":"v"}`))
	select {
	case <-hits:
		t.Fatal("gate off but a payload was delivered")
	case <-time.After(300 * time.Millisecond):
	}

	// Gate on → delivered.
	on := &Proxy{analysisRelay: true}
	on.relayEmit(sock, "/classify", []byte(`{"k":"v"}`))
	select {
	case <-hits:
	case <-time.After(2 * time.Second):
		t.Fatal("gate on but nothing delivered")
	}
}

// ── socket-path consts ─────────────────────────────────────────────────────

func TestRelaySocketPaths(t *testing.T) {
	if dpiSocket != "/run/secubox/dpi.sock" {
		t.Errorf("dpiSocket = %q", dpiSocket)
	}
	if cookiesSocket != "/run/secubox/cookies.sock" {
		t.Errorf("cookiesSocket = %q", cookiesSocket)
	}
	if ja4Socket != "/run/secubox/threat-analyst.sock" {
		t.Errorf("ja4Socket = %q", ja4Socket)
	}
}

// ── test helpers ───────────────────────────────────────────────────────────

func toStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		out = append(out, e.(string))
	}
	return out
}

func equalStrSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, g := range got {
		seen[g]++
	}
	for _, w := range want {
		seen[w]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
