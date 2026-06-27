// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestSWMatchSuffix(t *testing.T) {
	s := &SWNeuter{hosts: map[string]bool{"leparisien.fr": true, "cnn.com": true}}
	for _, h := range []string{"leparisien.fr", "www.leparisien.fr", "m.cnn.com", "CNN.COM"} {
		if !s.Match(h) {
			t.Fatalf("%q should match the allow-list", h)
		}
	}
	for _, h := range []string{"notleparisien.fr", "evil.com", "leparisien.fr.evil.com", ""} {
		if s.Match(h) {
			t.Fatalf("%q must NOT match", h)
		}
	}
}

func TestSWEmptyListNoOp(t *testing.T) {
	s := &SWNeuter{hosts: map[string]bool{}}
	if s.Match("www.leparisien.fr") {
		t.Fatal("empty allow-list must match nothing (targeted-strict no-op)")
	}
}

func TestSWIsScriptRequest(t *testing.T) {
	r1, _ := http.NewRequest("GET", "https://x/sw.js", nil)
	r1.Header.Set("Service-Worker", "script")
	if !isSWScriptRequest(r1) {
		t.Fatal("Service-Worker: script must be detected")
	}
	r2, _ := http.NewRequest("GET", "https://x/sw.js", nil)
	if isSWScriptRequest(r2) {
		t.Fatal("no Service-Worker header → not a SW script request")
	}
	if isSWScriptRequest(nil) {
		t.Fatal("nil request → false")
	}
}

func TestNeuterSWPassiveAndCorrect(t *testing.T) {
	if !strings.Contains(NeuterSW, "self.registration.unregister()") {
		t.Fatal("neuter SW must unregister itself")
	}
	if !strings.Contains(NeuterSW, "caches.delete") {
		t.Fatal("neuter SW must clear caches")
	}
	if strings.Contains(NeuterSW, "navigate(") {
		t.Fatal("neuter SW must be PASSIVE — no client.navigate / force reload")
	}
}

func TestSWCandidateRecordSnapshot(t *testing.T) {
	s := &SWNeuter{cand: map[string]int64{}}
	s.RecordCandidate("www.cnn.com")
	s.RecordCandidate("www.cnn.com")
	s.RecordCandidate("") // ignored
	got := s.snapshotCandidates()
	if len(got) != 1 || got[0] != "www.cnn.com" {
		t.Fatalf("snapshot = %v, want [www.cnn.com]", got)
	}
	if s.snapshotCandidates() != nil {
		t.Fatal("snapshot must read-and-CLEAR (second call → nil)")
	}
}
