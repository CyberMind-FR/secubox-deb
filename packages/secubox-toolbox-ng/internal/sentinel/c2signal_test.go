package sentinel

import "testing"

func TestC2SignalsDGA(t *testing.T) {
	s := NewC2Signals([]string{"t13d1516h2_browserfp"})
	// high-entropy random-looking label → dga fires
	fired := s.Fired(FlowMeta{Host: "x7f3q9zk2vw8plmn.example", JA4: "t13d1516h2_browserfp"})
	if !contains(fired, "dga") {
		t.Errorf("dga signal expected, got %v", fired)
	}
	// ordinary word domain, browser JA4, and seen-often → no signals
	for i := 0; i < 60; i++ {
		s.Observe("news.example.com")
	}
	fired = s.Fired(FlowMeta{Host: "news.example.com", JA4: "t13d1516h2_browserfp"})
	if len(fired) != 0 {
		t.Errorf("no signals expected for common browser-JA4 word-domain, got %v", fired)
	}
}

func TestC2SignalsNonBrowserJA(t *testing.T) {
	s := NewC2Signals([]string{"t13d1516h2_browserfp"})
	for i := 0; i < 60; i++ {
		s.Observe("cdn.example.com")
	}
	// non-browser JA4 → non_browser_ja fires (host common, low entropy)
	fired := s.Fired(FlowMeta{Host: "cdn.example.com", JA4: "q99xxbotfp"})
	if !contains(fired, "non_browser_ja") {
		t.Errorf("non_browser_ja expected, got %v", fired)
	}
	// empty JA4/JA3 (unknown) must NOT count as non-browser (avoid FP on missing data)
	fired = s.Fired(FlowMeta{Host: "cdn.example.com"})
	if contains(fired, "non_browser_ja") {
		t.Errorf("empty JA must not fire non_browser_ja, got %v", fired)
	}
}

func TestC2SignalsRare(t *testing.T) {
	s := NewC2Signals(nil)
	// first-ever contact with a low-entropy word host, no JA → rare only
	fired := s.Fired(FlowMeta{Host: "portal.example.com"})
	if !contains(fired, "rare") {
		t.Errorf("rare expected for never-seen host, got %v", fired)
	}
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
