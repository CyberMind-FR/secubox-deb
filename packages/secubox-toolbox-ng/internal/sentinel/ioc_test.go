// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package sentinel

import "testing"

func TestIOCSetExactMatches(t *testing.T) {
	s := NewIOCSet()
	must := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	must(s.Add(IOC{Type: IOCDomain, Value: "evil.example", Class: ClassBotnetC2, Severity: 90, Action: ActionBlock}))
	must(s.Add(IOC{Type: IOCJA4, Value: "t13d1516h2_8daaf6152771_02713d6af862", Class: ClassSpywarePegasus, Severity: 100, Action: ActionBlock}))
	must(s.Add(IOC{Type: IOCFileSHA256, Value: "abc123", Class: ClassMalware, Severity: 80, Action: ActionStrip}))

	if m, ok := s.MatchDomain("evil.example"); !ok || m.Class != ClassBotnetC2 {
		t.Fatal("domain miss")
	}
	if _, ok := s.MatchDomain("good.example"); ok {
		t.Fatal("false domain hit")
	}
	if m, ok := s.MatchJA4("t13d1516h2_8daaf6152771_02713d6af862"); !ok || m.Class != ClassSpywarePegasus {
		t.Fatal("ja4 miss")
	}
	if m, ok := s.MatchFileSHA256("abc123"); !ok || m.Action != ActionStrip {
		t.Fatal("hash miss")
	}
}

func TestIOCSetURLRegex(t *testing.T) {
	s := NewIOCSet()
	if err := s.Add(IOC{Type: IOCURLRegex, Value: `https://[a-z0-9]+\.free\.example/onetime/[A-Za-z0-9]{16}`, Class: ClassZeroClick, Severity: 70, Action: ActionReport}); err != nil {
		t.Fatal(err)
	}
	if m, ok := s.MatchURL("https://x1.free.example/onetime/ABCDEFGHIJKLMNOP"); !ok || m.Class != ClassZeroClick {
		t.Fatal("url miss")
	}
	if _, ok := s.MatchURL("https://normal.example/page"); ok {
		t.Fatal("false url hit")
	}
}

func TestIOCSetRejectsBadRegex(t *testing.T) {
	s := NewIOCSet()
	if err := s.Add(IOC{Type: IOCURLRegex, Value: `([`, Class: ClassPhishing, Action: ActionReport}); err == nil {
		t.Fatal("expected bad-regex error")
	}
}
