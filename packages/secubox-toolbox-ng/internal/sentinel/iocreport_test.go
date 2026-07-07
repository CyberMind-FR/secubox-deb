// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package sentinel

import (
	"os"
	"path/filepath"
	"testing"
)

func iocReportLoader(t *testing.T, packJSON string) *Loader {
	t.Helper()
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "p.json"), []byte(packJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := NewLoader(base, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestIOCReporterSurfacesBotnetAsReport(t *testing.T) {
	// a botnet_c2 domain declared action:block must surface REPORT-only.
	l := iocReportLoader(t, `{"version":"1","iocs":[
		{"type":"domain","value":"c2.evil.example","class":"botnet_c2","severity":90,"source":"abuse.ch","action":"block"}]}`)
	r := NewIOCReporter(l)
	vs := r.Analyze(MirrorMsg{Meta: FlowMeta{Host: "c2.evil.example", MacHash: "aa"}, TS: 1})
	if len(vs) != 1 {
		t.Fatalf("want 1 verdict, got %d", len(vs))
	}
	if vs[0].Class != ClassBotnetC2 {
		t.Errorf("class = %q", vs[0].Class)
	}
	if vs[0].Action != ActionReport {
		t.Errorf("action must be report (daemon observes), got %q", vs[0].Action)
	}
	if vs[0].Evidence["disposition"] != "observed" {
		t.Errorf("disposition must be observed, got %q", vs[0].Evidence["disposition"])
	}
}

func TestIOCReporterSkipsSpywareClasses(t *testing.T) {
	// spyware classes belong to the Spyware analyzer — reporter must not dupe.
	l := iocReportLoader(t, `{"version":"1","iocs":[
		{"type":"domain","value":"peg.example","class":"spyware_pegasus","severity":95,"source":"mvt","action":"block"}]}`)
	r := NewIOCReporter(l)
	vs := r.Analyze(MirrorMsg{Meta: FlowMeta{Host: "peg.example", MacHash: "aa"}, TS: 1})
	if len(vs) != 0 {
		t.Errorf("reporter must skip spyware classes (Spyware analyzer owns them), got %d", len(vs))
	}
}

func TestIOCReporterNoMatchNoVerdict(t *testing.T) {
	l := iocReportLoader(t, `{"version":"1","iocs":[
		{"type":"domain","value":"c2.evil.example","class":"botnet_c2","severity":90,"source":"x","action":"block"}]}`)
	r := NewIOCReporter(l)
	if vs := r.Analyze(MirrorMsg{Meta: FlowMeta{Host: "benign.example", MacHash: "aa"}, TS: 1}); len(vs) != 0 {
		t.Errorf("benign host must not match, got %d", len(vs))
	}
	// nil loader → no panic, no verdicts
	var rn *IOCReporter
	if vs := rn.Analyze(MirrorMsg{Meta: FlowMeta{Host: "x", MacHash: "a"}}); vs != nil {
		t.Error("nil reporter must be a no-op")
	}
}

func TestIOCReporterMatchesDestinationIP(t *testing.T) {
	// a bare C2 IP IOC (Feodo-style) matches when the flow's Host IS that IP
	// (direct-IP / no-SNI). ClientIP is never consulted (source-IP match would
	// be a false-positive vector).
	l := iocReportLoader(t, `{"version":"1","iocs":[
		{"type":"ip","value":"192.0.2.77","class":"botnet_c2","severity":90,"source":"abuse.ch-feodo","action":"block"}]}`)
	r := NewIOCReporter(l)
	vs := r.Analyze(MirrorMsg{Meta: FlowMeta{Host: "192.0.2.77", ClientIP: "10.0.0.5", MacHash: "aa"}, TS: 1})
	if len(vs) != 1 || vs[0].Class != ClassBotnetC2 || vs[0].Action != ActionReport {
		t.Fatalf("destination-IP C2 must surface report-only, got %+v", vs)
	}
	// the client's own source IP must NOT match a destination-C2 IP IOC
	vs = r.Analyze(MirrorMsg{Meta: FlowMeta{Host: "benign.example", ClientIP: "192.0.2.77", MacHash: "aa"}, TS: 1})
	if len(vs) != 0 {
		t.Errorf("client source IP must never match a destination-C2 IP IOC, got %+v", vs)
	}
}
