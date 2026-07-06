// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package sentinel implements the sbxmitm Sentinel threat-detection engine:
// the IOC model, pack loader, inline gate matcher, scorer, verdict store,
// behavioral/spyware heuristics, and reporting consumed by cmd/sbxmitm and
// cmd/sbx-sentinel.
package sentinel

import (
	"fmt"
	"regexp"
	"strings"
)

// IOCType identifies the kind of indicator-of-compromise value.
type IOCType string

const (
	IOCDomain     IOCType = "domain"
	IOCURLRegex   IOCType = "url_regex"
	IOCIP         IOCType = "ip"
	IOCJA3        IOCType = "ja3"
	IOCJA4        IOCType = "ja4"
	IOCCertSHA1   IOCType = "cert_sha1"
	IOCFileSHA256 IOCType = "file_sha256"
	IOCYara       IOCType = "yara"
)

// ThreatClass categorizes the nature of the threat an IOC represents.
type ThreatClass string

const (
	ClassMalware          ThreatClass = "malware"
	ClassTrojan           ThreatClass = "trojan"
	ClassBotnetC2         ThreatClass = "botnet_c2"
	ClassPhishing         ThreatClass = "phishing"
	ClassSpywarePegasus   ThreatClass = "spyware_pegasus"
	ClassSpywarePredator  ThreatClass = "spyware_predator"
	ClassSpywareIntellexa ThreatClass = "spyware_intellexa"
	ClassZeroClick        ThreatClass = "zero_click"
)

// Action is the neutralization/reporting action associated with an IOC hit.
type Action string

const (
	ActionBlock    Action = "block"
	ActionStrip    Action = "strip"
	ActionSinkhole Action = "sinkhole"
	ActionReport   Action = "report"
)

// IOC is a single indicator-of-compromise entry.
type IOC struct {
	Type     IOCType
	Value    string
	Class    ThreatClass
	Severity int
	Source   string
	Action   Action
}

// compiledURL pairs a compiled URL-matching regex with the IOC it belongs to.
type compiledURL struct {
	re  *regexp.Regexp
	ioc *IOC
}

// IOCSet holds all loaded indicators, keyed per-type for O(1) lookup on the
// hot path (domain/ip/ja3/ja4/cert-sha1/file-sha256), plus a compiled-regex
// slice for URL patterns. Zero value is not usable; use NewIOCSet.
type IOCSet struct {
	domains map[string]*IOC
	ips     map[string]*IOC
	ja3     map[string]*IOC
	ja4     map[string]*IOC
	certs   map[string]*IOC
	hashes  map[string]*IOC
	urls    []*compiledURL
}

// NewIOCSet returns an empty, ready-to-use IOCSet.
func NewIOCSet() *IOCSet {
	return &IOCSet{
		domains: make(map[string]*IOC),
		ips:     make(map[string]*IOC),
		ja3:     make(map[string]*IOC),
		ja4:     make(map[string]*IOC),
		certs:   make(map[string]*IOC),
		hashes:  make(map[string]*IOC),
	}
}

// Add inserts an IOC into the set, dispatching on its Type. For IOCURLRegex,
// the Value is compiled as a regular expression; a compile error is returned
// verbatim and the entry is not added. Host-like keys (domain, ip) are
// stored lowercased.
func (s *IOCSet) Add(ioc IOC) error {
	entry := ioc
	switch ioc.Type {
	case IOCDomain:
		s.domains[strings.ToLower(ioc.Value)] = &entry
	case IOCIP:
		s.ips[strings.ToLower(ioc.Value)] = &entry
	case IOCJA3:
		s.ja3[ioc.Value] = &entry
	case IOCJA4:
		s.ja4[ioc.Value] = &entry
	case IOCCertSHA1:
		s.certs[strings.ToLower(ioc.Value)] = &entry
	case IOCFileSHA256:
		s.hashes[strings.ToLower(ioc.Value)] = &entry
	case IOCURLRegex:
		re, err := regexp.Compile(ioc.Value)
		if err != nil {
			return fmt.Errorf("sentinel: compile url_regex IOC %q: %w", ioc.Value, err)
		}
		s.urls = append(s.urls, &compiledURL{re: re, ioc: &entry})
	case IOCYara:
		// YARA rule bodies are handled by the (build-tagged) yara matcher,
		// not by IOCSet; nothing to index here.
	default:
		return fmt.Errorf("sentinel: unknown IOC type %q", ioc.Type)
	}
	return nil
}

// MatchDomain looks up host (case-insensitive, exact match first) against
// the domain IOCs, then falls back to a registrable-domain suffix check
// (e.g. "sub.evil.example" matches an "evil.example" entry).
func (s *IOCSet) MatchDomain(host string) (*IOC, bool) {
	h := strings.ToLower(host)
	if ioc, ok := s.domains[h]; ok {
		return ioc, true
	}
	for i := 0; i < len(h); i++ {
		if h[i] == '.' {
			if ioc, ok := s.domains[h[i+1:]]; ok {
				return ioc, true
			}
		}
	}
	return nil, false
}

// MatchIP looks up ip against the IP IOCs.
func (s *IOCSet) MatchIP(ip string) (*IOC, bool) {
	ioc, ok := s.ips[strings.ToLower(ip)]
	return ioc, ok
}

// MatchJA3 looks up a JA3 fingerprint against the JA3 IOCs.
func (s *IOCSet) MatchJA3(fingerprint string) (*IOC, bool) {
	ioc, ok := s.ja3[fingerprint]
	return ioc, ok
}

// MatchJA4 looks up a JA4 fingerprint against the JA4 IOCs.
func (s *IOCSet) MatchJA4(fingerprint string) (*IOC, bool) {
	ioc, ok := s.ja4[fingerprint]
	return ioc, ok
}

// MatchCertSHA1 looks up a certificate SHA1 fingerprint against the cert IOCs.
func (s *IOCSet) MatchCertSHA1(sha1hex string) (*IOC, bool) {
	ioc, ok := s.certs[strings.ToLower(sha1hex)]
	return ioc, ok
}

// MatchFileSHA256 looks up a file SHA256 hash against the file-hash IOCs.
func (s *IOCSet) MatchFileSHA256(sha256hex string) (*IOC, bool) {
	ioc, ok := s.hashes[strings.ToLower(sha256hex)]
	return ioc, ok
}

// MatchURL scans url against the compiled URL-regex IOCs in insertion
// order, returning the first match.
func (s *IOCSet) MatchURL(url string) (*IOC, bool) {
	for _, cu := range s.urls {
		if cu.re.MatchString(url) {
			return cu.ioc, true
		}
	}
	return nil, false
}
