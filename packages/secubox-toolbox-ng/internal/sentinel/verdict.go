// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// Verdict is the outcome of matching a flow against the Sentinel IOC/YARA
// content: the threat classification, its severity/confidence, the
// neutralization action to take, and the evidence backing the decision.
// Identity is carried only as MacHash — no raw PII.
type Verdict struct {
	Class      ThreatClass
	Severity   int
	Confidence int
	Action     Action
	Evidence   map[string]string
	MacHash    string
	TS         int64
}
