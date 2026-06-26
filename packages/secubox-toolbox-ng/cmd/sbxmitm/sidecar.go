// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sidecar emit helper (#662 Phase 4)
//
// Fire-and-forget POST to a unix-socket'd SecuBox module, mirroring the Python
// addons' _common.fire_forget_post: it NEVER blocks the proxy flow and NEVER
// raises into the caller. The live engine will relay extracted signals to the
// existing module sockets; this is the transport only — NOT yet wired into the
// live request/response path (Phase 5+ wiring).
//
// Addon → socket mapping the live engine will use (verbatim from the Python
// addons' TARGET constants, packages/secubox-toolbox/mitmproxy_addons/*.py):
//
//	addon         socket path                       route
//	cookies   →   /run/secubox/cookies.sock         POST /inject
//	dpi       →   /run/secubox/dpi.sock             POST /classify
//	avatar    →   /run/secubox/avatar.sock          POST /fingerprint
//	ja4       →   /run/secubox/threat-analyst.sock  POST /ja4
//	soc_relay →   /run/secubox/soc.sock             POST /event
//	social_graph: correlated in-process (social.go) — edges (hash-only, never raw
//	  cookie values) are NOT emitted to a module socket but POSTed to the portal
//	  /__toolbox/social-event ingest (the social store lives in the toolbox/portal).
//
// Transport is now internal/relay. This file is retained for doc context only;
// the emit/emitSync/emitTimeout declarations have been moved to internal/relay
// as Emit/EmitSync/EmitTimeout (ref #744).
package main
