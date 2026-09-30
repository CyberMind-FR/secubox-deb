// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

// OrigineBox rend « https://<prefixe>.<domaine de CETTE box> », ou "" si le
// domaine est inconnu (#1727 — pour les services consommés, cf. --parc).
func OrigineBox(prefixe string) string { return origineBox(prefixe) }
