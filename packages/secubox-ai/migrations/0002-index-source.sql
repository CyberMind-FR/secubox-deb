-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Corrélateur (#3721) : fins de ban et membres de campagne lus par source sur 7 j.
CREATE INDEX IF NOT EXISTS idx_evt_source ON evenements(source, horodatage);
