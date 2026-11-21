-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Revue finale #3723 (phases 4-7).
-- `propositions.reessai_le` : un refus NON définitif de gk2 (`sade_observe`, `sade_reactive`, `protegee_inconnue`)
-- rend la proposition à son état (proposée ou approuvée) sans consommer de plafond ; elle ne repart pas avant cette
-- heure (jamais de renvoi en boucle), et expire comme les autres.
-- `evenements.rule_id` : la règle de sbxwaf (`rule_id`), rangée à part de `message` ; les touches d'un filtre WAF
-- d'office (`ia_filtres_*`) se lisent sur elle seule (un champ `message` ajouté par sbxwaf ne les masque jamais).
ALTER TABLE propositions ADD COLUMN reessai_le TEXT;
ALTER TABLE evenements ADD COLUMN rule_id TEXT;
CREATE INDEX IF NOT EXISTS idx_evt_rule ON evenements(rule_id, horodatage) WHERE rule_id IS NOT NULL;
