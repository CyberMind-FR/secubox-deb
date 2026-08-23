-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- MetaNews — vignettes : image d'article (media/enclosure/img) + image de sujet.
ALTER TABLE article ADD COLUMN image TEXT NOT NULL DEFAULT '';
ALTER TABLE topic   ADD COLUMN vignette TEXT NOT NULL DEFAULT '';
