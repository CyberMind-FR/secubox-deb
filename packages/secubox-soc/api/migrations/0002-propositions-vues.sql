-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
-- SADE ACTIVE (#3839) : première vue de chaque proposition d'actord, par empreinte. L'exécuteur automatique n'agit que
-- sur une proposition vue pour la première fois APRÈS le passage en ACTIVE (`mode.depuis`) : l'arriéré reste à la main.
CREATE TABLE IF NOT EXISTS propositions_vues (
    empreinte TEXT PRIMARY KEY,
    vu_ts TEXT NOT NULL
);
