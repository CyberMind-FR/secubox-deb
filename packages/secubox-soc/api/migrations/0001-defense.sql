-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
-- SADE (#3839) : mode, seuils, liste blanche, décisions.
CREATE TABLE IF NOT EXISTS mode (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    valeur TEXT NOT NULL,
    depuis TEXT NOT NULL,
    par TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS seuils (
    cle TEXT PRIMARY KEY,
    valeur TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS liste_blanche (
    cidr TEXT PRIMARY KEY,
    motif TEXT NOT NULL,
    par TEXT NOT NULL,
    ts TEXT NOT NULL,
    amorcee INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    menace_id TEXT NOT NULL,
    cible TEXT NOT NULL,
    geste TEXT NOT NULL,
    score INTEGER,
    etat TEXT NOT NULL,
    demande_ts TEXT NOT NULL,
    tranche_ts TEXT,
    par TEXT,
    resultat TEXT,
    UNIQUE (menace_id, geste)
);
