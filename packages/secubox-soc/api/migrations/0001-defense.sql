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

-- Entrées amorcées : ni suppression ni modification, au niveau des données.
CREATE TRIGGER IF NOT EXISTS liste_blanche_amorcee_no_delete BEFORE DELETE ON liste_blanche
WHEN OLD.amorcee = 1
BEGIN
    SELECT RAISE(ABORT, 'entree amorcee non supprimable');
END;
CREATE TRIGGER IF NOT EXISTS liste_blanche_amorcee_no_update BEFORE UPDATE ON liste_blanche
WHEN OLD.amorcee = 1
BEGIN
    SELECT RAISE(ABORT, 'entree amorcee non modifiable');
END;
-- Amorçage unique : réseaux privés, boucle, lien-local, CGNAT (IPv4 et IPv6).
INSERT OR IGNORE INTO liste_blanche(cidr, motif, par, ts, amorcee) VALUES
    ('10.0.0.0/8', 'RFC 1918', 'systeme', strftime('%Y-%m-%dT%H:%M:%SZ','now'), 1),
    ('172.16.0.0/12', 'RFC 1918', 'systeme', strftime('%Y-%m-%dT%H:%M:%SZ','now'), 1),
    ('192.168.0.0/16', 'RFC 1918', 'systeme', strftime('%Y-%m-%dT%H:%M:%SZ','now'), 1),
    ('127.0.0.0/8', 'boucle locale', 'systeme', strftime('%Y-%m-%dT%H:%M:%SZ','now'), 1),
    ('169.254.0.0/16', 'lien-local', 'systeme', strftime('%Y-%m-%dT%H:%M:%SZ','now'), 1),
    ('100.64.0.0/10', 'CGNAT', 'systeme', strftime('%Y-%m-%dT%H:%M:%SZ','now'), 1),
    ('::1/128', 'boucle locale IPv6', 'systeme', strftime('%Y-%m-%dT%H:%M:%SZ','now'), 1),
    ('fc00::/7', 'ULA IPv6', 'systeme', strftime('%Y-%m-%dT%H:%M:%SZ','now'), 1),
    ('fe80::/10', 'lien-local IPv6', 'systeme', strftime('%Y-%m-%dT%H:%M:%SZ','now'), 1);
