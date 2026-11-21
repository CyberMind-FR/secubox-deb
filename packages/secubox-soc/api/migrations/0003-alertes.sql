-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
-- SADE (#3839) : alertes d'état visibles dans /defense/status, partagées par l'API et l'exécuteur sade-auto.
-- `audit_indisponible` : un passage en OBSERVE (jamais bloqué par l'audit) n'a pas pu écrire ses lignes d'audit.
CREATE TABLE IF NOT EXISTS alertes (
    cle TEXT PRIMARY KEY,
    depuis TEXT NOT NULL,
    detail TEXT NOT NULL
);
