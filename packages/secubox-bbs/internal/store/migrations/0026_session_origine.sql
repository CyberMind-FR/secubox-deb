-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
--
-- L'ORIGINE D'UNE SESSION (#1440). Une session ouverte par le Hall
-- (/sbx/entrer, /sbx/auto) DÉRIVE d'une session SecuBox : elle ne doit pas lui
-- survivre. On le note sur la session, pas sur le compte — les comptes créés
-- par l'authentification unique portent auth_source='local'.
ALTER TABLE sessions ADD COLUMN origine TEXT NOT NULL DEFAULT 'local';
