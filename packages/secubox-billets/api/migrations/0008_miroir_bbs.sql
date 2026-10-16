-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- #2778 — MIROIR DES RÉPONSES PUBLIQUES DU BBS : un post public d'un fil BBS lié à un billet devient un commentaire SYSTÈME du billet.
--
-- `source`     : NULL = commentaire écrit ici ; 'bbs' = réponse publique miroir d'un fil du BBS (jamais saisi par un visiteur).
-- `source_ref` : identifiant du post d'origine (« bbs:1218 ») : rend la synchronisation idempotente et permet de retirer la réponse si elle cesse d'être publique.
-- `author_ref` : l'auteur en RÉFÉRENCE (« bbs:frodon ») : un nom affiché, pas un compte d'ici.
ALTER TABLE comment ADD COLUMN source TEXT;
ALTER TABLE comment ADD COLUMN source_ref TEXT;
ALTER TABLE comment ADD COLUMN author_ref TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_comment_source_ref ON comment(billet_id, source_ref) WHERE source_ref IS NOT NULL;
