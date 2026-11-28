-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- #4058 — CHRONOLOGIE AUDIO d'un billet : le diaporama suit la lecture de l'audio joint.
--
-- `chronologie` : NULL = pas de chronologie (diaporama au minuteur, comme avant) ; sinon JSON validé par models.valider_chronologie,
-- liste de {"debut_s", "fin_s", "diapo", "replique"}. Champ du billet (et non média JSON joint) : posé et effacé avec le billet,
-- dans la même écriture, versionné par ses révisions, sans fichier ni route de plus.
ALTER TABLE billet ADD COLUMN chronologie TEXT;
