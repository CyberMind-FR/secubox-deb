-- UNE PLAYLIST SE DEPLIE EN PROPOSITIONS, PAS EN VALIDATIONS (#1047).
--
-- Le premier jet faisait heriter les morceaux de la decision prise sur la
-- liste : valider la playlist, c'etait valider ses cinquante titres. C'est
-- commode et c'est trop grossier — on ne connait pas une liste avant de l'avoir
-- vue, et cinquante titres entrent alors sans que personne ne les ait regardes.
--
-- Ils arrivent donc en PROPOSITIONS, et le sysop tranche a l'unite. `lot` les
-- garde groupes pour que le panneau les presente ensemble : cinquante lignes
-- melees au reste seraient illisibles.
ALTER TABLE pistes ADD COLUMN lot TEXT NOT NULL DEFAULT '';
ALTER TABLE pistes ADD COLUMN lot_titre TEXT NOT NULL DEFAULT '';

-- « Que contient ce lot » est la question du panneau des qu'une liste est
-- depliee.
CREATE INDEX idx_pistes_lot ON pistes(lot) WHERE lot <> '';
