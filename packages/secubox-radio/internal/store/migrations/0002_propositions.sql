-- PROPOSITIONS : le membre propose, les autres soutiennent, le sysop valide
-- (#1047).
--
-- CE QUI EST AJOUTE, ET CE QUI NE L'EST PAS. On aurait pu creer une table
-- `propositions` separee, puis deplacer la ligne vers `pistes` a la
-- validation. C'est un piege : les coeurs poses sur la proposition seraient
-- restes attaches a une ligne disparue, et l'enthousiasme qui a fait entrer un
-- titre aurait ete perdu au moment precis ou il devient utile — c'est lui qui
-- doit peser dans le tirage.
--
-- Une piste est donc UNE ligne, qui change d'etat. Les coeurs la suivent.
ALTER TABLE pistes ADD COLUMN etat TEXT NOT NULL DEFAULT 'validee'
  CHECK (etat IN ('proposee','validee','refusee'));

-- QUI A TRANCHE, ET POURQUOI. Un refus sans motif se represente le lendemain :
-- la question « pourquoi pas celle-la » doit avoir une reponse ecrite.
ALTER TABLE pistes ADD COLUMN decide_par INTEGER;
ALTER TABLE pistes ADD COLUMN decide_le  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pistes ADD COLUMN motif      TEXT NOT NULL DEFAULT '';

-- `'validee'` par defaut, et c'est voulu : les pistes deja en base ont ete
-- ajoutees avant qu'il existe une file de propositions. Les basculer en
-- `proposee` aurait vide l'antenne d'un coup a la migration.

-- Les deux questions posees en boucle : « que joue-t-on » et « qu'y a-t-il a
-- valider ».
CREATE INDEX idx_pistes_etat ON pistes(etat, ajoute_le);
