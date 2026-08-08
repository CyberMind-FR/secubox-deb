-- Pour QUI une invitation a ete emise.
--
-- Purement indicatif : le code n'est lie a personne et quiconque l'a peut
-- s'en servir. Mais une console qui affiche « 3 invitations ouvertes » sans
-- dire a qui elles etaient destinees ne permet pas de decider laquelle
-- revoquer — donc on ne revoque jamais rien.
ALTER TABLE invites ADD COLUMN label TEXT;
