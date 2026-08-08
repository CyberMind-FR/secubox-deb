-- Derniere connexion reussie.
--
-- Sert a repondre a « ce compte sert-il encore ? » sans deviner. Un compte
-- inutilise depuis un an est un compte a desactiver ; sans cette date, on ne
-- desactive jamais rien, par prudence, et la liste des comptes ne fait que
-- croitre.
ALTER TABLE users ADD COLUMN last_login_at INTEGER;

-- Derniere adresse vue. Volontairement UNE seule, pas un historique :
-- conserver la trace de tous les acces d'un membre serait une surveillance que
-- personne n'a demandee, et qui ferait de ce fichier une cible.
ALTER TABLE users ADD COLUMN last_login_ip TEXT;
