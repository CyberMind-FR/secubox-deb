-- « MOINS SOUVENT » : le contraire du coeur, pose par le sysop.
--
-- Un titre pousse vers le bas RESTE dans la radio (ni supprime, ni refuse, ni renvoye en validation) mais le tirage lui applique un
-- facteur faible : il passe nettement plus rarement. 0 par defaut = traitement ordinaire.
ALTER TABLE pistes ADD COLUMN bas INTEGER NOT NULL DEFAULT 0;
