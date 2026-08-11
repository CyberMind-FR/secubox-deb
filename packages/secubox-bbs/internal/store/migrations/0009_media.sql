-- Le media jouable d'un fil.
--
-- On stocke une REFERENCE, jamais le fichier : le media vit chez le module qui
-- l'a produit — PeerTube pour les videos, le podcaster pour les episodes. Le
-- recopier remplirait le disque et poserait la question de savoir laquelle des
-- deux copies fait foi.
--
--   kind = 'video' -> url est une adresse d'integration (iframe)
--   kind = 'audio' -> url est une adresse SERVIE PAR NOUS, qui relit le
--                     fichier deja telecharge par le podcaster.
--
-- Pourquoi ne pas pointer l'enclosure d'origine pour l'audio : elle est chez un
-- tiers (Radio France et consorts). Chaque ecoute depuis une page de la board
-- ferait alors contacter ce tiers par l'auditeur, avec son adresse et son
-- navigateur — alors que le fichier est deja sur le disque, a un metre.
ALTER TABLE threads ADD COLUMN media_url TEXT;
ALTER TABLE threads ADD COLUMN media_kind TEXT;
