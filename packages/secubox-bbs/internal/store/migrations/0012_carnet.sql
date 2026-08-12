-- CARNET D'ADRESSES (#1008).
--
-- POURQUOI UNE TABLE PLUTOT QU'UNE LISTE DE BOUTONS.
--
-- Le selecteur de destinataire affichait TOUS les comptes ouverts, en pastilles.
-- Cela tient a cinq membres et devient illisible a cinquante : on cherche un
-- nom dans un mur, et la page grossit avec l'annuaire. Un carnet nomme ce qu'on
-- utilise vraiment — les quelques personnes a qui l'on ecrit — et l'annuaire
-- complet devient une RECHERCHE, pas un affichage.
--
-- LE FAVORI EST UNIDIRECTIONNEL, comme un carnet d'adresses papier : mettre
-- quelqu'un dans son carnet ne l'oblige a rien, ne le lui apprend pas, et ne
-- cree aucune relation reciproque. Ce n'est pas un « ami », c'est un raccourci.
CREATE TABLE carnet (
  proprietaire INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ajoute_at    INTEGER NOT NULL,
  -- Un libelle libre : « le voisin du dessus », « support fibre ». Le
  -- pseudonyme ne dit pas toujours qui c'est, six mois plus tard.
  note         TEXT,
  PRIMARY KEY (proprietaire, contact)
);

-- L'acces normal est « le carnet de X », toujours dans cet ordre.
CREATE INDEX idx_carnet_proprietaire ON carnet(proprietaire, ajoute_at DESC);
