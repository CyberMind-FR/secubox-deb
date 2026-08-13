-- SOUS-SALONS ET DEPUBLICATION (#1020 suite).
--
-- POURQUOI UN PARENT PLUTOT QUE DEUX NIVEAUX EN DUR.
--
-- Un BBS grandit par regroupement : « Technique » finit par contenir « Reseau »,
-- « Materiel », « Logiciel ». Modeliser ce regroupement par une colonne parent
-- coute une ligne ; le modeliser par deux tables (sections / forums) fige la
-- profondeur a deux et oblige a tout reecrire le jour ou l'on en veut trois.
--
-- NULL = salon de premier niveau. C'est l'etat de TOUS les salons existants, et
-- la migration ne touche donc a rien.
ALTER TABLE categories ADD COLUMN parent_id INTEGER REFERENCES categories(id);

-- La liste des salons est affichee a chaque page : sans index, l'arbre se
-- reconstruit par balayage complet a chaque fois.
CREATE INDEX idx_categories_parent ON categories(parent_id);
