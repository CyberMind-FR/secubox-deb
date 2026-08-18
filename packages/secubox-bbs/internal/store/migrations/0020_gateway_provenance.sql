-- Provenance : l'histoire de chaque contenu, dans une chaîne vérifiable.
--
-- La chaîne est GLOBALE et non par contenu. Une chaîne par contenu laisserait
-- effacer tout l'historique d'un objet — donc son origine — sans que rien ne le
-- signale ; ici, la disparition d'un seul maillon casse la chaîne commune.

CREATE TABLE gateway_provenance (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  empreinte TEXT NOT NULL,
  horodate  INTEGER NOT NULL,
  evenement TEXT NOT NULL,
  acteur    TEXT NOT NULL DEFAULT '',
  details   TEXT NOT NULL DEFAULT '{}',
  precedent TEXT NOT NULL DEFAULT '',
  somme     TEXT NOT NULL
);

CREATE INDEX gateway_provenance_empreinte ON gateway_provenance(empreinte, id);

-- Append-only imposé par la base : même un défaut de code ne doit pas pouvoir
-- réécrire une ligne déjà posée. La chaîne détecterait la falsification, mais
-- mieux vaut l'empêcher que la constater.
CREATE TRIGGER gateway_provenance_immuable_maj
BEFORE UPDATE ON gateway_provenance
BEGIN
  SELECT RAISE(ABORT, 'journal de provenance : écriture seule en ajout');
END;

CREATE TRIGGER gateway_provenance_immuable_suppr
BEFORE DELETE ON gateway_provenance
BEGIN
  SELECT RAISE(ABORT, 'journal de provenance : suppression interdite');
END;
