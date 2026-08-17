-- PIECES JOINTES : relier un fichier deja depose a un message (#1044).
--
-- CE QUI MANQUAIT, ET RIEN D'AUTRE. Le depot accepte deja `audio/ogg`,
-- `audio/webm`, `video/webm`, `video/mp4` — exactement ce que produit
-- `MediaRecorder` — les valide par leur CONTENU (`http.DetectContentType`) et
-- les sert avec `nosniff` et les requetes par plages. Il ne manquait donc pas la
-- capacite d'accepter un media : il manquait le LIEN entre ce media et un
-- message. Cette migration ne fait que cela.
--
-- DEUX CLES ETRANGERES PLUTOT QU'UN COUPLE (type, id). La solution
-- polymorphique — une colonne `cible_type` en texte et une `cible_id` — est
-- plus courte a ecrire et ne vaut rien : SQLite ne peut alors verifier aucune
-- integrite, et une piece jointe survit a la disparition de son message en
-- pointant dans le vide. Ici, chaque lien est une VRAIE cle etrangere : la base
-- refuse elle-meme l'incoherence, et le nettoyage est automatique.
--
-- EXACTEMENT UNE CIBLE, garantie par la base et non par la discipline du code.
-- Sans cette contrainte, une ligne pourrait viser un fil ET un message prive —
-- et la fuite serait silencieuse : le media d'une conversation privee
-- apparaitrait dans un salon public.
CREATE TABLE pieces_jointes (
  id         INTEGER PRIMARY KEY,

  -- Le fichier vient de la bibliotheque existante. `ON DELETE CASCADE` : si le
  -- fichier est efface pour de bon, le lien n'a plus d'objet.
  --
  -- ATTENTION : `files` connait aussi la suppression DOUCE (`deleted_at`), qui
  -- ne declenche pas cette cascade — c'est voulu. Un media retire par la
  -- moderation doit laisser sa trace dans le fil (« piece jointe supprimee »)
  -- plutot que de s'evaporer et de rendre la conversation incomprehensible.
  file_id    INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,

  -- L'une des deux, jamais les deux, jamais aucune.
  post_id    INTEGER REFERENCES posts(id)    ON DELETE CASCADE,
  message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,

  -- L'ORDRE EST DONNE, PAS DEVINE. Deux pieces jointes deposees dans la meme
  -- seconde sortiraient dans un ordre arbitraire si l'on triait par date ; un
  -- rang explicite rend l'affichage stable d'une lecture a l'autre.
  rang       INTEGER NOT NULL DEFAULT 0,

  cree_le    INTEGER NOT NULL,

  CHECK ((post_id IS NULL) <> (message_id IS NULL))
);

-- LES DEUX SENS SONT INTERROGES. Afficher un fil demande « les pieces de ce
-- message » ; moderer ou supprimer un fichier demande « ou est-il employe ».
-- Sans le second index, la seconde question balaie toute la table.
CREATE INDEX idx_pj_post    ON pieces_jointes(post_id, rang);
CREATE INDEX idx_pj_message ON pieces_jointes(message_id, rang);
CREATE INDEX idx_pj_file    ON pieces_jointes(file_id);

-- UN MEME FICHIER NE S'ATTACHE PAS DEUX FOIS AU MEME MESSAGE. Un double clic
-- sur « envoyer » ne doit pas afficher le vocal en double.
CREATE UNIQUE INDEX idx_pj_unicite_post
  ON pieces_jointes(post_id, file_id) WHERE post_id IS NOT NULL;
CREATE UNIQUE INDEX idx_pj_unicite_message
  ON pieces_jointes(message_id, file_id) WHERE message_id IS NOT NULL;

-- LA DUREE APPARTIENT AU FICHIER, PAS AU LIEN. Un meme vocal transfere dans un
-- second fil garde la meme duree ; la stocker sur le lien la dupliquerait et
-- ouvrirait la porte a deux valeurs contradictoires pour un seul son.
--
-- Elle est renseignee par le navigateur a l'enregistrement. C'est une donnee
-- d'AGREMENT — elle sert a ecrire « 0:23 » avant lecture — et jamais une donnee
-- de securite : rien ne doit en dependre pour decider quoi que ce soit.
ALTER TABLE files ADD COLUMN duree_ms INTEGER;
