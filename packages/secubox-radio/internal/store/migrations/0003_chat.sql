-- CHAT DE L'ANTENNE (#1047).
--
-- POURQUOI PAS DE WEBSOCKET, ET POURQUOI CE N'EST PAS UN RENONCEMENT.
-- Les auditeurs interrogent DEJA le serveur pour rester synchronises — c'est
-- le principe meme de la radio : « quoi, et a quel instant ». Le chat voyage
-- donc dans la meme reponse, sans un octet de connexion en plus. Ouvrir un
-- canal permanent par auditeur pour transporter trois phrases serait payer
-- cher une latence dont personne ne profite.
--
-- LE PSEUDONYME EST COPIE ICI, ET C'EST DELIBERE. Le demon radio n'a pas de
-- table d'utilisateurs — l'identite vient de l'authentification SecuBox. Sans
-- cette copie, il faudrait interroger un autre service pour afficher chaque
-- ligne du chat, et une panne de ce service viderait la conversation de ses
-- noms. On retient donc ce qui etait vrai au moment ou la phrase a ete dite,
-- ce qui est d'ailleurs la bonne semantique pour un journal de conversation.
CREATE TABLE chat (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  pseudo  TEXT NOT NULL,
  corps   TEXT NOT NULL,
  dit_le  INTEGER NOT NULL,

  -- La piste qui passait. Une phrase dite pendant un morceau se comprend mal
  -- sans lui — et cela permettra de retrouver « ce qui se disait quand ca
  -- passait ».
  piste_id INTEGER REFERENCES pistes(id) ON DELETE SET NULL
);

-- « Qu'est-ce qui s'est dit depuis ma derniere question » est LA requete du
-- chat, posee par chaque auditeur a chaque sondage.
CREATE INDEX idx_chat_recent ON chat(id DESC);
