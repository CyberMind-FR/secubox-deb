# Règles éditoriales

Le [guide de rédaction](documentation-guidelines.md) dit *quoi* écrire.
Celui-ci dit *comment* l'écrire.

## Le ton

Accessible, précis, **jamais infantilisant**.

Le lecteur ignore peut-être ce qu'est un enregistrement DNS. Il n'est pas sot
pour autant : il sait ce qu'il veut faire, il ne sait pas comment le dire à la
machine. C'est tout.

> ❌ « Pas de panique, c'est tout simple ! »
> ❌ « Il vous suffit de configurer le résolveur. »
> ✅ « Cette étape prend deux minutes. »

« Il suffit de » suppose que c'est évident. Si c'était évident, la fiche
n'existerait pas.

## Personne et temps

- **Vous** pour le lecteur.
- **Présent** de l'indicatif. Pas de conditionnel : « vous verrez » et non
  « vous devriez voir ».
- Voix active.

## Titres

Un titre annonce une **action** ou une **question**, pas un thème.

| Écrire | Plutôt que |
|---|---|
| Envoyer un courriel | Messagerie |
| Pourquoi mon site affiche 403 ? | Erreurs HTTP |
| Partager un fichier | Gestion du partage |

## Nombres, unités, chemins

- Chiffres en chiffres dès 2 : « 3 étapes », « 2 minutes ».
- Unités collées à l'usage courant : `8 Go`, `2 min`.
- Chemins, commandes et noms de fichiers en `code`, toujours.
- Domaines d'exemple : `exemple.fr`. Jamais le domaine réel d'une board.

## Ce qui varie d'une installation à l'autre

Écrire `<domaine>` et expliquer une fois :

> Remplacez `<domaine>` par l'adresse de votre SecuBox — celle que vous
> utilisez pour vous connecter.

Écrire `gk2.secubox.in` dans une fiche générale la rend fausse pour tout le
monde sauf une personne.

## Les listes

- Liste **à puces** quand l'ordre est indifférent.
- Liste **numérotée** quand l'ordre compte — donc toujours pour les étapes.
- Pas de liste à un seul élément : c'est une phrase.

## Les liens

Le texte du lien dit **où l'on va**.

> ❌ Pour en savoir plus, cliquez [ici](…).
> ✅ Voir [Envoyer un courriel](…).

« Cliquez ici » est illisible pour un lecteur d'écran, qui annonce souvent les
liens hors de leur phrase.

## Les captures d'écran

- Datées, dans la fiche source.
- Recadrées sur la zone utile.
- Sans donnée personnelle.
- Jamais porteuses d'un texte qui devrait rester du texte : une image n'est ni
  traduisible, ni sélectionnable, ni lisible par une synthèse vocale.

## Ce qui se dit une fois

Un concept s'explique **dans une seule fiche**, et les autres y renvoient. Le
réexpliquer partout garantit que les explications finiront par diverger — et
qu'on ne saura plus laquelle corriger.

## Anglicismes

| Écrire | Plutôt que |
|---|---|
| courriel | mail, email |
| téléverser | uploader |
| identifiant | login |
| mot de passe | password |
| sauvegarde | backup |
| conteneur | container |

Les noms de produits gardent leur graphie : Nextcloud, PeerTube, Mastodon,
WireGuard, HAProxy.
