# FAQ — pieges recurrents de SecuBox-DEB

Les questions qui reviennent, avec la reponse verifiee.

## Un service redemarre en boucle sans rien dire

Regarder `systemctl show <u> -p NRestarts --value`. Si le compteur est enorme,
c'est presque toujours la socket : `/run/secubox` est en **1777**, on n'y delie
que ce qu'on possede, et une socket laissee par un autre utilisateur rend le
demarrage impossible. Parade : `ExecStartPre=+/bin/rm -f <sa socket>`. **Le `+`
est indispensable** — sans lui la ligne echoue comme le demon.

## Une page web servie perimee apres un deploiement

Le cache media de sbxwaf garde une URL une heure. La parade durable est une
**empreinte du contenu dans l'URL** (`radio.css?v=<hash>`), comme le fait
`secubox-radio`. En depannage, purger l'entree — mais purger le corps SANS son
annexe `.m` produit un pire defaut : sans type stocke, Go devine et repond
`text/plain`, le navigateur jette la feuille.

## `grep` sur une directive systemd

**Inutilisable.** De nombreuses unites portent la directive dans un commentaire
expliquant qu'on ne la declare pas. Toujours
`systemctl show <u> -p <directive> --value`.

## `dch` introuvable

`devscripts` n'est pas installe sur le poste de developpement. Ecrire l'entree
de changelog a la main. Toute source modifiee et redeployee **doit** monter de
version : patch pour une correction, mediane pour une fonctionnalite, majeure
pour une release.

## Un correctif source qui n'atteint pas la board

Verifier que le depot n'est pas **en retard** sur la board : c'etait le cas de
`secubox-antirootkit` (depot 0.1.0, board 0.1.1). Corriger la source telle
quelle aurait ecrase une meilleure version. Comparer avant d'ecrire.
