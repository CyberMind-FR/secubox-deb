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

## Le WAF bloque un envoi de fichier

Regarder `waf-threats.log` : une categorie `rce`/`sqli` sur un `POST` de media
est presque toujours un FAUX POSITIF. Les regles cherchent du texte ; les
octets d'une image en contiennent par hasard. sbxwaf s'abstient desormais sur
les corps binaires — si le cas revient, verifier que le `Content-Type` est bien
reconnu par `corpsBinaire()`.

## `pkill -f` tue ma propre session

Le motif figure dans la ligne de commande du shell distant qui l'execute.
Utiliser les PID (`pgrep` puis `kill`), jamais `pkill -f` avec un motif qu'on
vient d'ecrire. Erreur commise trois fois le 2026-08-17.

## Un import de groupe prend des minutes

`secubox-groupd` importe 84 modules : compter plusieurs minutes, pas 40
secondes. Un controle trop precoce conclut a tort a l'echec — c'est ce qui m'a
fait replier trois groupes qui auraient marche.

## Un paquet s'installe mais le binaire ne change pas

Verifier QUEL paquet livre le binaire : `dpkg -S`. Les sources de `sbxwaf`
vivent dans `secubox-toolbox-ng` mais c'est `secubox-waf-ng` qui l'installe.
J'ai construit le mauvais paquet deux fois.
