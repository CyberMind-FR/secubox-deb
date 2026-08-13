# Défauts repérés en documentant

Cette page **constate**. Elle ne corrige rien.

Documenter oblige à suivre les chemins réels, et c'est là qu'on bute sur ce
qu'un développeur ne rencontre jamais : le cas où l'on s'est trompé. Les
entrées ci-dessous sont des observations vérifiées, à traiter dans le code, pas
dans la documentation.

Format : ce qui a été observé, ce que cela coûte à l'utilisateur, et où
regarder.

---

## BBS — une publication « locale » par erreur ne se corrige pas depuis l'interface

**Observé le 2026-08-12**, sur le fil `508` (« LA DOC SECUBOX ») de
`bbs.gk2.secubox.in`.

Le fil avait été publié en **local** alors qu'il était destiné au public. Le
rendre public a demandé **deux** modifications SQL directes en base :

```sql
UPDATE threads SET visibility = 'public' WHERE id = 508;
UPDATE posts   SET visibility = 'public' WHERE thread_id = 508;
```

Trois observations distinctes :

1. **Aucune commande ne le permet.** `bbsctl` expose quatorze verbes
   (`status`, `reindex`, `invite`, `salon`, `user-add`, `user-passwd`,
   `ingest`…) — aucun ne touche à la visibilité d'un fil ou d'un message.

2. **La visibilité du fil ne suffit pas.** `threads.visibility` et
   `posts.visibility` sont indépendants. Passer le fil en public sans ses
   messages produit une publication refusée par
   `internal/billets/client.go:153` :

   > `aucun message public dans ce fil`

   Le message est exact, mais l'utilisateur qui vient de rendre son fil public
   n'a aucun moyen de deviner qu'il restait un second interrupteur.

3. **Le choix est irréversible en pratique.** Une erreur au moment de la
   publication — un geste courant — ne se rattrape qu'avec un accès root et
   `sqlite3`.

**Coût utilisateur** : un billet destiné au public reste invisible, sans
recours, et le message d'erreur ne désigne pas le remède.

**Où regarder**

```text
package:  packages/secubox-bbs/
schema:   threads.visibility, posts.visibility  (CHECK IN ('local','public'))
refus:    packages/secubox-bbs/internal/billets/client.go:153
cli:      packages/secubox-bbs/cmd/bbsctl/
```

**Piste** — un verbe `bbsctl thread-visibility <id> <local|public>` qui traite
le fil **et** ses messages d'un seul geste, et une bascule équivalente dans la
webui. Le point de conception à trancher : rendre un fil public doit-il
publier ses messages existants, ou seulement autoriser les suivants ? Les deux
réponses se défendent — le silence actuel, non.

---

## MetaBlogizer — cinq sites publiés répondent 403, faute de page d'accueil

**Observé le 2026-08-12.**

Cinq sites n'ont pas d'`index.html` : `entamoir`, `files-70`, `perdu`, `zem`,
`zifon`. nginx répond alors **403 Forbidden**.

Le panneau les affiche pourtant comme **publiés**. C'est le même écart que
celui corrigé en #1012 : l'interface affirme une chose, le serveur en fait une
autre, et rien ne signale la contradiction.

`403 Forbidden` ne dit rien à un utilisateur non technique — surtout pour un
site qu'on vient de lui présenter comme publié.

**Coût utilisateur** : on croit avoir publié, on obtient une erreur d'interdit
sans rapport avec la cause réelle, qui est l'absence de page d'accueil.

**Où regarder**

```text
package:  packages/secubox-metablogizer/
sites:    /data/metablogizer/sites/<nom>/
```

**Piste** — signaler « ce site n'a pas de page d'accueil » à la publication, et
servir une page explicite plutôt qu'un 403 nu. Le module possède déjà une page
`empty-site.html` pour les sites vides : le cas « des fichiers mais pas
d'index » y échappe.

---

## secubox-mail — `publishctl cert` ne peut pas fonctionner sur cette board

**Observé le 2026-08-12**, en publiant `aletheiavox.eu`.

```sh
certbot certonly --standalone --preferred-challenges http -d "$domain"
```

`--standalone` demande à certbot d'ouvrir lui-même le port 80. Or **HAProxy le
détient** sur cette board. La commande ne peut aboutir.

La méthode qui fonctionne, et qu'emploient les certificats déjà en place
(`live.maegia.tv`, `mail.maegia.tv`, `money.maegia.tv`, `sliders.maegia.tv`) :

```sh
certbot certonly --webroot -w /usr/share/secubox/www -d "$domain"
```

**Coût utilisateur** : le chemin outillé échoue, et l'obtention d'un
certificat retombe sur une commande tapée à la main — donc sur la mémoire de
celui qui l'a déjà faite.

**Où regarder**

```text
outil:    /usr/sbin/secubox-publishctl, fonction cert()
temoin:   /etc/letsencrypt/renewal/*.conf  (authenticator = webroot)
webroot:  /usr/share/secubox/www
```

---

## Limite connue de l'inventaire — les modules en Go n'exposent pas leurs routes

`scripts/tutorial-audit.py` lit les décorateurs FastAPI (`@app.get`,
`@router.post`). Les modules écrits en **Go** — `secubox-bbs` au premier chef —
déclarent leurs routes autrement, et ressortent donc avec **0 route** dans le
catalogue.

Ce n'est pas un défaut du code mais une lacune de l'outil, signalée ici pour
qu'elle ne se lise pas comme un fait : `secubox-bbs` a bien une API web, le
catalogue ne sait simplement pas encore la voir.

**Où regarder** — `packages/secubox-bbs/internal/web/`, où les routes sont
enregistrées sur un `http.ServeMux`.
