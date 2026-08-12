# Guide de rédaction

## Le lecteur par défaut

Il ne connaît **pas** Linux, Debian, LXC, DNS, SMTP, IMAP, WireGuard, la
fédération ni les API. Il n'a pas à les connaître pour se servir de sa SecuBox.

Il n'est pas sot pour autant. Il ignore peut-être ce qu'est un enregistrement
DNS ; il sait parfaitement ce qu'il veut faire. Écrire pour lui, ce n'est pas
simplifier à l'excès — c'est **ne pas exiger de lui un savoir dont il n'a pas
besoin**.

Un terme technique s'explique **avant** d'être employé, ou ne s'emploie pas.

> ❌ « Le vhost est routé vers le backend via SNI. »
> ✅ « Votre site répond à son adresse : `monsite.exemple.fr`. »
>
> Et si le mot est inévitable, on le pose d'abord :
> ✅ « SecuBox range chaque service dans un **conteneur** — une boîte étanche
> qui l'empêche de gêner les autres. »

## Le principe qui commande tout

**Une source, tous les formats.**

Un sujet s'écrit **une fois**, dans une fiche source structurée, et se décline
ensuite en article, pas-à-pas, mémo, diaporama, script vidéo, aide contextuelle
ou FAQ.

Réécrire à chaque format, c'est diverger. Au troisième, les trois se
contredisent et plus personne ne sait lequel dit vrai. Voir la
[Content Factory](../factory/content-factory.md).

## Le principe qui protège le premier

**Rien ne s'invente.**

Toute affirmation technique doit être vérifiable dans le dépôt. Quand
l'information manque :

```text
À documenter
```

Quand on suppose :

```text
HYPOTHÈSE À VALIDER
```

Une hypothèse ne devient jamais un fait par simple ancienneté. Elle est datée,
signée, et vérifiée ou retirée.

**Pourquoi cette rigueur.** Une documentation qui comble ses trous par de la
vraisemblance ne se laisse plus auditer : on ne distingue plus ce qui a été
vérifié de ce qui a été supposé. Elle perd alors toute valeur — y compris là où
elle était juste.

## Chaque fiche cite sa source

En pied de fiche :

```text
Source technique :
  package:   packages/secubox-mail/
  service:   secubox-mail.service
  api:       GET /api/v1/mail/status
  web:       https://webmail.<domaine>/
```

Le but est qu'un lecteur puisse **vérifier la documentation contre le code**.
Une fiche invérifiable est une fiche qu'on ne peut pas corriger avec certitude.

## Écrire orienté action

| Écrire | Plutôt que |
|---|---|
| « Cliquez sur **Envoyer**. » | « Il convient de procéder à l'envoi. » |
| « Vous recevez un code par courriel. » | « Un code est envoyé. » |
| « Si rien ne s'affiche… » | « En cas de dysfonctionnement… » |

- Voix active. Deuxième personne.
- Une action par étape.
- L'étape dit ce que l'on **fait** et ce que l'on **voit ensuite**.

## Le vocabulaire des erreurs

Un message d'erreur dit **ce qui s'est passé** et **quoi faire**. Jamais
seulement qu'il y a eu un problème.

> ❌ « Erreur d'authentification. »
> ✅ « Mot de passe refusé. Vérifiez la casse, ou réinitialisez-le depuis
> *Mon compte*. »

## Longueur

- Un tutoriel : **5 à 8 étapes**. Au-delà, c'est deux tutoriels.
- Une phrase : une idée.
- Un paragraphe : trois ou quatre phrases.

Si une fiche déborde, ce n'est pas un problème de rédaction mais de découpage.

## Ce qu'on n'écrit pas

- Pas de « il suffit de », « simplement », « évidemment ». Si c'était évident,
  la fiche n'existerait pas.
- Pas de captures d'écran non datées : elles vieillissent en silence et finissent
  par contredire l'interface.
- Pas de chemin absolu propre à une board (`/data/lxc/…`) dans une fiche
  utilisateur — cela relève de l'administration.
- Pas de promesse au futur (« bientôt disponible ») : soit ça existe et on le
  documente, soit non et on n'en parle pas.

## Niveaux

| Niveau | Le lecteur… |
|---|---|
| **Débutant** | découvre SecuBox, ne connaît aucun terme technique |
| **Intermédiaire** | se sert de SecuBox tous les jours |
| **Avancé** | configure, règle, comprend ce qu'il change |
| **Administrateur** | dispose d'un accès système et en assume les conséquences |

Le niveau est déclaré dans la fiche. Il conditionne le vocabulaire admis :
un tutoriel *Débutant* qui emploie « socket Unix » a raté sa cible.

## Français

- Français par défaut ; les noms de produits gardent leur graphie
  (Nextcloud, PeerTube, Mastodon, WireGuard).
- Les commandes, chemins et noms de fichiers restent en anglais et en `code`.
- Voir [terminology.md](terminology.md) pour les termes tranchés une fois pour
  toutes.
