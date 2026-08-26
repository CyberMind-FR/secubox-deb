<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Cardlets SBXOS — guide du module

*Ce document ne raconte pas comment une carte devrait marcher. Il liste ce qui
a réellement cassé en la construisant, le symptôme exact que ça produisait, et
la règle qui en découle.* Chaque piège ici a été observé sur `gk2`, pas
supposé.

Le **contrat** d'une carte (ce qu'elle montre, ce qu'elle ne montre pas, les
trois degrés d'intégration) est dans [`WEBOS-DESIGN.md`](WEBOS-DESIGN.md) §2 et
§3. Ce guide-ci est la **liste de contrôle du développeur de module** : ce
qu'il faut faire, dans quel ordre, et ce qui va échouer silencieusement s'il
ne le fait pas.

---

## 0. La question préalable : ce service mérite-t-il une carte ?

Non par défaut. Une carte se justifie quand le service a **quelque chose à
dire sans qu'on le lui demande** — un dernier billet, un fil qui bouge, un
chiffre qui change, un flux qui joue.

kbin a eu une carte pendant des semaines. Un forum entier tassé dans 280 px ne
montre rien qu'on puisse lire : c'était une capture d'écran illisible qui
coûtait une requête et une iframe. Il a été retiré de `EMBEDDABLE` et garde sa
carte classique, donc son accès (#1321).

> **Règle.** Si le résumé d'un service tient en son nom et son état, il n'a pas
> besoin d'une carte — il a besoin d'un lien. Une carte qui n'apprend rien est
> pire qu'une absence de carte : elle occupe la place d'une qui aurait servi.

Corollaire : **ne jamais inventer à un service des fonctions qu'il n'a pas.**
YTSaS n'en a qu'une — une URL, un bouton de capture. Sa carte a longtemps porté
« Ouvrir » et « Nouvelle capture », qui menaient tous deux au même endroit, en
plus loin. Ils ont été retirés (#1320).

---

## 1. Servir la carte

### 1.1 Aucun `<style>` ni `<script>` en ligne

Un module qui sert une CSP stricte — et il le doit — bloque ses propres blocs
en ligne. `style-src 'self'` et `script-src 'self'` ne connaissent pas
d'exception pour « c'est ma page ».

**Symptôme observé** : la carte BBS puis la carte Billets se sont affichées en
**HTML brut**, balises visibles, aucune mise en forme. On a cru à une erreur de
gabarit ; c'était la CSP.

```
/micro          → le HTML seul
/static/micro.css → la feuille
/static/micro.js  → le script
```

Les données passent par **attributs** (`data-fils="…"`), jamais par un
`<script>` de sérialisation en ligne.

### 1.2 `Cache-Control: no-cache`, sur la carte ET ses assets

**Symptôme observé** : une erreur CSP déjà corrigée continuait de s'afficher.
On a perdu du temps à chercher le bug dans le code servi — puis on a **haché
tous les scripts en ligne servis, aucun ne correspondait au hash bloqué**. Le
navigateur rejouait une copie heuristiquement mise en cache d'une version
morte.

Une carte est rechargée à chaque ouverture du Hall. Elle n'a rien à gagner à
être cachée, et tout à perdre.

### 1.3 `add_header` dans un `location` **remplace** ceux hérités

Ce n'est pas un cumul. Poser un seul `add_header` dans un bloc annule tous ceux
du `server`. C'est utilisé volontairement pour le lecteur PeerTube — dont la
CSP doit autoriser `blob:` — mais c'est un piège partout ailleurs.

---

## 2. Se laisser encadrer

Le détail est en [`WEBOS-DESIGN.md`](WEBOS-DESIGN.md) §4. Ce qu'il faut retenir
côté module :

| | |
|---|---|
| `frame-ancestors` | réécrit **au proxy**, une fois, pas dans le module |
| `X-Frame-Options` | retiré au proxy — ne pas en poser |
| Témoins | `SameSite=None; Secure` — voir `MODULE-GUIDELINES.md` §8bis |
| `Partitioned` | **jamais** — cf. 2.2 |
| Safari / iOS / TV | ne recevront **aucun** témoin tiers — cf. 2.3 |

### 2.1 Les règles de réécriture s'émettent UNE fois

**Symptôme observé** : le webmail redemandait les identifiants à chaque clic.
La règle `Set-Cookie … ; SameSite=None; Secure` était émise **par vhost**, donc
appliquée cinq fois : le témoin sortait avec `Secure` cinq fois de suite, et
n'était plus reconnu.

Dans `haproxyctl`, chaque vhost pose seulement une **marque**
(`http-request set-var(txn.cookies_tiers)`), et les `http-response` sont émises
une seule fois après la boucle.

> Note pour qui débogue HAProxy : une règle `http-response` **ne peut pas** lire
> `hdr(host)` — à ce moment-là elle échantillonne la *réponse*. Les règles de
> cadrage n'ont donc jamais rien fait pendant des jours, sans une ligne de log.
> C'est ce qui a imposé le passage par `set-var(txn.…)`.

### 2.2 `Partitioned` casse ce qu'il prétend protéger

Il donne au site encadrant **sa propre** session. Le webmail affichait « non
concordance de témoin » : l'utilisateur était connecté dans son onglet et
inconnu dans la carte. Retiré.

### 2.3 Prévoir le porteur d'identité hors témoin

Safari, iOS et les téléviseurs refusent les témoins tiers, quelles que soient
les en-têtes. Un module dont la carte doit lire quelque chose d'authentifié
doit accepter **un identifiant dans l'URL**.

**Symptôme observé** : la radio était muette sur iPhone et sur la TV, et
seulement là. Trois causes empilées, dont celle-ci : `/media/40` répondait 401
faute de témoin. La radio accepte désormais `?a=<identifiant>` — vérifié
`/media/40?a=…` → 200, sans → 401.

### 2.4 `X-Forwarded-Proto`

À poser à HAProxy **et** à repasser à chaque `proxy_pass` nginx. Sans lui, le
module croit servir en clair et fabrique des URL `http://` qu'un cadre en HTTPS
refuse. *Encore incomplètement résolu entre HAProxy et l'application — noté
dans `WIP.md`.*

---

## 3. Parler au Hall

### 3.1 Annoncer ce qu'on joue, et continuer de l'annoncer

Le Hall retire de sa barre média tout flux muet depuis dix secondes — c'est ce
qui fait disparaître une rangée quand un service meurt. Une carte qui n'annonce
qu'au lancement disparaît de la barre dix secondes plus tard alors qu'elle joue
encore. **Il faut un battement.**

### 3.2 Une seule instance par service

Le Hall coupe les autres cadres d'un même service quand l'un démarre, et met en
pause l'audio quand une vidéo démarre. La carte doit **accepter** les commandes
`pause`, `vol`, `muet`, et `zoom` si elle porte de la vidéo.

### 3.3 Le thème arrive par `postMessage`, à tout moment

**Symptôme observé** : le basculement clair/sombre ne prenait plus sans
rechargement forcé. La diffusion du thème était conditionnée à un attribut posé
au `load` du cadre — or **un cadre restauré depuis le cache ne déclenche jamais
`load`**. La condition ne devenait donc jamais vraie.

Le Hall envoie maintenant sans condition. Côté carte : écouter en permanence,
ne rien supposer d'un événement de chargement.

### 3.4 Les liens restent dans le Hall

`target="_top"` remplace le Hall : mosaïque perdue, barre média coupée, lecture
interrompue. Une carte demande au Hall d'embarquer (`postMessage {sbx:'ouvre'}`)
plutôt que de naviguer elle-même.

---

## 4. Parler à un amont qu'on ne maîtrise pas

### 4.1 Un handshake n'est pas une requête

**Symptôme observé** : `Embed player crashed: can't access property "length",
n.publish is undefined`, puis le lecteur PeerTube affichait *« player is not
compatible with your web browser »*. Il accusait le navigateur d'une panne que
**nous** causions.

**Le message mentait, et il a coûté deux diagnostics.** Le lecteur installe
`window.onerror = displayIncompatibleBrowser` : **n'importe quelle** erreur
JavaScript s'y affiche sous le texte « votre navigateur est incompatible ». Le
navigateur n'avait rien.

La vraie cause était dans notre réponse. On répondait `params: 'pong'`, une
**chaîne**, là où leur implémentation lit :

```js
n.type === 'publish-request' && notify({ … publish: h })
for (var r = 0; r < n.publish.length; r++) …
```

`params.publish` valait `undefined`, d'où le `can't access property "length"`.
La réponse attendue est un **objet** — `{type:'publish-reply', publish:[]}` —
portant la liste des méthodes qu'on expose, vide quand on se contente
d'écouter.

> **Règle.** Un message d'erreur d'un composant tiers désigne rarement sa
> cause, et un `window.onerror` global les rend tous identiques. **Lire le code
> qui lève** avant de croire le texte affiché : ici, `grep` sur le bundle servi
> a donné la réponse en une commande, après deux hypothèses fausses fondées sur
> le seul message.

> **Règle.** Face à un protocole de fenêtre qu'on n'a pas écrit : **répondre,
> ne pas initier**, et répondre dans la forme exacte que son code attend — pas
> celle que sa documentation ou son nom suggèrent.

Deux détails qui coûtent chacun une demi-journée si on les ignore :
jschannel poste des **chaînes JSON**, pas des objets (un test « est-ce un
objet ? » rejette tout en silence) ; et ses méthodes sont **préfixées par la
portée** (`peertube::__ready`, pas `__ready`).

### 4.2 Les assets d'un amont sont demandés en chemin **absolu**

La page d'embarquement de PeerTube référence `/client/…` et `/plugins/…` sans
savoir qu'elle est servie sous `/pt/`. Ces requêtes tombaient dans le
`location /` du Hall, **qui répondait 200 avec son index.html** : du HTML là où
le navigateur attendait du JavaScript.

> **Règle.** Quand on sert un amont sous un préfixe, ouvrir aussi ses espaces
> d'assets à la racine — ou réécrire ses chemins. Et se souvenir qu'**un 404
> aurait été plus lisible qu'un 200 de la mauvaise nature** : c'est ce 200 qui
> a rendu la panne opaque.

---

## 5. Agir depuis une carte

Une carte qui n'affiche que des chiffres est une vignette. Les cartes utiles
**font** quelque chose. Cadre en place (`api/actions.py`) :

### 5.1 Liste fermée d'actions, champs déclarés

```python
ACTIONS = {
  "torrent": {"ajouter": ("POST", "/api/v1/torrent/add", ("magnet",))},
}
```

Méthode, chemin et **champs autorisés** sont déclarés. Ce qui n'est pas nommé
n'est pas transmis. Les identifiants substitués dans un chemin sont validés
contre un alphabet explicite — jamais interpolés tels quels.

### 5.2 Lire les vraies routes du module, pas les routes espérées

Le dépôt paraissait n'avoir rien à montrer : sa liste était vide. Ses routes
`/storage`, `/history`, `/summary` existaient, **authentifiées**, et disaient
l'essentiel. Il a suffi de les lire.

Corollaire : **relayer le jeton de l'appelant** vers ces routes. Ce n'est pas
une élévation — même personne, même box, même domaine d'authentification : on
relaie un droit déjà prouvé, on n'en fabrique pas.

### 5.3 Chaque module rend ses listes à sa façon

Un tableau nu ici, `{"droplets": [...]}` là. **Lire les deux formes** plutôt
qu'imposer un schéma commun à des services qui n'en ont jamais eu. Une carte
qui attendait un tableau et recevait un objet n'affichait rien, jamais, sans
erreur.

### 5.4 Le destructif s'arme, il ne se confirme pas

Une carte fait 280 px et le pointeur y dérape. `confirm()` dans une iframe est
laid et parfois bloqué. Le premier clic **arme** (le bouton devient ⚠), le
second exécute, et l'armement **retombe seul** au bout de quelques secondes.

### 5.5 Jamais de champ mot de passe dans une carte

Non négociable, développé en [`WEBOS-DESIGN.md`](WEBOS-DESIGN.md) §4bis. Une
carte qui manque d'accès **demande une validation** ; celle-ci se fait en
pleine page, à une adresse visible. On n'apprend à personne à taper son mot de
passe dans un cadre.

---

## 6. Écrire le JS d'une carte

### 6.1 La zone morte tue le rendu entier

**Quatre fois** dans `hall/index.html`. Une `const` ou une `let` déclarée après
la fonction qui l'utilise est en **zone morte temporelle** au moment où le
rendu s'exécute : `ReferenceError`, rendu interrompu — et avec lui les menus,
la barre média et les pastilles, qui n'avaient rien à voir.

> **Règle.** Toute valeur lue pendant l'évaluation initiale se déclare en `var`
> **au-dessus** de son usage. La déclaration de fonction, elle, est hissée.

Symptôme reconnaissable : *plusieurs* éléments sans rapport disparaissent d'un
coup. Chercher un `ReferenceError` dans la console avant de chercher ailleurs.

### 6.2 Ne jamais déplacer un nœud qui contient une iframe

Reparenter une iframe la **recharge** — une vidéo en cours s'arrête et
repart du début. Toute fonctionnalité qui *déplace* une carte doit donc être
pesée à cette aune, et ne déplacer que ce qui n'est pas déjà à sa place.

Le favori en est l'exemple : il a d'abord été implémenté en `column-span:all`,
précisément pour éviter le déplacement. Mais élargir la carte remettait son
aperçu à l'échelle d'une largeur nouvelle, et **l'aperçu paraissait zoomé de
travers** — la carte ne ressemblait plus à elle-même. Le remède était pire que
le mal : le favori ne change plus que l'**ordre**, et le code ne bouge un nœud
que s'il n'est pas déjà en tête.

> **Règle.** Éviter un rechargement d'iframe est un bon réflexe, mais pas au
> prix de déformer la carte. Quand les deux s'opposent, changer la
> fonctionnalité plutôt que la contourner.

### 6.3 Une carte fait la taille de ce qu'elle dit

La hauteur déclarée (`h`) doit être **appliquée**. Elle a été déclarée et
jamais lue pendant longtemps : toutes les cartes prenaient 252 px, y compris
celles qui n'avaient que trois chiffres à montrer. Et quand une carte perd des
éléments, sa hauteur descend d'autant — garder la place de ce qu'on a retiré
est un trou, pas une marge.

### 6.4 Une carte vide doit dire **pourquoi**

Les cartes déléguées s'affichaient vides depuis le domaine public. La cause
n'était pas une panne : le témoin de session est posé sur `.gk2.secubox.in` et
n'est jamais envoyé à `hall.gk2.net`. Une carte vide fait croire à une panne.

> **Règle.** Trois états, toujours distingués : *je charge*, *je n'ai pas le
> droit — et voici lequel*, *il n'y a rien*. « Dépôt vide » et « connectez-vous
> à la box » ne sont pas le même message.

---

## 7. Habillage

- **Définir tous ses jetons de couleur.** Le skin partagé force le fond sombre
  avec `!important` (195 règles) et ne définit aucun de ses jetons. Une carte
  qui compte dessus est illisible dans un thème et cassée dans l'autre.
- **Trois états de palette**, pas deux : `:root` nu (clair complet),
  `@media (prefers-color-scheme: dark)` gardé par `:root:not([data-theme="light"])`,
  et `:root[data-theme="dark"]`. Le réglage « système » ne pose **aucun**
  attribut : une couleur définie uniquement sous `[data-theme]` ne s'applique
  jamais dans cet état, qui est le plus courant.
- **Fond du `<body>` explicite.** Un corps transparent emprunte le fond de
  l'hôte et se retrouve à peindre le texte d'un thème sur le fond de l'autre.
- **En cadre, retirer son propre bandeau.** L'attribut `sbx-embed` masque
  l'en-tête de site et le pied : le Hall porte déjà le contexte, le répéter
  vole la moitié de la carte.

---

## 8. Empaquetage

- `dh_installsystemd --no-enable --no-start` s'applique **aussi à la mise à
  jour**. `sbx-authwatch` est resté arrêté après un upgrade sans que rien ne le
  dise. Le `postinst` doit **redémarrer le service s'il était activé**.
- `--force-confold` **garde l'ancien vhost**. Après chaque déploiement,
  vérifier l'absence de `.dpkg-dist` sous `/etc/nginx/sites-available/` — sinon
  la correction est dans le paquet et pas sur la machine.
- **Le masque ACL de `/etc/secubox/secrets`** neutralise toutes les entrées
  nommées quand il vaut `---`. Une dizaine de paquets font `install -d -m 0700`
  sur ce parent partagé. Poser `m::x`. *(`secubox-meshtastic` reste exposé.)*
- Un service qui écrit dans un journal partagé n'a pas `CAP_DAC_OVERRIDE` :
  root **ne peut pas** passer outre les droits du fichier. Ouvrir au **groupe**
  (0660 + `SupplementaryGroups=` + `create 0660` dans logrotate).

---

## 9. Liste de contrôle avant de livrer une carte

```
□ Le service a-t-il quelque chose à dire sans qu'on le lui demande ?   (§0)
□ Feuille et script servis depuis /static/, données par attributs      (§1.1)
□ Cache-Control: no-cache sur la carte et ses assets                   (§1.2)
□ Aucun X-Frame-Options ni frame-ancestors posé par le module          (§2)
□ Témoins SameSite=None; Secure — jamais Partitioned                   (§2.2)
□ Un porteur d'identité hors témoin si la carte lit de l'authentifié   (§2.3)
□ Battement d'annonce si elle joue ; pause / vol / muet acceptés       (§3.1-2)
□ Thème écouté en permanence, sans dépendre de `load`                  (§3.3)
□ Liens via le Hall, jamais target="_top"                              (§3.4)
□ Actions en liste fermée, champs déclarés, destructif en deux temps   (§5)
□ Aucun champ mot de passe                                             (§5.5)
□ Valeurs lues au rendu déclarées en `var` au-dessus                   (§6.1)
□ Hauteur déclarée ET appliquée                                        (§6.3)
□ Les trois états distingués : charge / pas le droit / rien            (§6.4)
□ Palette à trois états, fond du body explicite                        (§7)
□ Testée sur iPhone — c'est là que ça casse                            (§2.3)
```

---

## 10. Où c'est écrit

| | |
|---|---|
| Contrat et conception du Hall | [`WEBOS-DESIGN.md`](WEBOS-DESIGN.md) |
| Témoins, forme du module, empaquetage | [`MODULE-GUIDELINES.md`](MODULE-GUIDELINES.md) §8bis |
| Le Hall | `packages/secubox-webos/www/hall/index.html` |
| Cartes servies par le Hall | `packages/secubox-webos/www/hall/cardlets/` |
| Actions déléguées | `packages/secubox-webos/api/actions.py` |
| Accès délégués | `packages/secubox-webos/api/acces.py` |
| Vhost du Hall | `packages/secubox-webos/nginx/hall.vhost.conf` |
| Réécriture d'en-têtes | `packages/secubox-haproxy/sbin/haproxyctl` |
