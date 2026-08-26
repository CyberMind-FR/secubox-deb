<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SBXOS / WebOS — notes de conception

*Ce document décrit le Hall (`secubox-webos`) et le contrat que doit remplir un
service pour y vivre. Il est écrit pour la personne qui ajoutera le prochain
service — ou qui devra réparer celui-ci dans six mois.*

---

## 1. L'idée directrice

**Le Hall n'affiche pas les services : il les héberge.**

Un service n'y est pas décrit, il y est *présent*. La radio joue dans sa carte,
le pare-feu y compte ses bannissements, le BBS y fait défiler ses fils. La
navigation d'un service à l'autre ne coupe ni le son ni l'état.

De là découle toute la suite : si le service est réellement là, c'est lui qui
sait s'afficher, et le Hall n'a pas à peindre son portrait.

## 2. Trois degrés, et un seul ordre de préférence

| Degré | Ce que le Hall affiche | Qui décide du contenu |
|---|---|---|
| **1. Carte servie** | `/micro` servi par le service | le service |
| **2. Aperçu vivant** | la page réelle du service, mise à l'échelle | le service, sans le savoir |
| **3. Carte classique** | pictogramme, nom, une phrase | le Hall |

Le Hall choisit **toujours le degré le plus élevé disponible**, et bascule tout
seul : le jour où un service se met à servir `/micro`, sa carte remplace son
aperçu sans qu'on touche au Hall.

L'ordre par défaut de la mosaïque suit ces degrés — à la réinitialisation, les
cartes les plus abouties reviennent en tête. Le tri est **stable** : à degré
égal, l'ordre d'origine tient.

**Un portrait dérive de son modèle.** C'est la raison d'être du degré 2 : mieux
vaut montrer la vraie page, même illisible de près, qu'une phrase générique qui
sera fausse dans un mois.

## 3. Le contrat d'une carte `/micro`

Une carte, ce n'est pas une page réduite. **Une carte résume ; elle ne rétrécit
pas.**

```
Ce qu'elle fait                     Ce qu'elle ne fait pas
─────────────────────────────────   ──────────────────────────────
tient dans ~250 px de haut          pas d'ascenseur
dit UNE chose et ce qui suit        pas de navigation propre
tourne si le fond est multiple      pas d'en-tête de site
suspend la rotation au survol       pas de bouton « parent »
mène au service, sans en sortir     pas de maquette de données
```

### 3.1 Elle se sert elle-même

Le service expose `/micro` (ou `/micro.html`). Le Hall l'appelle avec
`?theme=dark|light`.

### 3.2 Elle est autonome en style

Un service peut servir une CSP stricte. **`style-src 'self'` et
`script-src 'self'` bloquent purement et simplement un `<style>` ou un
`<script>` en ligne** — la carte s'affiche alors en HTML brut, sans le moindre
message. Le BBS en a fait les frais.

> **Règle.** Feuille et script dans `/static/`, jamais en ligne. On ne relâche
> pas `'unsafe-inline'` pour le site entier au bénéfice d'une carte.

Et si la carte doit transporter des données rendues côté serveur, elles voyagent
par un **attribut** (`data-…`), jamais par un bloc `<script type="application/json">` :
sous `script-src 'self'`, un bloc de données dépend du bon vouloir du
navigateur, alors qu'un attribut n'est jamais un script.

### 3.3 Elle a sa propre palette, à trois états

Le vhost d'un service ne sert pas forcément `/shared/`. Chaque carte porte donc
ses jetons, et **les trois états du thème** :

```css
:root                      { /* clair : l'état par défaut, jamais dans un @media */ }
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) { /* l'état « système », sans attribut posé */ }
}
:root[data-theme="dark"]   { /* le choix explicite, qui gagne dans les DEUX sens */ }
```

`body` doit peindre un fond **explicite** : un corps transparent emprunte celui
de l'hôte, et la carte finit peinte dans un thème que son texte ne suit pas.

Pour un design sombre d'abord, on inverse — mais on garde les trois blocs.

### 3.4 Elle suit le thème sans se recharger

```js
// à l'arrivée
new URLSearchParams(location.search).get('theme')
// ensuite
addEventListener('message', ev => { if (ev.data?.sbx === 'theme') … })
```

> **Ne jamais réécrire `iframe.src` pour changer de thème.** Le cadre se
> recharge, le son s'arrête, le lecteur repart au début. C'est une régression
> qui a été livrée une fois ; elle ne doit pas l'être deux.

### 3.5 Ses liens restent dans le Hall

```js
if (parent !== window) {
  ev.preventDefault();
  parent.postMessage({ sbx: 'ouvre', id: '<service>', url: a.href }, '*');
}
```

Hors cadre, le lien fonctionne normalement — c'est ce repli qui autorise à
garder `target="_top"` dans le HTML. Le Hall n'honore la demande que si elle
vient d'un cadre **qu'il a lui-même posé**.

### 3.6 Si elle joue quelque chose, elle l'annonce

```js
parent.postMessage({ sbx:'media', id, titre, sous, joue, t, d, fin }, '*');
```

Le Hall en fait une rangée de barre média et une pastille. Il renvoie les
commandes par `{ sbx:'cmd', action:'toggle'|'prev'|'next'|'stop'|'vol'|'muet', v }`.

Le volume est **par flux** : deux flux peuvent jouer ensemble, et un volume
global ne permettrait pas de baisser la radio pour entendre le podcast.

## 4. Ce que coûte l'encadrement — le vrai sujet

Encadré par le Hall, un service est un **contexte tiers**. Quatre pièges, tous
rencontrés en production :

### 4.1 `frame-ancestors`

Un module SecuBox **nomme ses hôtes** — jamais `*`, qui accepterait n'importe
quel site et annulerait la directive :

```
frame-ancestors 'self' https://hall.gk2.secubox.in https://hall.gk2.net
```

Les services tiers (PeerTube, Nextcloud, PhotoPrism, Mastodon, webmail) refusent
d'être encadrés, et **ils ont raison de le faire par défaut**. Leur en-tête est
réécrit **au proxy**, une fois, opt-in par vhost (`cadrable = true`) :

- `X-Frame-Options` est **retiré** — il ne sait dire que `DENY` ou `SAMEORIGIN`,
  jamais nommer une origine ;
- une politique existante voit sa directive **réécrite** — ajouter un second
  en-tête ne servirait à rien, deux politiques s'**intersectent** et un `'none'`
  déjà posé continuerait de tout bloquer ;
- une politique **sans** `frame-ancestors` reçoit un second en-tête ne portant
  que cette directive.

> **Piège HAProxy.** Conditionner un `http-response` sur une ACL d'en-tête de
> *requête* ne matche pas : la règle est générée, la config valide, le
> rechargement propre — et rien ne bouge, sans un mot. Il faut marquer la
> transaction pendant la requête (`set-var(txn.…)`) et relire la marque dans la
> réponse.

### 4.2 Les cookies

`SameSite=Lax|Strict` est **rejeté** dans un cadre tiers. Le service ne
reconnaît plus le visiteur et rend 401 sur ses propres ressources — un lecteur
muet, une page vide, aucun message.

Tout module SecuBox pose donc `SameSite=None; Secure` en TLS, `Lax` en clair,
avec `SECUBOX_COOKIE_SAMESITE` pour refermer. Voir `MODULE-GUIDELINES §8bis`.

Cela n'affaiblit pas le jeton anti-rejeu : un site tiers ne peut pas **lire** un
cookie — c'est l'isolation d'origine qui l'en empêche, pas `SameSite`. Tant que
le module vérifie par **double envoi**, la protection reste entière. Un module
**sans aucune défense CSRF** ne doit pas franchir ce pas.

> **`Partitioned` : non.** Il cloisonne le cookie au couple (site encadrant,
> service). Le webmail ouvert dans le Hall et ouvert directement se retrouvent
> avec **deux sessions**, et Roundcube rend « non concordance de témoin ».
> Une session qui marche vaut mieux qu'une session cloisonnée qui n'en est plus
> une.

### 4.3 Safari, iOS et les téléviseurs

`SameSite=None` **ne suffit pas** : la prévention de pistage refuse les cookies
tiers quoi qu'on fasse. La radio restait muette sur iPhone et sur TV.

Quand ce que le cookie porte n'est **pas un secret** — l'identifiant de la radio
est un nombre que la page se donne au hasard, il attribue des gestes, il
n'authentifie rien — le faire voyager aussi par l'URL ne retire aucune
protection. Quand c'en est un, la réponse est le coffre avatar, pas un
contournement.

### 4.4 `X-Forwarded-Proto`

HAProxy termine le TLS ; nginx écoute en clair et transmettait `$scheme`. **Tous
les modules croyaient servir en clair** : permaliens en `http://`, `_secure()`
faux, et donc cookies retombés en `Lax` — le correctif du §4.2 annulé en
silence.

HAProxy pose l'en-tête sur ses deux frontends ; les vhosts nginx le
**transmettent** (`$http_x_forwarded_proto`) au lieu de l'écraser.

> **Piège dpkg.** Les vhosts nginx sont des *conffiles* : `--force-confold`
> conserve l'ancien. Après montée de version, comparer avec le `.dpkg-dist`.

## 4bis. Une carte ne demande jamais de mot de passe

Une carte vit dans un cadre. N'importe quelle page encadrée peut en dessiner
une identique, et la personne qui regarde n'a **aucun moyen de vérifier qui
demande**. Un champ mot de passe dans une carte, c'est un formulaire de
hameçonnage avec notre logo dessus — et le jour où l'on habitue quelqu'un à y
taper son mot de passe, on lui retire la seule défense qui lui restait : la
surprise.

On ne capture ni ne rejoue de témoin de session non plus. Le registre RGPD du
pare-feu ne garde qu'une **empreinte**, et c'est précisément ce qui le rend
inoffensif : voler `/var/log/secubox/cookie-audit/` ne donne rien. Le jour où
il garderait des valeurs rejouables, il deviendrait la cible la plus rentable
de la box — un seul fichier, toutes les sessions.

### Ce qu'on fait à la place

```
carte sans accès  →  dépose une DEMANDE
                     ↓
        page EN PLEINE PAGE (barre d'adresse visible)
                     ↓
        l'opérateur valide, hors du cadre
                     ↓
   flux de délégation du service (Nextcloud : Login Flow v2)
                     ↓
   mot de passe d'APPLICATION, révocable chez eux, stocké 0600
```

Le mot de passe est tapé **dans le service**, sur sa vraie page. SecuBox ne le
voit jamais.

Pour un service sans flux de délégation (Roundcube, Dovecot), l'identifiant
**dédié** se saisit dans la page authentifiée. Le secret transite alors une
fois, vers une page que l'on a choisi d'ouvrir et dont on peut vérifier le
domaine — et non depuis une vignette anonyme.

> C'est la différence entre **confier une clé** et **la laisser sur le
> paillasson**.

### Un avatar rassemble plusieurs identités

Les accès sont rangés par **personne**, pas par service : `/<qui>/<svc>.json`.
Deux habitants du même foyer ont chacun leur Nextcloud, et l'avatar de l'un ne
rejoue pas l'identité de l'autre.

**`qui` vient du jeton, jamais du client.** Un profil annoncé par la page est
déclaratif : il suffirait de prétendre être quelqu'un d'autre pour rejouer ses
accès. C'est pour cette raison qu'**aucune** route d'accès n'est publique — pas
même celle qui dit « as-tu un accès ? ». Le Hall est joignable sur le réseau
local sans se connecter : une route publique aurait laissé n'importe qui
déposer des demandes, et lire les données déléguées à travers la carte.

Sans jeton, il n'y a pas d'identité — donc rien à voir et rien à demander. La
carte affiche « connectez-vous », ce qui est la vérité.

Le **compte invoqué est nommé** partout où l'accès apparaît. Savoir qu'un accès
existe ne suffit pas : il faut voir *laquelle* des identités il rejoue, sans
quoi on ne peut ni la reconnaître ni la révoquer en connaissance de cause.

### Où chaque service se situe

| Service | Ce qu'il offre | Voie |
|---|---|---|
| **Nextcloud** | Login Flow v2 | délégation — approbation chez eux |
| **Mastodon** | OAuth2 (`/api/v1/apps` + `/oauth/token`) | délégation — retour sur la page |
| **PeerTube** | API publique suffisante | **aucune** — la carte lit sans identité |
| **PhotoPrism** | `401` sans jeton, pas de flux | identifiant dédié |
| **Gitea, Jellyfin** | jetons créés par l'opérateur | identifiant dédié |

Deux détails d'OAuth2 qui se paient si on les oublie : l'enregistrement de
l'application est un artefact de **box**, pas de personne — réenregistrer à
chaque demande crée une application de plus à chaque clic chez Mastodon ; et le
`state` doit porter le service **et** la personne, sans quoi le retour
d'autorisation est anonyme.

### La page d'accès s'encadre, sauf ce qui se tape

Consulter, valider, ouvrir un flux : aucun secret ne transite, le Hall peut
donc afficher la page dans son cadre.

La **saisie d'un identifiant dédié** s'ouvre en **popup** — une fenêtre de
premier niveau, avec sa barre d'adresse, donc vérifiable — et le Hall reste
ouvert derrière. Jamais `location=no` : cacher la barre d'adresse détruirait la
seule garantie qu'on cherche.

Trois règles qui en découlent, et qu'il ne faut pas contourner :

- **La validation ne se fait jamais dans un cadre.** Une confirmation qu'on ne
  peut pas authentifier ne confirme rien.
- **Les routes publiques ne révèlent rien** : savoir si un accès existe, et
  déposer une demande. Deux booléens et une ligne dans une file **bornée** —
  une file publique non bornée est un déni de service.
- **La révocation dit ce qu'elle fait.** Elle oublie de notre côté ; le mot de
  passe d'application reste valide dans le service tant que personne ne l'y
  supprime. Le dire vaut mieux que de laisser croire à une révocation complète.

## 5. Ce qui reste ouvert

- L'en-tête `X-Forwarded-Proto` se perd encore entre HAProxy et l'application ;
  l'application est correcte, interrogée directement elle émet bien `https://`.
- Le coffre avatar : une carte qui montrerait vos derniers mails ou fichiers a
  besoin d'une identité. Mot de passe d'application, compte IMAP dédié, ou
  coffre — pas de scraping.
- Le proxy navigateur + Tor, qui rendrait tout **même origine** et supprimerait
  d'un coup les quatre pièges du §4 — au prix d'une réécriture d'URL, des
  WebSockets, et d'une surface d'attaque nouvelle. **À maquetter et mesurer
  avant toute inclusion.**

## 6. Où c'est écrit

| | |
|---|---|
| Le Hall | `packages/secubox-webos/www/hall/index.html` |
| Le vhost du Hall | `packages/secubox-webos/nginx/hall.vhost.conf` |
| Réécriture d'en-têtes | `packages/secubox-haproxy/sbin/haproxyctl` |
| Registre des témoins | `sbxwaf` → `/var/log/secubox/cookie-audit/server.jsonl` |
| Règle des cookies | `docs/MODULE-GUIDELINES.md` §8bis |
