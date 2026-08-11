# Streamlit — réveil à l'accès URL

Spécification · 2026-08-05 · issue [#746](https://github.com/CyberMind-FR/secubox-deb/issues/746)

Suite de #982 (bascule vers les unités par appli) : le parc Streamlit est
désormais à zéro appli résidente. Le réveil se fait par le lien explicite des
tuiles du mur mosaïque. Cette spec traite le cas manquant : **un visiteur qui
arrive par l'URL publique d'une appli endormie**.

## Ce qui existe déjà

Le mécanisme de réveil à l'accès **existe**, livré par le pilote scale-to-zero
(#896), et il tourne sur la board :

- **sbxwaf** (`cmd/sbxwaf/wakerproxy.go`) : si un vhost est enregistré « à la
  demande » (`/etc/secubox/waf/on-demand-vhosts.json`) **et n'a pas de route
  vivante**, la requête n'est pas rejetée en 421 — elle est relayée par socket
  unix vers le waker, sur `/_wake/<hôte>`.
- **`secubox-waker.service`** (paquet `secubox-profiles`, `api/wake.py`) :
  sert une page d'attente, déclenche le réveil du module, et restaure sa route
  via `portal_routes.recall`.

Rien de tout cela n'est à réinventer. Ce qui manque tient en trois points
précis.

## Ce qui manque, et pourquoi

### 1. Le déclencheur ne couvre pas le cas Streamlit

sbxwaf appelle le waker quand le vhost est à la demande **et sans route**. Pour
une appli Streamlit, la route **est présente en permanence** —
`haproxy-routes.json` mappe l'hôte vers `10.100.0.50:<port>` que l'appli tourne
ou non. Ce n'est pas la route qui manque, c'est le processus derrière.

sbxwaf compose donc, aujourd'hui, la branche « connexion refusée → page 502 »
(`errpages.go`, appelée depuis `routes.go:191` et `main.go:348`).

**Le déclencheur doit être étendu** : vhost à la demande **et** connexion
refusée par l'amont → waker, au lieu de la page 502. Le cas « sans route » reste
inchangé.

Deux conditions, un seul aboutissement. Un vhost qui n'est pas déclaré à la
demande garde exactement le comportement actuel — pas de changement pour les
autres services.

### 2. Aucun vhost d'appli n'est déclaré à la demande

`on-demand-vhosts.json` contient 7 entrées, dont `streamlit.gk2.secubox.in` —
le mur lui-même, pas les applis. Aucun vhost d'appli n'y figure.

### 3. Le waker ne sait réveiller qu'un module LXC

`wake(module: str, ...)` réveille un conteneur. Une appli Streamlit n'est pas un
conteneur : c'est une unité `streamlit-app@<nom>.service` **à l'intérieur** du
conteneur `streamlit`, qui lui tourne déjà. Il faut un second type de cible.

## Périmètre

« Routé » recouvre **deux couches indépendantes**, et il faut les deux pour
qu'une requête atteigne une appli :

1. une ACL `hdr(host)` dans `haproxy.cfg`, sinon HAProxy répond 421 et sbxwaf ne
   voit jamais la requête ;
2. une entrée dans `haproxy-routes.json`, qui donne à sbxwaf l'amont
   `10.100.0.50:<port>`.

Le décompte réel :

| | vhosts |
|---|---|
| routes sbxwaf vers le conteneur | 29 |
| dont ACL HAProxy présente | 19 |
| dont le port est revendiqué par une appli réelle | **14 ← périmètre** |

**Le périmètre de cette spec est donc de 14 vhosts**, pas 29. Les deux classes
d'exclusion ne se traitent pas de la même façon :

**Dix vhosts n'ont pas d'ACL HAProxy** — `basic`, `console`, `entamoir_1`,
`files_40`, `pf`, `secubox_control`, `secubox_evolution`,
`secubox_report_streamlit`, `swg`, `test2new`. Ils ont une route sbxwaf qui ne
sert à rien : la requête meurt en 421 un cran plus haut. Aucun réveil ne peut
les concerner tant que leur vhost n'est pas publié.

**Cinq vhosts ont une ACL mais un port orphelin** — leur amont n'est revendiqué
par aucune appli, ils sont en 502 définitif indépendamment de tout réveil :

| vhost | port routé |
|---|---|
| `pix.gk2.secubox.in` | 8506 |
| `files.gk2.secubox.in` | 8517 |
| `yijing360.gk2.secubox.in` | 8521 |
| `pc.gk2.secubox.in` | 8526 |
| `generik.gk2.secubox.in` | 8528 |

Ceux-là ne sont pas déclarés à la demande : ils continuent de recevoir la page
502 brandée, qui est la réponse honnête. Les réveiller n'a pas de sens — il n'y
a rien à réveiller. Leur réconciliation est un chantier distinct (voir « Hors
périmètre »).

## Architecture

### Le principe directeur : pas de cinquième table

Ce module porte déjà quatre notions concurrentes de « quel port pour quelle
appli » — la table `[instances.*]`, le `.streamlit.toml` par appli,
`haproxy-routes.json`, et le processus réel. C'est la classe de bug qui a coûté
deux fois à ce projet (#958 puis #959). **Le réveil n'en introduit pas une
cinquième.**

D'où la forme du contrat : sbxwaf ne demande jamais « réveille l'appli X ». Il
demande **« réveille ce qui possède le port P »** — et P, il l'a déjà, c'est
l'amont qu'il vient d'essayer de joindre.

### Le chemin, de bout en bout

```text
visiteur → HAProxy → sbxwaf :8085
                      │
                      ├─ route connue (haproxy-routes.json) → dial 10.100.0.50:P
                      │                                        │
                      │                                   ECONNREFUSED
                      │                                        │
                      │            vhost déclaré à la demande ?┤
                      │                    non → page 502 (inchangé)
                      │                    oui ↓
                      └──────────── waker (/run/secubox/waker.sock) /_wake/<hôte>
                                             │
                                    page d'attente + réveil
                                             │
                                   module streamlit (socket unix)
                                             │
                                  port P → appli → systemctl start
                                             │
                                    sondage jusqu'à écoute
                                             │
                                   la page d'attente recharge
```

### Le nom d'appli ne vient jamais de la requête

Le visiteur envoie un `Host`. sbxwaf le normalise (déjà fait dans
`wakerproxy.go`) et le résout en port par sa propre table de routes. Le waker
transmet ce port au module Streamlit, qui résout port → appli par la vérité
`.streamlit.toml`.

À aucun moment un nom d'appli fourni par un tiers n'atteint `systemctl`. Un
visiteur ne peut donc pas provoquer le démarrage d'une appli arbitraire : il ne
peut solliciter que celle qui possède le vhost qu'il a demandé.

Le module ne devient pas joignable publiquement : son socket unix n'est atteint
que par le waker, lui-même atteint uniquement par sbxwaf.

### Port sans propriétaire

Le module répond explicitement « aucune appli ne possède ce port ». Le waker
sert alors une page d'erreur définitive, **jamais une page d'attente**. Une
attente perpétuelle serait un mensonge à l'utilisateur et une boucle de sondage
inutile sur une board déjà contrainte.

Ce cas ne devrait pas se produire (les 5 vhosts concernés ne sont pas déclarés à
la demande) — il est traité quand même, parce que la table des routes et la
table des applis peuvent diverger à nouveau entre deux réconciliations.

## Garde-fous

La board est contrainte en CPU : un réveil coûte un interpréteur Python et
plusieurs secondes de charge. Le chemin de réveil est donc, par construction, un
levier de déni de service s'il n'est pas borné.

- **Un seul réveil en vol par port.** Réutilise le verrou de réveil concurrent
  déjà livré en #963 côté module. Dix visiteurs sur le même vhost endormi
  déclenchent un démarrage, pas dix.
- **Plafond global de réveils simultanés.** Au-delà, la page d'attente est
  servie sans déclencher — le visiteur patiente, la board ne s'écroule pas.
- **Réveil réservé à l'amont du conteneur.** Seul un amont `10.100.0.50` est
  éligible ; aucun autre service ne peut être démarré par ce chemin.
- **Aucune minuterie ne réveille.** Le réveil est un effet de l'accès, jamais
  d'un sondage périodique — même invariant qu'en #958 pour le captureur de
  vignettes.

## Extinction

Hors périmètre de cette spec : `secubox-streamlit-idle.timer` éteint déjà les
applis inactives (seuil 30 min), et elle est active depuis #982. Le réveil à
l'accès en est le pendant symétrique, pas un remplacement.

Une appli déclarée `autostart = true` est exemptée de l'extinction (déjà le
cas) ; le réveil à l'accès ne la concerne donc jamais en pratique.

## Tests

Le défaut à épingler d'abord, en rouge, dans `cmd/sbxwaf` : **un vhost déclaré à
la demande dont l'amont refuse la connexion reçoit aujourd'hui la page 502 au
lieu du waker.** C'est la seule chose qui manque côté WAF, et c'est vérifiable
sans board.

- vhost à la demande + amont refusant → relayé au waker (rouge aujourd'hui)
- vhost **non** déclaré à la demande + amont refusant → page 502 (inchangé,
  garde contre la régression du cas général)
- vhost à la demande + amont en délai d'attente → 504, **pas** de réveil : un
  amont qui répond lentement est vivant, le réveiller n'a pas de sens
- vhost à la demande sans route → waker (cas #896, non régressé)
- waker : port sans propriétaire → page d'erreur définitive, pas d'attente
- module : résolution port → appli par `.streamlit.toml`, jamais par la table
  `[instances.*]`
- module : deux réveils concurrents sur le même port → un seul `systemctl start`

## Hors périmètre

- **Publier les 3 vhosts d'applis non routés** (`cybermind_fanzine`, `diapvid`,
  `files_51` déclarent un domaine sans route ; sur les 4 domaines déclarés au
  niveau `[apps.*]`, seul `enhance-app` est routé).
  Relève du chantier « les paquets enregistrent leur vhost dans `haproxy.toml` »
  déjà en file.
- **Réconcilier la table `[instances.*]`** — cinq instances déclarent un port
  qu'aucune appli ne binde, et la même appli y est parfois déclarée deux fois
  sur deux ports (`bazi_calculator` en 8506 et 8598). C'est la quatrième source
  de vérité sur les ports ; elle mérite sa propre issue, et probablement sa
  suppression au profit de la vérité `.streamlit.toml`.
- **Généraliser le réveil à l'accès aux autres applis lourdes** (piste
  « lazy-start générique » de #746). L'extension du déclencheur sbxwaf la rend
  possible sans travail supplémentaire côté WAF, mais chaque famille de service
  a son propre type de cible côté waker.
