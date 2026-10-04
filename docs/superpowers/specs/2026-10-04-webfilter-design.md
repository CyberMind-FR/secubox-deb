<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-webfilter — filtrage de contenus par catégories, profils et apprentissage (#1962)

## 1. Demande et décisions du propriétaire (2026-10-04)

Bloquer sur la navigation globale : adulte / porno / xxx, parking, « sensibles », publicité — « de la même manière » que pour les TV, avec apprentissage, dans un **module indépendant associé au DPI et à ad-guard**.

Réponses aux trois questions de cadrage :

0. **Défaut : « observe »** pour toutes les catégories et tout appareil non assigné (validé le 2026-10-04 ; le propriétaire aurait préféré un blocage par défaut, laissé à une bascule par catégorie ou par profil, par exemple `enfants`).
1. **« Sensibles »** = jeux d'argent, violence, drogues, armes, haine, phishing/malware, « … » (liste ouverte : le catalogue de catégories doit pouvoir s'étendre).
2. **Global pour tous avec exceptions par appareil, ET profils** (par exemple enfants / adultes) **associés aux appareils**.
3. **Observe d'abord, puis blocage** ; le **blocage immédiat** reste possible, avec **cumul** (listes publiques + règles apprises) « comme pour les TV ».

Piste voisine : la **publicité des radios en flux**, à tester sur une enceinte Google Cast (en cours, voir §7) ; elle rejoint la catégorie « publicité audio ».

## 2. Ce qui existe et ce qui a été mesuré (2026-10-04, gk2, Unbound 1.17.1)

- **Le puits d'ad-guard** compte 656 704 domaines issus de 6 listes publiques de publicité et de pistage (oisd, hagezi-pro, stevenblack, easylist, easyprivacy, adguard-base) : **aucune** liste adulte, parking ou sensible. Il s'applique à tous les clients par défaut ; les appareils déclarés dans ad-guard ont une vue propre (`view-first`).
- **Mesuré — les étiquettes d'Unbound font des profils.** Avec `define-tag`, `local-zone-tag` et `access-control-tag`, un second Unbound jouant l'amont :

| Client | zone « porno » étiquetée `enfants` | zone « jeux » étiquetée `enfants adultes` | nom ordinaire |
|---|---|---|---|
| sans étiquette | **résolu** | **résolu** | résolu |
| `enfants` | refusé | refusé | résolu |
| `adultes` | **résolu** | refusé | résolu |

  Une zone étiquetée ne s'applique **qu'aux clients qui portent l'étiquette** ; un client sans étiquette n'est jamais bloqué par une zone étiquetée. Plusieurs étiquettes sur une zone valent un « ou ».
- **Mesuré** : l'ajout d'une zone à chaud (`unbound-control local_zone`) marche, mais **sans étiquette** : tout changement d'étiquettes (zones ou clients) demande un rechargement d'Unbound (≈ 10 s, coupure du DNS ≈ 6,6 s, mémoire inchangée avec 656 704 zones). Les règles apprises qui doivent s'appliquer à chaud passeront par une vue de profil (mécanisme d'ad-guard).
- **À vérifier avant d'écrire du code** (spike de la tâche 1) : la **précédence** de `access-control-tag` (un `/32` d'appareil l'emporte-t-il sur `0.0.0.0/0` ?) ; l'interaction **étiquettes + vues** d'ad-guard sur un même client ; le type de zone `inform` pour la phase « observe » (voir §4) ; la mémoire et le temps de rechargement avec plusieurs centaines de milliers de domaines étiquetés en plus.

### Résultats de l'essai technique (2026-10-04, Unbound 1.17.1 jetable sur gk2, port 5399, rien touché en production)

Réalisé avec de vrais noms résolvables (`example.com` étiqueté `enfants`, `example.org` étiqueté `enfants adultes`, `example.net` en `inform`, `iana.org` sans étiquette), un client `adultes` par défaut (`127.0.0.0/8`) et une exception `enfants` en `/32`.

- **Précédence d'`access-control-tag` : le `/32` l'emporte sur le `/8`** (le client `enfants` est bloqué sur `example.com`, que le client `adultes` résout).
- **Zone `inform` : confirmée** pour la phase « observe ». La réponse est normale et le journal porte `info: example.net. inform <client>@<port> …` (avec `log-local-actions: yes`), donc un comptage « aurait bloqué » est possible sans rien bloquer.
- **Étiquettes et vues d'ad-guard : un client qui a une vue (`view-first: yes`) n'est PAS bloqué par les zones globales étiquetées**, alors qu'il porte l'étiquette `adultes` par son adresse (`example.org` résolu pour le client à vue, bloqué pour le même profil sans vue). Les étiquettes ne se combinent donc pas avec les vues d'ad-guard sur un même appareil.
- **Anomalie non expliquée (2 essais sur 3)** : dans un ordre donné de requêtes (client `adultes` d'abord, `enfants` ensuite), le client `enfants` n'est pas bloqué sur la zone étiquetée `enfants adultes`, alors qu'il l'est quand il est interrogé en premier. Le comportement dépend de l'ordre, donc **les étiquettes ne sont pas démontrées fiables** pour la phase de blocage. Le premier essai après redémarrage de l'instance ne bloquait rien du tout.

**Conséquence sur l'architecture (à décider, §4)** : le profil par étiquettes demande un rechargement pour chaque changement (≈ 6,6 s sans DNS) et n'est pas démontré fiable ; le profil **par vue** (une vue par profil, ajout et retrait à chaud avec `unbound-control view_local_zone`) est le mécanisme déjà éprouvé en production par ad-guard, se combine avec le puits global (`view-first`) et ne coupe jamais le DNS. Sa contrainte : un client n'a **qu'une vue**, donc les règles d'un profil webfilter doivent être composées avec la vue d'ad-guard du même appareil.

## 3. Objectifs

- **Catalogue de catégories** (identifiant, libellé, listes sources, mode par défaut) extensible : adulte (porno/xxx), jeux d'argent, violence, drogues, armes, haine, phishing/malware, parking, publicité audio ; la publicité et le pistage restent à **ad-guard**.
- **Profils** (`adultes`, `enfants`, et ceux que l'administrateur crée) : un ensemble de catégories en mode `observe` ou `block`. **Profil par défaut** pour tout appareil non assigné (le « global »).
- **Appareils** rattachés à un profil **par adresse MAC** (IPv4 et IPv6 ensemble, comme ad-guard), avec **exceptions** par appareil (catégorie autorisée ou bloquée en plus de son profil).
- **Observe puis blocage** par catégorie ; **cumul** : listes publiques + règles apprises, comme pour les TV.
- **Apprentissage** par le cycle de #1954 : candidat → essai (24 h) → confirmation → retrait, avec retour arrière en un clic.
- **Association** : **ad-guard** (publicité, pistage ; flux d'échange de ses appareils et de ses classifications) et **DPI** (catégories publiées pour étiqueter les destinations, comme #1960).

## 4. Architecture

Module indépendant `secubox-webfilter` (utilisateur dédié `secubox-webfilter`, jamais root ; un contrôleur root à arguments exacts, comme `secubox-adguard-tv`).

1. **Sources et compilation.** `webfilter-sync` télécharge les listes (versionnées, empreintes, validation des noms, plafonds de taille), les classe par catégorie et écrit un **drop-in Unbound** : `define-tag` pour chaque catégorie×profil, `local-zone` + `local-zone-tag` pour chaque domaine, `access-control-tag` pour les adresses des appareils (profil par défaut en `0.0.0.0/0` et `::/0`, exceptions en `/32` et `/128`). Contrôlé par `unbound-checkconf` **avant** d'être gardé, rechargement, retour arrière si échec (patron d'ad-guard).
2. **Observe.** Une catégorie en `observe` compte ce qui **aurait** été bloqué sans rien bloquer. Piste : type de zone `inform` (réponse normale, requête journalisée), à vérifier au spike ; sinon, une zone `transparent` plus un comptage par l'analyseur du journal.
3. **Comptage.** Un démon d'alimentation propre au module lit le journal d'Unbound (comme `secubox-adguard-dnsfeed`) et compte par appareil, catégorie, domaine et décision (`OBSERVE`, `BLOCKED`) ; rétention 30 jours ; les requêtes de la box elle-même sont exclues.
4. **Apprentissage.** Signaux : (a) TLD et lexique (`.xxx`, `.sex`, `.porn`, mots-clés) ; (b) **parking** : serveurs de noms et adresses d'hébergeurs de parking connus, par recherche **bornée** (limitée en débit, seulement pour les domaines non classés vus plusieurs fois, jamais un domaine privé) ; (c) catégories vues par le **DPI** sur les flux qui traversent gk2 ; (d) **agrégation** : un domaine confirmé sur plusieurs appareils est proposé aux autres ; (e) décision de l'administrateur. Jamais d'application sans essai ni confirmation.
5. **Panneau d'administration** : catégories (mode par catégorie), profils et appareils, exceptions, candidats, statistiques « aurait bloqué / bloqué » par catégorie et par appareil, journal. Pas d'interface usager en v1.
6. **API** : `/api/v1/webfilter/*`, `require_lecture` en lecture, `require_jwt` en écriture ; routes qui appellent le contrôleur **synchrones**.

## 5. Sécurité, vie privée, éthique

- **Aucun MITM, aucune inspection HTTPS** ; blocage par nom de domaine seulement (DNS).
- Le comptage par appareil est une **donnée de navigation** : réservée à l'administrateur, rétention 30 jours, fichiers `0640`, jamais exportée hors de la box.
- Chaque décision de sécurité (changement de mode, de profil, d'exception, application d'un blocage) est tracée dans `/var/log/secubox/audit.log`.
- Les noms des listes et du journal sont validés (`valider_domaine`) et ne sont jamais recopiés tels quels dans la configuration d'Unbound ; une valeur hostile n'atteint ni le drop-in ni les arguments d'`unbound-control` (leçon de la relecture de #1959).
- Le filtrage d'un appareil est **visible** par l'administrateur ; aucune surveillance cachée d'un adulte : un profil `adultes` sans catégorie en `block` est le comportement par défaut d'un appareil non assigné tant que l'administrateur n'en décide pas autrement.

## 6. Phases

- **P1 — Socle et observe.** Spike Unbound (précédence, vues, `inform`, mémoire) ; catalogue ; 2–3 catégories (adulte, phishing/malware, parking) avec une liste publique chacune ; profil unique ; mode `observe` ; comptage ; panneau minimal.
- **P2 — Profils et appareils.** Profils multiples, assignation par MAC, exceptions, bascule observe → block par catégorie, audit.
- **P3 — Apprentissage.** Candidats (lexique/TLD, parking, DPI), cycle essai/confirmation, agrégation.
- **P4 — Association.** Catégories publiées au DPI ; flux d'ad-guard ; publicité audio (§7).

## 7. Publicité audio des radios en flux (décision du propriétaire, 2026-10-04)

Le blocage actuel d'ad-guard est **conservé** : les publicités des radios en flux ont été en grande majorité bloquées sur l'enceinte Google Cast de test (règle confirmée pour `tunein-ondemand.cdnstream1.com`), et les radios sans publicité fonctionnent. Limite de principe : une publicité **insérée dans le flux audio** sort de la même adresse que le programme et ne se bloque pas par le DNS. La catégorie « publicité audio » ne contiendra donc que ce qui est mesuré comme séparé du flux ; la publicité et le pistage restent à ad-guard.

## 8. Tests et livraison

Tests purs (catalogue, profils, assignation, génération du drop-in, validation, apprentissage), tests sur un **vrai Unbound jetable** (étiquettes, précédence, vues), banc navigateur pour le panneau, relecture de sécurité avant déploiement ; paquet `secubox-webfilter` 0.1.0 ; déploiement par paquet sur gk2, agrégateur redémarré, vérification **par l'adresse publique** ; l'issue #1962 ne se ferme qu'après déploiement et validation du propriétaire.

## 9. Risques et limites assumés

- **DoH, VPN, adresse IP directe** contournent un filtre DNS : documenté dans le panneau ; le blocage des résolveurs DoH publics est une décision séparée.
- **Faux positifs** (éducation sexuelle, santé, art, sites en construction pour le parking) : d'où observe d'abord, essai avant confirmation, exceptions par appareil et retour arrière en un clic.
- **Qualité et licence des listes publiques** variables : chaque source est vérifiée (licence, taille, fraîcheur) avant d'être retenue.
- **Charge** : un rechargement d'Unbound par changement d'étiquettes (≈ 10 s sans DNS) ; les changements sont **regroupés** (au plus un par heure) ; la mémoire est **mesurée** à chaque ajout de liste importante.
- Le parking est un signal **faible** et trompeur : il ne bloque jamais sans confirmation.
