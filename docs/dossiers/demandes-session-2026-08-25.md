<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Inventaire EXHAUSTIF des demandes des sessions du 24 et 25 août 2026, dans
  l'ordre où elles ont été formulées. Rien n'est écarté : ce qui a été refusé,
  annulé ou laissé de côté figure aussi, avec la raison.
-->

# Demandes — sessions 24 & 25 août 2026

## 1. Livré et déployé

### Hall / WebOS (`secubox-webos` 1.0.24 → 1.0.35)
| Demande | Version |
|---|---|
| Référence de rendu de l'affiche SBXOS | 1.0.25 |
| Barre système sans aucun sous-menu ; menus en listes plates | 1.0.26 |
| Menus unifiés emoji + ⚙️ + ⧉ ; Système en **mosaïque** | 1.0.27 |
| Nav du service en **menu pop** de la mégabar (plus de colonne) | 1.0.28 |
| Le **titre du service EST son menu**, à gauche de ⟳ | 1.0.29 |
| « Profil » et « Alertes » retirés de la barre | 1.0.29 |
| Chaque menu s'ouvre **sous son bouton** (alignement à droite si à droite) | 1.0.30 |
| Le bouton du **mode courant s'efface** du switch | 1.0.31 |
| Switch ⧉ onglet · ⚙️ admin · ▦ service, **sans rechargement** | 1.0.26+ |
| Cadre d'embed occupant **tout le visible** (0 px perdu) | 1.0.34 |
| ⧉ ouvre l'URL **du mode affiché** (admin ≠ vhost public) | 1.0.34 |
| Logo **SbX** + **médaillon animé** six faces, boucle infinie | 1.0.34 |
| **Podcaster** ajouté aux services et aux cartes d'accueil (+ CSP `frame-src`) | 1.0.35 |

### BBS (`secubox-bbs` 0.30.10 → 0.30.20)
| Demande | Version |
|---|---|
| Salons BBS descendus dans le menu contextuel du Hall | (webos) |
| Seconde section « Accès » remontée… **puis retirée à la demande** | 0.30.11 → 0.30.12 |
| `/media-vignette` : **403 inapproprié levé** | 0.30.13 |
| `/vignette/` suit la **visibilité du fichier**, comme `/f/` | 0.30.14 |
| `/biblio` **n'annonce que ce qu'elle sert** | 0.30.15 |
| Vignettes d'actualité **scellées** (HMAC) au lieu de réservées aux membres | 0.30.16 |
| **Médaillon animé** de l'entête, six faces | 0.30.17 |
| Médaillon : **boucle infinie** rétablie (coupe-circuit + raccourci CSS) | 0.30.18 |
| **Rubriques privées invisibles** aux anonymes (API + menu du Hall) | 0.30.19 |
| **Vignette des topics vidéo**, prise dans la vidéo (`#t=0.5`) | 0.30.20 |

### Autres modules
- **`secubox-hub` 1.9.10** — coquille du panneau admin **entièrement masquée** en embarqué (sidebar, barre haute, barre basse, entête, pied), règle écrite en `.claude/WEBUI-PANEL-GUIDELINES.md §9`.
- **`secubox-socialrelay` 0.1.7** — **mur en mosaïque** multi-colonnes, quatre gabarits déduits du contenu (#1193).
- **`secubox-metrics` 1.11.1** — `localhost`, IP nues et `_` **hors des compteurs**, cache assaini au rechargement (#1191).
- **`secubox-repo` 1.1.2** — `repoctl` signe avec **l'email du nœud** (`gk2@secubox.in`).

### Infrastructure et outillage
- **Déploiement uniquement par paquet** — règle posée, mémorisée, appliquée depuis.
- `scripts/deploy.sh` : l'API Python partait dans un **répertoire fantôme** — 126 paquets sur 126 concernés.
- Paquets intégrés au dépôt apt (`bookworm-testing`, signés), **arm64 et amd64** là où c'est possible.
- Données du dépôt déplacées sur le **SSD** (`/data`), `/` était à 81 %.
- #1175, #1187, #1188, #1191, #1193 **closes**.

## 2. Ouvert — demandes tracées, pas encore faites

| # | Demande |
|---|---|
| **#1189** | MetaNews : **timestamp** des fils · **mots-clés cliquables** · **sources agrégées avec compteur** (`BFMTV 20`, pas vingt fois `BFMTV ·`) |
| **#1190** | Stats vhosts **et** PDF : **camembert par pays** + **histogramme des visites cumulées** depuis la première visite |
| **#1192** | Embarqué : **Radio et SocialRelay gardent leur entête** — appliquer §9 aux surfaces publiques |
| **#1194** | MetaNews : la **pondération multi-sources gèle la une** ; la fraîcheur doit primer puis redescendre vers la persistance |
| **#1195** | Mail : **antispam par règles Sieve** |
| **#1196** | BBS : la rubrique **Émissions n'est plus liée au podcaster** |
| **#1197** | Podcaster : **cardlets « émission »**, agrégation par source, épisodes précédent/suivant en commentaires, mosaïque de mini-cardlets, vignette relative |
| **#1198** | **Attrapeur d'URL** : lien intelligent ytsas, agrégation multi-source, **sync PeerTube + bouton « garder »**, autolien vers l'équivalent local ; pendant **audio** (musiques rapatriées, rejouées en embarqué, vignette vidéo) |
| **#1199** | BBS : **refonte de la page d'un topic** — barre de statut sous la mégabarre, flux en **cardlets dépliées** |
| **#1200** | **Carrousels et agrégation** partout où le contenu est une liste linéaire — chapeau des issues de rendu |
| **#1201** | **Cardlet Radio** : popups dimensionnables, même design imbriqué, lecteur micro BBS par défaut, **playlist avant les messages et après la saisie** |

Backlog antérieur, non touché : #1180, #1182, #1183, #1184, #1185, #1186.

## 3. Décisions qui attendent un arbitrage

1. **Caches Go dans le dépôt** — `.git` pèse 1,4 Go, 556 Mo de cache suivi (301 Mo préexistaient, le reste vient d'un `git add -A` de ma part). Désuivre, ou réécrire l'historique avec force-push ?
2. **`gitea` n'a rien reçu** de la session — dépôt injoignable depuis le poste. Seul GitHub est à jour.
3. **Le pool de `apt.secubox.in` est vide** : 175 entrées indexées, zéro `.deb` — un client apt aurait un 404 sur chaque téléchargement.
4. **`repoctl` et reprepro sont deux chemins pour un dépôt** ; `/data/apt` est celui qui sert.
5. **`secubox-metrics` est `disabled`** : il ne redémarrera pas au prochain reboot.
6. **`secubox-bbs` est arm64 uniquement** (`Architecture: arm64` + `GOARCH` figé) — le passer en `any` pour publier un amd64 ?
7. **Chrome « fenêtre » de l'affiche vs masthead AletheiaVox** : lequel gagne ? Bloque l'alignement sur la réf de rendu.
8. **Porter le webos en Go ?** Décision prise : *pas maintenant* — 421 lignes, 4 routes, et les mesures contredisent l'argument mémoire (webos Python 39,5 Mo contre bbs Go 196,5 Mo). Le déclencheur sera le Session Bridge et les adaptateurs cardlets.

## 4. Écarté ou annulé, avec la raison

- **Section « Accès » du BBS dans le menu du Hall** — livrée (0.30.11) puis **retirée à la demande** (0.30.12) : n'apportait rien, les entrées étant déjà atteignables depuis le BBS.
- **Refonte du wiki de #1188** — **abandonnée** : l'amont avait déjà fait ce travail sous #1179, en français, avec les vraies commandes et une version allemande. La remplacer aurait été une régression.
- **Mode « sans échec » du médaillon** (`prefers-reduced-motion`) — **retiré à la demande** : le Hall assume son allure.
- **`column-span:all` pour les cartes riches du mur** — **écarté** : un spanner fragmente le maçonnage en segments équilibrés séparément.
- **ffmpeg pour les vignettes vidéo** — **écarté**, conformément à la règle déjà posée dans `vignettes.go`.

## 5. Non fait, et il faut le dire

- **Aucune capture d'écran du dashboard** dans le dépôt (#1188 en demandait une ; je n'en ai pas fabriqué).
- **`Home-ZH` du wiki** non traduite.
- **La panne « médias BBS » n'a jamais été reproduite telle que décrite** au départ : ce sont trois causes distinctes qui ont été trouvées et corrigées (`/media-vignette`, `/vignette/`, `/biblio`), plus les vignettes d'actualité. `/c/emissions` n'était pas cassé — il est **vide**.
