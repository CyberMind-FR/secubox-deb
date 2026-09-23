<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WebOS / Hall — référence de rendu « SBX OS » (#1347, remplace #1175)

> **Réécrite le 2026-09-23.** La version #1175 transcrivait l'affiche
> *« SBXOS · le bureau numérique souverain »* du 24 août : un modèle à menus
> (Fichier, Édition, Affichage, Outils, Aide) avec « Studio SBX ». L'affiche en
> usage montre depuis une grille de vingt cartes, une barre du bas à cinq
> onglets et un mode téléphone en une colonne.
>
> **Deux cibles coexistaient, et rien ne disait laquelle faisait foi** — on
> pouvait donc déclarer le Hall conforme ou non selon celle qu'on choisissait.
> C'est le même défaut que la table de routes sbxwaf, le `frame-src` du Hall ou
> le test CSP périmé : une déclaration que personne ne possède. Il n'y a plus
> qu'une référence, et c'est ce fichier.
>
> **Ce qui n'existe pas encore s'y signale.** Chaque élément absent du Hall au
> 2026-09-23 porte un liseré orange et son numéro d'issue (#1337 à #1346). Une
> référence qui ressemble à une capture laisse croire que tout est fait ;
> celle-ci est mesurable — le jour où plus aucun liseré n'apparaît, l'écart est
> clos. **Retirer la marque en même temps que l'issue se ferme.**
>
> **Verrouillée en sombre**, à l'inverse de la précédente qui l'était en clair :
> l'affiche est en bleu nuit, et une cible qui bascule avec le thème du lecteur
> n'est plus un témoin.

## L'écart mesuré au 2026-09-23

| Manque | Issue |
|---|---|
| Carte **Mesh** — SecuBox du parc | #1337 |
| Carte **Énergie** — CPU/RAM/disque/température | #1338 |
| Carte **Identité** — GPG, certificats, LSCloud | #1339 |
| Carte **Invitations** — accès invité par QR | #1340 |
| Cartes **redimensionnables** (le glisser-déposer existe) | #1341 |
| Priorités **Focus / Normal / Veille** | #1342 |
| **Palette de commandes** (Ctrl+K ou Espace) | #1343 |
| **Centre de notifications** | #1344 |
| **Barre du bas** à cinq onglets | #1345 |
| **Shell mobile** une colonne | #1346 |

Les seize autres cartes de l'affiche existent. Le registre du Hall en déclare
**34** au total : l'affiche est une sélection, pas l'inventaire.

---

## Historique — la version #1175

**Fichier témoin** : `packages/secubox-webos/www/hall/render-ref.html` → servi sur
`https://hall.gk2.net/render-ref.html` (installé par `debian/rules`).
**Brief produit** : [`webos-sbx-hall-cardlets.md`](webos-sbx-hall-cardlets.md) — ce document
n'ajoute pas de scope, il **fige la cible visuelle** du §12 « Design visuel ».

## 1. Ce que c'est / ce que ce n'est pas
Transcription statique de l'affiche *SBXOS · le bureau numérique souverain* (maquette
fournie par Gérald, 2026-08-24). Zéro JS, zéro API, chiffres fictifs, aucune origine
tierce (polices locales, vignettes en dégradés CSS) → passe la CSP du vhost `hall`.

- **Sert à** : comparer côte à côte avec `index.html` (desktop **et** iPhone), arbitrer
  un désaccord de rendu, cadrer un nouveau module cardlet.
- **Ne sert pas à** : être le Hall, héberger de la donnée réelle, être forké en template.
- **Verrouillée en clair** : le canon est le papier. Le mode sombre ne se dessine pas ici,
  il se dérive des tokens `[data-theme="dark"]` de `index.html`.

## 2. Tokens — identiques à `index.html`, aucun token neuf sauf un
| Rôle | Token | Valeur |
|---|---|---|
| Encre | `--ink` | `#17232d` (titres d'affiche : `#16233a`) |
| Fond écran | `--paper` | `#eef2f6` |
| **Fond affiche** | `--poster` | `#f2f1ec` — *seul ajout*, papier plus chaud, hors app |
| Surface | `--panel` / `--soft` | `#ffffff` / `#f1f4f7` |
| Filets | `--line` / `--line-2` | `#dbe3e9` / `#c5cfd7` |
| Secondaire | `--dim` | `#647685` |
| Action / lien | `--sky` | `#1655a0` |
| Santé OK | `--mint` | `#1f7a58` |
| Alerte / live | `--coral` | `#a73d42` |
| Accent rare | `--gold` | `#b8912f` — filet sous le tagline, ornement, point final |

Si un écran a besoin d'une couleur absente de cette table : c'est un signal de
conception, pas un token à inventer.

## 3. Typographie — trois voix, jamais quatre
| Voix | Police | Emploi |
|---|---|---|
| Titre | **Fraunces** 400 | wordmark, `Hall`, **nom de cardlet** (~1,4 rem), baseline |
| Interface | **Inter** | texte courant, boutons |
| Donnée | **JetBrains Mono** | *tout* le factuel : états, compteurs, heures, tailles, chemins, libellés d'action |

Règle forte de l'affiche : **le chiffre est toujours en mono**, le **nom** toujours en
serif. Les libellés d'action et d'état sont en mono `.58–.62rem`, `letter-spacing ≈ .11em`,
capitales. Cinzel n'apparaît pas dans cette référence (réservé au médaillon AletheiaVox).

## 4. Anatomie — chrome de fenêtre
`titlebar` (pastille `--sky` · menus *Fichier Édition Affichage Aller Outils Aide* ·
à droite : LED + « Système opérationnel », séparateur, horloge, `− ▢ ×`), puis
`viewhead` (titre serif + sous-ligne mono `4 services actifs · Tout est sous votre
contrôle.`, santé alignée à droite sur deux lignes), puis grille, puis `statusbar`
(*Chiffrement actif* · *Données locales uniquement* · droite : *Utilisateur : vous* + roue).

La barre d'état n'est pas décorative : elle porte les **deux promesses souveraines**
(chiffrement, localité). Elle reste présente sur toutes les vues.

## 5. Anatomie — cardlet en trois bandes
```
┌ clh ── icône 34px · nom serif + état mono LED ······ action mono à droite ┐
│ clb ── la capacité vivante (une seule idée, pas de tableau de bord)       │
└ clf ── verbe/lien mono à gauche ······ métrique factuelle mono à droite ──┘
```
Filets `1px --line` entre les bandes, rayon `8px`, ombre `--shadow` seulement.
Chaque cardlet montre **une** métrique dominante ; l'affiche ne double jamais
l'information entre `clb` et `clf`.

Les quatre exemplaires figés :
- **Radio** — LED live, `Studio SBX` / `Émission en cours` / chrono à droite, forme
  d'onde pleine largeur, pied `▶ · 128 kbps · Stéréo · Auditeurs 342`. C'est la
  cardlet de référence du brief §6 : densité fonctionnelle à égaler, pas à dépasser.
- **Forum** — 4 sujets max, `titre / par auteur`, heure + **badge compteur encadré
  `--sky`**, pied `Voir tous les sujets ›`.
- **Cloud** — **quota AVANT les noms** (défaut privacy du brief §7) : jauge 9px, `25 %
  utilisé`, puis 4 lignes dossier/fichier, pied horodaté.
- **Photos** — mosaïque 3×2, ratio 4/3, rayon 4px, pied `Sauvegarde active` + LED.

## 6. Écarts assumés vs `index.html` (à trancher, pas encore appliqués)
1. **Rayon** : la maquette est à `8px` sur les cardlets (`10px` fenêtre) ; `index.html`
   est à `13–16px` (`--r`). L'affiche est plus « papier », plus sobre.
2. **Chrome** : la maquette a une *barre de fenêtre* (menus + horloge + `− ▢ ×`) ;
   `index.html` a un *masthead* logo + recherche + avatar. Les deux modèles coexistent
   mal — arbitrage produit à faire.
3. **Ombres** : maquette = `--shadow` seule sur les cartes, pas de `:hover` qui soulève.
4. **Densité** : grille 2 colonnes fixes à 4 cardlets vs `auto-fill minmax(280px,1fr)`.

## 7. Interdits (repris du brief §12, visibles dans la maquette)
Pas de mascotte Zanimalos par carte · pas de gradient lourd sous du texte · pas de
glass/néon · pas de donnée décorative · **jamais** santé ou latence masquées par
l'illustration · pas d'état encodé par la couleur seule (LED **+** mot).

## 8. Entretien
La référence évolue quand l'affiche évolue — pas quand le code évolue. Si `index.html`
s'en écarte volontairement, la divergence se note en §6 plutôt que de repeindre la réf.
