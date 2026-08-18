<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Tutoriels SecuBox

Cette documentation poursuit deux effets à la fois :

> **« C'est simple, je peux le faire. »**
> et
> **« Derrière cette simplicité, le système est sérieux. »**

SecuBox est complexe à l'intérieur. La documentation n'a pas à cacher cette
complexité — elle a à la rendre **navigable**.

---

## Le principe qui commande tout le reste

**Une seule source produit tous les formats.**

Un même sujet doit pouvoir devenir un article, un pas-à-pas, une fiche mémo, un
diaporama, un script vidéo, une aide contextuelle ou une entrée de FAQ — sans
être réécrit à chaque fois. Réécrire, c'est diverger : au troisième format, les
trois se contredisent et plus personne ne sait lequel dit vrai.

C'est l'objet de la [Content Factory](factory/content-factory.md).

## Le principe qui protège le premier

**Le dépôt est la source de vérité. Rien ne s'invente.**

Chaque affirmation technique doit pouvoir être vérifiée dans le code. Quand une
information manque, on écrit `À documenter` — jamais une valeur plausible.

Ce n'est pas de la prudence rédactionnelle : une documentation qui comble ses
trous par de la vraisemblance **ne se laisse plus auditer**. On ne peut plus
distinguer ce qui a été vérifié de ce qui a été supposé, et elle perd toute
valeur, y compris là où elle était juste.

Une hypothèse assumée s'écrit `HYPOTHÈSE À VALIDER`. Elle ne devient jamais un
fait par simple ancienneté.

---

## Où aller

| Vous voulez… | Allez à |
|---|---|
| découvrir SecuBox pas à pas | [Parcours d'apprentissage](learning/learning-path.md) |
| savoir quoi documenter en premier | [Priorité des tutoriels](learning/tutorial-priority.md) |
| savoir ce que SecuBox contient | [Catalogue des modules](catalog/modules.md) |
| écrire un tutoriel | [Modèle de tutoriel](templates/tutorial-template.md) |
| connaître les règles d'écriture | [Guide de rédaction](guidelines/documentation-guidelines.md) |
| dessiner une illustration | [Design system](design/design-system.md) |
| produire une vidéo | [Règles vidéo](design/video-guidelines.md) |
| comprendre l'état documentaire réel | [Rapport d'audit](AUDIT-DOCUMENTATION.md) |

---

## Structure

```text
tutorial/
  README.md                    ← vous êtes ici
  AUDIT-DOCUMENTATION.md       état réel, mesuré
  CODE-ISSUES-DISCOVERED.md    défauts vus en documentant, NON corrigés

  guidelines/                  comment écrire
  design/                      comment illustrer
  learning/                    dans quel ordre apprendre
  catalog/                     ce qui existe (généré depuis le dépôt)
  fiches/                      les tutoriels eux-mêmes
  templates/                   les moules
  factory/                     comment une source devient plusieurs formats
```

### `catalog/` est **généré**, pas écrit

`catalog/modules.yaml` et `catalog/modules.md` sortent de
`scripts/docs-audit.py`, qui lit le dépôt.

Les éditer à la main serait perdre son temps : la prochaine exécution écraserait
la correction. Pour corriger une entrée, corriger sa **source** — le plus souvent
`packages/<module>/debian/secubox.yaml`.

```bash
python3 scripts/docs-audit.py
```

Le YAML est la source machine ; le Markdown en dérive. Cet ordre n'est pas
arbitraire : l'inverse obligerait à saisir deux fois la même chose, donc à
diverger.

---

## Ce que le catalogue dit aujourd'hui

Mesuré sur le dépôt, non supposé :

| | |
|---|---|
| **173 modules** | dont **41 sans manifeste** |
| 140 avec API | 138 avec interface web |
| 63 avec CLI | 24 en conteneur LXC |
| | **30 sans README** |

Les 41 modules sans manifeste et les 30 sans README sont la première dette à
résorber. Le [rapport d'audit](AUDIT-DOCUMENTATION.md) les nomme.

---

## Pour qui

Le lecteur par défaut **ne connaît pas** Linux, Debian, LXC, DNS, SMTP, IMAP,
WireGuard, la fédération ni les API. Il n'a pas à les connaître pour se servir de
sa SecuBox.

Un terme technique s'explique **avant** d'être employé, ou ne s'emploie pas.

Le ton est accessible et précis. Jamais infantilisant : le lecteur ignore peut-être
ce qu'est un enregistrement DNS, il n'est pas sot pour autant.

---

## Préparer la suite

Cette documentation a vocation à devenir une application web SecuBox : recherche
plein texte, filtres par module, niveau et rôle, enchaînement précédent/suivant,
génération de pages, de diaporamas et de vidéos, traduction, versionnage.

D'où le format structuré du catalogue et des fiches sources. Enfermer la
connaissance dans du Markdown libre fermerait toutes ces portes d'un coup.
