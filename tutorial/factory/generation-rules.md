<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Règles de génération

Comment une fiche source devient chaque format. Ces règles doivent rester
assez précises pour qu'un programme les applique.

## Communes à tous les formats

1. **Rien ne s'invente.** Un champ absent produit `À documenter` dans la
   sortie, jamais une valeur plausible ni un silence.
2. **Le champ `source` est reporté** dans tout format écrit. Une fiche
   diffusée sans sa source n'est plus vérifiable par celui qui la reçoit.
3. **Le `level` conditionne le vocabulaire.** Un rendu `debutant` qui contient
   un terme non expliqué est une erreur de génération, pas de style.
4. **Une fiche `brouillon` ne produit que du texte.** Ni vidéo, ni diaporama :
   ces formats coûtent trop cher à refaire.

## Article wiki

- Titre = `title`.
- Bandeau : `level` · `duration` · `module`.
- `prerequisites` en tête, avec leurs liens.
- `steps` numérotées ; chaque `expected_result` en retrait sous son action.
- `success_criteria` sous « Ça marche si… ».
- `troubleshooting` en tableau `symptom` / `cause` / `fix`.
- `next` en fin de page.

## Mémo

- Une page. **Coupe dure** au-delà.
- Uniquement `steps[].action` — les résultats attendus sautent.
- Deux entrées de `troubleshooting`, les plus fréquentes.
- `success_criteria` conservé : c'est ce qu'on vient vérifier.

## Diaporama

Huit diapositives, correspondance fixe :

| Diapo | Source |
|---|---|
| 1 | `title`, `level`, `duration` |
| 2 | `title` reformulé en objectif |
| 3 | `steps[0]` |
| 4 | l'étape portant le geste principal |
| 5 | `success_criteria` |
| 6 | `troubleshooting[0]` |
| 7 | trois points tirés des `steps` |
| 8 | `next` |

Une fiche de moins de trois étapes ne produit pas de diaporama : il n'y aurait
rien à mettre en diapositives 3, 4 et 7.

## Script vidéo

- Intro ← `title` + objectif.
- Situation ← à écrire par l'auteur : **la fiche source ne la contient pas**.
  C'est le seul apport humain obligatoire, et il doit être signalé comme tel.
- Démonstration ← `steps`, une phrase par étape.
- Astuce ← `troubleshooting[0].fix`, reformulé en conseil préventif.
- Validation ← `success_criteria`. **Segment non supprimable.**
- Outro ← `next`.

## Aide contextuelle

- Déclenchée par la route web de `source.web_route`.
- Ne montre que l'étape correspondant à l'écran affiché.
- Toujours un lien vers la fiche entière : l'aide contextuelle répond à
  « et maintenant ? », pas à « comment ça marche ? ».

## FAQ

Chaque `troubleshooting` devient une entrée :

```text
Q ← symptom, tourné en question
R ← fix, précédé d'une phrase tirée de cause
```

La FAQ ne contient **que** du `troubleshooting`. Y verser des étapes en fait un
tutoriel mal rangé, que personne ne trouvera.

## Traduction

- Champs traduisibles : `title`, `steps[].action`, `steps[].expected_result`,
  `success_criteria`, `troubleshooting[*]`.
- Champs jamais traduits : `id`, `module`, `source`, `next`, `prerequisites[].id`.

Traduire un `id` casse tous les liens entre fiches, dans toutes les langues à
la fois.
