# Content Factory

## Le problème qu'elle résout

Un même sujet doit exister en article, en pas-à-pas, en mémo, en diaporama, en
vidéo, en aide contextuelle et en FAQ.

Les écrire séparément, c'est les faire **diverger**. Au troisième format, les
trois se contredisent et plus personne ne sait lequel dit vrai. La documentation
devient alors pire qu'absente : elle induit en erreur avec autorité.

D'où la règle : **une source, tous les formats.**

```text
                    FICHE SOURCE
                  (en-tête YAML)
                         │
     ┌──────────┬────────┼────────┬──────────┐
     │          │        │        │          │
  article    pas-à-pas  mémo  diaporama   script
   wiki                                    vidéo
     │                                        │
   FAQ ◄──────── aide contextuelle ──────► short
```

## La fiche source

Tout part de l'en-tête YAML du [modèle de
tutoriel](../templates/tutorial-template.md).

```yaml
id: communication.webmail.login
title: Se connecter au Webmail
module: secubox-mail
category: communication
level: debutant
duration: 2m
role: utilisateur

prerequisites:
  - id: getting-started.compte
    label: Disposer d'un compte SecuBox

steps:
  - action: Ouvrir l'adresse du webmail dans le navigateur.
    expected_result: La page de connexion s'affiche.

success_criteria: La liste des messages reçus s'affiche.

troubleshooting:
  - symptom: Mot de passe refusé
    cause: Identifiant saisi sans le domaine
    fix: Saisir l'adresse complète.

next:
  - communication.webmail.envoyer

source:
  package: packages/secubox-mail/
  service: secubox-mail.service
  api: GET /api/v1/mail/status
  web_route: https://webmail.<domaine>/
```

### Pourquoi chaque champ existe

| Champ | Sans lui |
|---|---|
| `id` | pas de lien stable entre fiches ; renommer un titre casse tout |
| `module` | impossible de filtrer par module, ni de savoir quoi mettre à jour quand un module change |
| `level` | on sert de l'avancé à un débutant |
| `duration` | le lecteur ne peut pas décider s'il commence maintenant |
| `prerequisites` | on envoie quelqu'un dans un mur |
| `steps[].expected_result` | le lecteur ne sait pas s'il peut continuer |
| `success_criteria` | il ne sait pas s'il a réussi |
| `troubleshooting` | le premier obstacle est définitif |
| `next` | pas de parcours, seulement des fiches isolées |
| `source` | **la fiche n'est pas vérifiable** — une fausse ressemble à une vraie |

`source` est le champ qui rend la documentation auditable. Une fiche sans lui
peut être fausse sans que personne ne puisse le démontrer.

## Ce que chaque format prend

| Format | Champs consommés |
|---|---|
| **Article wiki** | tout, dans l'ordre |
| **Pas-à-pas** | `steps`, `success_criteria` |
| **Mémo** | `title`, `steps[].action`, deux `troubleshooting` |
| **Diaporama** | `title`, `duration`, `level`, `steps`, `success_criteria`, `next` |
| **Script vidéo** | idem + narration dérivée des `action` |
| **Short** | une seule `step`, celle qui porte le geste principal |
| **Aide contextuelle** | `title`, la `step` correspondant à l'écran, `troubleshooting` |
| **FAQ** | `troubleshooting`, transformé en questions |

Aucun format n'invente : tout provient de la fiche. Un format qui a besoin
d'une information absente signale que **la fiche source est incomplète**, pas
qu'il faut l'écrire dans ce format-là.

## Règle de propagation

Une correction se fait **dans la fiche source**, jamais dans un format dérivé.

Corriger le diaporama sans la source garantit que la prochaine génération
réintroduira l'erreur — et que le diaporama et l'article diront deux choses
différentes en attendant.

## Statut d'une fiche

| Statut | Signification |
|---|---|
| `brouillon` | écrite, non vérifiée contre le code |
| `verifie` | chaque affirmation technique confrontée au dépôt |
| `a-revoir` | le module a changé depuis la vérification |
| `obsolete` | la fonction décrite n'existe plus |

Seules les fiches `verifie` peuvent produire des formats destinés à être
diffusés. Une vidéo est coûteuse à refaire : on ne la tire pas d'un brouillon.

## Ce que la Factory prépare

La documentation deviendra une application web SecuBox. Le format structuré
permet, sans réécriture :

- la recherche plein texte sur les champs ;
- les filtres par module, niveau, rôle, catégorie ;
- l'enchaînement précédent/suivant, depuis `next` et `prerequisites` ;
- la génération de pages, de diaporamas, de vidéos ;
- la traduction — seuls les champs textuels partent au traducteur ;
- le versionnage par version de SecuBox.

Enfermer la connaissance dans du Markdown libre fermerait ces sept portes d'un
seul coup.
