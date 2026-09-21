<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# Références SBX OS — documents de conception

Le **guide 16 pages** est la référence produit. Il définit le *reverse design*
— ses maquettes d'interface fixent la cible que l'implémentation doit
atteindre — et il porte la **feuille de route** (court / moyen / long terme,
page 14).

| document | rôle | SHA-256 |
|---|---|---|
| `SecuBox-DEB_Guide_16_pages_Mockup_v3.pdf` | référence produit et reverse design | `504f1330a9e41817bef4…` |
| `LDXOS-Hall-Sketchbook.pdf` | carnet de croquis du Hall | `7e69b5d63af7263712a7…` |
| `SBX_OS_Compagnon_Mockup_v1.pdf` | compagnon SBX OS | `7977b8e05dda938ac358…` |

## La transcription, et pourquoi elle existe

[`Guide_16_pages_v3.0.0-alpha.2.txt`](Guide_16_pages_v3.0.0-alpha.2.txt)

Le PDF ne contient **aucun texte extractible** : 16 pages, 18 images, zéro
caractère récupérable par `pdftotext`.

Ce n'est pas un détail de forme. Sans transcription, le document n'est :

* **ni cherchable** — impossible de savoir si « Photoprism » y figure sans
  ouvrir les 16 pages et les regarder une à une ;
* **ni comparable** — on ne peut pas *differ* une v4 contre la v3 ;
* **ni citable** depuis une issue, un commit ou une spécification ;
* **ni accessible** aux lecteurs d'écran ;
* **ni visible** d'aucune chaîne automatique.

La démonstration a été faite à nos dépens : ce document était **déjà la
référence** pendant qu'un audit interne affirmait le contraire, faute de
pouvoir le lire. L'écart n'était pas dans les faits, il était dans le format.

**Le PDF reste la forme diffusée ; le texte est la forme vérifiable.** Les
deux doivent avancer ensemble — une transcription qui prend du retard est
pire qu'aucune, parce qu'on la croit à jour.

## Points relevés à la lecture

| | |
|---|---|
| Page 2 | « pour des **pitsoyens** libres » → *citoyens* |
| Pied de page | `v3.0.0-alpha.2` alors qu'**alpha.4** est publiée |
| Page 14 | annonce **128 modules** ; le dépôt en porte **174** |
| Page 5 | **OnlyOffice / Collabora** : seule des onze fonctions montrées sans paquet |
| Liens | `radio.gk2.secubox.in`, `all.gk2.net` — adresses du **nœud de développement** |
| Page 15 | engage des **tarifs** (49 / 69 / 99 €/mois) — seul engagement contractuel |

Analyse complète :
[`../../audits/ANALYSE-DOCUMENTS-REFERENCE.md`](../../audits/ANALYSE-DOCUMENTS-REFERENCE.md)
