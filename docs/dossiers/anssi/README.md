<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# Dossiers institutionnels — archive versionnée

Les documents envoyés à des tiers institutionnels sont archivés **ici**, dans
le dépôt, et non seulement dans un répertoire personnel.

**Pourquoi.** L'audit `docs/audits/AUDIT-DOSSIER-ANSSI-vs-CODE.md` compare une
VERSION PRÉCISE du dossier à une version précise du code. Si le PDF vit hors
du dépôt et qu'il bouge, l'audit devient invérifiable : on ne peut plus savoir
ce qui a été comparé. Les empreintes ci-dessous rattachent l'audit à son objet.

Le texte extrait accompagne chaque dossier technique : il permet de *differ*
une V1.2 contre la V1.1 sans rouvrir un PDF, ce qu'aucun outil de revue ne
sait faire proprement.

| Document | SHA-256 | Taille |
|---|---|---|
| `Courriel_ANSSI_SecuBox-Deb.pdf` | `1a55ef744a0c07f8c613759fd71addc5…` | 25.6 Ko |
| `Dossier_saisine_CNIL_SecuBox_SBXOS.pdf` | `b795693b85af838d8b4860c4e4230c93…` | 149.9 Ko |
| `Dossier_technique_SecuBox-Deb_ANSSI_V1.1_illustree.pdf` | `5b4e49464d04052d8950a1ea694c34c1…` | 626.6 Ko |

## Contenu

- **Dossier technique ANSSI V1.1** (22 août 2026) — présentation technique et
  sollicitation d'un regard critique. C'est la référence de l'audit comparatif.
- **Courriel ANSSI** — échange d'accompagnement.
- **Dossier de saisine CNIL** (SecuBox / SBXOS) — à rapprocher de l'écart RGPD
  relevé dans l'audit : le collecteur `cookie_audit` ne tourne pas (#1311).

## Règle

Un document envoyé à l'extérieur est **figé**. Une révision ne remplace jamais
un fichier existant : elle s'ajoute sous son propre numéro de version. Écraser
une V1.1 par une V1.2 détruirait la seule preuve de ce qui a été effectivement
transmis, et à quelle date.
