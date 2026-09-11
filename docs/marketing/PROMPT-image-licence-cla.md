<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Infographie « en couches » — Licence CMSD-1.0 & CLA (prompts image)

Infographie **multi-couches, une bande par public**, expliquant d'un coup d'œil la
licence [CMSD-1.0](../../LICENCE-CMSD-1.0.md) et le [CLA](../../CLA.md). Ci-dessous :
(A) le **contenu** de chaque couche (la substance, fidèle aux textes), puis les
prompts image pour (B) **Gemini** et (C) **GPT/DALL·E**.

> ⚠️ **Limite des modèles d'image.** Ils rendent mal les longs paragraphes (texte
> déformé). Les prompts imposent donc des **libellés COURTS et EXACTS**. Pour un
> rendu propre, deux options : (1) garder le texte minimal comme ici ; (2) générer
> le visuel/icônes puis **incruster le texte réel** dans un éditeur (Figma, etc.).

---

## A. Contenu des couches (source de vérité — fidèle aux articles)

**Titre :** SecuBox-DEB — Licence CMSD-1.0 & CLA
**Sous-titre :** Code OUVERT pour l'audit · Droits d'usage RÉSERVÉS

| # | Public | Icône | ✅ Peut | ⛔ Ne peut pas / doit | Réf. |
|---|--------|-------|--------|----------------------|------|
| 1 | Curieux | 👁️ | Lire, étudier, analyser le code | Utiliser en production | art. 3-4 |
| 2 | Chercheur sécurité | 🔬 | Auditer, compiler en labo, publier | Divulgation coordonnée 90/30 j | art. 7-8 |
| 3 | Contributeur | 💻 | Proposer un patch, garder sa paternité | Droits patrimoniaux cédés à CyberMind, sans paiement | CLA art. 2-3 |
| 4 | DSI / entreprise | 🏢 | Évaluer, auditer | Prod = licence écrite obligatoire ; brevets réservés | art. 4-6 |
| 5 | Journaliste / public | 📰 | Vérifier, citer, relayer | Transparence ≠ droit d'exploitation | art. 2 |

**Pied :** Droit français · Cour d'appel de Chambéry · *Ceci n'est pas un avis juridique.*

**Palette (charte projet) :** fond noir cosmos `#0a0a0f`, or hermétique `#c9a84c`,
cyan `#00d4ff`, vert « ✅ » `#00ff41`, rouge « ⛔ » `#e63946`, texte crème `#e8e6d9`.

---

## B. Prompt pour GEMINI (Imagen 3 / « Nano Banana »)

```
Crée une infographie verticale, format 3:4, style flat-vector épuré et
« cyber-souverain ». Fond noir profond (#0a0a0f) avec une fine trame de lignes.

Composition : un EMPILEMENT de 5 bandes horizontales (des « couches »), plus un
bandeau-titre en haut et un pied de page en bas. Chaque bande a la même largeur,
un liseré cyan lumineux (#00d4ff), une grande icône ronde à gauche, un titre de
public à côté, puis deux mini-blocs à droite : un « ✅ » vert (#00ff41) et un
« ⛔ » rouge (#e63946).

Bandeau-titre : grand texte or (#c9a84c) « SecuBox-DEB — CMSD-1.0 & CLA », sous-
titre crème « Code OUVERT pour l'audit · Droits d'usage RÉSERVÉS ».

Les 5 bandes, de haut en bas (icône / public / ✅ / ⛔) :
1. Icône œil 👁 · « Curieux » · ✅ « Lire & étudier » · ⛔ « Pas de prod »
2. Icône loupe 🔬 · « Chercheur sécu » · ✅ « Auditer & publier » · ⛔ « Divulgation 90/30 j »
3. Icône code </> 💻 · « Contributeur » · ✅ « Garde sa paternité » · ⛔ « Droits cédés, non payés »
4. Icône immeuble 🏢 · « DSI / entreprise » · ✅ « Évaluer » · ⛔ « Prod = licence écrite »
5. Icône journal 📰 · « Journaliste » · ✅ « Citer & relayer » · ⛔ « Transparence ≠ exploitation »

Pied de page, petit texte cyan : « Droit français · Chambéry · Pas un avis juridique ».

Contraintes : rends le texte EXACTEMENT comme indiqué, en français, très LISIBLE,
sans faute et sans texte inventé. Libellés courts, pas de paragraphes. Icônes
minimalistes en ligne dorées. Look premium, aéré, haute lisibilité, contraste fort.
```

---

## C. Prompt pour GPT (gpt-image-1 / DALL·E 3, via ChatGPT)

```
A clean flat-vector infographic, 1024x1365 (portrait 3:4), premium "sovereign
cyber" style. Deep near-black background #0a0a0f with a faint tech grid.

Layout = a vertical STACK of 5 equal horizontal bands ("layers"), with a title
header on top and a footer at the bottom. Each band: thin glowing cyan border
(#00d4ff), a round line-icon on the left, an audience title, and on the right two
small chips — a green "✅" chip (#00ff41) and a red "⛔" chip (#e63946).

HEADER: large gold text (#c9a84c) "SecuBox-DEB — CMSD-1.0 & CLA"; cream subtitle
"Code OUVERT pour l'audit · Droits d'usage RÉSERVÉS".

The 5 bands, top to bottom (icon / audience / ✅ / ⛔), render the French text
EXACTLY and legibly, no invented words, no long paragraphs:
1) eye icon — "Curieux" — ✅ "Lire & étudier" — ⛔ "Pas de prod"
2) magnifier icon — "Chercheur sécu" — ✅ "Auditer & publier" — ⛔ "Divulgation 90/30 j"
3) code </> icon — "Contributeur" — ✅ "Garde sa paternité" — ⛔ "Droits cédés, non payés"
4) building icon — "DSI / entreprise" — ✅ "Évaluer" — ⛔ "Prod = licence écrite"
5) newspaper icon — "Journaliste" — ✅ "Citer & relayer" — ⛔ "Transparence ≠ exploitation"

FOOTER small cyan text: "Droit français · Chambéry · Pas un avis juridique".

Style: gold thin-line icons, cream text (#e8e6d9), strong contrast, generous
spacing, high legibility, no watermark, no logos other than the wordmark text.
Keep every label short so the text renders crisp.
```

---

## D. Variante « carte unique » (bannière large 16:9)

Pour un en-tête de dépôt / réseau social, remplacer « empilement vertical de 5
bandes » par : « 5 colonnes côte à côte (une par public), format 16:9 (1600x900),
même icône/✅/⛔ par colonne, titre or centré en haut, pied de page en bas ». Le
reste (couleurs, libellés exacts, contraintes de texte) est identique.

---

*Rappel : la version française des textes source fait foi (licence art. 13.5).
Toute vulgarisation, texte ou image, n'a qu'une valeur pédagogique — pas un avis
juridique.*
