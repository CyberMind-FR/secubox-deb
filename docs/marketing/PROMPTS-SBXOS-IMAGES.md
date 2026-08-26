<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SBXOS — prompts d'image

*Trois registres, trois usages. Chacun tient debout seul ; ensemble ils
racontent la même chose sous trois lumières.*

**Ce qui doit rester constant d'une image à l'autre**, sans quoi elles ne
formeront pas une famille :

| | |
|---|---|
| Fond | noir cosmos `#0a0a0f` |
| Accents | violet `#6e40c9` · cyan `#00d4ff` · or `#c9a84c` |
| Alerte | cinabre `#e63946`, **jamais** comme accent décoratif |
| Texte | ivoire `#e8e6d9` |
| Titres | Cinzel (gravé, lapidaire) |
| Données | JetBrains Mono |

> **Une règle à répéter dans chaque prompt** : *pas de faux texte*. Les
> générateurs inventent des mots ; on demande donc explicitement soit du texte
> exact, soit aucun texte.

---

## 1 · L'affiche — pour montrer le produit

> **Prompt.**
> A dark technical poster for a self-hosted appliance operating system called
> SBXOS. Deep cosmos-black background `#0a0a0f`. At the centre, a floating
> mosaic of eight rectangular cards of unequal heights, arranged like a
> puzzle — not a grid — each card a slightly lighter panel `#14141c` with a
> thin `#282836` border, each glowing faintly from within in a different
> accent: violet `#6e40c9`, cyan `#00d4ff`, gold `#c9a84c`. One card shows an
> abstract audio waveform, one a small bar chart, one a video frame with a
> play triangle, one a stack of text lines. Below the mosaic, a single
> horizontal bar with three small round pills glowing violet, like a media
> transport. Above, a thin gold rule. Lighting: cold, low-key, the glow comes
> from the cards themselves and nothing else — no lens flare, no bloom, no
> gradient wash. Composition centred and calm, generous negative space,
> engraved-serif restraint. Vertical poster, 3:4.
> **No text, no letters, no numbers, no logos anywhere in the image.**

*Pourquoi ces contraintes.* La mosaïque **inégale** est le sujet : c'est ce qui
distingue le hall d'une grille d'icônes. La lueur vient **des cartes**, pas
d'un éclairage extérieur — parce que ce sont les services qui s'affichent
eux-mêmes. Et l'interdiction de texte évite les mots inventés que les
générateurs collent sur ce genre d'image.

---

## 2 · Le schéma — pour expliquer la délégation

> **Prompt.**
> A clean technical diagram on a deep black background `#0a0a0f`, drawn in thin
> precise lines like an engineering schematic. Four rounded rectangles in a
> horizontal row, evenly spaced, outlined in ivory `#e8e6d9` at 1.5px, except
> the second which is outlined in gold `#c9a84c` and slightly emphasised.
> Between them, three short horizontal arrows in gold pointing right. Below the
> row, a long dashed ivory line looping from the fourth box back to the first,
> with an arrowhead at the first. Under everything, a thin horizontal rule and,
> beneath it, three small crossed-out circles in cinnabar `#e63946`. Flat,
> two-dimensional, no perspective, no shadows, no 3D, no gloss. Generous
> margins. Wide format, 16:9.
> **Contains no text of any kind — the labels will be added afterwards.**

*Pourquoi sans texte.* Les libellés de ce schéma sont **exacts** — « la carte »,
« la validation, hors du cadre », « le service, sa vraie page », « la box » — et
un générateur les rendra faux. On produit la géométrie, on pose les mots
ensuite dans un éditeur vectoriel. La boîte dorée est celle qui compte : la
validation qui se fait **hors du cadre**.

*Libellés à composer par-dessus, dans l'ordre :*
`la carte` → `la validation · pleine page` → `le service · sa vraie page` →
`la box · 0600`, la boucle en pointillé portant *« lit au nom de la personne,
et ne rend que des titres »*, et sous la règle : *« votre mot de passe · un
témoin capturé · le jeton jusqu'au navigateur »*.

---

## 3 · L'ambiance — pour la couverture, le partage social

> **Prompt.**
> A single small appliance sitting on a wooden desk in a dark room at night,
> photographed from a low three-quarter angle with a 50mm lens, shallow depth
> of field. The device is a matte black aluminium box the size of a hardback
> book, with one thin horizontal light slit across its front glowing cyan
> `#00d4ff`. Behind and above it, out of focus, several faint rectangular
> screens float in the darkness at different depths, each glowing softly in
> violet `#6e40c9` or gold `#c9a84c` — suggested, never legible. The room is
> otherwise unlit; the only light sources are the device and the distant
> panels. Cool colour temperature, deep blacks that stay black, no haze, no
> volumetric beams, no neon signage, no cables in frame. Quiet, domestic,
> unmistakably *someone's home* rather than a data centre. 16:9.
> **No text, no screen content, no brand marks.**

*Pourquoi une maison, pas un centre de données.* C'est l'argument du produit :
l'infrastructure est **chez vous**. Une salle serveur dirait exactement le
contraire. Les écrans flottants restent illisibles — dès qu'ils deviennent
lisibles, le générateur y écrit du charabia.

---

## Variantes utiles

**Format carré, pour Mastodon et les vignettes** — reprendre le prompt 1 en
remplaçant la dernière ligne par : *Square format, 1:1, the mosaic tightened to
five cards.*

**Version claire, pour l'impression** — inverser les fonds sans toucher aux
accents : *paper-white background `#f6f5f0`, cards in white with `#e2e0d6`
borders, accents unchanged but drawn as solid strokes rather than glows.* Les
lueurs ne survivent pas au papier ; les traits, oui.

**Bandeau large, pour l'en-tête du dépôt** — prompt 2 en `21:9`, avec *only the
four boxes and three arrows, everything else removed.*

---

## Ce qu'il ne faut pas demander

- **Un bouclier, un cadenas, une empreinte digitale.** Le vocabulaire visuel de
  la sécurité est épuisé, et il dit « produit de sécurité générique » là où
  SBXOS dit « votre infrastructure ».
- **Des lignes de code à l'écran.** Elles seront fausses, et elles s'adressent
  à la mauvaise personne.
- **Une silhouette à capuche.** Elle raconte l'attaquant ; le sujet est
  l'habitant.
- **Un dégradé violet-bleu plein cadre.** C'est la signature visuelle par
  défaut de la génération d'images, et elle se reconnaît immédiatement.
