<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SBXOS — le Hall 🪟

[EN](WebOS) | **[FR](WebOS-FR)** | **🟣 ACCÈS** | tous vos services sur une page

> Vos services ne sont pas *listés* sur cette page. Ils y sont.

## En un mot

Ouvrez `https://hall.<votre-box>/`. La radio joue dans sa vignette, le pare-feu
y compte ce qu'il a bloqué, le forum y fait défiler ses discussions. Vous passez
d'un service à l'autre **sans que la musique s'arrête**.

## Ce que vous pouvez faire

| Geste | Ce qui se passe |
|---|---|
| Cliquer une vignette | Le service s'ouvre **dans** le Hall, pas ailleurs |
| Attraper le ⠿ d'une vignette | Vous la déplacez ; la position est retenue |
| ▶ dans une vignette | Le son démarre et **suit** votre navigation |
| ⌄ sur la barre du bas | La barre se range ; les pastilles restent |
| Cliquer une pastille | La barre revient |
| ◐ en haut à droite | Bascule clair / sombre, retenue pour votre profil |
| 🧙 votre avatar | Vos réglages, et **où vous êtes connecté** |

## La barre du bas

Dès que quelque chose joue, une barre apparaît en bas. Elle survit au
changement de page : c'est le même son qui continue, pas un nouveau qui
recommence.

Chaque ligne a **son propre volume** — vous pouvez baisser la radio pour
entendre le podcast, sans couper l'une pour l'autre.

- **⌄** range la barre. **✕** ferme le flux. Ce n'est pas la même chose.
- Une fois rangée, les **pastilles rondes** en haut vous disent ce qui joue
  encore ; survolez-les pour le titre, cliquez pour retrouver la barre.

## Vos identités

Le menu de votre avatar liste **les services où une session est ouverte**, et
depuis quand. Un service silencieux depuis plus d'un jour apparaît en grisé :
la session y est sans doute expirée.

Un clic vous y emmène.

> **Ce que le Hall ne sait pas.** Ni vos mots de passe, ni le contenu de vos
> témoins de connexion. Le registre qu'il consulte n'en garde qu'une empreinte,
> jamais la valeur — il peut dire *« vous êtes connecté ici »*, jamais *« voici
> comment »*.

## Pourquoi certaines vignettes sont différentes

Trois cas, et le Hall prend toujours le meilleur disponible :

1. **Le service dessine sa propre vignette** — la radio, le pare-feu, le
   podcaster, les billets, MetaNews, le forum, SocialRelay. C'est le service
   lui-même qui décide de ce qui mérite d'être montré.
2. **Le service n'en a pas encore** — le Hall affiche alors sa **vraie page**,
   réduite. Rien n'est inventé.
3. **Le service refuse d'être affiché** — vous voyez une carte simple avec un
   bouton pour l'ouvrir.

Le jour où un service apprend à dessiner sa vignette, elle remplace la
précédente toute seule.

## Réinitialiser

Menu avatar → **↺ Réinitialiser l'affichage**. Vos vignettes retrouvent leur
ordre d'origine — les plus abouties en premier — et le thème repart de celui de
votre système. Cela ne touche **que votre profil** : les réglages des autres
personnes du foyer restent intacts.

## Si quelque chose ne va pas

| Symptôme | Piste |
|---|---|
| Une vignette reste vide | Le service est peut-être arrêté — ouvrez-le en onglet pour voir |
| Le son ne démarre pas au clic | Votre navigateur attend un geste **dans** la vignette : recliquez dedans |
| Vous êtes déconnecté d'un service | Ouvrez-le en direct une fois, puis revenez au Hall |
| Tout est en clair alors que vous voulez du sombre | ◐ en haut à droite ; le choix est retenu par profil |

## Pour aller plus loin

Les notes de conception — contrat des vignettes, contraintes d'affichage,
cookies et politique de sécurité — vivent dans `docs/WEBOS-DESIGN.md` du dépôt.
