<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Analyse des documents de référence — guide SBX OS 16 p. & dossier ANSSI V1.1

> **Correction préalable.** Une première version de cette analyse concluait que
> « le document ne décrit plus le projet qu'il pilote », la couche applicative
> — Hall, Nextcloud, PeerTube, radio, photos — étant absente du dossier ANSSI.
>
> C'était faux, et la méthode était en cause. Je n'avais lu que le **texte
> extractible**. Or :
>
> * le dossier ANSSI porte une **planche illustrée** (page 2) qui contient une
>   matrice de positionnement notée, le concept **TIAWOX** nommé, les fonctions
>   clés et une feuille de route en quatre colonnes — rien de tout cela n'est
>   extractible ;
> * et la référence produit est un **autre document**, un guide de 16 pages,
>   **entièrement graphique**, que mes outils textuels ne pouvaient pas voir.
>
> La couche applicative est documentée. Elle l'est **ailleurs**, et dans un
> format qu'aucune chaîne automatique ne lit.

---

## 1. Les deux documents, et ce qu'ils font

| | dossier ANSSI V1.1 | guide SBX OS 16 p. |
|---|---|---|
| Date | 22 août 2026 | **21 septembre 2026, 07:19** |
| Pages | 8 | 16 |
| Version produit | « Alpha » | `v3.0.0-alpha.2` |
| Destinataire | évaluateur institutionnel | **utilisateur, collectivité, association** |
| Registre | positionnement technique | produit, usage, souveraineté |
| Texte extractible | ~1 300 mots + 1 planche | **zéro** |

Ils ne se recouvrent pas : le premier décrit la **fonction de bordure** (VHOST,
WAF, déception, mesh), le second décrit **le produit** (100+ modules, un
appareil multi-services).

**Aucun des deux ne mentionne l'autre.** Un lecteur qui n'en reçoit qu'un
repart avec une moitié, sans savoir qu'il lui en manque une.

---

## 2. Le guide 16 pages comme référence de *reverse design*

C'est sa vraie fonction : les maquettes d'interface qu'il porte **définissent
la cible**. SecuMail, SecuBBS, SecuBox Radio, la galerie Photoprism, le lecteur
RSS — chacune fixe ce que l'implémentation doit atteindre.

### Le dispositif éditorial est un instrument de conception

Chaque service est présenté en triptyque :

```
le service   ·   « Ce que ça remplace »   ·   « Pourquoi ce choix ? »
```

Ce n'est pas de l'argumentaire. C'est une **discipline** : tout module doit
nommer l'incumbent qu'il déloge et justifier son existence face à lui. Un
module qui ne sait pas remplir les deux colonnes n'a pas sa place. Peu de
projets s'imposent cette contrainte, et elle vaut mieux qu'une liste de
fonctionnalités.

### L'écart maquette ⟷ réalité, mesuré

| service montré | paquet | installé sur gk2 |
|---|---|---|
| Mail · Chat · Visio · Forum/BBS | ✅ | ✅ |
| Nextcloud · Agenda · Contacts | ✅ | ✅ |
| PeerTube · Radio · RSS/Blog | ✅ | ✅ |
| **Photoprism** | ✅ | ✅ |
| **OnlyOffice / Collabora** | ❌ **aucun paquet** | ❌ |

**Dix sur onze.** Le document décrit donc un produit qui existe — ce qui est
rare pour une maquette, et ce qui rend le onzième d'autant plus visible.

**L'édition collaborative est la seule promesse non tenue.** La page 5 en
montre une capture OnlyOffice complète, avec un document nommé « Projet
SecuBox ». C'est le genre de détail qui fait croire à une fonction livrée.

---

## 3. Le défaut central : un document de référence que les machines ne lisent pas

Le guide ne contient **aucun texte extractible**. 16 pages, 18 images, zéro
caractère récupérable.

Les conséquences ne sont pas esthétiques :

* **Il n'est pas cherchable.** Personne ne peut savoir si « Photoprism » y
  figure sans ouvrir les 16 pages et les regarder.
* **Il n'est pas comparable.** On ne peut pas *differ* une v4 contre la v3 :
  il faut relire.
* **Il n'est pas citable.** Aucun moyen de référencer une phrase depuis une
  issue, un commit ou une spécification.
* **Il n'est pas accessible** — lecteurs d'écran, malvoyants, et tout
  utilisateur qui dépend du texte.
* **Il échappe à toute chaîne automatique**, y compris à un audit interne.
  C'est démontré : ce document est passé inaperçu de toutes mes recherches
  jusqu'à ce qu'on m'en signale l'existence.

**Un document de référence que seule une lecture humaine peut consulter cesse
d'être une référence dès que l'équipe s'élargit ou que son auteur est
indisponible.**

### Ce que ça coûte concrètement

Ce document est daté d'aujourd'hui, 07:19. Il était déjà la référence pendant
que j'écrivais un audit qui affirmait le contraire. L'écart n'était pas dans
les faits : il était dans le **format**.

### Le remède est simple

Exporter en regard une version texte ou Markdown du même contenu — ce que fait
déjà `docs/dossiers/anssi/` pour le dossier ANSSI. L'image reste la forme
diffusée ; le texte devient la forme **vérifiable**.

---

## 4. Points mineurs, mais à corriger avant diffusion

| | |
|---|---|
| Page 2 | « pour des **pitsoyens** libres » → *citoyens* |
| Pied de page | `v3.0.0-alpha.2` alors que **alpha.4** est publiée |
| Liens | `radio.gk2.secubox.in`, `all.gk2.net` — adresses du **nœud de développement**, pas du produit. À vérifier avant diffusion large. |

Le troisième point n'est pas cosmétique : un guide public qui pointe vers la
box personnelle de son auteur expose un nœud réel à un lectorat inconnu.

---

## 5. Ce que les deux documents disent ensemble, et qu'aucun ne dit seul

Mis côte à côte, ils décrivent une thèse cohérente et, à ma connaissance,
singulière :

> une même petite machine protège la bordure **et** héberge les services
> qu'elle protège — et c'est précisément parce qu'elle héberge qu'elle sait
> ce qui mérite protection.

Le dossier ANSSI le dit par la déception (« observer ce que l'on n'a jamais
publié »). Le guide le dit par les usages (« vos données restent chez vous »).
**C'est la même idée vue des deux bouts.**

Ni l'un ni l'autre ne l'énonce. C'est pourtant la phrase qui justifierait à la
fois le périmètre CSPN restreint et l'ampleur du catalogue applicatif — les
deux choses qui, prises séparément, paraissent en tension.

---

## 6. Recommandations, par effet décroissant

1. **Donner au guide une version textuelle.** C'est ce qui le fait entrer dans
   le dépôt, dans les revues, dans les audits — et dans les outils.
2. **Livrer ou retirer l'édition collaborative.** Une capture OnlyOffice dans
   un guide diffusé est une promesse ; c'est la seule des onze qui n'est pas
   tenue.
3. **Se citer l'un l'autre.** Une ligne dans chaque document renvoyant à
   l'autre suffit à supprimer l'effet « une moitié du produit ».
4. **Aligner la version** sur la release courante.
5. **Vérifier les URL** avant diffusion large.
6. **Énoncer la thèse du §5** — elle est la colonne vertébrale des deux
   documents et n'est écrite dans aucun.

---

*Analyse du 21 septembre 2026. Elle corrige une version antérieure fondée sur
une lecture incomplète : voir l'encadré en tête.*
