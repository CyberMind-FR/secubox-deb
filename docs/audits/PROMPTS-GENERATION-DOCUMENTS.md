<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Deux prompts de génération — appendice d'audit, et diaporama HTML

Versionnés pour être **rejouables** : une V1.2 du dossier doit pouvoir être
régénérée à six mois d'écart sans que la question ait bougé entre-temps.

Matière première commune :

| | |
|---|---|
| Guide produit, 16 p. | `docs/dossiers/sbxos/SecuBox-DEB_Guide_16_pages_Mockup_v3.pdf` |
| **Sa transcription texte** | `docs/dossiers/sbxos/Guide_16_pages_v3.0.0-alpha.2.txt` |
| Dossier ANSSI V1.1 | `docs/dossiers/anssi/Dossier_technique_ANSSI_V1.1.txt` |
| Audit code ⟷ dossier | `docs/audits/AUDIT-DOSSIER-ANSSI-vs-CODE.md` |
| Analyse des documents | `docs/audits/ANALYSE-DOCUMENTS-REFERENCE.md` |

**Toujours donner la transcription, jamais le seul PDF** : il ne contient
aucun texte extractible, et un modèle à qui on ne fournit que lui inventera
son contenu avec aplomb.

---

## 1 — Appendice technique au PDF, issu de l'audit

Ce que ce prompt produit : les pages qui **manquent** au guide et au dossier —
les mesures. Ni l'un ni l'autre ne contient un seul chiffre, alors que les
mesures existent.

```
Tu rédiges un APPENDICE TECHNIQUE destiné à être ajouté au dossier ANSSI
V1.1 de SecuBox-Deb. Pas un résumé, pas une réécriture : les pages qui
manquent.

CE QUI MANQUE, ET QUE TU DOIS COMBLER

Le dossier V1.1 ne contient AUCUNE mesure chiffrée. Zéro. C'est son défaut
principal auprès d'un lecteur technique : il demande la contradiction sans
rien offrir à contredire.

Or les mesures existent, dans l'audit fourni. Ton travail est de les
transformer en appendice publiable.

SOURCES (fournies)
  · l'audit code ⟷ dossier
  · l'analyse des documents de référence
  · la transcription du guide produit 16 pages
  · le dossier ANSSI V1.1 lui-même

STRUCTURE ATTENDUE

  A. Périmètre mesuré — ce qui a été instrumenté, sur quelle machine, sur
     quelle fenêtre. Un lecteur doit pouvoir juger si l'échantillon vaut
     quelque chose AVANT de lire les résultats.

  B. Efficacité du filtrage — nombre de motifs, prises, faux positifs, et
     SURTOUT la méthode : comment le zéro faux positif a été établi. Un zéro
     non expliqué ne vaut rien.

  C. Ce que la mesure a révélé et qui n'était pas cherché — les motifs
     inertes, la journalisation sans identifiant de règle, le collecteur
     RGPD à l'arrêt. C'est la partie la plus crédible de l'appendice :
     elle montre une chaîne qui trouve ses propres défauts.

  D. Ce qui n'est pas mesuré — rollback, comportement en charge, et tout ce
     que l'audit marque comme non vérifié. À énoncer, pas à taire.

  E. Reproductibilité — comment un tiers referait ces mesures.

RÈGLES DE RÉDACTION, dans l'ordre d'importance

  1. AUCUN CHIFFRE SANS SA SOURCE. Chaque nombre porte ce qui l'a produit :
     fichier, commande, ou issue. Un chiffre invérifiable dans un dossier
     destiné à l'ANSSI est pire que son absence.

  2. NE RIEN INVENTER. Si une mesure manque, écris qu'elle manque. La section
     D existe pour ça, et elle vaut mieux qu'une estimation.

  3. DISTINGUER MESURÉ / OBSERVÉ / DÉDUIT. « 659 requêtes nouvellement
     qualifiées » est un rejeu sur données réelles ; « le WAF bloque » est une
     observation ; « donc la déception fonctionne » serait une déduction.
     Les trois n'ont pas la même force et le lecteur doit pouvoir les séparer.

  4. LES DÉFAUTS TROUVÉS SONT UN ARGUMENT, PAS UN AVEU. Une chaîne qui
     détecte cinq motifs inertes vaut mieux qu'une chaîne silencieuse. Écris-le
     ainsi, sans forfanterie et sans excuse.

  5. Ton sobre. Pas de superlatif, pas de « robuste », pas de « de pointe ».
     Les chiffres parlent ; les adjectifs les affaiblissent.

FORMAT
  Markdown, 3 à 5 pages une fois mis en page. Tableaux pour les mesures.
  Titre : « Appendice technique — mesures Alpha ». Daté. Numéroté en continuité
  du dossier (§13 et suivants).

CE QUE JE NE VEUX PAS
  · un résumé du dossier, que son lecteur a déjà lu ;
  · des recommandations de durcissement génériques ;
  · un chiffre arrondi ou « approximativement » quoi que ce soit.
```

---

## 2 — Diaporama HTML autonome, depuis le PDF

Ce que ce prompt produit : une version **web, navigable et cherchable** du
guide 16 pages — ce que le PDF ne sera jamais.

```
Tu produis un DIAPORAMA HTML AUTONOME à partir du guide produit SecuBox-DEB
(16 pages). Un seul fichier .html, qui s'ouvre hors ligne, sans build et sans
dépendance réseau.

MATIÈRE
  · la transcription texte du guide (fournie) — c'est ELLE le contenu
  · les 16 pages rendues en PNG, si fournies, comme illustrations

POURQUOI CE DIAPORAMA EXISTE

Le PDF ne contient aucun texte extractible : il n'est ni cherchable, ni
citable, ni accessible aux lecteurs d'écran. Le diaporama doit corriger
exactement cela. Si tu produis une galerie d'images, tu as reproduit le
problème au lieu de le résoudre.

  → LE TEXTE EST DU VRAI TEXTE dans le DOM. Toujours. Les images ne sont
    qu'illustration, et chacune porte un `alt` qui dit ce qu'elle montre.

EXIGENCES FONCTIONNELLES

  · 16 sections, une par page, dans l'ordre.
  · Navigation : flèches ←/→, Espace, Origine/Fin, et clic. Numéro de page
    visible. Une barre de progression.
  · RECHERCHE PLEIN TEXTE (touche « / »), qui saute à la section et surligne.
    C'est la fonction qui justifie tout le reste.
  · Lien profond : `#p7` ouvre directement la page 7. Sans lien profond, on
    ne peut toujours pas citer le document.
  · Mode plan : une vue qui liste les 16 titres, cliquable.
  · IMPRESSION PROPRE : `@media print`, une page par feuille, sans chrome de
    navigation.
  · Responsive : lisible sur téléphone. Le public visé — associations, écoles,
    collectivités — lira souvent sur mobile.

EXIGENCES TECHNIQUES

  · UN SEUL FICHIER. CSS et JS en ligne. Aucune requête réseau : ce document
    doit s'ouvrir sur une clé USB dans une salle de classe sans connexion.
  · Images en `data:` URI si elles sont fournies, sinon prévoir le texte seul
    — le diaporama doit rester valable sans elles.
  · Aucun framework. Le contenu est statique ; y ajouter une dépendance
    ajouterait une chose à maintenir sans rien résoudre.
  · Accessibilité : structure de titres correcte, navigation au clavier
    complète, focus visible, contraste suffisant, `prefers-reduced-motion`
    respecté.
  · Thème clair ET sombre, suivant le réglage du lecteur.

IDENTITÉ VISUELLE — à reprendre du guide, sans le copier
  Bleu SecuBox dominant, titres à deux tons (sombre + bleu), accents de
  couleur par domaine (communication, cloud, médias, sécurité, réseau,
  système). Bandeau « SOUVERAIN · SÛR · MODULAIRE · OUVERT ». Pied :
  « Un numérique plus humain, c'est possible ! »

  Le guide imprimé est chaleureux et illustré. Le diaporama n'a pas à
  l'imiter : il a une autre fonction — être consulté, cherché, cité. Sobre et
  rapide vaut mieux que décoratif.

CE QUE TU NE DOIS PAS FAIRE
  · une galerie d'images sans texte — c'est le problème, pas la solution ;
  · charger une police, un script ou une feuille depuis un CDN ;
  · inventer du contenu absent de la transcription ;
  · masquer les anomalies qu'elle signale (version, typo, URL du nœud de
    développement) : si tu reprends ces éléments, reprends-les corrigés, et
    dis en commentaire HTML ce que tu as corrigé.
```

---

## Après génération

Verser le résultat dans `docs/dossiers/` sous un nom daté, **avec le prompt
qui l'a produit**. Un document généré dont on a perdu la commande n'est pas
reproductible — et ce qui n'est pas reproductible n'est pas auditable.
