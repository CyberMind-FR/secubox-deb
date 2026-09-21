<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Prompt de contradiction externe — audit ANSSI ⟷ code

## À quoi sert ce fichier

Le dossier technique ANSSI V1.1 demande explicitement « un regard critique »
(§ objet) et inscrit en §7 la « contradiction extérieure » parmi les objectifs
de validation Alpha. L'audit `AUDIT-DOSSIER-ANSSI-vs-CODE.md` a été produit
**en interne** : il est donc, par construction, le moins bien placé pour
repérer ses propres angles morts.

Ce prompt sert à faire contredire cet audit par un modèle tiers. Il est
versionné pour que la contradiction soit **rejouable** : on doit pouvoir
comparer deux contradictions à six mois d'écart, ce qui suppose que la
question n'ait pas bougé entre-temps.

## Précaution de lecture

Un modèle sollicité sur un document tend à **l'approuver** — c'est sa pente
naturelle, et elle rend une revue complaisante inutile. Le prompt ci-dessous
est écrit contre cette pente : il demande des contre-exemples vérifiables, pas
un avis.

Une réponse qui se contente de féliciter l'audit doit être considérée comme un
échec du prompt, pas comme une validation de l'audit.

---

## Le prompt

```
Tu es un évaluateur technique indépendant, mandaté pour CONTREDIRE un audit
interne — pas pour le valider. Ton utilité se mesure à ce que tu trouves
qu'il a manqué. Un rapport qui conclut « audit solide, rien à signaler » est
un rapport inutile : si tu ne trouves rien, dis précisément CE QUE TU AS
CHERCHÉ et où tu t'es arrêté, faute de quoi ton absence de résultat n'est pas
interprétable.

CONTEXTE

SecuBox-Deb est une appliance de sécurité libre sur Debian ARM64 (cible
MOCHAbin), visant à terme une certification ANSSI CSPN. Son dossier technique
V1.1 a été transmis à l'ANSSI le 22 août 2026 ; un audit interne l'a confronté
au code le 21 septembre 2026.

Dépôt public : https://github.com/CyberMind-FR/secubox-deb

DOCUMENTS

  1. Le dossier transmis (référence, figé) :
     docs/dossiers/anssi/Dossier_technique_ANSSI_V1.1.txt
     (le PDF d'origine est à côté, avec son empreinte SHA-256)

  2. L'audit à contredire :
     docs/audits/AUDIT-DOSSIER-ANSSI-vs-CODE.md

  3. Le code, dans le même dépôt.

CE QUE JE TE DEMANDE, dans cet ordre

A. VÉRIFIER LES AFFIRMATIONS DE L'AUDIT, pas celles du dossier.

   L'audit avance des faits précis et chiffrés — nombre de motifs WAF, nombre
   de modules par profil, arithmétique de partitions, mesures de faux
   positifs, existence ou absence de telle fonction. Prends-en au moins six et
   va les vérifier dans le code. Dis lesquels tu as pu confirmer, lesquels tu
   n'as pas pu, et lesquels sont faux.

   Cite un chemin de fichier et une ligne pour chaque vérification. Une
   affirmation que tu ne peux pas rattacher à du code est une affirmation que
   tu dois classer « invérifiable en l'état », ce qui est un résultat.

B. ATTAQUER LA CONCLUSION LA PLUS FRAGILE.

   L'audit classe les écarts en trois types et affirme n'avoir trouvé AUCUN
   écart de type 1 — « le document promet ce que le code ne fait pas ». C'est
   sa conclusion la plus flatteuse pour le projet, donc celle qui mérite le
   plus de méfiance.

   Reprends le dossier §3 (fonctions du profil Alpha), §5 (architecture
   distribuée), §6 (conditions de confiance) et §8 (roadmap) et cherche
   activement une promesse que le code ne tient pas. Sois attentif aux verbes :
   le dossier distingue ce qui EST de ce qui est « envisagé », et la frontière
   est exactement là que le type 1 se cache.

C. CHERCHER CE QUE L'AUDIT N'A PAS REGARDÉ.

   L'audit signale lui-même deux vérifications non conduites (rollback,
   comportement en charge). Ce sont des angles morts DÉCLARÉS, donc les moins
   intéressants. Cherche les angles morts NON déclarés : des sections du
   dossier que l'audit ne mentionne jamais, des composants du dépôt qu'il
   n'ouvre pas, des affirmations qu'il tient pour acquises sans les mesurer.

D. ÉPROUVER LA MÉTHODE, PAS SEULEMENT LES RÉSULTATS.

   L'audit se donne en §9 une règle : « quand un document justifie une
   ABSENCE, c'est là qu'il faut aller mesurer », après avoir découvert qu'une
   justification consignée (issue #503) était fausse sur ses deux moitiés.

   Cette règle est-elle appliquée partout dans l'audit, ou seulement à
   l'endroit où elle a été découverte ? Reste-t-il, dans le dépôt, d'autres
   absences justifiées par écrit et jamais revérifiées — tests désactivés,
   modules exclus, contrôles commentés, `|| true` qui avalent un échec ?

E. LE POINT DE VUE ANSSI / CSPN.

   Indépendamment du code : si tu recevais ce dossier V1.1 comme évaluateur,
   quelles questions poserais-tu que l'audit interne n'a pas anticipées ?
   Concentre-toi sur les exigences habituelles d'un CSPN — cible de sécurité,
   périmètre de l'objet évalué, hypothèses d'environnement, biens à protéger,
   agents menaçants — et dis lesquelles ce dossier ne permet pas encore
   d'instruire.

FORME DE LA RÉPONSE

  * Une liste de constats. Chacun : ce que l'audit ou le dossier affirme, ce
    que tu as vérifié, la conclusion, et le chemin de fichier qui l'appuie.
  * Classe chaque constat en : CONFIRMÉ / CONTREDIT / INVÉRIFIABLE.
  * Termine par les TROIS points que tu jugerais les plus graves si ce projet
    entrait réellement en évaluation, et pourquoi — en distinguant ce qui est
    grave pour la SÉCURITÉ de ce qui est grave pour l'ÉVALUABILITÉ. Les deux
    ne se recouvrent pas, et un dossier peut décrire un produit sain d'une
    manière qui le rend inévaluable.

CE QUE JE NE VEUX PAS

  * Un résumé de l'audit : je l'ai écrit, je le connais.
  * Des recommandations génériques de durcissement non rattachées à ce code.
  * Un jugement sur la qualité rédactionnelle.
  * De la complaisance. Si l'audit a raison sur un point, dis-le en une ligne
    et passe au suivant : le temps se dépense sur ce qui cloche.
```

---

## Après la réponse

Verser la contradiction reçue dans `docs/audits/` sous un nom daté et portant
le modèle interrogé — par exemple `CONTRADICTION-2026-09-21-<modèle>.md`.

**Y compris quand elle a tort.** Une contradiction erronée reste une trace de
ce qui a été cherché, et elle évite qu'on repose deux fois la même question en
croyant l'inaugurer.
