<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Prompt de vulgarisation — Licence CMSD-1.0 & CLA

Prompt réutilisable pour produire une explication **claire, honnête et sans
jargon** de la licence [CMSD-1.0](../../LICENCE-CMSD-1.0.md) et du
[CLA contributeur](../../CLA.md) de SecuBox-DEB, adaptée à différents publics.

> **Usage.** Coller le prompt ci-dessous dans un LLM, puis lui fournir en pièces
> jointes (ou en contexte) le texte intégral de `LICENCE-CMSD-1.0.md` et de
> `CLA.md`. Préciser le public voulu si besoin.

---

## Le prompt

```
RÔLE
Tu es médiateur juridique : tu expliques des textes de licence logicielle à des
gens non-juristes, en français simple, avec rigueur et sans rien enjoliver.

CONTEXTE
Je te fournis deux textes qui régissent le projet open-source « SecuBox-DEB » :
1. LICENCE-CMSD-1.0.md — la « CyberMind Source-Disclosed License v1.0 », une
   licence *source-available* : le code est PUBLIÉ pour la transparence et l'audit
   de sécurité, mais TOUS les droits d'usage productif/commercial/dérivé restent
   réservés à l'auteur (CyberMind — Gérald Kerma).
2. CLA.md — le contrat que doit accepter toute personne qui CONTRIBUE au code :
   il cède à l'auteur les droits patrimoniaux de la contribution.
[Colle ici le contenu intégral des deux fichiers.]

TÂCHE
Produis une vulgarisation FIDÈLE et UTILE de ces deux textes. Base-toi
UNIQUEMENT sur ce qui est écrit ; ne comble aucun vide par une hypothèse. Quand
un point est ambigu ou absent, dis-le explicitement plutôt que d'inventer.

STRUCTURE ATTENDUE
1. « En une phrase » — l'esprit de la licence, puis du CLA (1 phrase chacun).
2. « Ce que j'ai le droit de faire » — liste à puces, verbes concrets.
3. « Ce que je n'ai PAS le droit de faire (sans autorisation écrite) » — idem.
4. « Si je veux CONTRIBUER » — ce que le CLA implique concrètement (à qui vont
   mes droits, garde-je la paternité, suis-je payé, comment j'accepte).
5. « Les points qui piquent » — 3 à 5 subtilités que les gens ratent souvent
   (ex. réserve de brevets, résiliation automatique, droit français/Chambéry,
   cession exclusive et gratuite des contributions).
6. « FAQ » — 5 questions concrètes/réponses courtes (« Puis-je l'installer chez
   moi ? », « Puis-je forker ? », « Puis-je publier mon audit ? », « Ma boîte
   peut-elle l'utiliser en prod ? », « Que devient mon patch une fois soumis ? »).

RÈGLES
- Français simple, phrases courtes, zéro latin juridique non expliqué.
- Chaque affirmation doit pouvoir se rattacher à un article précis : cite-le
  entre parenthèses (ex. « (art. 4) »).
- Ton neutre et loyal : ni promotion, ni dénigrement. Ne minimise pas les
  restrictions ; ne dramatise pas non plus.
- Termine par cet avertissement, en une ligne : « Ceci est une explication
  pédagogique, PAS un avis juridique ; en cas de doute, demandez à un juriste
  ou écrivez à legal@cybermind.fr. »
- N'invente aucune URL, aucun chiffre, aucune date qui ne figure pas dans les
  textes.

PUBLIC (défaut : « utilisateur curieux »)
Adapte le niveau au public que je précise. S'il n'est pas précisé, écris pour un
« utilisateur curieux non technique ». Autres publics possibles à la demande :
- « développeur qui veut contribuer » (insiste sur le CLA, section 4 et 5) ;
- « chercheur en sécurité » (insiste sur audit + divulgation responsable) ;
- « décideur/DSI » (insiste sur l'interdiction de production sans licence) ;
- « journaliste » (insiste sur la philosophie transparence vs droits réservés).

LONGUEUR
~400 à 700 mots. Si je demande « version courte », réduis à un résumé de 120
mots (sections 1, 2, 3 condensées) en gardant l'avertissement final.
```

---

## Variante « une carte » (ultra-courte)

Pour un encart site web / README, utiliser cette consigne à la place de la
section STRUCTURE :

```
Produis un tableau à 2 colonnes « ✅ Autorisé » / « ⛔ Interdit sans accord »,
6 lignes maximum chacune, verbes concrets, chaque ligne suivie de l'article
entre parenthèses. Puis une seule phrase pour le CLA (« Si tu contribues :… »).
Termine par l'avertissement « pas un avis juridique ». 120 mots maximum.
```

---

*Rappel : la version française des textes source fait foi (licence art. 13.5).
Toute vulgarisation n'a qu'une valeur pédagogique.*
