<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# Profil projet référence Aurora — règles de design déduites

Nom retenu le 2026-10-11 pour le style commun des pages d'administration refondues : vue d'ensemble WAF, Guardian, DPI, SOC,
Actor Intelligence, puis les six onglets WAF, threats, les cinq onglets ndpid, metrics et le Toolbox (#2354, #2358, #2362, #2363,
#2364, #2370, #2373).

**Référence vivante** : `packages/secubox-waf-ng/composants/waf/www/waf/vue.html` (le modèle), puis `historique.html`, `visites.html`,
`attaquants.html` (onglets) et `packages/secubox-soc/www/soc/reseau.html` (courbes). Ce document dit *pourquoi* et *comment* ;
en cas de doute, le code de `vue.html` fait foi. Il complète `WEBUI-PANEL-GUIDELINES.md` (ancienne peau « hybrid-dark » monospace,
conservée pour les pages non encore refondues) et ne le remplace pas.

## 1. Principe : une page, un fichier, aucune dépendance

- Un HTML **autonome** : CSS et JS en ligne. Aucune bibliothèque, aucune police distante, aucun `<script src>` : la CSP des vhosts
  (`default-src 'self'; script-src 'self' 'unsafe-inline'`) l'interdit, et une dépendance de plus est une surface de plus.
- Graphiques : **SVG écrits à la main** (courbes, aires, barres, donuts, jauges, graphes à disposition déterministe). Pas de canvas,
  pas de bibliothèque de graphes.
- Police : `"IBM Plex Sans","Inter",system-ui,-apple-system,"Segoe UI",sans-serif` (repli système, rien à télécharger) ; chiffres
  `font-variant-numeric:tabular-nums` partout où des nombres s'alignent ; monospace seulement pour les identifiants techniques
  (interfaces, hachages, IP).
- En-tête de licence SPDX CMSD-1.0 identique à `vue.html`. Aucun secret affiché, jamais (clé privée, jeton, mot de passe) ; une clé
  publique tronquée suffit.

## 2. Jetons de couleur (à copier tels quels)

```css
:root{--fond:#060d1b;--trait:rgba(86,150,255,.22);--trait2:rgba(86,150,255,.38);--texte:#eaf1ff;--doux:#9fb3d6;--faible:#6f84a8;
  --cyan:#29b6f6;--bleu:#3b82f6;--vert:#2ecc71;--rouge:#ff4d5e;--orange:#ff9f1c;--violet:#a78bfa;--jaune:#ffd23f}
```

- **Fond** : deux dégradés radiaux (bleu en haut à droite `rgba(59,130,246,.2)`, rouge ou cyan en bas à gauche `.10`) sur `--fond`.
- **Sens des couleurs** : cyan = information, entrant, primaire ; vert = sain, actif, bloqué avec succès ; orange = attention,
  démonstration, périmé ; rouge = menace, critique, paquets écartés, hors ligne ; jaune = sortant ; violet et bleu = séries secondaires.
  Une même couleur garde le même sens dans toutes les pages.
- Texte : `--texte` pour la valeur, `--doux` pour l'étiquette, `--faible` pour la note et l'unité.
- Thème unique (sombre) : le profil ne propose pas de thème clair.

## 3. Squelette et composants

```
.cadre   (container-type:inline-size; container-name:a; padding:10px — SANS min-height)
 └ .app  (bordure --trait2, rayon 16, dégradé 160deg rgba(15,32,64,.92)→rgba(7,15,32,.96), ombre cyan, grille gap 10)
    ├ .tete      marque (b 1.3–1.4rem/800, small cyan .72rem) · pastille d'état · .droite (heure + bouton Rafraîchir)
    ├ bandeaux   .demo (orange) · .info « session requise » (cyan)
    ├ .tuiles    2 colonnes, 4 à 6 au-delà (container query)
    └ .grille    de .pan (titre h3 .88rem, mention faible à droite)
```

- **Tuile** : rayon 12, bord `--trait`, dégradé `rgba(18,40,78,.7)→rgba(8,18,38,.7)` ; étiquette `.74rem --doux` ; valeur
  `1.45rem/700 tabular-nums` ; sous-ligne `.68rem --faible`. **Chaque tuile porte sa définition en infobulle** (`title`).
- **Panneau** `.pan` : rayon 12, bord `--trait`, fond `rgba(10,22,46,.6)`. Cartes à ombre/rayon réservés aux objets qu'on veut
  distinguer — pas de carte partout.
- **Pastilles** : rayon 999, bord et texte de la couleur sémantique, fond de la même couleur à 12 %. Gravité : critique rouge, haute
  orange, moyenne jaune, basse bleu/vert.
- **Listes et barres** : ligne `nom · valeur · barre` (`.barre` 6 px, fond `rgba(159,179,214,.16)`).
- **Tableaux** : en-tête petites capitales `.66rem` `--faible`, lignes séparées par `rgba(86,150,255,.12)`, survol
  `rgba(41,182,246,.07)`, tri/filtre/recherche **côté client**, défilement horizontal dans son propre conteneur.
- **Courbes** : une échelle (le plus grand des deux séries), graduations réelles, aire translucide `fill-opacity .14`,
  `vector-effect:non-scaling-stroke`. Jamais de série inventée.

## 4. Mise en page : container queries, pas media queries

- La grille se décide sur la **largeur du `.cadre`** (`@container a (min-width:700px|900px|1100px)`), donc la même page sert en
  carte, en onglet encadré et en plein écran.
- `?embed=1` ou largeur < 900 px : **une colonne**, rien ne déborde (`min-width:0` sur les enfants de grille qui portent du texte).
- À 420 px de large (téléphone) : pas de défilement horizontal de la page ; seuls tableaux, code et diagrammes défilent, chacun dans
  son conteneur.

## 5. Vérité des données

- **Données réelles uniquement.** Mesure absente = **« — »**, jamais 0 ; 0 est une mesure.
- **Honnêteté sur les limites** : si l'API ne fournit pas une série, pas de courbe ; si une valeur est déduite côté page (famille,
  catégorie, confiance, tendance), la page le **dit** (note ou infobulle). Un chiffre partiel est annoncé partiel.
- **Session absente ou refusée (401/échec)** : bandeau « Aucune mesure : session requise. Se connecter », tuiles en « — ».
- **`?demo=1`** : données de démonstration réalistes, **annoncées par un bandeau orange** ; adresses de documentation (RFC 5737/3849),
  noms fictifs ; **aucun appel d'écriture** en démonstration.
- **Collecteur arrêté / données périmées** : un état visible (pastille orange « DONNÉES PÉRIMÉES — COLLECTEUR ARRÊTÉ ? »), pas un
  silence.

## 6. Accès aux données

- `fetch(url, {headers:{Accept:'application/json'}, credentials:'same-origin', cache:'no-store'})` ; jeton `localStorage.sbx_token`
  en `Authorization: Bearer` s'il existe (lecture protégée par `try/catch`, `localStorage` peut lever).
- **Même origine** : la page parle aux routes `/api/v1/<module>/…` de son hôte ; jamais d'appel inter-origine.
- Préférer les **lectures agrégées** (`/pub/…`) aux routes legacy retirées : sur l'hôte admin, `/api/v1/dpi/stats` renvoyait
  « retiré » sans champ `connected` et la vue affichait « HORS LIGNE » à tort (#2368).
- Actualisation **15–60 s si `document.hidden` est faux** ; **jamais** pendant une saisie ou une confirmation ouverte.

## 7. Hauteur annoncée à l'hôte (iframes)

La page encadrée mesure **son cadre**, pas le document :

```js
parent.postMessage({sbxVue: Math.ceil(document.querySelector('.cadre').getBoundingClientRect().bottom + scrollY), onglet:'nom'}, location.origin)
```

au chargement, au redimensionnement et à chaque rendu (`ResizeObserver` sur `body`).

- **Interdits** : `documentElement.scrollHeight` et `min-height:100vh` sur le cadre — la mesure ne peut alors que **croître** (le
  document n'est jamais plus court que l'iframe) et l'on obtient des milliers de pixels de vide (#2323, #2354, #2358).
- L'hôte borne la hauteur reçue (300–4000 px) et ajoute 4 px ; une page qui n'annonce rien garde la hauteur par défaut de l'iframe.
- Clés existantes : `sbxwafVue` (vue WAF, w minuscule), `sbxWafVue`+`onglet` (onglets WAF), `sbxdpiVue`, `sbxSocVue`, `sbxNdpidVue`,
  `sbxThreatsVue`, `sbxMetricsVue`, `sbxToolboxVue`, `sbxVue` (générique, SOC/Toolbox). **Une page neuve poste `sbxVue` + `onglet`.**
- L'écouteur de l'hôte vérifie `e.origin === location.origin` et, pour plusieurs cadres, que `onglet` correspond au cadre.

## 8. Actions : lecture par défaut, écriture à l'identique

- Une page Aurora est **en lecture seule** sauf si l'ancien onglet écrivait. Les actions existantes restent **fonctionnelles avec
  exactement le même appel** (routes, corps, en-têtes) : on refait la peau, pas le contrat. N'inventer aucune action.
- **Confirmation intégrée à la page** (boutons Confirmer/Annuler dans le panneau), **jamais** `confirm()`, `alert()` ni `prompt()` : le
  navigateur du viewer les ignore (`confirm()` renvoie faux sans rien dire). Résultat ou erreur affichés dans la page.
- Actions inertes en `?demo=1`. Une action sans retour arrière demande la confirmation ; ne jamais proposer de vider des listes
  apprises.

## 9. Intégrer une page dans un hôte (onglets, SOC, Hall)

- Chaque onglet d'une page à onglets est une **page autonome** encadrée en iframe de **même origine** ; l'ancien contenu reste dans le DOM,
  masqué, pour ne pas casser le reste du script.
- **Une seule source** : le SOC encadre `/waf/*.html`, `/dpi/vue.html`, `/actor-intelligence/` ; le Toolbox encadre
  `/soc/reseau.html`. On ne copie jamais une page. Corollaire : l'hôte déclare dans `Depends` les paquets qui portent les pages qu'il
  encadre (sinon l'onglet est vide), et le profil `lite` les embarque par fermeture des dépendances.
- Les pages sont servies par un `root` statique (jamais un `alias` + `try_files`, qui perd l'extension). Un relais du Hall est une liste
  de routes **exactes** derrière `auth_request`.
- Le menu latéral commun (`/shared/sidebar.js`) reste chargé **hors** `?embed=1` et hors démonstration.

## 10. Pièges connus

- **Le skin partagé** `hybrid-skin.css` est injecté **après** la page et pose ses teintes en `!important` : une page qui garde ce
  skin doit répondre à **spécificité supérieure** (`html :is(.hybrid-skin, body) …`), sans quoi onglets et tuiles retombent sur son vert
  et ses lueurs. Une page Aurora complète ne charge pas ce skin.
- Les sources de journaux d'un proxy peuvent masquer le client réel : « visiteur unique = 1 » peut venir d'une IP de proxy ; l'infobulle
  l'explique, le chiffre n'est pas masqué.
- Une timeline sans jours vides n'est pas comblée à zéro : l'axe ne montre que les jours mesurés, et les moyennes ne comptent que ceux-là.

## 11. Tests et vérification

1. **Test statique** (pytest, sans navigateur) pour chaque page : en-tête SPDX, clé de hauteur postée, `demo`, aucun `<script src=`
   externe, ni « lorem », ni secret, pas de `confirm(`/`alert(`/`prompt(`, routes d'API citées, **routes d'écriture présentes à
   l'identique** de l'ancienne page, et, pour une page lecture seule, aucun `POST`.
2. **Capture réelle** (Playwright, `file://…?demo=1`) en **1400×900 puis 420 px de large** ; **lire les PNG** ; corriger jusqu'à : pas de
   débordement horizontal, pas de texte coupé.
3. **Cas vide** : sans `?demo=1` (les `fetch` relatifs échouent sous `file://`, c'est le cas « sans session ») : « — », bandeau, **aucune
   erreur JS** (`page.on('pageerror')`).
4. **Intégration** : basculer tous les onglets, relever `src` et hauteur de l'iframe, aucune erreur.
5. Un déploiement se vérifie sur la box : `curl` des pages (200) **et** un coup d'œil humain sur le rendu avec les vraies données —
   une capture à vide ne prouve pas la lisibilité des vraies séries.

## 12. Contenu et accessibilité

- Français, vocabulaire du projet ; titres sobres (un emoji discret admis, jamais obligatoire) ; infobulle de définition sur chaque
  mesure ; libellés explicites (« Entrant maintenant », pas « In »).
- `aria-selected` sur les onglets, focus visible, cibles tactiles confortables, contraste texte/fond conforme aux jetons ci-dessus.

## 13. Process

Issue → worktree → PR (`AGENTS.md`). Version montée pour toute source déployée ; entrée `HISTORY.md` ; changelog du paquet qui dit ce
qui change **et ce qui n'est pas repris** (actions retirées, données que l'API ne fournit pas). Une page de plusieurs onglets se
fait en parallèle : un fichier par onglet, un brief commun, l'intégration par une seule main.
