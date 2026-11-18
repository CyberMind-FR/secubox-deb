# SecuBox AI V2 — complément : corrélation multicouche, outils de l'attaquant, tout automatique (#3795)

Date : 2026-11-18. Statut : conception, à valider par le propriétaire. Complète (ne remplace pas)
`docs/superpowers/specs/2026-11-14-secubox-ai-v2-design.md` (branche #3583, ci-après « V2 »). Ce qui n'est pas dit ici
reste comme dans V2.

## Intention

Le propriétaire (18/11) : « détecter une attaque évoluée et identifier les outils » ; « il y a trop d'informations
multi-sources à mettre en relation, multi-couches » ; ce qu'il en fait : « lire et auto-appliquer » ; périmètre de
l'automatique : « tout auto » ; c'est « la suite de la V2 ».

Une attaque évoluée enchaîne des étapes discrètes (repérage, essais, exploitation, persistance) dont aucune ne déclenche
seule un capteur, et laisse des traces dans des couches qui ne se parlent pas : nftables (bans, SYN sans état), WAF
(menaces, leurres, empreintes), DPI (risques nDPI, JA3/JA4), DNS (anomalies), leurres de service (identifiants
tentés), authentification (sbx-authwatch), hôte (antirootkit), et maintenant les décisions de `secubox-garde` (#3794).
Personne ne relie cela à la main. La valeur de ce complément : **un dossier par attaquant ou campagne**, qui relie les
couches, nomme les étapes et les outils avec leurs preuves, et **applique seul** les réglages sûrs.

## Objectifs (en plus de V2)

1. **Dossier d'attaquant / de campagne** (prolonge les incidents de V2 § 8) : chronologie unique sur toutes les couches,
   étapes reconnues, outils probables, réglages appliqués et leur effet.
2. **Identification des outils** de l'attaquant (sqlmap, Nuclei, Nmap/masscan/zmap, Mirai et dérivés, Hydra, frameworks
   de commande et contrôle connus…), chaque attribution avec ses preuves.
3. **Sources ajoutées** au collecteur V2 (§ 7) : décisions de `secubox-garde`, propositions et mesures d'actord
   (DPI par adresse), alertes du capteur DNS, leurres de service (#3728).
4. **Tout automatique** : chaque geste du catalogue s'applique d'office quand le **code** juge le cas sûr ; la console
   sert à lire, comprendre et défaire.

## Non-objectifs

- Pas de nouveau capteur ni de nouvel IDS : on relie ce qui existe (comme V2 C10).
- Pas d'action hors des gestes audités existants (V2 décision 3) ; pas de règle nftables, nginx ou WireGuard écrite
  depuis gk3.
- Pas de carte du monde (V2 décision 8).
- Pas les appareils de la maison : ils restent l'affaire de `secubox-garde`. Ici : les attaquants d'Internet vers gk2.

## Anti-objectifs

- **Une attribution d'outil inventée.** Jamais un nom d'outil sans preuve vérifiable par le code (#3509 : l'IA
  n'invente jamais). Le modèle de langue explique et résume ; il ne décide ni du cas sûr ni de l'outil.
- Bannir une adresse protégée (box, maillage, Freebox, robots vérifiés) ou défaire un ban d'une autre source.
- Un geste automatique sans borne, sans plafond, sans audit ou impossible à défaire.

## Décisions du propriétaire (18/11) qui modifient V2

- **V2 décision 7 (« hybride avec approbation humaine ») est remplacée par « tout automatique ».** Tous les gestes du
  catalogue ont `auto = true` par défaut ; l'approbation n'est plus requise. Restent : le cas sûr décidé par le code
  (V2 C9), les bornes et plafonds de gk2, l'audit, la réversibilité, et l'interrupteur `automatique_suspendu` (défaut
  **false** désormais, puisque le propriétaire a donné son accord).
- Ce chantier est la **suite de V2** : il complète ses phases 2 (collecteur), 3 (corrélateur), 4 (analyste),
  5 (réponses) et 6 (console), sans nouveau paquet (`secubox-ai` 2.x sur gk3).

## Conception

### 1. Sources ajoutées au collecteur (V2 § 7)

Lues sur gk2 par des routes de lecture (`require_lecture`), jamais par fichier distant :
- `secubox-garde` : `GET /api/v1/garde/historique` et `/etat` (décisions, signaux, intrusions bannies).
- actord : propositions et mesures (`/run/secubox/actord-propositions.json`, `actord-mesures.json`) exposées par une
  route de lecture à ajouter côté gk2 si absente.
- Capteur DNS : alertes de `alerts.jsonl` (même voie).
- Leurres de service (#3728) : identifiants tentés, outils déclarés par la bannière.
Chaque source a sa position de lecture et son « dernier vu » (V2 § 7).

### 2. Dossier d'attaquant / de campagne

- Clé : l'acteur d'actord quand il existe, sinon l'adresse ; une campagne regroupe des acteurs par règles écrites
  (même empreinte d'outil, même bloc, même cible et même fenêtre).
- **Étapes** reconnues par règles déterministes nommées (comme V2 § 8) : `reperage` (balayages, SYN sans état, robots
  de cartographie), `essais` (sondes de produits absents, leurres touchés, identifiants tentés), `exploitation`
  (règles WAF d'attaque, risques DPI d'exploitation), `persistance` (retour après ban, rotation d'adresses du même
  outil). Le dossier liste les étapes atteintes, avec leurs preuves et leurs heures.
- Règles de corrélation V2 conservées ; ajouts : `meme_outil_multi_adresses`, `etapes_enchainees` (≥ 2 étapes
  successives), `garde_et_waf` (une intrusion bannie par la garde aussi vue par le WAF ou authwatch).

### 3. Identification des outils

- **Catalogue d'empreintes** versionné (`/usr/share/secubox-ai/empreintes/*.toml`, livré par le paquet, plus un
  fichier local de l'opérateur) : chaque entrée = un outil, des **traits** (JA4/JA3, motif d'agent HTTP, ensemble de
  chemins caractéristiques, ordre et rythme des ports, identifiants de dictionnaire, bannière) et **une source**
  obligatoire (documentation publique de l'outil, relevé mesuré sur gk2 avec sa date). Pas d'entrée sans source.
- Le **code** compare les faits du dossier aux traits ; une attribution exige au moins **deux traits indépendants**
  (ex. agent HTTP + chemins), sinon « outil inconnu » avec les traits observés. La sortie dit quels traits ont
  correspondu.
- Le modèle de langue (V2 § 9, contrat Pydantic strict) reçoit le dossier et les attributions du code ; il rédige
  l'explication et peut **suggérer** une entrée de catalogue (« ces traits reviennent sur 30 adresses »), suggestion
  qui n'est jamais appliquée seule : elle va dans un fichier de suggestions lisible dans la console.

### 4. Réponses : tout automatique

Catalogue de V2 § 10.1, plus les filtres WAF de `ai-filtres` (#3732), tous en `auto = true` :

| Geste | Cas sûr (décidé par le code de gk3, recontrôlé par gk2) | Borne |
|---|---|---|
| `ban_bloc` /24 | V2 inchangé (`CATEGORIES_SURES`, `SEUIL_BLOC`) | 24 h d'office |
| `ban` (adresse) | **nouveau d'office** : l'adresse a des preuves d'au moins deux sources ou deux étapes dans le dossier, n'est pas protégée, et gk2 la retrouve dans ses propres journaux de menaces des dernières 24 h | 24 h, ×4 par récidive, 7 j au plus |
| `prolonger` | retour après ban (règle `retour_apres_ban`) | 7 j au plus |
| `unban` | seulement ce que V2 a posé (par `id`) | — |
| filtre WAF (`ai-filtres`) | règle construite d'un outil identifié (≥ 2 traits) et testée par le vérificateur de #3732 | essai 24 h puis confirmation |

Côté gk2, `POST /ai/ban` en `mode = auto` doit accepter une **adresse seule** sous la condition « vue dans ses propres
journaux de menaces < 24 h » (aujourd'hui : bloc seul) — changement de `gestes_ia.py`, avec plafonds inchangés.
Un 409 `plafond_*` répété ou un 503 suspend l'automatique (V2 § 10.3), avec alerte.

### 5. Console (V2 phase 6)

Planches Radar et Chaîne approuvées, plus une vue **Dossier** : chronologie multicouche, étapes, outils et traits,
gestes appliqués et leur effet (le ban a-t-il fait cesser le trafic ?), bouton « défaire ». Maquette Aurora avant code.

## Précisions après relecture (18/11)

### Décidé par le propriétaire

- **Mise en service : tout automatique dès l'installation** (pas de période d'observation). Le déploiement lève aussi
  la suspension de l'automatique du compte `ai-ban` sur gk2 (#3716) ; l'interrupteur reste dans la console pour la
  remettre.
- **Plafonds de gk2 par geste**, relevés pour le ban d'adresse : `ban` adresse 60/h et 400/j ; `ban_bloc` et
  `prolonger` gardent leurs plafonds actuels ; filtres WAF selon `ai-filtres`. Quand un plafond approche, la V2 sert
  d'abord les dossiers les plus graves (gravité, puis nombre d'étapes, puis récence).

### Décidé par l'assistant (à vérifier)

- **Ban d'adresse seule d'office** : gk3 décide du croisement (≥ 2 sources ou 2 étapes) ; gk2 revérifie seulement ce
  qu'il sait : adresse présente dans ses propres journaux de menaces < 24 h et non protégée par ses gardes existantes
  (box, maillage, Freebox, robots vérifiés, privées). Les plages protégées font foi côté gk2 ; gk3 les lit par la route
  de lecture pour ne pas proposer en vain.
- **Premier catalogue d'outils** : outils web (agent HTTP, chemins, ordre des requêtes) et leurres de service (bannière,
  identifiants de dictionnaire). Deux traits sont « indépendants » s'ils viennent de couches différentes (ex. chemins
  WAF + identifiants de leurre) ou de champs que l'outil ne fixe pas ensemble par défaut ; agent HTTP + chemins d'un même
  outil comptent pour **un** trait. JA4 et rythme des ports viendront quand le collecteur lira actord (DPI).
- **Filtres WAF d'office** : par le compte `ai-filtres` existant (#3732, sa route et son vérificateur côté gk2) ; la
  confirmation après 24 h d'essai est automatique si le filtre n'a touché aucune requête d'adresse protégée ni de
  vhost routé avec réponse légitime (2xx/3xx) ; sinon retrait automatique et alerte.
- **Questions ouvertes de V2** (Q2 compte de lecture `waf-lecture`, Q6 moteur) : vérifiées en tête du plan ; chaque
  nouvelle source a une route de lecture côté gk2 dans son propre paquet (garde : existe ; DNS, actord, leurres : à
  ajouter si absentes).

## Laissé au constructeur

- Format exact des fichiers d'empreintes et premier jeu d'outils (sources publiques + mesures de gk2).
- Seuils de fenêtres (reprendre V2 : 30 min de corrélation, 6 h calme, 7 j clos).
- Découpage : enrichir les issues de phases V2 (#3719 à #3725) plutôt qu'en créer de nouvelles, sauf le changement
  `ai-ban` adresse seule en `auto` (côté gk2).

## Décisions prises par l'assistant (à vérifier)

- `automatique_suspendu = false` par défaut (confirmé par le propriétaire : tout auto dès l installation).
- Attribution d'outil : au moins deux traits indépendants ; sinon « inconnu ».
- Ban d'adresse seule d'office : ≥ 2 sources ou 2 étapes, recontrôle gk2 sur ses journaux < 24 h, 24 h ×4, 7 j max.
- Hors périmètre : appareils de la maison (garde) ; DNS côté gk3 (aucun geste DNS dans ce complément).
