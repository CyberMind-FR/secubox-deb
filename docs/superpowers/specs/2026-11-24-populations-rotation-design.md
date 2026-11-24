# Populations d'attaquants et campagnes à rotation d'adresses — conception

Issue #3919 · suite du dossier de l'aspirateur Gitea (#3905) · 2026-11-24

## 1. Intention

Des attaquants échappent à l'identification par adresse en répartissant leur activité sur des milliers d'adresses, une à
trois tentatives chacune. Un ban par adresse ne les voit jamais : chaque adresse est neuve. SecuBox doit :

- **A — voir** : savoir de quels réseaux vient chaque population d'attaquants (loueur de proxies, fournisseur d'accès,
  cloud, scanner de recherche…), regrouper l'activité en populations par comportement et montrer cette tendance dans
  un tableau du Radar de SecuBox AI ;
- **B — isoler** : reconnaître une campagne à rotation par ce qui reste stable (signature de requête, compte visé) et
  la bannir comme un seul acteur, y compris ses adresses neuves dès leur première requête.

Décisions du propriétaire (24/11) : A puis B ; B est un **détecteur déterministe dans le code**, pas une proposition de
l'IA ; il couvre le web **et** le SMTP. Jamais de ban d'un réseau entier.

## 2. Constat qui fonde la conception (gk2, waf-threats, 17→24/11)

| Population | Adresses | Réseaux | Tentatives / adresse | Réseaux d'origine |
|---|---|---|---|---|
| Collecte Gitea (aspirateur, #3905) | 7 207 (depuis le 31/10) | 337 | 1 à 3, 1 pour la plupart | ~92 % loueurs de proxies en centre de données, reste proxies « résidentiels » |
| Botnet SMTP (mots de passe) | 2 203 | 597 | 1 : 833 adr., 2 : 571, 3 : 356 | fournisseurs d'accès grand public (Cox, Korea Telecom, Chinanet…) |
| Leurres de service | 2 432 | 481 | 1-2 | scanners de recherche déclarés (Driftnet, Censys), clouds |
| Scanners web | 658 | 68 | 3-8 | clouds (Amazon, Google, Cloudflare, Tencent) |

Recouvrement entre populations : 7 adresses sur ~12 500. Conséquences :

1. **Le réseau qualifie, il ne condamne pas.** Le seul vrai botnet observé vit chez des fournisseurs d'accès, là où
   sont les vrais usagers ; les loueurs de proxies portent aussi un vrai CDN (Datacamp = CDN77) et d'autres clients.
2. **Ce qui trahit la rotation est le comportement** : même signature ou même compte visé, depuis beaucoup d'adresses,
   chacune presque une seule fois.
3. Le SMTP a déjà son détecteur de rotation : `sbx-authwatch` regroupe par **compte visé** (#1220, `campagne.go`) et
   bannit dès le premier échec une fois la campagne établie. Le web n'en a pas : l'aspirateur n'a été arrêté que par
   une règle écrite à la main (`aspirateur_ua`, waf-rules 1.8.x).

## 3. Buts, non-buts, anti-buts

**Buts**
- Chaque événement de menace porte son réseau (ASN, opérateur) et la classe de ce réseau.
- Un relevé « populations » calculé sur gk2 (7 jours) et servi au Radar.
- La liste « Campagnes » du Radar SecuBox AI refaite : populations lisibles, repères emoji de réseau, famille, pays.
- La liste « Campagnes » de la page Actor Intelligence refaite avec les mêmes repères, campagnes enrichies (cibles, classes de réseau, pays, rotation).
- Un détecteur de rotation web dans `sbxwaf` qui bannit une campagne établie dès la première requête de chaque adresse.
- Le détecteur SMTP existant relié aux populations (ses campagnes apparaissent comme telles) et aux classes de réseau.

**Non-buts**
- Aucun ban, limitation ou défi appliqué à un réseau ou à une classe de réseaux entière (l'option C a été écartée).
- Aucune requête vers un service tiers (réputation, whois en ligne) depuis le chemin de décision ; tout est local.
- Aucune action vers l'infrastructure des attaquants (pas de hack-back) ; aucun contact de leurs adresses.
- Pas de déploiement sur gk1/gk3 dans ce lot : gk2 seul est exposé à Internet.
- L'IA ne décide rien ici ; elle peut commenter le tableau comme le reste du Radar.

**Anti-buts** (ce qui ferait échouer le projet même s'il « marche »)
- Bannir un usager réel parce que son réseau ressemble à celui d'un attaquant (Starlink, iCloud Private Relay,
  CDN77, adresses mobiles partagées).
- Un chiffre du tableau qui viendrait du modèle, ou un tableau qui affiche « 0 » faute d'avoir lu la source.
- Un détecteur qui se déclenche sur un trafic légitime réparti (un lien partagé, un robot d'indexation vérifié,
  le LAN, le maillage, les adresses protégées).
- Alourdir gk2 (charge ~20-30, swap élevé) : rien de coûteux sur le chemin d'une requête.

## 4. Approches envisagées

1. **Détecteur déterministe dans `sbxwaf` (retenue).** Fenêtre glissante par signature ; seuils explicites ; ban à la
   première requête une fois la campagne établie. Réagit en minutes, sans gk3, chaque décision s'explique par des
   chiffres. L'IA se contente de raconter.
2. **Proposition par l'IA, décision par un vérificateur** (modèle des filtres IA #3732). Plus souple mais plus lent,
   dépendant de gk3, et l'épisode des filtres Nuclei du 22/11 (281 bans à lever) en montre le risque. Écartée.
3. **Tout dans Actor Intelligence** (`sbx-actord`, voie `--actor-ban`). Moteur encore en mode observation, plafond de
   20 bans/heure incompatible avec ~1 000 adresses/heure. Écartée pour la décision ; actord reçoit les nouveaux champs.

Pour la vue, une seule voie sensée : le Radar existant de SecuBox AI, qui lit déjà le relevé de gk2 par
`menaces.py` (`CHEMINS`). Pas de nouvelle page ni de nouveau module.

## 5. Conception

### 5.1 Classes de réseau (catalogue)

- Fichier livré : `/usr/share/secubox/waf/reseaux-classes.toml` (paquet secubox-waf-ng) ; surcharge opérateur :
  `/etc/secubox/waf/reseaux-classes.toml` (fusion : l'opérateur gagne, ASN par ASN).
- Classes : `acces` (fournisseur d'accès grand public), `mobile_partage` (CGNAT, satellite : Starlink…),
  `hebergeur` (cloud, VPS), `proxy_loue` (loueur de proxies), `cdn`, `relais_vie_privee` (iCloud Relay, WARP, Tor),
  `scanner_recherche` (scanners déclarés : Censys, Driftnet…), `inconnu` (défaut).
- Amorçage tiré du constat : `proxy_loue` = AS212238, 62874, 55286, 18779, 203020, 207990, 203061, 50131 ;
  `hebergeur` = AS20473, 14061, 16509, 14618, 15169, 396982, 43515, 8075, 132203 ; `scanner_recherche` = AS211298,
  398324 ; `mobile_partage` = AS14593 ; `relais_vie_privee` = AS13335 (Cloudflare porte WARP et iCloud Relay : classé
  relais, jamais proxy). Les nœuds de sortie Tor sont reconnus par le flux de sortie Tor de `secubox-ipblock`
  (`api/main.py`, flux des sorties Tor) s'il est installé, sinon non reconnus (le garde-fou Tor est alors inactif et le
  relevé le dit) — choix du concepteur.
- Un ASN absent du catalogue est `inconnu`, **jamais** `acces` ni `proxy_loue` par déduction du nom. `inconnu` est
  **neutre** : il ne compte jamais en faveur d'une campagne (voir 5.4).

### 5.2 Enrichissement des événements (A)

- `sbxwaf` ouvre `GeoLite2-ASN.mmdb` (chemin déjà maintenu sur gk2 par la mise à jour GeoIP :
  `/var/lib/GeoIP/GeoLite2-ASN.mmdb`, option `--geoip-asn`) avec la même bibliothèque et le même patron que
  `geo.go` (#1240) : lecture locale, absence de base = champs vides, jamais d'erreur bloquante.
- Champs ajoutés aux lignes de `waf-threats.log` et à l'enveloppe actord (`envelope.ASN` existe déjà) :
  `asn`, `asn_org`, `reseau_classe` (l'enveloppe actord a déjà un champ `ASN`, jamais rempli jusqu'ici). Les lignes écrites par `sbx-authwatch` (SMTP, SSH, leurres) reçoivent les mêmes
  champs (même code partagé dans `internal/`).
- **Empreinte TLS** : sbxwaf lit **déjà** une empreinte JA4 posée par HAProxy (`--ja4-header`, champ `ja4`), mais
  l'unité ne la configure pas. On active ce mécanisme existant (HAProxy 3.0 calcule l'empreinte et pose l'en-tête
  interne, retiré de toute requête entrante) au lieu d'en créer un autre. **À valider sur gk2** (calcul exact, coût) ;
  sans empreinte, le détecteur fonctionne quand même (5.4).

### 5.3 Relevé « populations » sur gk2 (A)

- Calcul en **tâche de fond** (toutes les 10 min, `nice`), jamais à la requête ; cache fichier
  `/var/cache/secubox/waf/populations.json` en **double tampon** (#3011 : une passe dégradée n'écrase jamais un relevé
  complet ; un relevé daté et marqué `complet: false` s'il manque une source).
- Source : `waf-threats.log*` sur 7 jours, plus l'état des campagnes SMTP d'authwatch et des campagnes web (5.4).
- **Familles** (catégorie → famille, table explicite dans le code) : `messagerie` (auth_smtp*), `acces_distant`
  (auth_ssh*, leurre:*), `balayage_web` (scanners, honeypot, lfi, api_abuse, host_anomaly:*, waf_fingerprint),
  `collecte` (aspirateur_ua, recon_crawler, robots), autres → `autre`.
- **Population** (règle unique, choix du concepteur) : une campagne de **rotation web** établie (5.4) est sa propre
  population ; les campagnes SMTP par compte visé d'authwatch sont **réunies** dans la population « messagerie »
  (chaque compte visé devient une ligne du détail) ; une campagne du profileur (`/waf/campaigns`, #1070) est sa propre
  population si elle compte ≥ 10 adresses, sinon elle se fond dans sa famille ; tout le reste est rangé par famille.
  Les campagnes d'actord ne deviennent pas des populations : elles sont rapprochées (5.7). Pour chacune : nombre
  d'adresses, de réseaux, distribution des tentatives par adresse (part à 1, à ≤3, médiane), répartition par classe de
  réseau, 5 premiers réseaux (ASN, opérateur, classe, adresses), série par jour sur 7 jours, un exemple de requête
  (chemin ou compte visé — **jamais de mot de passe**), date de première et dernière activité.
- **Recouvrement** : nombre d'adresses communes entre populations (matrice), pour dire « acteurs distincts ».
- **Indicateur de rotation** : population dont ≥ 80 % des adresses ont ≤ 3 tentatives et qui compte ≥ 50 adresses.
- Route : `GET /api/v1/waf/populations` (module WAF, garde `require_lecture_ai` comme toutes les routes lues par gk3),
  renvoie le cache tel quel avec son âge.

### 5.4 Détecteur de rotation web dans sbxwaf (B)

- **Signature** = condensé de (navigateur déclaré exact, `ja4` si présent, hôte). Une signature sans navigateur
  déclaré n'est pas suivie. Ce détecteur est **distinct** du ban de campagne existant (`campagneban.go`, #2238), qui
  vise les campagnes porteuses de sondes de haute valeur avec une preuve par adresse ; il réutilise ses briques
  (`BanFor`, journal de bans, plafond horaire, état pour le panneau) sans le modifier.
- **Fenêtre glissante** d'1 h par signature : adresses distinctes et nombre de requêtes par adresse.
- **Campagne établie** quand, dans la fenêtre : ≥ 50 adresses distinctes, ≥ 80 % d'entre elles à ≤ 3 requêtes, et
  ≥ 60 % d'entre elles **dans** les classes `proxy_loue` ou `hebergeur` (`inconnu` ne compte pas).
- **Effet — verdict différé (décision du propriétaire, 24/11 : « b ou a »)**. Une adresse qui porte la signature d'une
  campagne établie n'est pas bannie sur-le-champ : sa requête est servie, puis le verdict tombe après ~10 s. Elle est
  bannie 24 h (catégorie `rotation:<8 premiers caractères de la signature>`) **seulement si elle s'est comportée en
  robot** pendant ce délai : aucune ressource de page chargée (CSS, JS, images, polices) depuis la même adresse, pas de
  cookie de session renvoyé, pas de référent. Un vrai navigateur charge ses ressources dans la seconde et n'est jamais
  banni ; l'attaquant lit au plus une page par adresse, ce qu'il fait déjà.
- **Option « immédiat »** (`--rotation-verdict differe|immediat`, défaut `differe`) : ban dès la première requête,
  pour une campagne dont le propriétaire juge le risque acceptable (signature qui n'imite aucun navigateur courant).
  Le réglage est global, déclaratif, et sa valeur figure dans l'état et le relevé.
- **Critère d'acceptation ajouté** : au rejeu, un client qui charge les ressources de sa page n'est jamais banni en
  mode `differe`, même s'il porte la signature d'une campagne établie.
- **Garde-fous** (refus au dernier moment, dans `NftBanner.banAt` de sbxwaf, qui écarte déjà les robots vérifiés) : jamais une adresse privée, du LAN, du maillage ou
  protégée ; jamais une adresse de la liste blanche ; jamais un robot d'indexation vérifié (la vérification existante
  des robots est consultée avant) ; jamais le relais Tor/relais de vie privée.
- Une campagne expire après 24 h sans nouvelle source. Au plus 10 campagnes actives ; au-delà, la plus ancienne
  inactive sort. Chaque établissement et chaque fin de campagne est écrit dans le journal d'audit du WAF
  `/var/log/secubox/waf/audit.log` (le journal central est fermé à `secubox-waf` ; même choix que
  `reevaluation.go`). Plafond propre au détecteur : 1 500 bans par heure glissante (celui de #2238, 30/h, ne tient
  pas face à ~1 000 adresses/heure) — choix du concepteur.
- **Mode** : `--rotation off|propose|auto` (même vocabulaire que `--campagne-ban` et `--actor-ban`). En `propose`, la campagne est établie, journalisée et visible dans le
  relevé, mais rien n'est banni. Réglage déclaratif dans la conf de l'unité (même patron que `--actor-ban`, unité et
  `conf/honeypot.conf` ensemble).
- État persistant : `/var/lib/secubox/waf/rotation-etat.json` (campagnes actives), relu au démarrage ; fichier périmé
  ignoré.
- Mémoire bornée : nombre de signatures suivies plafonné (LRU), pas de croissance avec le trafic.

### 5.5 SMTP et SSH (B, élargissement)

- Le mécanisme existe (`sbx-authwatch/campagne.go`, pivot = compte visé). Ajouts : écrire l'état des campagnes
  actives dans `/run/secubox/authwatch-campagnes.json` (compte visé masqué au-delà de ses 3 premiers caractères,
  nombre de sources, première/dernière activité) pour le relevé populations ; poser `asn`, `asn_org`,
  `reseau_classe` sur ses lignes ; marquer ses lignes d'un identifiant de campagne.
- Le comportement de ban SMTP existant ne change pas.

### 5.6 Liste « Campagnes » du Radar refaite (A)

Décision du propriétaire (24/11) : pas de panneau supplémentaire. La liste existante « Campagnes les plus actives »
du Radar (`rCampagnes` dans `www/ai/index.html`) est **refaite** pour devenir compréhensible et visible. Aujourd'hui
elle affiche une empreinte hexadécimale, un nom d'outil et « N attaquants » ; elle est vide la plupart du temps.

- `secubox-ai` (gk3) : `menaces.py` ajoute `/waf/populations` **à la fin** de `CHEMINS` (`ESSENTIELS = CHEMINS[:4]`
  dépend de la position), donc hors des essentiels : son absence ne bloque pas le résumé. La liste se nourrit du relevé populations (5.3) ; les campagnes de `/waf/campaigns` restent
  intégrées comme populations quand elles existent.
- La carte passe en pleine largeur dans la colonne centrale ; une carte par population, triée par activité des
  dernières 24 h, 6 au plus, les autres repliées sous « autres populations ».
- **Chaque carte se lit en clair**, emojis comme repères, **toujours accompagnés de leur texte** (jamais un emoji
  seul, jamais la couleur seule ; `title`/`aria-label` sur chaque puce) :

```
📚 Collecte de l'historique Gitea            🌀 rotation   🛑 bannie 24 h
7 207 adresses · 337 réseaux · 1 requête par adresse pour 98 %
🔁 proxy loué 92 %  🏠 accès grand public 8 %      🇺🇸 US 31 %  🇬🇧 GB 18 %  🇨🇦 CA 8 %
Cible : gitea.gk2 — pages de commit et blame        ▁▂▁▃█▄▅ 7 j · depuis le 31/10
```

- Repères de **classe de réseau** : 🔁 proxy loué · 🏢 hébergeur / cloud · 🏠 accès grand public ·
  🛰️ mobile ou satellite partagé · 🌐 CDN · 🕶️ relais de vie privée · 🔬 scanner de recherche · ❔ inconnu.
- Repères de **famille** : 📚 collecte · ✉️ messagerie (mots de passe) · 🚪 accès distant et leurres ·
  🕷️ balayage web · ❔ autre. Repères d'**état** : 🌀 rotation (indicateur 5.3) · 🛑 bannie · 👁️ observée
  (mode `propose`) · 💤 inactive depuis 24 h.
- **Pays** : drapeau tiré du code ISO (indicateurs régionaux) suivi du code en texte ; 3 premiers pays par part
  d'adresses. Le pays reste un indice secondaire, comme ailleurs dans le Radar.
- **Nom de la carte** : composé par le code à partir de la famille et de la cible (« Collecte de l'historique
  Gitea », « Mots de passe sur la messagerie : comptes ger… », « Balayage des leurres de service »), jamais par le
  modèle ; la signature hexadécimale passe en détail.
- **Détail dépliable** : 5 premiers réseaux (ASN, opérateur, repère de classe, adresses), exemple de requête ou compte
  visé masqué, première et dernière activité, signature.
- **Pied de liste** : recouvrement entre populations (« 7 adresses communes sur 12 500 : acteurs distincts »).
- Relevé absent ou incomplet : « relevé indisponible » ou « relevé partiel (date) », jamais de zéro inventé.
  Mode démonstration : données fictives en adresses de documentation, comme le reste du Radar.
- Aucun chiffre ni nom de carte ne vient du modèle ; le pied du Radar le dit déjà.

### 5.7 Liste « Campagnes » d'Actor Intelligence refaite (A)

Demande du propriétaire (24/11). La page Actor (`packages/secubox-waf-ng/www/actor/index.html`, `rendCampagnes`)
liste les campagnes de `sbx-actord` (`/api/v1/actor/campaigns`) : sur gk2, 54 campagnes, chacune nommée par une
empreinte (`3030717d`) avec des compteurs (acteurs, sources, pays, cibles). La première réunit 1 144 acteurs, 5 722
sources, 73 pays et **une** cible : très probablement l'aspirateur, mais rien ne permet de le lire.

- **Même vocabulaire visuel que le Radar** (5.6) : nom composé en clair par le code (famille + cible), repères de
  famille, de classe de réseau, d'état et de pays, toujours avec leur texte ; l'empreinte passe en détail.
- `sbx-actord` enrichit chaque campagne de `/campaigns` (champs ajoutés, aucun retiré) : `cibles_noms` (3 premiers
  hôtes ou comptes visés, comptes masqués), `famille`, `classes` (répartition des sources par classe de réseau, grâce
  à l'ASN désormais posé dans l'enveloppe par 5.2), `pays_top` (3 premiers codes ISO avec part), `tentatives_par_source`
  (part à 1, part à ≤ 3), `rotation` (même indicateur que 5.3).
- **Rapprochement avec les populations** : quand une campagne d'actord et une population du relevé (5.3) partagent la
  même cible et ≥ 50 % de leurs adresses, la carte le dit (« même population que … dans le Radar ») ; le relevé
  populations porte en retour l'identifiant de campagne actord. Aucune fusion automatique des deux modèles.
- Les repères (table emoji → texte, drapeau depuis code ISO, nom de carte) sont **une seule définition** : un petit
  fichier JS partagé servi par waf-ng et copié à l'identique dans secubox-ai au build, avec un test qui vérifie que les
  deux copies sont identiques. Le Python de secubox-ai et le Go d'actord composent le nom de la même façon (table
  famille → libellé dans le code, testée des deux côtés sur les mêmes cas).
- Le tri reste celui d'actord (priorité) ; les campagnes à une seule source ou inactives depuis 24 h sont repliées.

## 6. Contraintes

- AGENTS.md : socket Unix par module, `require_lecture` sur la lecture, stats lourdes en tâche de fond + cache fichier,
  audit append-only, version montée à chaque source modifiée, en-tête SPDX.
- Modifier `common/` impose de publier secubox-core d'abord : **éviter `common/`** ; le code partagé Go vit dans
  `packages/secubox-toolbox-ng/internal/`.
- gk2 : vérifier `uptime`/`free -m` avant déploiement, waf-ng seul dans sa transaction apt, couture vérifiée après.
- Le dépôt est public (et c'est lui qu'aspirait la campagne) : aucune signature d'attaquant réelle (navigateur déclaré,
  adresses) dans le code ou les tests ; adresses de documentation dans les tests, signatures fictives.

## 7. Critères d'acceptation

1. Rejeu sur les **journaux d'accès nginx complets** de gk2 (tous les vhosts, l'entrée réelle du détecteur, pas
   seulement `waf-threats.log`), conservés hors dépôt dans `/var/lib/secubox/waf/rejeu-3919/` (instantané pris dès le
   début des travaux : adresses réelles, jamais dans le dépôt public) : la campagne de l'aspirateur est établie en
   moins de 15 min après son retour ; aucune campagne n'est établie sur le trafic du LAN, du maillage, des robots
   vérifiés ni des usagers réels de Gitea.
2. Sur gk2 en `propose` pendant 48 h : liste des campagnes établies relue par le propriétaire avant passage en
   `bannir`.
3. `GET /api/v1/waf/populations` renvoie, sur la même fenêtre de 7 jours, des chiffres égaux à ±5 % à ceux d'un
   script de référence indépendant lancé sur les mêmes journaux (le §2 n'est qu'un ordre de grandeur : la population
   Gitea y est comptée depuis le 31/10) ; réponse en moins de 50 ms (cache).
4. Le Radar affiche la liste refaite ; `/waf/populations` coupé → « relevé indisponible », le reste du Radar inchangé.
5. Aucune hausse mesurable de la latence de sbxwaf (p95) ni de sa mémoire au-delà de 30 Mo.

## 8. Laissé au constructeur

- Structure exacte des fichiers Go, nom des options, format interne de l'état.
- Calcul exact de l'empreinte TLS dans HAProxy (ou son report si la capture n'est pas propre).
- Mise en forme fine du panneau, dans le style existant du Radar (`.rpan`, tokens du Radar).
- Découpage en paquets et ordre de livraison (waf-ng d'abord, secubox-ai ensuite).
