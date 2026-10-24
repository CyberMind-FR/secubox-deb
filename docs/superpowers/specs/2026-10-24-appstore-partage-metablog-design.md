<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# App Store partagé : les sites metablog de gk2 disponibles sur les pairs

Issue #3119 (partie 2), projet 4 du maillage. Demande du propriétaire (2026-10-24) : « gk2 distribue le catalogue de ses sites
metablogizer aux pairs p2p, comme gk1 » ; un blog metablog d'un nœud distant devient disponible en local (configuration clonée,
données synchronisées).

## État constaté (2026-10-24)

- **gk2 est l'autorité de la fédération SBX** (`sbx-certd`) : certificat premium, canaux stable/beta/alpha, un catalogue local
  d'objets `.sbx` **signés** (164 objets `metablog`, dont 162 « tous droits réservés »), publiés par `sbxctl app publish`. Le serveur
  re-vérifie l'éditeur, mais compare le canal à son **propre** certificat (celui de gk2), pas à celui du demandeur : **rien
  n'authentifie qui lit** `GET /api/appstore/catalog` et `…/object/{id}/sbx`. Vérifié le 2026-10-24 : 200 sans jeton depuis le LAN
  et depuis Internet (via Tor), 164 objets, paquets téléchargeables. Les tiers (`public`, `public+sites`, `complet`…) existent
  dans la configuration mais ne filtrent aucune réponse.
- **gk1 est `member` sans certificat** : « hors fédération », tier community, catalogue vide. Le service `federation` tourne,
  `/etc/secubox/federation.yaml` est absent.
- **Rien ne copie le catalogue de l'autorité vers un membre.** Les réglages `sync.appstore` existent (15 m, 5 m sur gk2) mais je n'ai
  trouvé aucun code qui tire le catalogue distant ; `sbxctl federation fetch` ne récupère que le certificat émis. L'installation
  (`POST /api/appstore/install`, administrateur) lit le catalogue **local**, ne remplace jamais un site existant et l'installe **non publié**.
- Le maillage donne déjà : l'ancre du maître sur chaque box associée (#3100), l'IP maillée du maître (10.10.0.1), le relais public.

## Objectifs

A. **Adhésion.** Une box du maillage obtient un certificat de l'autorité, donc un tier et des canaux. Même règle que l'association
   automatique (déjà arbitrée) : une box **flashée par le maître** (ancre posée) adhère seule ; toute autre box fait une demande,
   acceptée **d'un clic** par l'administrateur de gk2.
B. **Catalogue distant.** Un membre lit le catalogue de l'autorité par le maillage, avec son certificat ; les canaux visibles sont
   ceux de son certificat. La page App Store affiche « Catalogue du maître » à côté du catalogue local.
C. **Installation.** Le membre télécharge le `.sbx`, **vérifie** éditeur et signature (mécanisme existant), puis l'installe non publié.
   Rien ne s'installe seul : un administrateur confirme dans la page.
D. **Mises à jour.** Le membre relève le catalogue à sa cadence (`sync.appstore`), signale « mise à jour disponible » ; jamais d'installation automatique.

E. **Authentification du demandeur côté autorité** (prérequis de B et C). La requête d'un membre porte son certificat SBX et une
   signature Ed25519 de la requête (méthode, chemin, horodatage) avec la clé de la box. L'autorité vérifie le certificat (CA,
   expiration, liste de révocation), en déduit tier et canaux, et **filtre** catalogue et paquets en conséquence. Sans
   certificat valide : le catalogue ne montre que ce que le tier `community` ouvre (aujourd'hui : rien tant que les objets ne
   sont pas marqués publics), jamais le paquet. Une décision à prendre avec le propriétaire : quels objets sont « publics »
   (aujourd'hui tous sont lisibles par tous, y compris sur Internet).

## Hors champ

- Synchronisation continue des **données** d'un blog vivant entre deux nœuds (deltas) : suite du projet 4, après C.
- Publication d'un objet par un membre vers l'autorité.
- Les box sans maillage ni certificat : rien ne change pour elles.

## Conception

1. **Adhésion.** `sbxctl federation join` existe. Le maître accepte sans décision humaine une demande dont le DID figure parmi
   les pairs du maillage **et** dont l'ancre correspond (la preuve est celle de #3100 : code de jonction signé). Réglage
   `ca.auto_join_maillage` (défaut `true` sur gk2) ; `auto_join` général reste `false`. Toute émission est inscrite dans l'audit.
2. **Authentification (E).** `sbx-certd` : middleware sur `/api/appstore/{catalog,object/*}` qui exige l'en-tête de certificat et la
   signature de la requête, vérifie CA, expiration et révocation, et filtre par tier et canaux du demandeur. Un demandeur sans
   certificat reçoit 401 ; la page locale de la box autorité (session administrateur) continue de tout voir.
3. **Récupération.** Nouveau sous-programme `sbxctl catalogue tirer` (minuteur `secubox-federation-catalogue`, cadence `sync.appstore`) :
   `GET https://<maître>/api/appstore/catalog` par le maillage (adresse maillée du maître, jamais l'URL publique tant que le
   maillage répond), authentifié par le certificat de la box. Résultat écrit dans un **cache fichier** de la box
   (double tampon : écrit, validé, remplacé) ; un échec garde le dernier cache.
4. **Page.** Section « Catalogue du maître » (lecture du cache), bouton « Installer » → confirmation → téléchargement du `.sbx`
   du maître, vérification locale (éditeur + signature + sha256 du catalogue), installation non publiée via la route existante.
5. **Garde.** Aucune route nouvelle sans `require_jwt` (action) ou `require_lecture` (lecture). Le téléchargement n'a lieu que vers
   l'adresse du maître ancrée sur la box (#3100), pas vers une adresse fournie par la requête.

## Sécurité

- Intégrité : signature d'éditeur et de la CA, sha256 du catalogue ; un objet dont l'éditeur n'est pas certifié n'est pas installable.
- Confidentialité : tout transite dans le tunnel WireGuard du maillage.
- Décision humaine : adhésion hors flash = un clic ; installation = confirmation dans la page.
- Audit : adhésion émise, catalogue relevé (nombre d'objets), installation (id, sha256, nom du site).

## Tests et preuves

- Unitaires (Go et Python) : requête sans certificat, avec certificat révoqué ou expiré, signature altérée ou horodatage périmé refusées ; refus d'une demande hors maillage, refus d'un objet non certifié, canal masqué selon le certificat,
  cache conservé sur échec, téléchargement refusé vers une adresse autre que celle du maître.
- Banc : gk1 adhère (flashée par gk2 → seule ; sinon un clic), son App Store montre les sites de gk2, en installe un (non publié),
  puis le publie.

## Laissé au constructeur

- Libellés de la page ; cadence par défaut du minuteur (15 m semble suffire) ; taille maximale d'un `.sbx` accepté.
