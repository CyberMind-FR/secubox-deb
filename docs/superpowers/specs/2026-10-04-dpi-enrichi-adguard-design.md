<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# DPI enrichi par les données d'ad-guard (#1960)

## 1. Demande et relevé du 2026-10-04

Demande du propriétaire : « améliorer le DPI avec les données d'ad-guard ». Choix : pistes A puis B (recommandation acceptée). Le relevé des données réelles **corrige la piste B**.

**Ce que voit le DPI.** `secubox-dpi` : un collecteur (Go) et le moteur d'enrichissement `sbxdpi`. Les « appareils » du DPI sont les clients **WireGuard du toolbox** : identifiant
`sha256(clé publique)[:16]`, 4 appareils au relevé (« iPhone · .204 », « Android · .189 »…), avec leurs destinations et leurs octets. Les noms viennent du SNI et des requêtes DNS observés
dans les flux ; une destination sans nom reste une **adresse seule** (ex. `82.67.100.75`, `160.79.104.10`) et tombe dans la liste « inconnu » de `/usage`. Des règles d'enrichissement
(`/etc/secubox/dpi/rules.json`, 15 règles, propriété de root, rechargées à chaud par `sbxdpi`) donnent usage, fournisseur et application par suffixe de domaine ; l'API Python en garde un miroir (`_classify`).

**Ce que voit ad-guard.** Les noms demandés au DNS par les appareils du **LAN** (≥ 12 sources : TV, téléphones, PC) et les conteneurs (`10.100.0.10`), classés par service et par type
(`lists/services.txt`) et par catégorie (`lists/*.txt`), avec les blocages. **Aucun client `10.99.1.x`** (WireGuard) n'apparaît dans ses compteurs.

**Conséquence.** Les deux populations **ne se recouvrent presque pas** : le DPI ne voit pas les TV (qui passent par la Freebox), ad-guard ne voit pas les clients WireGuard. Une « vue unifiée
par appareil » qui joindrait les deux n'a donc pas de clé de jointure. La piste B est ramenée à ce qui est réalisable : B'.

## 2. Objectifs

- **A — Nommer l'inconnu.** Les destinations que le DPI ne classe pas reçoivent une étiquette issue de la connaissance d'ad-guard : organisation et type (`services.txt`), et catégorie
  publicité / pistage / télémétrie / réseaux sociaux (listes). Elles sont **marquées** « publicité » ou « pistage » quand les listes le disent. Source de l'étiquette affichée : « ad-guard ».
- **B′ — Vue DNS des appareils du LAN dans la page DPI.** Une section distincte, par appareil du LAN (regroupé par MAC) : services et types les plus demandés, taux de blocage, mode
  (observe/block/auto), nombre de noms. Chaque ligne porte la mention **« vu au DNS »** ; la section DPI existante garde **« mesuré par le DPI »**. Aucun volume n'est affiché dans la section DNS.
- **Hors périmètre (v1).** Jointure par appareil entre les deux sources (impossible, §1) ; modification de `sbxdpi` (Go) ; écriture dans `rules.json` (propriété de root) ; piste C (boucle de
  retour DPI → ad-guard), à rouvrir si A et B′ plaisent.

## 3. Architecture

**Un fichier d'échange, pas un appel d'API.** La lecture d'une API d'un module par un autre exige un jeton (« lecture gardée », constaté : 401 depuis l'agrégateur) ; un fichier en lecture seule est
découplé, tolérant à l'absence (`fail-empty`) et sans chemin d'authentification à inventer.

1. **Classification (A)** : le DPI lit **directement** les fichiers de données d'ad-guard livrés par son paquet (`/usr/share/secubox/ad-guard/lists/services.txt`, `lists/*.txt`), lecture seule,
   sans jamais exécuter de code d'ad-guard. Le DPI applique ces données **après** ses propres règles : une règle du DPI gagne toujours (l'opérateur a raison).
2. **Résumé des appareils du LAN (B′)** : ad-guard écrit `/var/lib/secubox/ad-guard/dnstv/dpi-feed.json` (écriture atomique, `0600` (propriétaire `secubox`, qui est aussi l'utilisateur de l'API du DPI)), recalculé par le moteur existant
   (minuterie d'une minute) au plus toutes les 5 minutes : par appareil — nom, MAC, adresses, mode, requêtes et blocages sur 24 h, **top 10 services**, répartition par type. Rien de plus que
   ce que `/adblock-tv/sources` et `/flux` exposent déjà à l'administrateur ; pas d'historique requête par requête ; fenêtre fixe de 24 h.
3. **API du DPI** (admin, `require_jwt` comme le reste) : l'enrichissement A est appliqué dans la réponse de `/usage` (liste « inconnu » → étiquetée) ; nouvelle route `GET /lan_dns` lit le
   fichier d'échange et répond `{"disponible": false}` s'il manque ou s'il date de plus de 15 minutes (jamais de chiffres périmés présentés comme frais).
4. **Page du DPI** : section « Appareils du LAN (vue DNS) » à la charte existante, rendue par `textContent`, avec la mention de source et l'âge des données.

## 4. Sécurité et vie privée

- Les noms demandés par appareil sont des métadonnées de navigation : déjà visibles de l'administrateur dans ad-guard ; le fichier d'échange est `0600` et n'est lu que par l'API admin du DPI.
- Aucun nom n'est interprété : tout nom passe par `valider_domaine` (côté ad-guard) puis par `textContent` (côté page) ; une valeur hostile n'est jamais recopiée dans une règle.
- Aucune écriture dans `rules.json` ni dans la configuration d'un service : v1 est **lecture seule** côté DPI.
- Le fichier d'échange ne contient ni secret, ni cookie, ni URL, ni contenu.

## 5. Tests

- Classification : un nom inconnu du DPI reçoit organisation, type et catégorie d'ad-guard ; une règle du DPI qui le connaît **gagne** ; un nom hostile n'est ni classé ni recopié ; données absentes ⇒
  comportement actuel inchangé.
- Fichier d'échange : écriture atomique, permissions, contenu borné (10 services par appareil), aucun nom invalide, rafraîchissement au plus toutes les 5 min.
- Route `/lan_dns` : garde JWT, fichier absent, périmé, corrompu, lien symbolique refusé.
- Page : rendu navigateur réel, texte piégé, API en erreur ou HTML (502), mention de source présente.
- Essai réel sur gk2 : la liste « inconnu » du DPI se réduit, la section LAN montre les TV ; vérification **par l'adresse publique** après redémarrage de l'agrégateur.

## 6. Livraison

`secubox-dpi` (version mineure) et `secubox-ad-guard` 1.6.0 (producteur du fichier d'échange) ; README des deux ; HISTORY/WIP ; déployés par paquet sur gk2 ; agrégateur redémarré (il sert les modules dans
son processus). L'issue #1960 ne se ferme qu'après déploiement et validation du propriétaire.

## 7. Risques et limites assumés

- **Le DNS donne des noms, pas des volumes ni du contenu.** Les deux sections ne se mélangent jamais ; une ligne « vu au DNS » ne dit rien de l'octet.
- **Les populations diffèrent** : le DPI continue d'ignorer les TV (trafic hors gk2) ; la section B′ comble l'absence d'information, pas l'absence de mesure.
- Une classification par suffixe peut se tromper sur un domaine partagé (pub et contenu sur un même nom, cas C du banc d'ad-guard) : l'étiquette dit « d'après ad-guard », sans certitude.
- Le fichier d'échange ajoute une écriture d'ad-guard toutes les 5 minutes et une lecture du DPI à chaque appel de `/lan_dns` : coût négligeable, à mesurer.
- Si l'on veut plus tard que `sbxdpi` (Go) applique ces étiquettes à la source, il faudra un dossier de règles (`rules.d`) rechargé à chaud : autre chantier.
