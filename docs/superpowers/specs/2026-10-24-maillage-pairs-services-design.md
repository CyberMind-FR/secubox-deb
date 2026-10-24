<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Maillage, projet 2 : services des pairs dans chaque box, liens directs entre pairs

Issue #3133. Suite de la conception « association automatique » (#3100, § 3) : le maître garde la gestion et la
télé-administration ; les liens et le partage de services se font de pair à pair.

## Intention

Le propriétaire (2026-10-24) : « ajouter les services locaux des p2p » — sur chaque box, voir et ouvrir les services
des autres box du maillage, et que les box se parlent sans que tout passe par le maître.

## État constaté (2026-10-24)

- wg-mesh est une étoile : gk2 (10.10.0.1) a chaque pair en /32 ; un pair a le maître en 10.10.0.0/24. gk2 route
  (ip_forward = 1) : gk1 joint déjà gk3 (10.10.0.5:9080 répond 200) **à travers gk2**. Si gk2 tombe, plus rien.
- Chaque box publie ses noms publics (`GET /api/v1/webos/public/noms`) ; gk2 les relaie sur Internet (#1682, #3132).
- L'annuaire (secubox-annuaire) publie déjà, par nœud, des **offres de services signées** (Hall, onions, apt — #3021),
  collectées chaque jour en root puis signées par la clé du nœud, et `GET /services` liste les offres de tout le parc.

## Objectifs

A. **Services des pairs dans chaque box.** Le Hall de chaque box a une rubrique « Pairs » : pour chaque autre box du
   maillage, son nom et ses services (libellé, icône, lien). Le lien est le **nom public** du service
   (`hall.gk3.secubox.in`), servi par le relais (TLS, WAF) : il marche depuis le LAN comme d'ailleurs, sans que le
   poste de l'usager soit dans le maillage.
B. **Liens directs entre pairs.** Chaque pair a les autres pairs comme pairs WireGuard directs (/32) ; le maître reste
   la route par défaut du maillage (10.10.0.0/24) et le chemin de secours. WireGuard choisit l'adresse la plus précise :
   le trafic gk1 → gk3 passe en direct dès que le lien existe, par gk2 sinon.

## Hors champ

- Montage de données ou clonage de modules entre box (projet 4).
- Télé-administration (projet 3, TR-369, #3126).
- Box hors du LAN du maître sans endpoint joignable (NAT des deux côtés) : le lien direct n'est pas tenté, la route
  par le maître reste.
- Aucune ouverture nouvelle vers Internet ; aucun service servi hors du WAF.

## Conception

### A. Services des pairs

1. **Collecte.** `annuaire/offres.py::collecter_faits()` ajoute une source « services » : les noms de
   `public/noms` de la box (lus en root depuis la même source que webos, pas par HTTP), chacun avec son libellé
   et l'URL `https://<nom>`. Ils deviennent des offres `scope.source == "sync"`, signées par le nœud comme les autres :
   la synchronisation existante publie, met à jour et révoque. Rien à la main.
2. **Diffusion.** Les offres circulent déjà dans l'annuaire du parc (`/services/pull` entre nœuds). Pas de nouveau canal.
3. **Affichage.** webos expose `GET /public/pairs` (lecture LAN ou session, comme `/public/services`) : les offres
   « services » des AUTRES nœuds, groupées par nœud, signature vérifiée, offres révoquées ou expirées écartées.
   Le Hall v2 ajoute la rubrique « Pairs » dans la sidebar (pas de double navigation, #2996).
4. **Confiance.** Une offre n'est montrée que si son nœud est membre du parc dans l'annuaire, et si son URL est un
   nom du domaine que ce nœud a déclaré : un nœud ne peut pas annoncer le service d'un autre.

### B. Liens directs

1. **Liste des pairs.** Le maître publie la liste des pairs du maillage (`nom`, `ip_maillee`, `cle_publique`,
   `endpoint` observé par `wg show wg-mesh endpoints`), **signée** par sa clé netboot/ancre ; servie sur le
   master-link (7331, maillage seulement). L'empreinte du maître est déjà ancrée sur chaque box (#3100,
   `ancre-maitre.json`) : un pair n'accepte qu'une liste signée par SON maître.
2. **Application.** `secubox-maillage-pairs` (root, CLI confinée, minuteur 5 min) sur chaque pair : vérifie la
   signature, puis pour chaque autre pair `wg set wg-mesh peer <clé> allowed-ips <ip>/32 endpoint <endpoint>
   persistent-keepalive 25`. Un pair absent de la liste est retiré. Le pair du maître et son 10.10.0.0/24 ne sont
   jamais touchés. Persistance : fichier d'état `/etc/secubox/p2p/pairs-directs.json`, réappliqué au démarrage.
3. **Pare-feu.** Rien de plus large qu'aujourd'hui : les règles d'entrée `iifname "wg-mesh"` restent par service et
   par source. Les pairs ne routent pas (ip_forward inchangé : seul le maître route).
4. **Repli.** Un lien direct sans poignée de main depuis 3 minutes est retiré : le trafic reprend la route du maître.

## Sécurité

- Aucun secret nouveau ; la liste des pairs ne contient que des clés publiques. Elle est signée par la clé du maître,
  et une liste non signée ou signée par une autre clé est refusée et inscrite au journal d'audit.
- Les offres de services sont signées par leur nœud (mécanisme de l'annuaire) ; le Hall vérifie la signature et le
  domaine.
- Chaque ajout et chaque retrait de pair direct s'écrit dans `/var/log/secubox/audit.log`.
- Lien de pair mal formé (clé, IP hors 10.10.0.0/24, endpoint non IPv4:port) : refusé, rien n'est appliqué.

## Tests et preuves

- Unitaires : collecte des offres « services », filtre domaine/signature de `/public/pairs`, vérification de la
  liste signée (bonne clé, autre clé, liste altérée), calcul des ajouts/retraits de pairs WireGuard.
- Banc gk1/gk2/gk3 : Hall de gk1 montre les services de gk3 ; `wg show` de gk1 a gk3 en /32 avec poignée de main ;
  gk1 joint gk3 avec gk2 arrêté côté maillage (`wg set` du maître retiré temporairement), puis retour.

## Laissé au constructeur

- Libellés et icônes des services dans la rubrique « Pairs » (reprendre ceux du registre webos).
- Fréquence de collecte des offres (aujourd'hui quotidienne ; une heure semble suffire pour les services).

## Ordre de livraison

1. A (annuaire + webos + Hall) : sans risque réseau, visible tout de suite.
2. B (liste signée sur le maître, puis application sur les pairs) : gk1 et gk3 au banc avant tout autre nœud.
