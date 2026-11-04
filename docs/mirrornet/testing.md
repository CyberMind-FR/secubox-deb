<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MirrorNet — plan de tests et mesures (#3429, phase B)

CONCEPTION. Aucun test n'est écrit. Modèle testé : la vision du 2026-11-03 (`architecture.md` § 0) — publication
automatique, nom court au premier publieur, miroir d'office, aucune signature de contenu (décision 3 reportée).

Banc : **gk2** (seule entrée Internet), **gk6 et gk4** (nœuds publieurs et copies), **gk9** (clé USB locale) ; gk3 et
gk1 **intouchables** (Voice Studio de gk3 : simulé par un service factice de même classe sur gk6/gk4, A22) ; gk5
headless en secours ; gk7 (RPi4) pour la mesure ARM petite mémoire. Matériel et mémoire de gk4/gk6/gk9, adresse maillée
et `/data` de gk9 : **NON VÉRIFIÉ**, à relever (`lscpu`, `free -m`, `df -h /data`) en tête de campagne.

## 1. Niveaux de test

| Niveau | Où | Outil | Quand |
|---|---|---|---|
| unitaires | dépôt, `.venv` local | `pytest` (Python), `go test ./...` (sbxwaf) | chaque PR |
| contrat | dépôt | format `haproxy-routes.json` ancien/nouveau rejoué ; schéma TOML ; `ConfigBlob` | chaque PR |
| paquet | dépôt | tests `test_paquet*.py` : unités durcies (RULES-CODE § 10), sudoers argv exact, AppArmor, exception écrite | chaque PR qui touche un paquet |
| banc | gk6, gk4 puis gk2 | scénarios § 3, déploiement **par apt** | fin de lot, sur accord |
| non-régression parc | gk2 | table de routes réelle relue, `haproxyctl generate` sans `waf_bypass` ajouté | avant tout déploiement sbxwaf sur gk2 |

## 2. Tests par composant (unitaires et contrat)

| Composant | Cas obligatoires |
|---|---|
| manifeste de module (N1) | `mirrornet.d` : clé inconnue, type inconnu, `version_api` non prise en charge → module ignoré, registre servi ; manifeste cassé n'abat pas les autres (comme `capabilities.d`) |
| API adaptateur (N1/N6) | contrat metablogizer : `publications` reflète une publication locale, `exporter` reproductible (même empreinte), `installer` d'une archive hostile refusé, `activer` idempotent, refus → ancienne version servie ; mirrornet n'écrit jamais sous `/srv/metablogizer` (AppArmor) |
| manifeste de service généré (N1) | schéma strict ; nom réservé (`admin`, `apt`, `live`, noms de nœuds, classes) ; `waf_bypass = true` refusé ; type non pris en charge refusé ; 4R : échec → ancien conservé ; aucune signature exigée |
| registre des noms courts (N1) | fonction pure : premier publieur titulaire ; contenu différent ultérieur → `refuse` ; écart < `marge_horloge` → `bloque` ; `annonce_le` antidatée au-delà de la marge → datée à réception ; concurrente plus ancienne découverte après convergence → `conteste`, titulaire toujours servi ; même `racine`/`empreinte_tete` → miroir ; annuaire non synchronisé depuis > fenêtre → aucune conclusion ; source révoquée → `suspendu` ; source absente → titulaire conservé ; arbitrage prime ; résultat identique sur tous les nœuds pour un même journal |
| placement automatique (N1/N6) | ≥ 1 copie hors du nœud source sans geste ; nœud sans module/`/data`/quota ou `accepter = false` jamais élu ; refus → re-placement |
| identités (N2) | `NodeRecord` ancien (sans champs) toujours lu ; empreinte OpenPGP non liée par `openpgp_bind` → identité non liée ; désaccord WG → journal seul (A21) |
| niveaux (N3) | table de vérité complète du § 3 de `federated-trust.md` ; Grant expiré ; Grant TRUSTED d'une autre box ignoré ; aucun effet sur le comportement (A21) |
| révocation (N4) | pair en ligne retiré ; maître et soi-même refusés ; annuaire injoignable → rien ; idempotence ; délai mesuré |
| sbxwaf (N5) | forme tableau inchangée (golden test sur 300 routes) ; forme objet ; 17 cibles refusées ; cible publique refusée ; cible = WAF refusée ; santé périmée → toutes saines ; repli GET rejoué, POST jamais ; aucun accès fichier dans `Lookup` (bench) ; `site_id` présent dans l'enveloppe et borné |
| transfert (N6) | annonce d'un nœud non enrôlé ou révoqué ignorée ; empreinte fausse → rejet et autre source ; mirrornet n'extrait jamais l'objet ; archive hostile (refusée par l'adaptateur) (`..`, absolu, lien sortant, périphérique, 20 001 entrées, dépassement de quota) → refus avant écriture ; bascule atomique (lecture concurrente jamais vide) ; disque insuffisant → refus ; fast-forward ; seul le titulaire prolonge la chaîne servie sous le nom court |
| USB | voir `usb-master-source.md` § 7 |
| défense étape A | `allow_admin` jamais bannie ; table `secubox_ddos` présente après `systemctl reload nftables` ; sets bornés ; mode compteurs sans drop |
| threatmesh retiré | plus d'écoute 8780 (`ss -tlnp`) ; `blacklist-sync` sans IoC maillage ; aucun paquet ne dépend encore de l'ingest |

## 3. Scénarios de banc (A21)

| # | Scénario | Critère de réussite |
|---|---|---|
| S1 | enrôler gk6, gk4 (et gk9) ; niveaux affichés | OBSERVER → LIMITED après MEMBER ; aucune différence de comportement |
| S2 | site `toto` publié dans metablogizer sur gk6, **sans autre geste** | `toto.gk6.secubox.in` servi via gk2 (relais wg-mesh) ; `toto.secubox.in` servi après `fenetre_convergence` ; une copie installée d'office sur un autre nœud (gk4 ou gk2), même empreinte (sonde du module) ; panneau : copies et état `titulaire` |
| S3 | `toto.secubox.in` sous charge GET | visites réparties entre les copies saines ; gk2 sert sa copie locale s'il en a une, sinon relaie ; journal WAF porte `site_id=toto` |
| S4 | arrêt de gk6 (nœud source) pendant une charge GET | 0 erreur 5xx ; nom court conservé, servi par la copie ; aucune nouvelle version possible ; panneau « source absente » ; gk6 revenu → réintégré |
| S5 | arrêt du vhost de copie de gk2 (WAF actif) | service par les autres copies, 0 erreur 5xx |
| S6 | nouvelle version de `toto` publiée sur gk6 | fast-forward de toutes les copies, nom court inchangé |
| S7 | conflit : `toto` au contenu différent publié sur gk4 **après** convergence de gk6 | gk4 servi sur `toto.gk4.secubox.in` seulement (`refuse`) ; `toto.secubox.in` reste à gk6 |
| S8 | conflit simultané : `tata` publié sur gk6 et gk4 dans la `marge_horloge` (contenus différents) | aucun `tata.secubox.in` ; chaque copie sur son nom de nœud ; arbitrage administrateur sur gk2 → nom court au choisi, audit |
| S9 | même contenu : archive `toto` identique publiée sur gk4 | pas de conflit : gk4 devient copie de plus de `toto.secubox.in` |
| S10 | clé `SBXSITE` (`titi`) branchée sur **gk9** | `titi.gk9.secubox.in` sans geste, puis `titi.secubox.in`, puis copie hors gk9 ; archive hostile sur une seconde clé → refus, rien publié |
| S11 | partition gk4 / reste du maillage pendant une publication concurrente | au retour : `conteste` ou `bloque` selon les horodatages, jamais deux titulaires ; masterlink absent de `p2p.toml` |
| S12 | révocation de gk4 en ligne | hors wg-mesh, 403 pilotage, plus cible sbxwaf, ses noms courts suspendus, en < 60 s ; audit |
| S13 | WAF : liste des chemins publics | aucun vhost en `waf_bypass` ajouté ; aucun HAProxy multi-serveurs public |

## 4. Mesures ARM64 et x86_64

Même protocole sur une box ARM64 (MOCHAbin de banc ou gk7 RPi4 pour la petite mémoire) et sur un nœud x86_64
(VM ou PC de banc), noyau et paquets identiques :

| Mesure | Méthode | Seuil d'alerte (proposé) |
|---|---|---|
| latence sbxwaf p50/p99, 1 cible vs 3 cibles | `wrk`/`hey` depuis le LAN, 60 s, 50 connexions | p99 +5 % au plus |
| débit maximal sbxwaf (req/s) avec forme objet | idem | −3 % au plus |
| délai de bascule passif / actif | charge GET + arrêt d'une cible, horodatage des erreurs | 0 erreur ; ≤ 30 s |
| propagation d'une version (annonce → servie partout) | horodatages audit | ≤ 2 min pour 50 Mo |
| débit de transfert wg-mesh et CPU (chiffrement WG + BLAKE2b) | `pidstat`, `time` | plafonné à 4 Mo/s sans saturer un cœur |
| extraction 10 000 fichiers par l'adaptateur | `time` | < 5 s ARM64 |
| publication → nom de nœud servi ; → nom court servi | horodatages audit | ≤ 2 min ; ≤ `fenetre_convergence` + 2 min |
| calcul du registre des noms sur journal réel de gk2 | `time`, RSS | < 1 s |
| RSS de `secubox-mirrornet` au repos et en synchro | `ps`, `smem` | < 80 Mo ARM 1 Go |
| calcul des niveaux sur journal réel de gk2 | `time`, RSS | < 2 s, < 50 Mo |
| mémoire des sets nft `secubox_ddos` remplis à `size` | `nft list`, `/proc/meminfo` | documentée |
| espace `/data` par réplique | `du` | sous quota |

Résultats consignés dans le compte rendu de lot (HISTORY) avec matériel, noyau, versions de paquets.

## 5. A22 (rappel)

Adaptateur streamlit (état des applis, basculement manuel) ; adaptateur Voice Studio et services équivalents (deux
instances factices de même classe sur gk6/gk4, jamais gk3 : nom de classe réparti selon la charge) ; quorum et fencing (partition minoritaire en lecture seule, ancien écrivain refusé par terme), bans fédérés (faux ban
visant l'IP d'administration refusé, consensus k=2, éditeur < PARTNER ignoré, IPv6 /64), réputation
(`node-reputation.md` § 5), keepalived (VIP = passerelle refusée). Chantier ultérieur : tests de signature de site (octet modifié, clé hors
trousseau, support USB révoqué).
