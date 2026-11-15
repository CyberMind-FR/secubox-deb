<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# Filtres WAF conçus par l'IA à partir des avis et des preuves de concept (#3732)

Conception validée en conversation avec le propriétaire le 2026-11-15. Les choix marqués *(choix de conception)*
sont les miens ; le reste est ce qu'il a décidé.

## Intention

Le jour où une faille est publiée avec sa preuve de concept, la box doit savoir reconnaître son exploitation, en tirer
un **filtre**, l'appliquer **d'office sur ses leurres** et le **proposer** pour ses vrais services, puis suivre ce que
chaque filtre devient. Aujourd'hui, `cve-triage` (#3584) produit déjà des leurres HTTP depuis le CERT-FR et un
sous-ensemble Nuclei figé ; la chaîne voulue l'élargit (plus de sources, leurres de service, l'IA locale qui rédige
le filtre, suivi des versions) sans lui retirer ses garde-fous.

## Décisions du propriétaire

- **Prototype d'abord dans le relais du POC sur gk0**, comme les conseils de bans (#3716) ; paquet sur gk3 (V2 de
  SecuBox AI) ensuite, une fois le POC jugé.
- **Sources, preuves de concept en premier** : modèles Nuclei, Exploit-DB, modules Metasploit ; puis avis CERT-FR
  (avis et alertes), CISA KEV, NVD avec score EPSS, GitHub Security Advisories, OSV ; et **nos propres leurres**
  (requêtes et identifiants captés, #3728/#3734).
- **Application** : **automatique sur les leurres** (HTTP de sbxwaf, de service de sbx-authwatch) ; **manuelle sur
  les services hébergés** (Nextcloud, PeerTube, mail…) : proposé, appliqué sur clic du propriétaire.
- **Ban dès la première touche** sur un filtre `leurre`, comme les leurres de service (#3728) ; les leurres existants
  de `cve-triage` (3 touches en 24 h) ne changent pas.
- **Suivi des évolutions** de chaque filtre : naissance (source), versions, attrapes jour par jour, retrait et motif.

## Buts

1. Tenir un **catalogue de filtres** né des sources, chacun relié à sa CVE et à sa preuve de concept.
2. Qu'un filtre visant un **produit absent** de la box devienne un **leurre actif** sans intervention.
3. Qu'un filtre visant un **produit présent** soit **proposé** avec son bilan sur les leurres (attrapes, faux
   positifs : aucun par construction sur un leurre) et ne s'applique que sur clic.
4. Que chaque filtre ait un **historique** lisible : d'où il vient, ce qui a changé, ce qu'il a attrapé.

## Non-buts

- Pas de correctif logiciel : le filtre **pallie** le temps que la mise à jour arrive, il ne la remplace pas.
- Pas de filtre appliqué d'office sur un service réel, quelle que soit la confiance.
- Pas de nouveau moteur WAF : on écrit dans les formats que sbxwaf et sbx-authwatch lisent déjà.

## Anti-buts (échec même si « ça marche »)

- **Le modèle décide** : un filtre appliqué parce que l'IA l'a dit. Le modèle **propose**, le code **vérifie**
  ([[feedback_ia_jamais_inventer]], #3509, chaîne #3716).
- **Du code produit par le modèle** atteint gk2. Un filtre est une **donnée** dans un catalogue de formes fermé.
- **Un vrai visiteur bloqué** sans que le propriétaire l'ait voulu.
- **La box étouffe** : une passe de sources ou d'IA qui coûte la mémoire de gk2 (incident du 15/11). Tout le travail
  lourd tourne sur gk0 (POC) puis gk3 ; gk2 ne fait que vérifier et appliquer.

## Forme d'un filtre *(choix de conception)*

Un filtre est un objet JSON borné, dans un catalogue de formes **fermé** :

| Champ | Contenu |
|---|---|
| `id` | identifiant stable ; une nouvelle version garde l'`id`, incrémente `version` |
| `sources` | liste : `{type: nuclei\|exploitdb\|metasploit\|certfr\|kev\|nvd\|ghsa\|osv\|leurres, ref, url}` |
| `cve`, `epss`, `kev` | CVE, score EPSS, présence dans KEV |
| `produit` | produit visé (nom normalisé) et `present` (vrai/faux, d'après l'inventaire de la box) |
| `cible` | `http` (sbxwaf) ou `service:<port>` (sbx-authwatch) |
| `motif` | **une** des formes fermées : `chemin_exact`, `chemin_prefixe`, `parametre_egal`, `entete_contient`, `corps_contient` (HTTP) ; `trame_contient`, `compte_egal` (service). Chaînes littérales bornées, **jamais d'expression régulière libre** |
| `famille` | famille d'attaque (rce, lfi, sqli, auth_bypass, ssrf, deserialisation, credentials…) |
| `action` | `leurre` (produit absent) ou `proposition` (produit présent) |
| `ban` | durée bornée (1 h à 7 j) |

## La chaîne (POC sur gk0)

1. **Collecte** (relais gk0, tâche de fond, cache disque) : flux des sources ; Nuclei et Metasploit par dépôt git
   local mis à jour ; Exploit-DB par son CSV ; KEV, NVD/EPSS, GHSA, OSV par leurs API ou exports. Aucune lecture de
   source dans le chemin d'une requête.
2. **Tri par le code** : CVE déjà couverte, produit concerné, exploitation à distance, présence de PoC, EPSS/KEV pour
   l'ordre de passage. L'inventaire des produits de gk2 vient de `cve-triage` (lecture).
3. **Rédaction par l'IA locale** : pour chaque candidat, le modèle reçoit la preuve de concept **en données
   isolées** (balises de données non fiables, jamais comme consigne) et rend un filtre au format ci-dessus. Pour un
   modèle Nuclei « raw », le code extrait directement le chemin et le motif sans IA ; l'IA sert les sources en prose
   (Exploit-DB, avis) et la famille.
4. **Vérification par le code** (relais) — un filtre qui échoue est rejeté, avec son motif, jamais corrigé en silence :
   - forme connue, champs bornés, motif littéral non vide et assez spécifique (pas `/`, pas `index.php` seul) ;
   - le motif apparaît dans la preuve de concept source (anti-invention) ;
   - **rejeu sur le trafic légitime récent de gk2** (journal des visites du WAF, hors adresses bannies) : zéro
     correspondance exigée pour une `proposition` ; pour un `leurre`, le produit doit être **absent** de l'inventaire ;
   - collision avec un filtre existant → nouvelle **version** du même `id`, pas un doublon.
5. **Envoi à gk2** par un **compte de service** dédié (même patron que `ai-ban`, #3716 : jeton signé d'une requête,
   audience, rejeu refusé), vers une route qui **revérifie** la forme et l'absence du produit, puis écrit :
   - filtre HTTP `leurre` → catégorie de leurres de sbxwaf (celle de `cve-triage`, `product_absent_probes`), en
     ban directement (ce sont des leurres) ;
   - filtre `service:<port>` `leurre` → règle de reconnaissance de sbx-authwatch (fichier de motifs déclaratif) ;
   - `proposition` → file d'attente ; appliqué en blocage WAF **seulement** sur clic du propriétaire (audit).
6. **Suivi** : chaque attrape (ligne du journal des menaces portant l'`id` du filtre) alimente l'historique ; un
   filtre sans attrape depuis N jours et dont la faille est corrigée partout peut être **retiré** (proposé, pas
   d'office *(choix de conception)*).

## Ce que voit le propriétaire

Une page « Filtres » dans le POC (maquette Aurora **avant** tout code) : filtres actifs (leurres) et proposés, chacun
avec sa source, sa CVE, sa version, ses attrapes par jour et son bouton (appliquer à mes services, retirer) ; un
historique des versions par filtre ; les rejets du vérificateur et leur motif.

## Contraintes

- Règles d'AGENTS.md : nftables, socket Unix, `require_jwt` (le compte de service est l'exception écrite de #3716),
  AppArmor, audit de chaque décision, double tampon pour la config du WAF, LXC seulement, aucun secret versionné.
- gk2 = production ; ne rien y faire tourner de lourd ; grouper les déploiements du WAF (relance de `sbx-actord`).
- Sources externes : télécharger depuis gk0/gk3 seulement, cache local, respect des conditions d'usage ; aucune
  exécution de preuve de concept, jamais.

## Arbitrages techniques après relecture *(choix de conception)*

- **Moteur sbxwaf inchangé au lot 1** : chaque motif littéral devient une expression régulière **générée et échappée
  par le code** (jamais rédigée par le modèle), ancrée sur le texte que sbxwaf inspecte (chemin, requête, corps,
  agent). `entete_contient` est reporté (sbxwaf n'inspecte pas les en-têtes) ; `parametre_egal` se traduit en
  `[?&]nom=valeur` échappé.
- **Catégorie dédiée** `ia_filtres` dans `waf-rules.json` (action ban, seuil 1), distincte de
  `product_absent_probes` et `product_absent_probes_ban` : la régénération de `cve-triage` ne l'écrase jamais.
  Une collision de motif avec `cve-triage` : le filtre IA est rejeté (`deja_couvert`), l'existant fait foi.
- **Écriture** : nouveau verbe de `secubox-cvectl` (root, verrou, double tampon, audit), appelé par la route du
  compte de service via sudoers exact (patron ctl + sudoers). Retrait par le même verbe.
- **Autorité** : gk2 tient l'état appliqué (actif, proposé, retiré) ; gk0 tient le catalogue des candidats et des
  rejets. L'`id` du filtre est l'identifiant de motif de la règle : chaque attrape du journal des menaces lui est
  rattachée sans modifier sbxwaf.
- **Rejeu sur le trafic légitime** : sur gk2, par la route de vérification, borné (7 jours, lecture en flux, plafond
  de lignes), et seulement pour une `proposition` ; un `leurre` exige l'absence du produit.
- **Produit absent = deux sources concordantes** : inventaire de `cve-triage` ET liste des vhosts servis par le WAF
  (`haproxy-routes.json`) ; un doute vaut « présent » (donc proposition, jamais leurre).
- **Plafonds** : au plus 10 filtres `leurre` nouveaux par heure et 50 par jour (comme les plafonds de #3716), contre
  l'empoisonnement par une fausse preuve de concept.
- **Spécificité** : un motif est refusé, leurres compris, s'il compte moins de 8 caractères utiles ou s'il figure
  parmi les 200 chemins les plus fréquents du trafic légitime de gk2.
- **Leurres de service** (`service:<port>`) : lot 3 ; leur format déclaratif (motifs `trame_contient` sur la première
  trame, `compte_egal` sur les `essais` de #3728) sera fixé à ce lot ; le schéma de filtre le prévoit déjà.
- **Modèle** : le modèle local actif du relais gk0 ; la preuve de concept lui arrive en données isolées.

## Laissé au constructeur

Format exact du fichier de motifs de sbx-authwatch ; seuil de spécificité d'un motif ; rythme de collecte par source ;
nom du compte de service ; découpage en lots du POC (je proposerais : 1. Nuclei + vérificateur + leurres HTTP ;
2. Exploit-DB/Metasploit via l'IA ; 3. leurres de service ; 4. propositions pour services réels ; 5. suivi et page).
