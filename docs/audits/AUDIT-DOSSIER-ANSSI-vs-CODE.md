<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Audit comparatif — Dossier technique ANSSI V1.1 ⟷ code réel

| | |
|---|---|
| **Document audité** | `Dossier_technique_SecuBox-Deb_ANSSI_V1.1_illustree.pdf` — 8 pages |
| **Version du document** | V1.1 illustrée, **22 août 2026** |
| **État du code au moment de l'audit** | `master`, **21 septembre 2026** — un mois plus tard |
| **Méthode** | Chaque affirmation vérifiable du dossier confrontée au code et, quand c'était possible, au comportement observé sur `gk2` |

## Ce que cet audit cherche

Un dossier technique vieillit dans un seul sens : le code avance, le document
reste. Un mois sépare les deux. Ce n'est pas long, mais SecuBox-Deb a connu
sur cette période le décommissionnement de CrowdSec, celui de mitmproxy, et
le passage à Trixie.

L'audit cherche donc **trois espèces d'écart**, et elles ne se corrigent pas
de la même manière :

1. **Le document promet ce que le code ne fait pas.** C'est le seul écart
   réellement grave : il fait dire au dossier une chose fausse à un lecteur
   institutionnel.
2. **Le code fait ce que le document ne dit pas.** Bénin en apparence, mais
   c'est ainsi qu'on sous-vend un travail réel, et qu'on classe en « à
   développer » quelque chose qui tourne déjà.
3. **Le document et le code s'accordent, mais sur une chose creuse.** La plus
   difficile à voir : la fonction existe, elle est nommée partout, et elle ne
   produit pas ce qu'on croit. Trois cas ont été trouvés, et ils faisaient
   tous silence.

---

## 1. Fonctions annoncées du profil Alpha (§3)

Le dossier liste sept fonctions. Six sont **réalisées**, la septième est
correctement annoncée comme future.

| Fonction annoncée | Verdict | Preuve |
|---|---|---|
| Terminaison et routage des VHOST | ✅ | `packages/secubox-haproxy` + `haproxyctl` |
| Reverse proxy vers services publiés | ✅ | `haproxy.toml` → backend `sbxwaf_inspector` |
| Filtrage applicatif WAF | ✅ | `sbxwaf`, **159 motifs**, règles v1.5.2 |
| Journalisation et classification | ⚠️ **creux corrigé** | `threatlog.go` — voir §4.1 |
| Détection noms / chemins / services inexistants | ✅ | `hostanomaly.go`, `negativespace.go` |
| Leurres contrôlés **sans contre-attaque** | ✅ | `leurrehttp.go`, catégorie `honeypot` ; aucun code sortant vers l'attaquant |
| Export d'événements normalisés | 🕒 annoncé « futur » | Non fait — **annonce exacte**, voir §3 |

La formule « expérimentation de leurres contrôlés **sans contre-attaque** »
est tenue au sens strict : la lecture du moteur ne montre aucun chemin qui
émette vers le système distant. La déception se limite à répondre et à
journaliser.

---

## 2. Ce que le document sous-estime

### 2.1 Le profil Edge/WAF minimal **existe déjà**

Le dossier classe en « à développer / valider » (§8) un « profil Edge/WAF
minimal ». Or `packages/secubox-profiles/profiles/secure-gateway.toml`
existe : **16 modules**, dont `waf`, `haproxy`, `vortex-firewall`, `certs`,
`hardening`, `ipblock`. C'est exactement le profil décrit.

À titre de comparaison : `lite` en compte 37, `full` 95.

**Écart de type 2.** Le document se sous-vend. La correction est d'une ligne
dans le dossier, pas dans le code.

### 2.2 La cible ESPRESSObin n'est jamais construite — et on savait mal pourquoi

Le dossier écrit : « Un profil Edge/WAF plus minimal est envisagé pour des
plateformes telles qu'ESPRESSObin. »

Les configurations existent (`board/espressobin-v7`, `board/espressobin-ultra`)
et **la CI les exclut** depuis #503, dont la justification écrite était :

> those board builds fail in the cross-arm64 chroot stage and block the
> downstream release.yml job for every image

**Cette phrase était fausse sur ses deux moitiés.** L'audit a déclenché une
construction pour la vérifier, plutôt que de recopier la justification.

#### Le blocage de la publication n'existait plus

Il a été corrigé en **#1294** : le job `release` porte désormais
`if: !cancelled()`, posé précisément parce que la chute de `mochabin/full` sur
`v3.0.0-alpha.4` avait emporté cinq images abouties. Un échec ESPRESSObin ne
coûtait donc plus, depuis des semaines, que sa propre jambe. **L'exclusion
survivait à sa raison d'être.**

#### Et l'échec n'était pas dans le chroot

Le chroot aboutissait. Le journal de la construction témoin dit :

```
6/7 Construction image GPT 3584M...
Image trop petite : ROOT ferait 1024 MiB, 3072 minimum
```

Arithmétique : `IMG 3584 − DATA 1536 − ESP 1024 = ROOT 1024`.

`ESP 1024` et `DATA 1536` sont des parts **fixes**, dimensionnées pour une
image `full` de 8 à 12 Gio où elles pèsent 20 à 30 %. Sur les 3584 MiB de
l'ESPRESSObin elles prennent **72 % du disque** avant le moindre paquet.

Et ces 3584 MiB ne sont pas une erreur : `# Image size: 3.5G for 4GB eMMC
compatibility`, confirmé par le README de la carte — « 3.5GB max » pour les
modèles à eMMC 4 Go. **Agrandir l'image l'aurait rendue inflashable sur le
matériel visé.**

L'image était donc **arithmétiquement impossible depuis toujours**. Personne
ne l'avait vu parce que personne ne la bâtissait : **l'exclusion masquait le
défaut qu'on lui imputait.**

#### Troisième couche : la CI écrasait le profil déclaré par la carte

`board/espressobin-v7/config.mk` déclare, en connaissant le matériel :

```make
# Profil Lite (RAM limitée 1-2 GB)
SECUBOX_PROFILE=secubox-lite
SWAP_SIZE=512M
```

Mais la matrice CI passait `profile: ["full","isp"]` **en dur pour toutes les
cartes**, et `build-image.sh` applique `--profile` de manière
inconditionnelle. La CI répondait donc **`full` — 95 modules** à une carte qui
demande `lite`, sur un Armada 3720 dual-core A53.

#### Ce qui a été corrigé (#1318)

| | |
|---|---|
| Matrice | dérivée des `config.mk` — espressobin-v7 bâtit **lite + isp**, les autres cartes inchangées |
| Découpage | proportionnel sous 6144 MiB : ESP 256 / DATA 512 ; minimum ROOT dépendant du **profil** (3072 pour `full`, 2048 sinon) |
| Exclusion #503 | levée — sa raison avait disparu avec #1294 |

Vérifié pour chaque carte et chaque profil : `espressobin-v7/lite` obtient
ROOT 2816 ≥ 2048 (**passe**), `espressobin-v7/full` obtient 2816 < 3072
(**refusé**, ce qui est correct — il ne tient pas). Les cartes ≥ 6 Gio sont
inchangées.

#### Ce qui reste, et qui n'est pas propre à cette carte

La construction bute désormais plus loin, à l'étape 3/7, sur un défaut
**connu, intermittent et commun à toutes les images arm64** :

```
E: Could not read from .../bookworm-security_InRelease
   - getline (12: Cannot allocate memory)
```

Le dépôt le documente déjà dans `runner-headroom` : « la jambe qui tombe
change d'un run à l'autre […] ce n'est pas le profil, c'est la pression
mémoire du runner ». `qemu-user` double l'empreinte de chaque processus émulé,
et apt lit ses index en mémoire. La parade de #1294 — 12 Gio de swap — a
réduit la fréquence sans supprimer la panne.

Une configuration apt frugale a été ajoutée dans le chroot (`Languages
"none"`, `GzipIndexes`, acquisition sérielle) : aucune n'y était posée, apt
tournait avec ses défauts. **Cela réduit une probabilité, cela ne ferme pas le
défaut** — et un run vert ne prouvera pas le contraire, seulement que la panne
n'a pas frappé cette fois.

**Aucune image ESPRESSObin n'a donc encore été produite.** L'affirmation du
dossier reste au conditionnel (« envisagé »), ce qui la sauve ; elle
deviendrait fausse à l'indicatif.

---

## 3. Ce qui est annoncé comme futur, et l'est bien

Le dossier est **honnête sur ses manques**, et c'est à porter à son crédit.
Les §5 (architecture distribuée), §6 (conditions de confiance) et la ligne
« export d'événements normalisés » de §3 décrivent une intention, pas un
état. La vérification confirme qu'aucune de ces briques ne prétend exister :

| Promesse §6 | État réel |
|---|---|
| Identité et authentification forte des nœuds | Non fait |
| Signature et intégrité des événements | `packages/secubox-threatmesh` existe ; **aucune signature** trouvée dans son API |
| Horodatage, durée de vie, révocation, provenance | Horodatage seul (`timestamp` dans le journal) |
| Niveaux de confiance, corrélation multi-source | Corrélation **locale** faite (`profiler.go`, signatures de campagne) ; rien de multi-nœud |
| Résistance à l'empoisonnement de réputation | Non fait |
| Explicabilité des décisions de blocage | ⚠️ **corrigé dans cette passe** — voir §4.1 |

Et **aucun format d'événement normalisé** (CEF, ECS, STIX/TAXII, OCSF) n'est
implémenté nulle part. Le journal de menaces est un NDJSON maison :
`timestamp, client_ip, host, method, path, category, severity, rule_id,
action, user_agent, tool, ja4`.

Ce schéma est propre et suffisant en local. Il n'est **pas** interopérable,
et c'est précisément ce que la §3 annonce comme restant à faire.

---

## 4. Les écarts de type 3 — la fonction existe et ne produit pas ce qu'on croit

Ce sont les trois trouvailles de fond de cet audit. Chacune concerne
directement l'objectif §7 « journalisation exploitable et traçable », et
chacune **faisait silence** : rien, dans le fonctionnement normal, ne
signalait le défaut.

### 4.1 Le journal ne disait pas QUELLE règle avait décidé — **corrigé**

Le champ `rule_id` du journal de menaces était écrit **vide, en dur**, à
trois endroits de `main.go`, avec un commentaire qui l'assumait : la fonction
`Match` ne rendait que `(catégorie, sévérité, mode)` et **jetait**
l'identifiant du motif, que la boucle avait pourtant sous la main.

Conséquence : une ligne de journal disait `product_absent_probes` sans dire
**lequel** des motifs de cette catégorie avait tranché.

Ce n'est pas une gêne cosmétique. Elle rend impossible, en lisant le journal :

- de savoir si un motif sert encore ;
- de mesurer les faux positifs **par motif** (objectif §7) ;
- de rattacher une décision de blocage à sa règle — c'est-à-dire
  **l'explicabilité promise en §6**.

**Corrigé dans cette passe.** `MatchDetail` expose l'identifiant ; les trois
méthodes existantes gardent leur signature (25 appels de test en dépendent,
et les faire bouger aurait mélangé un changement de fond avec du bruit de
refonte). `logEscalate` porte aussi la règle. 7 tests.

### 4.2 Cinq motifs CVE ne s'exécutaient pas — **corrigé (#1310)**

Trois `cve_voip` (Asterisk ×2, OpenSIPS) et deux `cve_xmpp` (Prosody,
Strophe.js) utilisaient un échappement unicode que RE2 ne connaît pas.
`sbxwaf` les rejetait au chargement **et poursuivait** : écrits, relus,
livrés, versionnés — et inertes depuis leur introduction. 154 motifs chargés
sur 159 déclarés.

**La leçon n'est pas l'échappement, c'est le silence.** Un motif absent ne se
distingue **en rien** d'un motif qui ne matche jamais : les deux produisent
zéro prise, zéro ligne, zéro alerte.

**Reste à faire** : comparer le nombre de motifs **chargés** au nombre de
motifs **déclarés**, en permanence et pas une fois au démarrage. C'est le
seul contrôle qui aurait levé ce défaut tout seul.

### 4.3 Le collecteur RGPD ne tourne pas — **ouvert (#1311)**

`CookieAuditAggregator` n'est instancié **nulle part** hors tests. 20 tests
verts sur du code que rien n'exécute, section de configuration `enabled =
true`, cache figé au **17 août**, et **170 Mo** de registre écrits par sbxwaf
que personne ne lit.

C'est le module RGPD / ePrivacy : l'inventaire des cookies déposés par vhost
n'est pas produit. Le dossier ne le mentionne pas — mais la saisine CNIL,
elle, existe (`Dossier_saisine_CNIL_SecuBox_SBXOS.pdf`).

---

## 5. Objectifs de validation Alpha (§7) — état

| Objectif | État | Note |
|---|---|---|
| Installation de bout en bout reproductible | ✅ | Images CI ; Trixie mochabin bâtie et démarrée |
| Profils matériels validés et personnalisables | ⚠️ | 4 profils ; **ESPRESSObin non bâti** (§2.2) |
| Mises à jour, rollback, récupération | 🔍 non vérifié dans cette passe | `secubox-profiles` porte du rollback ; non éprouvé ici |
| Stabilité et comportement en charge | 🔍 non vérifié | |
| Journalisation exploitable et traçable | ⚠️ → ✅ | Trois défauts trouvés (§4), deux corrigés |
| Validation VHOST / reverse proxy / WAF | ✅ | Vérifié en production |
| **Mesure des faux positifs et faux négatifs** | ✅ **fait, non documenté** | Voir ci-dessous |
| Tests sur hosts inconnus, scans, déception | ✅ | `host_anomaly`, `leurre:telnet` observés en journal |
| Revue de la chaîne de développement assistée par IA | 🔍 hors périmètre de cet audit | |

### La mesure de faux positifs a été faite, et n'est écrite nulle part

L'objectif §7 « mesure des faux positifs et faux négatifs » a été atteint le
20 septembre, sur trafic réel :

```
10 422 lignes de journal rejouées, 5 152 requêtes externes

wordpress-001   394 requêtes nouvellement qualifiées   0 faux positif
wordpress-002   261                                    0
livewire-001      4                                    0
```

Le zéro est **vérifié, pas espéré** : chaque chemin légitime du parc
(`/netmodes/`, `/system/`, `/portal/`, `/api/v1/`, les clones gitea) a été
testé contre chaque motif.

Un quatrième motif candidat, `scan-012`, a été **retiré après mesure** : il
était redondant, le moteur décodant déjà les chemins avant comparaison.

**Cette mesure est un livrable §7 et ne figure dans aucun document.** Elle
devrait entrer dans la V1.2 du dossier — c'est exactement le genre de
résultat qu'un lecteur institutionnel attend d'une phase Alpha.

---

## 6. Ce que le dossier ne dit plus, et qu'il faut vérifier en V1.2

Le document date d'avant deux décommissionnements majeurs. **Bonne
nouvelle** : la relecture intégrale du texte ne trouve **aucune mention** de
CrowdSec ni de mitmproxy. Le dossier ne porte donc pas de vestige.

Mais la V1.2 devra intégrer ce qui a changé depuis :

- le moteur WAF est **sbxwaf** (Go), et non plus un dérivé mitmproxy ;
- le bannissement est **nftban autonome** ; CrowdSec est purgé ;
- la cible est **Debian 13 Trixie** pour les nouvelles images.

---

## 7. Écarts repris dans cette passe

| Écart | Action |
|---|---|
| §4.1 `rule_id` vide — explicabilité §6 non tenue | **Corrigé** : `MatchDetail`, `logEscalate`, 7 tests |
| §4.2 cinq motifs CVE inertes | **Corrigé** (#1310), 159/159 chargés |
| §2.1 profil Edge/WAF classé « à développer » alors qu'il existe | **Documenté ici** ; correction à porter en V1.2 |
| Mesure FP/FN faite et non publiée | **Documentée ici** ; à porter en V1.2 |
| §2.2 ESPRESSObin exclue de la CI sur une justification **périmée et inexacte** | **Corrigé** (#1318) : matrice dérivée, découpage proportionnel, exclusion levée |

## 8. Écarts ouverts, par ordre de gravité

1. **Aucun contrôle motifs chargés ⟷ motifs déclarés** (§4.2). Sans lui, le
   défaut qui a laissé cinq motifs inertes peut se reproduire à l'identique,
   et se taire de la même manière.
2. **Le collecteur RGPD ne tourne pas** (#1311). 170 Mo collectés, jamais
   réconciliés, alors qu'une saisine CNIL est en cours.
3. **ESPRESSObin : trois couches retirées, une quatrième reste** (§2.2). La
   matrice, le découpage et l'exclusion sont corrigés (#1318). La
   construction bute maintenant sur le défaut mémoire apt/qemu, **commun à
   toutes les images arm64** et seulement atténué. Tant qu'aucune image n'est
   produite, la mention du dossier doit rester au conditionnel.
4. **Le défaut mémoire apt sous émulation n'est pas fermé.** Il frappe au
   hasard, toutes cartes confondues, et la parade actuelle est
   probabiliste — 12 Gio de swap, plus une configuration apt frugale. Une
   construction d'image qui réussit *en moyenne* n'est pas une chaîne de
   production reproductible, ce que §7 exige pourtant en premier point.
5. **Aucun format d'événement normalisé** (§3). Annoncé futur, donc pas un
   mensonge — mais c'est le verrou de toute la vision Mesh.
6. **threatmesh ne signe rien** (§6). Le paquet existe ; la condition de
   confiance n°1 du dossier n'a pas commencé.

---

## 9. Ce que cet audit a appris sur les audits

L'écart §2.2 n'a pas été trouvé en lisant le code : il a été trouvé en
**déclenchant une construction** pour vérifier une justification écrite.

La justification de #503 était consignée, datée, et citée de bonne foi partout
— y compris dans la première version de cet audit. Elle était fausse sur ses
deux moitiés. Une raison écrite vieillit exactement comme le code qu'elle
décrit, à ceci près que **personne ne la relit** : elle est devenue la preuve
qu'on n'avait pas besoin de vérifier.

La règle qui en sort : quand un document justifie une **absence** — une carte
non bâtie, un test non lancé, une fonction désactivée — c'est là qu'il faut
aller mesurer. Une fonction présente se vérifie en la regardant ; une absence
ne se vérifie qu'en essayant de la lever.

---

*Audit mené le 21 septembre 2026. Les vérifications marquées 🔍 n'ont pas été
conduites dans cette passe et sont signalées comme telles plutôt que
supposées acquises.*
