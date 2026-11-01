<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SBX TV PRIVACY — lot 4 « DPI par appareil » (#3374)

Rendre visibles, **par appareil**, les applications et protocoles que le DPI (nDPI) détecte, y compris ce que le DNS
ne voit pas : flux sans DNS (adresse en dur), DoH/DoT, résolveurs de contournement. Ajouter l'**anti faux repli** :
repérer et dater les régies et les spots de secours qui apparaissent après un blocage, et dire honnêtement quand la
publicité arrive par le domaine qui sert la vidéo (SSAI). On filtre (DNS) et on observe (DPI) ; on ne touche jamais au
flux.

Retour du propriétaire sur `/tv-privacy/` : « sympa, pas très DPI causant ». Le lot 4 fait parler le DPI.

## 1. Buts, non-buts, anti-buts

**Buts**
- Par appareil (MAC) : applications nDPI (`TLS.Google`, `QUIC.YouTube`, `HTTP.Amazon`…), catégories nDPI, noms SNI/QUIC,
  volume, première et dernière vue, sur 1 h / 24 h / 7 j.
- Trois constats nouveaux : **flux sans DNS**, **DNS chiffré** (DoH/DoT, DoQ si nDPI le classe), **résolveur de
  contournement** (port 53/853 vers un autre résolveur que la box).
- **Anti faux repli** : corrélation temporelle refus DNS → nouveau domaine ou nouveau flux sur le même appareil
  (« apparu 3 s après le blocage de pagead2.googlesyndication.com ») ; repérage d'un **spot de secours récurrent**.
- **SSAI honnête** : un domaine de contenu connu pour insérer des publicités (`replay-0x.oqee.net`) est marqué comme tel ;
  la page explique pourquoi la box ne peut pas le filtrer.
- Une interface stable de **découvertes** que le lot 5b (assistant en direct) consommera.

**Non-buts (lots suivants)**
- Décider d'un blocage à partir du DPI seul : le DPI produit des **constats** ; seules les découvertes de repli (fondées sur
  le DNS) deviennent candidats puis essais du moteur AUTO, avec sa garde (§ 3.5, arbitrage 3).
- Blocage anticipé des régies de secours partagé par le profil agrégé (point 2 de l'anti faux repli) : lot 5b, une fois
  les couples régie → secours mesurés.
- Webapp kiosque : rien de nouveau au lot 4.

**Anti-buts (jamais)**
- Jamais de modification du flux : ni proxy, ni MITM, ni réécriture de manifeste HLS/DASH, ni coupure d'un flux vidéo.
- Jamais de contournement ou d'inspection d'un DRM (`license.oqee.net` reste DRM protégé).
- Jamais de blocage automatique d'une catégorie protégée (`STREAMING`, `CDN`, `DRM`, `AUTHENTIFICATION`, `MISE_A_JOUR`,
  `INCONNU`), même si le DPI l'associe à une coupure publicitaire. Le domaine qui sert le contenu n'est jamais candidat.
- Jamais de contenu applicatif conservé : nDPI ne donne que métadonnées de flux (5-uplet, octets, SNI, classification).
- Jamais de port TCP, jamais de capture permanente sur disque (pas de pcap).

## 2. État des lieux du DPI (cartographie)

| Brique | Paquet | Ce qu'elle fait | Ce qui manque au lot 4 |
|---|---|---|---|
| `nDPId` + `nDPIsrvd` | `secubox-ndpid-engine` 1.7.3 | capture (`-i` = interface de la route par défaut, `secubox-ndpid-engine-run`), nDPI 6.1 statique, socket distributeur `/run/secubox/ndpi/distributor.sock` | aucun filtre de capture ; aucune limite CPU (`CPUQuota`) dans l'unité |
| `sbxdpi` (Go) | `secubox-toolbox-ng` | seul consommateur du distributeur ; agrège top apps/protocoles/catégories, `talkers` « src → dst », risques, JA3/JA4 ; API `dpi-live.sock` ; instantané `/data/secubox/sbxdpi/stats.json` ; `MemoryMax=128M` | **aucune agrégation par appareil** (paires d'adresses seulement, « sans PII » par construction) ; aucun accès MAC |
| API `secubox-dpi` | `secubox-dpi` 1.14.5 | relaie sbxdpi (`/devices` = `talkers`), lit `dpi-feed.json` d'ad-guard (sens DNS → DPI, `/lan_dns`) | le sens nDPI → ad-guard n'existe pas |
| `dnstv_dpifeed.py` | `secubox-ad-guard` | résumé DNS par MAC pour le DPI | — |
| `dnstv_taxonomie.SOURCES` | `secubox-ad-guard` | source `ndpi` réservée, sans flux | à brancher |
| `dnstv_appareils.py` | `secubox-ad-guard` | adresses par MAC (NAC `devices.db` en lecture, repli `ip neigh`) | — : sert au rattachement |
| `dnstv_reponses.py` | `secubox-ad-guard` | noms → adresses A/AAAA depuis `unbound-control dump_cache` (`reponses.db`) | — : sert au constat « sans DNS » |

**Le point dur est la visibilité, pas le code.** Le README de `secubox-dpi` le dit : « le DPI ne voit pas le trafic qui
ne traverse pas gk2 (par exemple les TV) ». Sur le LAN plat de gk2 (Freebox passerelle), le DNS des TV arrive à gk2,
mais leurs flux vont directement à la Freebox. nDPId ne voit donc les flux d'une TV que si :
1. gk2 est la passerelle (`secubox-pseudo-routeur`, #2940 : fusionné, **jamais essayé sur gk2**) ; ou
2. un port miroir du commutateur recopie le port de la TV vers une interface de gk2 ; ou
3. la TV est branchée derrière gk2 (zone dédiée).

Le lot 4 est conçu pour fonctionner dans les trois cas et pour **dire** le cas courant (§ 3.6). Sans visibilité, la page
affiche « DNS seulement » et rien n'est inventé. Arbitrage 1 : on construit tout ce qui marche sans toucher la topologie,
on livre le chemin DPI (inerte tant que les flux ne passent pas par gk2), et le mode LAN est étudié au § 10.

## 3. Architecture

```
nDPId (filtre BPF : seules les MAC du périmètre)  →  nDPIsrvd  →  sbxdpi (Go)
     │                                                      └─ agrégat PAR APPAREIL, opt-in, borné
     │                                                         → /run/secubox/sbxdpi/appareils.json (0640, groupe secubox-adguard)
     └─ cible écrite par ad-guard : /run/secubox/ad-guard/dpi-cibles.json (MAC + adresses du périmètre)
ad-guard (moteur secubox-adguard-auto, chaque minute)
     → rattachement adresse → MAC → dpi-appareils.db (SQLite, 7 j)
     → constats (sans DNS, DNS chiffré, contournement) + corrélation refus → découvertes
     → API /protection/dpi/*  → onglet « Applications » de /tv-privacy/
```

### 3.1 Source DPI : sbxdpi, pas un second consommateur Python

- Décoder en Python tout le flux JSON de nDPIsrvd coûterait cher sur un gk2 déjà à 85-95 % de CPU par moments. sbxdpi
  décode déjà chaque événement en Go : on y ajoute un agrégat **par adresse cible**, sans nouveau socket ni nouveau
  décodage.
- **Opt-in et borné au périmètre** : sbxdpi ne compte par appareil que les adresses listées dans `dpi-cibles.json`
  (écrit par ad-guard : appareils déclarés hors `off`, 64 au plus). Hors liste : comportement actuel, sans PII. La
  posture « sans PII » de sbxdpi reste vraie pour tout le reste ; l'exception est documentée dans son README.
- Événements lus : `detected` / `detection-update` (application, catégorie, `hostname` SNI/QUIC, risques),
  `end` / `idle` (octets). Les événements `packet-flow` restent réservés aux empreintes TLS existantes.
- Clé d'agrégat : `(adresse locale, application nDPI, nom d'hôte racine, port distant, minute)` ; pour chaque flux
  terminé ou détecté : flux, octets, premier et dernier horodatage, adresse distante si **aucun** nom d'hôte (sinon le
  nom suffit). Plafonds : 20 000 clés en mémoire, 2 000 par adresse, éviction des plus anciennes ; fichier réécrit
  atomiquement toutes les 30 s (`DPI_FLUSH_INTERVAL`), 4 Mio au plus, seulement si quelque chose a changé.
- Le fichier est la seule interface (lecture par ad-guard, pas de route HTTP nouvelle dans sbxdpi) : pas de socket à
  ouvrir entre deux utilisateurs dédiés, droits de fichier simples (`secubox-toolbox` écrit, groupe `secubox-adguard`
  lit).

### 3.2 Réduire le coût à la source : filtre BPF par MAC

- `secubox-ndpid-engine-run` accepte un filtre de capture (variable `FILTRE_BPF` de `/etc/secubox/ndpid-engine.env`,
  passé à nDPId par son option de filtre BPF — option exacte à vérifier sur nDPId 1.7, tâche T1).
- ad-guard **ne réécrit pas** l'environnement d'un autre paquet : il dépose `dpi-cibles.json` ; un verbe root borné
  `secubox-adguard-tv dpi-cibles` (sudoers existant étendu) valide les MAC, compose `ether host aa:… or ether host bb:…`
  dans `/etc/secubox/ndpid-engine.d/tv-privacy.env` et redémarre `secubox-ndpid-engine` **seulement si la liste
  change** (ajout/retrait d'appareil, rare). Audit : `audit.log`.
- Un filtre par MAC suit la TV quand son adresse IPv6 temporaire change (§ 3.3). **Choix par défaut** (§ 9) : seules les
  TV du périmètre, filtrées par MAC ; pas de mode « tout le LAN » au lot 4.
- Garde-fou de charge : `CPUQuota=25%` et `Nice=10` sur `secubox-ndpid-engine`, posés par son propre paquet (1.7.4),
  jamais par ad-guard ; sbxdpi garde `MemoryMax=128M`.

### 3.3 Rattachement par MAC (IPv6 privacy)

- sbxdpi compte par **adresse** ; ad-guard rattache à la **MAC** à chaque passage avec `dnstv_appareils` (NAC, puis
  `ip neigh` v4 et v6). Une adresse vue dans `appareils.json` mais absente de la table de voisinage au moment du
  passage est gardée en attente 10 min (adresse → MAC mémorisée à la première résolution, table `voisins` de
  `dpi-appareils.db`, durée de vie 24 h) ; au-delà, compteurs « appareil inconnu » (jamais attribués au hasard).
- Une TV Android qui change d'adresse IPv6 temporaire garde ainsi une seule ligne par MAC : test dédié (T4).
- Avec filtre BPF par MAC, tout flux capturé appartient à une MAC du périmètre ; le rattachement ne sert qu'à dire
  laquelle.

### 3.4 Stockage borné : `dpi-appareils.db`

SQLite dans `DOSSIER_ETAT` (0640, `secubox-adguard`), même gabarit que le cache de l'analyseur du lot 3 :

```sql
flux(mac, minute, appli, categorie_ndpi, hote, racine, port, distant, flux, octets, sans_dns, chiffre_dns, PRIMARY KEY(mac, minute, appli, hote, port, distant))
decouvertes(id, ts, mac, type, domaine, appli, confiance, raison, refus_domaine, refus_ts, delai_s, etat)
voisins(adresse, mac, vu)
meta(cle, valeur)
```

- Rétention : `flux` 7 jours à la minute, puis plus rien (l'analyseur du lot 3 garde déjà 30 j de DNS) ; `decouvertes`
  30 jours, 5 000 lignes au plus. Ménage à chaque passage du moteur. Taille cible < 20 Mio (mesurée, T9).
- Écrit par le seul moteur (`secubox-adguard-auto`), sous le verrou des règles ; l'API ne fait que lire (`mode=ro`).
- Base corrompue : renommée, recréée vide, `dpi: {disponible: false, raison: "corrompue"}` le temps d'un passage.

### 3.5 Constats et corrélation (fonctions pures, `api/dnstv_dpi.py`)

- **Sans DNS** : flux d'un appareil vers une adresse publique **sans** nom d'hôte nDPI **et** absente des réponses DNS
  récentes de cet appareil (`reponses.db` × noms demandés par la MAC dans les 24 h). Exceptions : NTP, STUN/WebRTC
  classés par nDPI, multicast/lien-local. Affiché « adresse en dur » avec ASN et organisation (base déjà utilisée par
  `dnstv_reponses`).
- **DNS chiffré** : application nDPI `DoH_DoT` (ou équivalent DoQ), port 853, ou nom d'hôte présent dans une liste
  livrée de résolveurs DoH (`/usr/share/secubox/ad-guard/lists/resolveurs-doh.txt`, nouvelle, source citée).
- **Résolveur de contournement** : flux DNS (port 53 ou application `DNS`) vers une autre adresse que la box. Croisé
  avec le signal « aucune requête reçue » existant (`dnstv_routes`, cas F).
- **Repli publicitaire** (point 1 de l'anti faux repli) : pour chaque refus `PUBLICITE`/`TRACKING` d'un appareil à `t0`
  (`dnstv_recents`), les domaines **nouveaux pour cet appareil** (jamais vus en 30 j, cache du lot 3) et les **nouveaux
  noms SNI** du DPI apparus dans `[t0, t0 + 30 s]` deviennent des découvertes `repli`, confiance 40 + 30 si la
  catégorie est publicitaire selon la taxonomie + 20 si le même couple réapparaît sur deux coupures. Raison lisible :
  « apparu 3 s après le blocage de pagead2.googlesyndication.com ». Un domaine protégé (§ 1) devient une découverte
  `repli-protege` : **jamais candidat**, expliquée. Source taxonomie : `apprentissage-repli`.
- **Spot de secours récurrent** : même nom d'hôte et volume comparable (± 10 %) observés dans les 60 s suivant un refus
  sur deux coupures ou plus → découverte `secours`, avec horodatages. C'est une hypothèse étiquetée comme telle ; si
  l'hôte est le CDN de contenu, on le dit et on ne propose rien.
- **SSAI** : attribut `ssai = true` dans la référence de la taxonomie (`replay-*.oqee.net`, source « mesure gk2
  2026-11-01 ») ; l'application correspondante porte le badge « publicités insérées dans la vidéo : non filtrables par la
  box sans toucher au flux ».
- Les découvertes `repli` publicitaires deviennent **candidats puis essais** du moteur AUTO dès le lot 4 (arbitrage 3),
  motif « repli publicitaire : apparu N s après le blocage de X » : garde du lot 2 (`refus_auto`, catégorie protégée jamais en
  essai), retrait automatique par « rafale de refus » ou « contenu habituel plus demandé » (lecture cassée), journal et audit
  par `regles-appliquer`.

### 3.6 Couverture affichée

Chaque appareil porte `couverture` ∈ `dns+dpi` (flux vus dans l'heure), `dns` (DNS seulement : flux hors de gk2),
`aucune`. Le moteur la calcule ; elle évite qu'une page vide passe pour un appareil sage.

### 3.7 Coût visé (à confirmer par la mesure, T9)

| Poste | Estimation | Garde |
|---|---|---|
| nDPId, filtré sur 2-4 TV en lecture vidéo (~10-25 Mbit/s) | quelques % d'un cœur A72 ; le gros du coût est la capture | `CPUQuota=25%`, `Nice=10`, filtre BPF |
| sbxdpi, agrégat par adresse | négligeable devant le décodage JSON déjà fait | 20 000 clés, `MemoryMax=128M` |
| Moteur ad-guard (lecture de 4 Mio, SQL) | < 1 s par minute | passage sauté si le précédent n'est pas fini |
| API | requêtes SQL bornées, cache 30 s | `limite` ≤ 200 |
| Disque | < 20 Mio (`DOSSIER_ETAT`) + 4 Mio en `/run` | rétention 7 j |

Arrêt de sécurité (passe 2) : si la charge moyenne sur 5 min dépasse le nombre de cœurs pendant **au moins 5 min** ET que nDPId
prend lui-même ≥ 20 % d'un cœur (cgroup `cpu.stat`), le verbe root `ndpid-arreter` — qui **revérifie** les deux conditions et refuse
sinon — arrête `secubox-ndpid-engine`, donc **tout** le DPI de la box ; sinon on signale sans arrêter. État unique `charge.etat`
(normal | haute | arrete) écrit sous verrou ; reprise manuelle (**choix par défaut**, § 9).

## 4. API (préfixe `/api/v1/ad-guard`)

| Route | Garde | Rôle |
|---|---|---|
| `GET /protection/dpi/etat` | `require_lecture_nominative` | disponibilité de la source, âge, couverture par appareil (nom seulement pour un lecteur délégué), pause de charge |
| `GET /protection/dpi/applications?mac=&fenetre=1h\|24h\|7j&limite=` | **`require_jwt`** | applications d'un appareil : appli, catégorie nDPI, noms d'hôte, octets, flux, premier/dernier, badges (`sans_dns`, `dns_chiffre`, `contournement`, `ssai`, catégorie taxonomie) |
| `GET /protection/dpi/flux?mac=&appli=&fenetre=&decalage=&limite=` | **`require_jwt`** | lignes détaillées (minute, hôte, adresse distante, port), paginées |
| `GET /protection/dpi/decouvertes?depuis=&type=&mac=&limite=` | **`require_jwt`** | découvertes (`repli`, `repli-protege`, `secours`, `sans-dns`, `dns-chiffre`, `contournement`) triées par date |
| `GET /protection/dpi/coupures?mac=&fenetre=` | **`require_jwt`** | frise d'un appareil : refus publicitaires et ce qui suit dans les 30 s (DNS et DPI) |
| `POST /protection/dpi/perimetre` `{mode: "tv"\|"lan"\|"off"}` | **`require_jwt`** | périmètre de capture ; passe par le verbe root `dpi-cibles` (audit) |

- Données par appareil = **administrateur réel seulement** (`require_jwt`), comme `detail=1` au lot 3. Le lecteur délégué
  n'a que l'état agrégé (`/etat`), sans MAC ni adresse ni domaine. Aucune route d'usager.
- Paramètres fermés (Pydantic `extra=forbid`) : MAC canonique, `fenetre` énumérée, `limite` 1-200, `appli` et `type`
  `[A-Za-z0-9._-]{1,48}`.
- Les routes admin sont déclarées dans `routes-ouvertes.d` pour la page relayée par le maître, comme au lot 3.
- Source absente, périmée (> 120 s) ou illisible : 200 avec `disponible: false` et `raison`, jamais 500.

## 5. Page `/tv-privacy/` : onglet « Applications »

Gabarit Aurora (`AURORA-REFERENCE.md`), coque partagée et CSP du lot 3 ; tout texte réseau par `textContent`.

- **Sélecteur d'appareil** (nom, catégorie, pastille de couverture `DNS + DPI` / `DNS seulement`). En « DNS
  seulement », un encart dit pourquoi (flux hors de gk2) et renvoie à la question de topologie, sans fausse liste vide.
- **Cartes d'applications** de l'appareil, triées par octets : icône de catégorie, nom nDPI, noms d'hôte dépliables,
  barre de volume, badges. Badges rouges : `adresse en dur`, `DNS chiffré`, `contourne la box`. Badge neutre `SSAI` avec
  le texte : « Ce service insère des publicités dans sa propre vidéo. La box les voit passer mais ne peut pas les
  retirer sans toucher au flux, ce qu'elle ne fait jamais. »
- **Frise des coupures** : par coupure (refus publicitaire), une ligne temporelle de 30 s : le refus à 0 s, puis les
  domaines et flux apparus (« +3 s metaproxy.francetvpub.fr — nouveau, PUBLICITE », « +5 s replay-03.oqee.net — contenu,
  protégé »). Les spots de secours récurrents portent « même spot qu'à 20:41 ».
- **Découvertes** (liste simple, lecture seule au lot 4 ; les actions arrivent avec le lot 5b) : type, appareil, domaine,
  confiance, raison.
- Rafraîchissement : interrogation toutes les 30 s quand l'onglet est visible, jamais en arrière-plan.

## 6. Interfaces pour le lot 5b

- `GET /protection/dpi/decouvertes?depuis=<id>` est **l'interface** : identifiant croissant, champs stables `{id, ts, mac,
  appareil, type, domaine, appli, categorie, confiance, raison, refus: {domaine, ts, delai_s}, etat}`. `etat` ∈
  `nouvelle`, `candidat`, `ecartee-protegee` ; le lot 5b ajoutera `confirmee`, `legitime`, `plus-tard` par sa file.
- Fonctions pures `dnstv_dpi.correler(refus, apparitions, deja_vus, taxonomie)` et `dnstv_dpi.secours(...)` réutilisables
  par l'assistant.
- Les couples `(régie refusée → domaine de repli)` sont comptés dans `decouvertes` : matière du blocage anticipé et du
  partage par le profil agrégé (lot 5b).

## 7. Tests

- Go (`cmd/sbxdpi`) : agrégat par adresse cible seulement (adresse hors liste = aucune donnée par appareil), plafonds et
  éviction, fichier atomique, rechargement de `dpi-cibles.json` à chaud, événements `detected`/`end` tirés de vraies
  trames nDPIsrvd (cadrage 5 chiffres).
- Python (`tests/test_dnstv_dpi_*.py`) : rattachement IPv6 temporaire → même MAC ; adresse non résolue en attente puis
  « inconnu » ; constat sans DNS (avec et sans réponse dans `reponses.db`, NTP exclu) ; DoT 853, DoH par liste ;
  contournement port 53 ; corrélation sur le **cas gk2 du 2026-11-01** (refus `pagead2`, `googleads.g.doubleclick.net`
  puis apparitions `metaproxy.francetvpub.fr`, `audiences.free.fr`, `stats.oqee.net`, `imasdk.googleapis.com`,
  `m.media-amazon.com`, `firebase-settings.crashlytics.com`, `replay-03.oqee.net`) : les cinq premiers deviennent
  découvertes `repli`, `replay-03.oqee.net` devient `repli-protege` avec badge SSAI, **aucun** domaine protégé n'est
  candidat ; spot de secours sur deux coupures ; rétention et ménage ; base corrompue.
- API : gardes (lecteur délégué refusé sur les routes par appareil, sans MAC dans `/etat`), paramètres fermés, source
  absente → `disponible: false`.
- Page : rendu sans `innerHTML` de texte réseau, couverture « DNS seulement », CSP inchangée (tests Aurora existants).
- Verbe root `dpi-cibles` : MAC invalide refusée, filtre composé, redémarrage seulement si changement, audit.

**Mesure sur gk2 (avec accord, T9)** : `pidstat` de nDPId, nDPIsrvd, sbxdpi et du moteur pendant 30 min de lecture
OQEE sur la TV banc, filtre par MAC puis sans filtre ; taille de `appareils.json` et `dpi-appareils.db` ; latence DNS
(Unbound) avant/pendant. Puis l'essai OBSERVE / AUTO du lot 7 avec la frise des coupures pour départager SSAI pure et
repli.

## 8. Découpage

| Tâche | Contenu | Paquet |
|---|---|---|
| T0 | Prérequis topologie : établir comment les flux de la TV banc traversent gk2 (question 1) | — |
| T1 | Filtre BPF et garde CPU de nDPId (`FILTRE_BPF`, `ndpid-engine.d/`, `CPUQuota`, `Nice`) | `secubox-ndpid-engine` 1.7.4 |
| T2 | Agrégat par adresse cible dans sbxdpi, `appareils.json`, README (exception PII) | `secubox-toolbox-ng` |
| T3 | Verbe root `dpi-cibles`, sudoers, audit | `secubox-ad-guard` |
| T4 | `dnstv_dpi.py` : ingestion, rattachement MAC, `dpi-appareils.db`, rétention | `secubox-ad-guard` |
| T5 | Constats sans DNS, DNS chiffré, contournement ; liste `resolveurs-doh.txt` | `secubox-ad-guard` |
| T6 | Corrélation repli, spot de secours, attribut `ssai`, candidats `apprentissage-repli` | `secubox-ad-guard` |
| T7 | Routes `/protection/dpi/*`, `routes-ouvertes.d`, README | `secubox-ad-guard` |
| T8 | Onglet « Applications », frise, découvertes | `secubox-ad-guard` |
| T9 | Relectures (`relecteur-securite`), mesure gk2, essai OBSERVE/AUTO, suivi | — |

Versions visées : `secubox-ad-guard` 1.21.0, `secubox-toolbox-ng` (mineure suivante), `secubox-ndpid-engine` 1.7.4.
`secubox-ad-guard` recommande (`Recommends`) `secubox-ndpid-engine` et `secubox-toolbox-ng` : sans eux, l'onglet dit
« DPI absent ».


## 9. Arbitrages du propriétaire (2026-11-01) et choix par défaut

1. **Topologie** : « faire ce que tu peux, et approfondir le mode LAN ». Sans changer la topologie : rattachement par MAC,
   flux sans DNS repérés depuis ce que gk2 voit (DNS, `reponses.db`, conntrack quand il y a du trafic transféré),
   corrélation de repli fondée sur le DNS, badge SSAI, onglet « Applications » qui dit honnêtement « DNS seulement » ou
   « DNS + DPI ». Le chemin DPI (sbxdpi étendu, filtre par MAC, `CPUQuota`) est livré, inerte sans flux transférés. Mode LAN :
   § 10.
2. **Contournement** : afficher **et** forcer le DNS pour les appareils du périmètre en PROTECT ou AUTO (§ 11).
3. **Replis** : candidats AUTO **en essai** dès le lot 4, gardes existantes (§ 3.5).
4. **Choix par défaut** (recommandation retenue) :
   - ~~capture nDPI limitée aux seules TV par filtre MAC~~ — **remplacé** (arbitrage § 13) : capture complète, tri par appareil
     dans sbxdpi ;
   - garde de charge : arrêt automatique de nDPId quand gk2 sature (charge sur 5 min > nombre de cœurs pendant **5 min**, et nDPId
     ≥ 20 % d'un cœur ; sinon signal seul), revérifié par root, annoncé dans la page, audité, reprise manuelle par l'administrateur.

## 10. Mode LAN approfondi

### 10.1 Ce que fait réellement `secubox-pseudo-routeur` 0.1.0 (#2940, lu dans le code)

- **Pas d'ARP** : aucune usurpation ARP, aucun proxy ARP. Le paquet ne touche à la couche 2 que par les ensembles MAC du NAC.
- **Passerelle DHCP** : `pseudo-routeurctl activer` appelle `freeboxctl passerelle-dhcp 192.168.1.200`, qui fait un `PUT
  dhcp/config/ {"gateway": …}` sur l'API Freebox (droit « Modification des réglages ») et relit la valeur. C'est un réglage
  **global** du serveur DHCP de la Freebox : **tous** les clients du LAN reçoivent gk2 comme passerelle à leur prochain
  renouvellement de bail. Aucune sélection par appareil n'existe dans le paquet.
- **nftables** : table `inet secubox_pseudo_routeur`, chaîne `forward` priorité `filter - 1`, **policy drop** ; `blocked` et
  `quarantine_zone` du NAC rejetés d'abord, puis acceptation des zones `lan_allowed`, `lxc_zone`, `guest_zone`, `iot_zone` ;
  compteur des rejets. Puis `sysctl net.ipv4.ip_forward=1`. **IPv4 seulement** : rien sur `net.ipv6.conf.*.forwarding`.
- **Retour arrière** : `sonde-secours` (minuterie 60 s) vérifie `ip_forward`, la table nft et un `ping 1.1.1.1` ; au 3ᵉ échec
  consécutif, `OnFailure=` lance `pseudo-routeur-retour.service` → `freeboxctl passerelle-dhcp 192.168.1.254`.
  `activer` refuse sans sonde active.

### 10.2 Risques sur un LAN de production (gk2 = production : **jamais d'activation par un agent**)

- **Portée** : la bascule touche tout le foyer (visio gk1, voicestudio gk3, téléphones), pas seulement les TV.
- **Retour lent** : le retour change le réglage DHCP, mais chaque client garde gk2 comme passerelle jusqu'au renouvellement
  de son bail (souvent la moitié de sa durée, des heures). Les « < 3 min » du paquet sont le délai de **décision**, pas de
  rétablissement. Si gk2 tombe, le foyer est sans Internet pendant ce temps.
- **Routage asymétrique** : sur le /24 plat, la Freebox répond directement aux clients ; gk2 ne voit que le sens montant.
  nDPI classe moins bien (le ClientHello TLS reste lisible, donc le SNI aussi) ; conntrack voit des flux à moitié.
- **IPv6 hors champ** : les TV Android parlent surtout IPv6 ; les annonces RA viennent de la Freebox, le trafic IPv6 ne passe
  pas par gk2. La redirection DNS (§ 11) et le DPI ne couvrent alors que l'IPv4.
- **Charge** : tout le trafic du foyer traverse un gk2 déjà à 85-95 % de CPU par moments.
- **WAN mvpp2** : jamais de MTU ni de down/up d'interface à distance (gk1 perdu le 2026-10-26).

### 10.3 Ce qu'il faut pour les seules TV du périmètre

Le paquet ne sait faire que « tout le LAN ». Trois pistes pour limiter aux TV, par ordre de préférence :

1. **Passerelle fixée sur la TV** (réglage réseau manuel de la TV : IP fixe, passerelle 192.168.1.200, DNS 192.168.1.200).
   Aucun changement Freebox, retour immédiat en remettant la TV en DHCP. Côté gk2 : `ip_forward=1` et la chaîne
   `forward` du pseudo-routeur restreinte à `ether saddr @sbx_tv_perimetre` (nouvel ensemble alimenté par ad-guard) —
   **à développer** dans `secubox-pseudo-routeur` 0.2 (verbe `activer-transfert --tv-seulement`, sans bascule DHCP).
2. **Bail DHCP par appareil** servi par gk2 : impossible proprement tant que la Freebox sert le DHCP (deux serveurs sur le
   même segment). Écarté.
3. **Proxy ARP / usurpation ARP** pour les seules TV : contraire au cadre (modification du chemin à l'insu des appareils),
   fragile. Écarté.

### 10.4 Comparaison

| Option | Voit | Coût / risque | Retour arrière | Verdict |
|---|---|---|---|---|
| Pseudo-routeur, tout le LAN | IPv4 montant de tout le foyer | élevé (portée, baux, CPU) | lent (baux) | non pour la production |
| Pseudo-routeur, passerelle fixée sur la TV | IPv4 montant de la TV ; DNS forcé effectif | faible (une TV) | immédiat (TV en DHCP) | **recommandé pour l'essai** |
| Port miroir du commutateur | les deux sens, IPv4 + IPv6 | nul sur le chemin ; commutateur administrable requis ; DPI seulement (aucune redirection possible) | débrancher | meilleur pour le DPI |
| TV banc derrière gk2 (zone dédiée) | tout, deux sens, v4 + v6 | nul pour le foyer | rebrancher | idéal au banc, pas chez l'utilisateur |

### 10.5 Procédure d'essai (avec le propriétaire, hors heures d'usage, jamais par un agent seul)

1. Préalables : `df -h /` sur gk2 ; `dpkg -l secubox-ad-guard secubox-toolbox-ng secubox-ndpid-engine` aux versions du lot 4 ;
   la TV banc (pas une TV du foyer) déclarée dans TV Privacy, en OBSERVE.
2. Relever la référence : 10 min de lecture OQEE ; onglet « Applications » = « DNS seulement » (attendu).
3. Côté gk2 : `sysctl net.ipv4.ip_forward` (noter la valeur ; gk2 transfère peut-être déjà pour les LXC et WireGuard).
   Installer `secubox-pseudo-routeur` 0.2 **depuis le dépôt apt** (source d'abord, jamais d'édition à chaud) et lancer
   `pseudo-routeurctl activer-transfert --tv-seulement` avec la MAC de la TV banc. **Attention** : la table du pseudo-routeur 0.1
   est en `policy drop` sur `forward` ; posée telle quelle, elle couperait les LXC et WireGuard de gk2. La 0.2 doit limiter sa chaîne
   à `ether saddr @sbx_tv_perimetre` sans changer la politique des autres flux (test de paquet exigé). Vérifier
   `nft list table inet secubox_pseudo_routeur` puis qu'un LXC (ex. roundcube) répond toujours.
4. Sur la TV banc : IP fixe, passerelle et DNS = 192.168.1.200. Vérifier qu'elle lit une vidéo.
5. Attendre 2 min : onglet « Applications » = « DNS + DPI », applications nDPI visibles ; `pidstat 5` sur nDPId, nDPIsrvd,
   sbxdpi pendant 30 min de lecture (budget § 3.7).
6. Passer la TV banc en AUTO : vérifier la redirection DNS (`nft list table inet secubox_adguard_contournement`, compteurs qui
   montent) ; essayer un résolveur tiers sur la TV (8.8.8.8) : la résolution doit passer par Unbound.
7. Essai OBSERVE / AUTO du lot 7 avec la frise des coupures.
8. Retour : TV en DHCP ; retirer la chaîne ; remettre `ip_forward` à sa valeur de l'étape 3 ; contrôler que le foyer n'a
   rien vu (aucun autre client n'a changé de passerelle).
9. Critère d'arrêt immédiat à toute étape : lecture cassée, charge gk2 > 4 sur 5 min, DNS du foyer lent, garde de charge
   déclenchée (onglet « Applications » : « DPI ARRÊTÉ »). Après l'essai : vérifier que `secubox-ndpid-engine` tourne (sinon reprise
   manuelle depuis l'onglet) et que `/ndpid/` montre tout le trafic.
10. Déploiement : la table `inet secubox_adguard_contournement` est chargée dès l'installation pour toute TV en PROTECT/AUTO, même
   sur le LAN plat (inerte). Un fichier de `/etc/nftables.d` qui ne se charge plus ferait échouer `nftables.service` : le contrôleur
   le revalide (`nft -c`) à chaque application et le retire s'il est invalide (audit `contournement-invalide`).

## 11. Contournement : afficher et forcer le DNS

- **Portée** : appareils du périmètre **en PROTECT ou AUTO effectif** (pause comprise : un appareil en pause est en OBSERVE)
  et qui ont une MAC. **Rien n'est appliqué à un appareil en OBSERVE ou OFF.** « Je débloque » et la pause passent par
  `apply`, qui régénère le jeu de règles : la redirection et les blocages sont levés en même temps que le filtrage DNS.
- **Limite écrite noir sur blanc** : ces règles ne s'appliquent **qu'au trafic qui traverse gk2**. Sur le LAN plat (passerelle
  Freebox), une TV qui interroge 8.8.8.8 ne passe pas par gk2 : rien n'est redirigé. Seul le mode LAN (§ 10) les rend
  effectives. L'onglet l'affiche (« forçage DNS : posé, effectif seulement si la TV passe par gk2 »).
- **Règles** (table `inet secubox_adguard_contournement`, nftables uniquement) :
  - `prerouting` nat (dstnat) : `ether saddr @sbx_tv_force udp/tcp dport 53 redirect to :53` (vers l'Unbound local, IPv4 et IPv6) ;
  - `forward` filter : `ether saddr @sbx_tv_force tcp dport 853 reject`, `udp dport 853 reject` (DoT, DoQ) ;
    `ip daddr @sbx_doh_v4 tcp dport 443 reject`, `ip6 daddr @sbx_doh_v6 tcp dport 443 reject`, idem UDP 443 (DoH/HTTP3)
    vers la liste livrée `lists/resolveurs-doh.txt` (adresses IP de résolveurs DoH publics, source citée par ligne) ;
  - compteurs nommés par règle (lus pour l'onglet).
- **Jamais une catégorie protégée, jamais le DRM** : on ne bloque que des **adresses de résolveurs DNS** et le port 853 ; aucun
  domaine de contenu, de CDN ni de DRM n'est concerné. Le port 53 est redirigé vers le résolveur de la box, qui laisse passer
  les catégories protégées comme aujourd'hui.
- **Verbe root borné** : `secubox-adguard-tv apply` (et `regles-appliquer` quand il recharge) reconstruit le jeu de règles à
  partir de l'état revalidé ; rien n'est lu en clair depuis l'API. **Double tampon** : fichier fantôme
  `/var/lib/secubox-adguard-tv/contournement.nft.new`, contrôle `nft -c -f`, échange atomique, `nft -f` ; si le chargement
  échoue, la version précédente est rechargée (retour arrière). **La commande n'échoue pas** : le filtrage DNS prime ; le refus est
  audité (`contournement-refuse`, `contournement-retour`), publié (`contournement-resultat.json`) et **affiché dans la page**
  (« Forçage DNS refusé par nftables »). Un fichier en place que `nft -c` refuse est retiré (`contournement-invalide`).
  `disable` retire la table ; un échec du retrait est audité (`contournement-retrait-echec`).
  Chaque changement écrit `contournement` dans `audit.log` (appareils forcés, nombre d'adresses DoH).
- **Retour arrière si la lecture casse** : le moteur AUTO surveille déjà « contenu habituel plus demandé ». Au lot 4, si ce
  signal se déclenche pour un appareil dont le forçage a été posé depuis moins de 24 h, le forçage est suspendu pour cet appareil
  (`contournement_suspendu` dans l'état, horodaté, 24 h), journalisé et audité ; l'administrateur peut le relever.

## 12. Questions ouvertes restantes

1. **Essai du mode LAN** : préférez-vous la passerelle fixée sur la TV banc (recommandé, § 10.3-1, demande pseudo-routeur 0.2)
   ou un port miroir (DPI seulement, sans forçage DNS) ? Cela décide si `secubox-pseudo-routeur` 0.2 est construit.
2. **IPv6** : sur LAN plat, le forçage DNS ne couvre que l'IPv4 même en mode LAN. Faut-il, pour une TV du périmètre, proposer
   plus tard de couper son IPv6 (au prix de sa connectivité v6) ?

## 13. Réalisation (2026-11-01) et écarts

Livré dans le worktree #3374 : `secubox-ad-guard` 1.21.0, `secubox-toolbox-ng` 0.14.0 (sbxdpi), `secubox-ndpid-engine` 1.7.4. Rien déployé.

- Écarts assumés : `POST /protection/dpi/perimetre` non construit (choix par défaut fixé : seules les TV, par MAC) ; un forçage refusé par
  `nft -c` ou au chargement est audité et rendu (`contournement: refuse|retour`) **sans** faire échouer l'application du DNS (le filtrage DNS
  prime) ; « nouveau » pour la corrélation = non demandé dans les 10 min précédant la coupure (pas 30 jours) ; les constats « sans DNS » se
  fondent sur les réponses du cache d'Unbound de toute la maison (24 h), pas par appareil.
- **Arbitrage du 2026-11-01 (remplace § 3.2)** : aucun filtre de capture dans nDPId (il aurait réduit toute la capture aux TV et cassé
  la carte DPI du Hall et `/ndpid/`). nDPId garde sa capture complète ; le tri par appareil se fait **uniquement dans sbxdpi** (cibles
  écrites par `dpi-cibles`, qui ne pose plus que ce fichier). L'option `-B` sort du lot. Bridage conservé : `Nice=10` et `CPUQuota=40%`
  (et non 25 %) : aucune mesure de nDPId sur gk2 n'existe, nDPId est mono-fil et capture tout le LAN ; un plafond trop bas ferait perdre
  des paquets à pcap et dégraderait `/ndpid/`. À confirmer par la mesure T9 (`pidstat` de nDPId, pertes pcap).
- Garde de charge : arrêt seulement après **5 minutes** de saturation continue (charge à 5 min > nombre de cœurs) ; elle arrête **tout** le
  DPI de la box, ce que la page annonce (« DPI ARRÊTÉ pour toute la box (Hall, /ndpid/ compris) ») et que `audit.log` trace ; reprise
  manuelle.
- `secubox-pseudo-routeur` 0.2 (`activer-transfert --tv-seulement`, § 10.3) : non construit, en attente de la question 1 du § 12.

### Passe 2 (relectures du 2026-11-01)

Corrigé, chaque fois avec un test rouge d'abord (rapport) :
- **B1** `dpi-appareils.db` bornée à 20 Mio (`auto_vacuum=INCREMENTAL`, purge des plus anciennes minutes puis `incremental_vacuum`),
  testée avec 400 000 lignes conntrack. **B2** `imasdk.googleapis.com` en STREAMING (protégé, #2146) ; test de non-régression.
- **I1** verrou ≠ corruption ; API en lecture seule (`mode=ro`) ; `quick_check` une fois par heure côté moteur. **I2** garde de charge
  à état unique sous verrou, reprise jamais écrasée, garde réarmée. **I3** corrélation linéaire (bissection) et incrémentale (curseur
  par MAC, horodatage de la dernière coupure close), faite une seule fois dans `passage` ; `tick` reçoit les découvertes
  (50 000 événements, 500 coupures : 0,054 s sur x86). **I4** 5 min + part CPU de nDPId ≥ 20 %. **S1** root revérifie, audit du code
  réel, pause affichée seulement si l'arrêt a réussi. **S2** cibles dans `/run/secubox/sbxdpi-cibles/` (0750 root:secubox-toolbox,
  fichier 0640), sbxdpi refuse un fichier non root et vérifie la taille avant lecture.
- m1 mémoire de 24 h dans les cibles ; m2 clé avec adresse locale et protocole ; m3 frise sur toutes les adresses de la MAC ; m5 fichier
  nft toujours chargeable ; m6 conntrack « indisponible » si `/proc/net/nf_conntrack` manque, lecture bornée à 5 s ; m7 purge au
  rechargement des cibles ; écritures par `mkstemp` ; échecs écrits sur stderr ou audités ; découvertes récentes d'abord.

Reportés :
- **m4** : `a_suspendre` ne vérifie pas « forçage posé depuis moins de 24 h » ; une suspension n'est appliquée au noyau qu'au prochain
  `apply`/`regles-appliquer` (la suspension pose `.a-appliquer`, donc au passage suivant du moteur).
- **Doute 4** : « nouveau » = absent des 10 min précédentes ; « sans DNS » s'appuie sur le cache d'Unbound de toute la maison (faux
  négatifs plutôt que faux positifs) — à noter dans l'onglet.
- **Doute 6** : commit `4766505fd` regroupant deux tâches (effacé par la fusion en squash).
- **Doute 7** : GET par appareil en `require_jwt` : la page relayée par le pilotage n'a que `/dpi/etat` — à écrire dans la note du
  pilotage.
