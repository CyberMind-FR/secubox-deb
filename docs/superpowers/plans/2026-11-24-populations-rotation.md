# Populations d'attaquants et campagnes à rotation — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** chaque alerte porte son réseau et son type de réseau ; un relevé « populations » alimente des listes de
campagnes lisibles (Radar SecuBox AI, page Actor) ; un détecteur déterministe bannit les campagnes web à rotation
d'adresses, avec verdict différé.

**Architecture :** un paquet Go partagé `internal/reseau` (ASN local + catalogue de classes) est branché dans `sbxwaf`,
`sbx-authwatch` et l'enveloppe actord. Le module WAF (FastAPI) calcule les populations en tâche de fond et les sert à
gk3. Un fichier JS de repères unique, copié à l'identique dans les deux pages, compose les cartes. Le détecteur de
rotation vit dans `sbxwaf` à côté du ban de campagne #2238, sans le modifier.

**Tech Stack :** Go 1.22 (vendor, `maxminddb-golang`), Python 3.13 / FastAPI / `maxminddb` / `tomllib`, JS sans
bibliothèque, Debian (`dpkg-buildpackage`), HAProxy 3.0.

**Spec :** `docs/superpowers/specs/2026-11-24-populations-rotation-design.md` (issue #3919). Les chemins ci-dessous
sont relatifs à la racine du worktree ; `TNG` = `packages/secubox-toolbox-ng`, `WAF` = `packages/secubox-waf-ng`.

## Global Constraints

- Jamais de ban, limite ou défi appliqué à un réseau ou une classe de réseau entière.
- Aucun appel réseau tiers depuis le chemin de décision : base `GeoLite2-ASN.mmdb` locale
  (`/var/lib/GeoIP/GeoLite2-ASN.mmdb`), base pays existante (`/usr/share/GeoIP/GeoLite2-Country.mmdb`).
- Base absente ou illisible = champs vides, jamais d'erreur bloquante ni de plantage.
- Un ASN absent du catalogue est `inconnu` ; `inconnu` ne compte jamais en faveur d'une campagne.
- Classes exactes : `acces`, `mobile_partage`, `hebergeur`, `proxy_loue`, `cdn`, `relais_vie_privee`,
  `scanner_recherche`, `inconnu`.
- Garde des routes lues par gk3 : `require_lecture_ai`.
- Audit des décisions de `sbxwaf` : `/var/log/secubox/waf/audit.log` (ajout seul).
- Aucun chiffre ni nom de carte ne vient du modèle ; relevé absent = « relevé indisponible », jamais un zéro inventé.
- Emoji toujours accompagné de son texte (`title`/`aria-label` + libellé visible).
- Comptes visés masqués au-delà de 3 caractères (`ger…`) ; jamais de mot de passe.
- Le dépôt est public : aucune signature d'attaquant réelle (navigateur déclaré, adresses) dans le code ni les tests ;
  tests en adresses de documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) —
  attention, Python `ipaddress` les classe « private » : pour un test qui exige une adresse publique, utiliser une
  vraie adresse publique neutre (`8.8.8.8`, `1.1.1.1`).
- Pas de modification de `common/` (imposerait de republier secubox-core).
- Version montée à chaque paquet modifié (`X.Y.Z-1~trixie1`), en-tête SPDX CMSD-1.0 sur tout fichier créé.
- Go : `cd TNG && CGO_ENABLED=0 GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local go test ./...`.
- Python : `python3 -m pytest <dossier de tests du paquet> -q`, un paquet à la fois (collision `api/`).

## Review Focus

1. Base ASN remplacée pendant la mise à jour GeoIP (fichier tronqué, absent quelques secondes) : aucun plantage, champs
   vides, réouverture au prochain chargement — test dans la tâche 1.
2. Adresses IPv6, adresse `local` (privée masquée par `Record`) et adresses mal formées dans les journaux : classées ou
   ignorées sans erreur — tests dans les tâches 1 et 5.
3. Journaux tournés et compressés, lignes tronquées ou JSON invalide, très gros volumes : le relevé ignore les lignes
   fautives et garde une mémoire bornée — tests dans la tâche 5.
4. Un vrai navigateur, ou un bureau derrière une seule adresse NAT, qui porte la signature d'une campagne établie et
   charge ses ressources : jamais banni en verdict différé — test dans la tâche 9.
5. gk3 lit `/waf/populations` alors que le cache est absent, périmé ou partiel : « relevé indisponible » ou « relevé
   partiel (date) », le reste du Radar inchangé — test dans la tâche 7.

---

## Phase 1 — Le réseau de chaque alerte

### Task 1 : paquet Go `internal/reseau` et catalogue des classes

**Files :**
- Create : `TNG/internal/reseau/reseau.go`, `TNG/internal/reseau/catalogue.go`, `TNG/internal/reseau/reseau_test.go`
- Create : `WAF/composants/waf/config/reseaux-classes.toml`

**Interfaces :**
- Produces :
  - `type Info struct { ASN uint32; Org string; Classe string }`
  - `func Ouvrir(cheminMMDB string, catalogues ...string) *Annuaire` (nil-safe : base absente → annuaire vide)
  - `func (a *Annuaire) Classer(ip string) Info` (nil-safe ; adresse invalide/privée/`local` → `Info{Classe:"inconnu"}`)
  - `func (a *Annuaire) Recharger()` (rouvre base et catalogues ; garde l'ancienne base si la nouvelle est illisible)
  - `func (a *Annuaire) Close()`
  - `func LireCatalogue(r io.Reader) (map[uint32]string, error)`
  - Constantes des 8 classes (`ClasseAcces = "acces"`, …, `ClasseInconnu = "inconnu"`).

- [ ] **Step 1 : écrire le catalogue** `reseaux-classes.toml`, format restreint (lu par Go **et** par `tomllib`) :

```toml
# SPDX… (en-tête CMSD)
# Classes de réseau par ASN (#3919). Surcharge opérateur : /etc/secubox/waf/reseaux-classes.toml (gagne ASN par ASN).
[classes]
proxy_loue = [212238, 62874, 55286, 18779, 203020, 207990, 203061, 50131]
hebergeur = [20473, 14061, 16509, 14618, 15169, 396982, 43515, 8075, 132203]
scanner_recherche = [211298, 398324]
mobile_partage = [14593]
relais_vie_privee = [13335]
acces = []
cdn = []
```

- [ ] **Step 2 : tests qui échouent** (`reseau_test.go`) :
  - `TestLireCatalogue` : le texte ci-dessus donne `m[212238]=="proxy_loue"`, `m[13335]=="relais_vie_privee"` ;
    commentaires, lignes vides, tableaux sur plusieurs lignes acceptés ; classe inconnue → erreur ; ASN non numérique → erreur.
  - `TestSurchargeOperateur` : `Ouvrir("", livre, operateur)` où l'opérateur met `20473` en `acces` → `acces` gagne.
  - `TestClasserSansBase` : `Ouvrir("/inexistant")` puis `Classer("8.8.8.8")` → `Info{Classe:"inconnu"}`, pas de panique ;
    `(*Annuaire)(nil).Classer(...)` → idem.
  - `TestClasserAdressesSpeciales` : `"local"`, `""`, `"pas-une-ip"`, `"10.0.0.1"`, `"::1"` → `inconnu`, ASN 0.
  - `TestRechargerBaseTronquee` : base valide chargée (utiliser `testdata/GeoLite2-ASN-Test.mmdb` du vendor
    `maxminddb-golang` s'il existe, sinon un test marqué `t.Skip` documenté), puis fichier remplacé par 10 octets →
    `Recharger()` garde l'ancienne base et `Classer` répond comme avant.
- [ ] **Step 3 : vérifier l'échec** — `go test ./internal/reseau/` → FAIL (paquet inexistant).
- [ ] **Step 4 : implémenter** `reseau.go` (même patron que `cmd/sbxwaf/geo.go` : `maxminddb.Open`, `sync.RWMutex`,
  lookup `autonomous_system_number` / `autonomous_system_organization`) et `catalogue.go` (analyseur ligne à ligne
  du sous-ensemble ci-dessus, sans dépendance nouvelle).
- [ ] **Step 5 : vérifier** — `go test ./internal/reseau/ -v` → PASS ; `go vet ./internal/reseau/` propre.
- [ ] **Step 6 : commit** — `feat(reseau): annuaire ASN local et catalogue de classes de réseau (ref #3919)`.

### Task 2 : `sbxwaf` pose le réseau sur ses alertes et dans l'enveloppe

**Files :**
- Modify : `TNG/cmd/sbxwaf/threatlog.go` (`logEntry` l.170, `entryToEnvelope` l.136, `Record` l.244, setter à côté de `SetGeo`)
- Modify : `TNG/cmd/sbxwaf/main.go` (flags près de l.1347, câblage près de l.1550)
- Test : `TNG/cmd/sbxwaf/reseau_threatlog_test.go`

**Interfaces :**
- Consumes : `reseau.Ouvrir`, `(*Annuaire).Classer` (tâche 1).
- Produces :
  - champs JSON de `logEntry` : `asn` (`uint32,omitempty`), `asn_org` (`string,omitempty`), `reseau_classe` (`string,omitempty`)
  - `func (l *ThreatLog) SetReseau(a *reseau.Annuaire)`
  - flags `--geoip-asn` (défaut `/var/lib/GeoIP/GeoLite2-ASN.mmdb`) et `--reseaux-classes` (défaut
    `/usr/share/secubox/waf/reseaux-classes.toml,/etc/secubox/waf/reseaux-classes.toml`, liste séparée par virgules).

- [ ] **Step 1 : tests qui échouent** :
  - `TestRecordPoseLeReseau` : un `ThreatLog` avec un annuaire factice (interface locale `classeur` que `*reseau.Annuaire`
    satisfait) qui classe `8.8.8.8` en `{15169,"GOOGLE","hebergeur"}` ; après `Record`, la ligne JSON écrite contient
    `"asn":15169,"asn_org":"GOOGLE","reseau_classe":"hebergeur"`, et l'enveloppe émise a `ASN == 15169`.
  - `TestRecordSansAnnuaire` : sans `SetReseau`, la ligne ne contient aucune des trois clés (omitempty) et rien ne plante.
  - `TestRecordAdresseLocale` : `ClientIP` privée → ligne `client_ip:"local"`, aucune clé réseau.
- [ ] **Step 2 : vérifier l'échec** — `go test ./cmd/sbxwaf/ -run 'TestRecord(PoseLeReseau|SansAnnuaire|AdresseLocale)'` → FAIL.
- [ ] **Step 3 : implémenter.** L'annuaire est construit **indépendamment** de `--actor-socket` (contrairement à `Geo`),
  rechargé à chaque `SIGHUP` existant s'il y en a un, sinon toutes les 24 h par un ticker. Classer avec l'adresse
  **avant** masquage en `local`.
- [ ] **Step 4 : vérifier** — `go test ./cmd/sbxwaf/` → PASS (toute la suite).
- [ ] **Step 5 : commit** — `feat(sbxwaf): réseau et classe de réseau sur chaque alerte et dans l'enveloppe actord (ref #3919)`.

### Task 3 : `sbx-authwatch` pose le réseau et publie l'état de ses campagnes

**Files :**
- Modify : `TNG/cmd/sbx-authwatch/menaces.go` (`entreeMenace` l.35, `Inscrit` l.75)
- Modify : `TNG/cmd/sbx-authwatch/campagne.go` (ajout d'une méthode d'état)
- Modify : `TNG/cmd/sbx-authwatch/main.go` (flags)
- Test : `TNG/cmd/sbx-authwatch/reseau_test.go`, `TNG/cmd/sbx-authwatch/campagne_etat_test.go`

**Interfaces :**
- Consumes : `reseau.Ouvrir`, `Classer` (tâche 1).
- Produces :
  - mêmes champs JSON `asn`, `asn_org`, `reseau_classe` sur `entreeMenace`, plus `campagne` (`string,omitempty`,
    identifiant = 8 premiers hex du SHA-256 du compte visé en minuscules)
  - `type EtatCampagne struct { ID string \`json:"id"\`; Compte string \`json:"compte"\`; Sources int \`json:"sources"\`; Premier int64 \`json:"premier"\`; Dernier int64 \`json:"dernier"\` }`
  - `func (c *Campagnes) Etat(maintenant time.Time) []EtatCampagne` (uniquement les campagnes établies, compte masqué)
  - `func masquerCompte(c string) string` (`"gerald@gk2.net"` → `"ger…"` ; ≤ 3 caractères → `"…"`)
  - flags `--geoip-asn`, `--reseaux-classes` (mêmes défauts que tâche 2), `--campagnes-etat`
    (défaut `/run/secubox/authwatch-campagnes.json`), écrit toutes les 60 s par renommage atomique.

- [ ] **Step 1 : tests qui échouent** :
  - `TestInscritPoseLeReseau` : `Inscrit` avec une source `8.8.8.8` et un annuaire factice → clés réseau présentes.
  - `TestEtatSeulementCampagnesEtablies` : `NewCampagnes(time.Hour, 3)` ; compte A vu de 3 sources, compte B de 2 →
    `Etat` renvoie un seul élément, `Compte=="ger…"` pour `gerald@exemple.test`, `Sources==3`.
  - `TestMasquerCompte` : `"gerald@gk2.net"`→`"ger…"`, `"ab"`→`"…"`, `""`→`"…"`.
  - `TestEtatEcritAtomique` : l'écriture passe par un fichier temporaire puis `os.Rename` ; le fichier final est un
    tableau JSON valide.
- [ ] **Step 2 : vérifier l'échec** — `go test ./cmd/sbx-authwatch/` → FAIL.
- [ ] **Step 3 : implémenter.** Le comportement de ban SMTP/SSH existant ne change pas (tous les tests existants passent).
- [ ] **Step 4 : vérifier** — `go test ./cmd/sbx-authwatch/` → PASS.
- [ ] **Step 5 : commit** — `feat(authwatch): réseau sur les alertes, état des campagnes par compte visé (ref #3919)`.

### Task 4 : actord enrichit `/campaigns`

**Files :**
- Modify : `TNG/cmd/sbx-actord/api.go` (struct `campagne` l.269, `campagnes()` l.298), `TNG/cmd/sbx-actord/vue.go`
  (`campagneReduite` l.127)
- Create : `TNG/internal/reseau/famille.go` (+ test dans `reseau_test.go`)
- Test : `TNG/cmd/sbx-actord/campagnes_enrichies_test.go`

**Interfaces :**
- Consumes : enveloppes portant `ASN` (tâche 2) ; `reseau` pour la classe (actord ouvre son propre annuaire, mêmes flags
  `--geoip-asn`/`--reseaux-classes`).
- Produces :
  - `func Famille(categorie string) string` dans `internal/reseau` — table : `auth_smtp*`→`messagerie` ;
    `auth_ssh*`, `leurre*`→`acces_distant` ; `aspirateur_ua`, `recon_crawler`, `robots`→`collecte` ;
    `scanners`, `honeypot`, `lfi`, `api_abuse`, `waf_fingerprint`, `host_anomaly:*`→`balayage_web` ;
    `rotation:*`→`collecte` ; sinon `autre`. Même table recopiée en Python (tâche 5), testée sur les mêmes cas.
  - champs ajoutés à `campagne` (aucun retiré) : `famille string`, `cibles_noms []string` (3 max, comptes masqués via
    `masquerCompte` — déplacer cette fonction dans `internal/reseau` et l'utiliser depuis authwatch),
    `classes map[string]int` (pourcentages entiers des sources par classe), `pays_top []PaysPart`
    (`{code string; part int}`, 3 max), `une int` et `le3 int` (part en % des sources à 1 et à ≤ 3 événements),
    `rotation bool` (`le3 >= 80 && sources >= 50`).
  - vue réduite : mêmes nouveaux champs **sauf** `cibles_noms`.

- [ ] **Step 1 : tests qui échouent** :
  - `TestFamille` (dans `internal/reseau`) : les 12 cas de la table ci-dessus + `"inconnue"`→`"autre"`.
  - `TestCampagneEnrichie` : un serveur actord de test alimenté de 60 enveloppes (60 sources distinctes, 1 événement
    chacune, ASN 212238 pour 50 d'entre elles, pays `US`×40/`GB`×20, catégorie `aspirateur_ua`, vhost `forge.exemple.test`)
    → la campagne a `famille=="collecte"`, `cibles_noms==["forge.exemple.test"]`, `classes["proxy_loue"]==83`,
    `pays_top[0]=={"US",67}`, `une==100`, `rotation==true`.
  - `TestVueReduiteSansCiblesNoms` : la vue réduite n'a pas la clé `cibles_noms`.
- [ ] **Step 2 : vérifier l'échec** — `go test ./internal/reseau/ ./cmd/sbx-actord/` → FAIL.
- [ ] **Step 3 : implémenter.** Calculer à partir des événements déjà conservés par actord pour chaque acteur membre ;
  si une donnée manque (enveloppes antérieures sans ASN), la classe est `inconnu` et le pays est ignoré.
- [ ] **Step 4 : vérifier** — `go test ./...` → PASS.
- [ ] **Step 5 : commit** — `feat(actord): campagnes enrichies (famille, cibles, classes, pays, rotation) (ref #3919)`.

## Phase 2 — Relevé populations et listes lisibles

### Task 5 : relevé « populations » du module WAF

**Files :**
- Create : `WAF/composants/waf/api/populations.py`
- Modify : `WAF/composants/waf/api/main.py` (route près de `/campaigns` l.1094, boucle `_warm_loop`, constante de cache près de l.92)
- Test : `WAF/composants/waf/tests/test_populations_3919.py`

**Interfaces :**
- Consumes : lignes de `waf-threats.log*` portant `asn`/`asn_org`/`reseau_classe` (tâches 2-3) ;
  `/run/secubox/authwatch-campagnes.json` (tâche 3) ; `CAMPAIGNS_FILE` existant ;
  `/var/lib/secubox/waf/rotation-etat.json` (tâche 9, absent avant).
- Produces :
  - `FAMILLE` : même table que `reseau.Famille`, fonction `famille(categorie: str) -> str`.
  - `def calculer(lignes: Iterable[str], maintenant: float, pays: Callable[[str], str], classer: Callable[[str], tuple[int, str, str]], campagnes_smtp: list, campagnes_profileur: list, rotation: list) -> dict`
  - `def lignes_du_journal(dossier: str, jours: int = 7) -> Iterator[str]` (lit `.log`, `.log.N`, `.log.N.gz`)
  - `def ecrire_cache(chemin: str, releve: dict) -> bool` (double tampon : n'écrase pas un relevé `complet: True` par
    un relevé `complet: False` de moins de 1 h) ; `def lire_cache(chemin: str) -> dict | None`
  - Route `GET /populations`, garde `require_lecture_ai`, renvoie le cache + `age_s`, ou
    `{"disponible": False}` si absent.
  - Forme du relevé :
    `{"genere_le", "complet", "fenetre_jours": 7, "populations": [{"id" /* stable : famille:<famille> | rotation:<8 hex> | profileur:<signature> */, "famille", "nom_cible", "cibles": [...3], "adresses", "reseaux", "une", "le3", "classes": {classe: %}, "pays_top": [[code, %]...3], "reseaux_top": [{"asn","org","classe","adresses"}...5], "serie": [7 entiers, J-6→J], "bans", "premier", "dernier", "rotation": bool, "etat": "bannie"|"observee"|"inactive", "campagne_actord": str|None, "cves": [identifiants CVE des filtres ia_filtres_* déclenchés par les adresses de la population, 20 max]}], "recouvrement": {"adresses_communes": int, "adresses_total": int}}`
  - Règles de population (spec 5.3) : campagne de rotation (tâche 9) = sa population ; campagnes SMTP réunies dans
    `messagerie` (comptes masqués dans `cibles`) ; campagne du profileur ≥ 10 adresses = sa population, sinon sa
    famille ; reste par famille ; `autre` exclu de la liste.
  - **Rapprochement actord** (choix de plan, écart assumé à la spec qui disait « ≥ 50 % des adresses » : actord expose
    des acteurs, pas leurs adresses) : une population reçoit `campagne_actord` = signature de la campagne d'actord de
    même `famille` dont `cibles_noms` contient sa cible principale ; lecture de `/campaigns` sur `/run/secubox/actor.sock`
    (vue complète), une fois par calcul ; actord absent → `None`.
  - Classes recalculées côté Python avec `maxminddb` + `tomllib` (mêmes chemins que les flags Go) pour les lignes
    antérieures sans `reseau_classe`.

- [ ] **Step 1 : tests qui échouent** (`test_populations_3919.py`, `sys.path.insert` comme `test_historique.py`) :
  - `test_famille_table` : mêmes 13 cas que `TestFamille`.
  - `test_rotation_collecte` : 60 lignes `aspirateur_ua` de 60 adresses publiques neutres générées
    (`f"8.{i}.0.1"`), classées `proxy_loue` → une population `famille=="collecte"`, `adresses==60`, `une==100`,
    `rotation is True`.
  - `test_messagerie_reunie` : deux campagnes SMTP (comptes `ger…`, `adm…`) + lignes `auth_smtp:sasl_failed` →
    **une** population `messagerie` avec `cibles==["ger…","adm…"]`.
  - `test_lignes_fautives` : lignes vides, JSON tronqué, `client_ip:"local"`, IPv6 `2606:4700::1` → aucune exception ;
    `local` ignoré ; IPv6 comptée.
  - `test_serie_7_jours` : lignes datées J-6…J → `serie` de longueur 7 dans l'ordre.
  - `test_id_stable` : deux calculs successifs sur les mêmes lignes donnent les mêmes `id` (`famille:collecte`, …).
  - `test_cves_population` : une adresse de la population collecte déclenche `ia_filtres_critique` avec un `rule_id`
    contenant `CVE-2026-0001` → `cves == ["CVE-2026-0001"]` sur cette population.
  - `test_acl_datascope` : documenté plutôt que testé ici — le cache doit rester lisible par le groupe
    `secubox-datascope` (tâche 12 pose l'ACL dans le postinst).
  - `test_recouvrement` : 2 adresses communes à deux familles → `adresses_communes==2`.
  - `test_double_tampon` : un relevé complet écrit puis un partiel 10 min après → le fichier garde le complet ;
    2 h après → le partiel remplace.
  - `test_route_sans_cache` : `TestClient(app)` avec cache absent → 200 `{"disponible": False}` ; garde
    `require_lecture_ai` présente sur la route (introspection des dépendances, comme les tests existants du module).
- [ ] **Step 2 : vérifier l'échec** — `python3 -m pytest WAF/composants/waf/tests/test_populations_3919.py -q` → FAIL.
- [ ] **Step 3 : implémenter.** Calcul dans `asyncio.to_thread` toutes les 10 min dans `_warm_loop`, lecture en flux
  (pas de chargement du journal en mémoire), compteurs bornés (au plus 200 000 adresses suivies ; au-delà, le relevé
  est marqué `complet: False`). Cache : `/var/cache/secubox/waf/populations.json`.
- [ ] **Step 4 : vérifier** — `python3 -m pytest WAF/composants/waf/tests -q` → PASS (toute la suite du module).
- [ ] **Step 5 : commit** — `feat(waf): relevé populations d'attaquants, servi à gk3 (ref #3919)`.

### Task 6 : repères partagés des cartes de campagne

**Files :**
- Create : `WAF/www/actor/reperes.js`, `packages/secubox-ai/www/ai/reperes.js` (copie **identique**)
- Create : `packages/secubox-ai/tests/test_reperes_3919.py`, `packages/secubox-ai/tests/reperes_3919.test.mjs`
- Modify : `WAF/debian/rules` (installer `reperes.js` à côté de `www/actor/index.html`, l.192-194),
  `packages/secubox-ai/debian/rules` (à côté de `www/ai/index.html`, l.44)

**Interfaces :**
- Produces (global `window.SbxReperes`, sans module ES) :
  - `CLASSES` : `{proxy_loue:["🔁","proxy loué"], hebergeur:["🏢","hébergeur / cloud"], acces:["🏠","accès grand public"], mobile_partage:["🛰️","mobile ou satellite"], cdn:["🌐","CDN"], relais_vie_privee:["🕶️","relais de vie privée"], scanner_recherche:["🔬","scanner de recherche"], inconnu:["❔","inconnu"]}`
  - `FAMILLES` : `{collecte:["📚","Collecte"], messagerie:["✉️","Mots de passe sur la messagerie"], acces_distant:["🚪","Balayage des leurres de service"], balayage_web:["🕷️","Balayage des sites web"], autre:["❔","Autre activité"]}`
  - `ETATS` : `{rotation:["🌀","rotation"], bannie:["🛑","bannie"], observee:["👁️","observée"], inactive:["💤","inactive"]}`
  - `drapeau(code: string): string` (indicateurs régionaux ; code invalide → `"🏳️"`)
  - `nomCarte(famille: string, cibles: string[]): string` — `collecte` + `["gitea.gk2.secubox.in"]` →
    `"Collecte : gitea.gk2"` (suffixe `.secubox.in` retiré) ; `messagerie` → libellé de famille seul ; sans cible →
    libellé de famille.
  - `puce(doc, [emoji, libelle], suffixe?): HTMLElement` — `<span class="puce" title="libelle" aria-label="libelle suffixe">emoji libelle suffixe</span>`
- [ ] **Step 1 : tests qui échouent** :
  - `test_copies_identiques` (Python) : les deux fichiers ont le même contenu octet pour octet.
  - `reperes_3919.test.mjs` (`node --test`, charge le fichier dans un `vm` avec un `window` factice) :
    `drapeau("FR")==="🇫🇷"`, `drapeau("x1")==="🏳️"`, `nomCarte("collecte",["gitea.gk2.secubox.in"])==="Collecte : gitea.gk2"`,
    `nomCarte("messagerie",["ger…"])==="Mots de passe sur la messagerie"`, 8 classes et 5 familles présentes, chaque
    entrée a un libellé non vide.
  - `test_reperes_node` (Python) : lance `node --test tests/reperes_3919.test.mjs` si `node` existe, sinon `skip`.
- [ ] **Step 2 : vérifier l'échec** — `python3 -m pytest packages/secubox-ai/tests/test_reperes_3919.py -q` → FAIL.
- [ ] **Step 3 : implémenter** `reperes.js`, puis copier dans secubox-ai.
- [ ] **Step 4 : vérifier** — PASS.
- [ ] **Step 5 : commit** — `feat(www): repères partagés des cartes de campagne (ref #3919)`.

### Task 7 : liste « Campagnes » du Radar SecuBox AI

**Files :**
- Modify : `packages/secubox-ai/api/menaces.py` (`CHEMINS` l.43, `releve_menaces` l.166)
- Modify : `packages/secubox-ai/www/ai/index.html` (`rCampagnes` l.1087, carte l.275, chargement de `reperes.js`,
  données de démonstration)
- Test : `packages/secubox-ai/tests/test_populations_radar_3919.py`

**Interfaces :**
- Consumes : route `/waf/populations` (tâche 5) ; `window.SbxReperes` (tâche 6).
- Produces : `releve["populations"]` = la liste `populations` du relevé gk2, ou `None` si la source manque ;
  `releve["populations_meta"] = {"complet", "genere_le", "age_s", "recouvrement"}`.

- [ ] **Step 1 : tests qui échouent** (fixtures de `test_menaces_3583` / `test_radar_3811`) :
  - `test_chemins_populations_en_dernier` : `CHEMINS[-1]=="/waf/populations"` et `ESSENTIELS` inchangé (4 premiers).
  - `test_releve_avec_populations` : transport factice renvoyant un relevé de 2 populations → `releve["populations"]`
    les contient, `populations_meta["complet"] is True`.
  - `test_releve_sans_populations` : `/waf/populations` en 503 → `releve["populations"] is None`, le résumé reste
    possible (les 4 essentiels présents).
  - `test_releve_partiel` : `complet: False` → `populations_meta["complet"] is False`.
- [ ] **Step 2 : vérifier l'échec** — `python3 -m pytest packages/secubox-ai/tests/test_populations_radar_3919.py -q` → FAIL.
- [ ] **Step 3 : implémenter** `menaces.py`, puis réécrire `rCampagnes(r)` : carte « Campagnes et populations » en
  pleine largeur de la colonne centrale ; une carte par population triée par activité des dernières 24 h (dernier
  élément de `serie`), 6 visibles, le reste sous « autres populations » ; contenu de chaque carte exactement comme la
  maquette publiée (`https://claude.ai/artifact/UCsm4akYd6LkBGmMST7THM`) : titre `FAMILLES` + `nomCarte`, puces d'état,
  ligne de chiffres, barre de classes, puces de classes, puces de pays, cible, mini-série 7 j, détail repliable des 5
  réseaux, pied « recouvrement ». `populations === null` → `rNR(z, 'relevé indisponible')` ; `complet === false` →
  bandeau « relevé partiel (date) ». Styles via les tokens existants du Radar. Le mode démonstration fournit 3
  populations fictives en adresses de documentation.
- [ ] **Step 4 : vérifier** — `python3 -m pytest packages/secubox-ai/tests -q` → PASS ; ouvrir la page en mode
  démonstration (comme les autres tests visuels du Radar) et vérifier à 400 px de large : aucune barre horizontale de
  la page, emojis tous suivis de leur texte.
- [ ] **Step 5 : commit** — `feat(ai): liste des campagnes du Radar en populations lisibles (ref #3919)`.

### Task 8 : liste « Campagnes » de la page Actor

**Files :**
- Modify : `WAF/www/actor/index.html` (`rendCampagnes` l.373, chargement de `reperes.js`, démo l.~501)
- Test : `WAF/tests/test_actor_campagnes_3919.py`

**Interfaces :**
- Consumes : champs de `/api/v1/actor/campaigns` (tâche 4) ; `window.SbxReperes` (tâche 6).

- [ ] **Step 1 : tests qui échouent** (dans l'esprit de `WAF/tests/test_actor_aurora_2682.py`, lecture statique du HTML) :
  - `test_reperes_charge` : `index.html` charge `reperes.js` avant le script principal.
  - `test_rend_campagnes_utilise_reperes` : `rendCampagnes` référence `SbxReperes.nomCarte` et `SbxReperes.CLASSES` ;
    la signature n'est plus le titre (elle apparaît dans le détail).
  - `test_demo_enrichie` : les campagnes de démonstration portent `famille`, `classes`, `pays_top`, `une`, `le3`, `rotation`.
- [ ] **Step 2 : vérifier l'échec** — `python3 -m pytest WAF/tests/test_actor_campagnes_3919.py -q` → FAIL.
- [ ] **Step 3 : implémenter.** La page lit aussi `/api/v1/waf/populations` ; quand une population a
  `campagne_actord` égal à la signature d'une campagne, la carte affiche « ↔ même population que « <nom> » dans le
  Radar ». Même carte que le Radar (titre, puces d'état, chiffres « N acteurs · M adresses »,
  barre et puces de classes, pays, cibles en clair, période d'activité), anneau existant conservé ; clic inchangé
  (ouvre le profil). Campagnes à une source ou inactives depuis 24 h repliées sous « autres campagnes ». Champs absents
  (actord plus ancien) → la carte retombe sur l'affichage actuel, sans erreur.
- [ ] **Step 4 : vérifier** — `python3 -m pytest WAF/tests -q` → PASS ; contrôle visuel en mode démonstration à 400 px.
- [ ] **Step 5 : commit** — `feat(actor): campagnes lisibles avec les repères partagés (ref #3919)`.

## Phase 3 — Détecteur de rotation web

### Task 9 : détecteur de rotation dans `sbxwaf`

**Files :**
- Create : `TNG/cmd/sbxwaf/rotation.go`, `TNG/cmd/sbxwaf/rotation_test.go`
- Modify : `TNG/cmd/sbxwaf/main.go` (appel après `isStatic := staticAsset(rawPath)` l.657, flags, démarrage à côté
  de `CampagneBan` l.1685)

**Interfaces :**
- Consumes : `*reseau.Annuaire` (tâche 2) ; `banneurDuree` (`BanFor`) ; `adresseProtegee`, `parseCIDRs`
  (`--actor-ban-protegees`) ; `(*Crawlers).Verifie` ; `staticAsset`.
- Produces :
  - `type Rotation struct` ; `func NewRotation(cfg RotationConfig, b banneurDuree, a classeur) *Rotation`
  - garde Tor : `RotationConfig.SortiesTor string` = fichier local de sorties Tor tenu par `secubox-ipblock` (l'exécutant
    repère son chemin dans `packages/secubox-ipblock/api/main.py`, flux des sorties Tor) ; fichier absent → garde
    inactive, signalée dans l'état (`tor_garde`) ;
  - `type RotationConfig struct { Mode string /* off|propose|auto */; Verdict string /* differe|immediat */; Fenetre time.Duration /* 1h */; Delai time.Duration /* 10s */; SeuilSources int /* 50 */; PartUneATrois int /* 80 */; PartLouee int /* 60 */; Duree time.Duration /* 24h */; MaxParHeure int /* 1500 */; MaxCampagnes int /* 10 */; MaxSignatures int /* 20000 */; Etat string; Audit string; Protegees []*net.IPNet }`
  - `func (r *Rotation) Observe(ip, ua, ja4, host string, ressource, cookie, referent bool, t time.Time)`
  - `func (r *Rotation) Tick(t time.Time)` (verdicts échus, expiration, écriture de l'état)
  - `func Signature(ua, ja4, host string) string` (SHA-256 hex de `ua+"\x00"+ja4+"\x00"+host`)
  - état JSON `/var/lib/secubox/waf/rotation-etat.json` :
    `{"genere_le", "mode", "verdict", "campagnes": [{"signature", "hote", "etablie_le", "dernier", "sources", "une", "le3", "classes": {...}, "bannies", "epargnees"}]}`
  - flags : `--rotation` (`off`), `--rotation-verdict` (`differe`), `--rotation-etat`, `--rotation-max-heure` (1500).

- [ ] **Step 1 : tests qui échouent** (adresses publiques neutres générées, signatures fictives, horloge injectée) :
  - `TestPasDeSuiviSansUA` : `ua==""` → aucune signature suivie.
  - `TestCampagneEtablie` : 50 adresses classées `proxy_loue`, 1 requête chacune sur la même signature → campagne
    établie ; 49 adresses → non établie.
  - `TestInconnuNeComptePas` : 50 adresses classées `inconnu` → non établie.
  - `TestAccesNeComptePas` : 30 `proxy_loue` + 20 `acces` (60 %) → établie ; 29 + 21 → non.
  - `TestVerdictDiffereRobot` (mode `auto`) : campagne établie, nouvelle adresse X porte la signature, aucune ressource
    ni cookie ni référent pendant 10 s → `Tick(t+11s)` appelle `BanFor(X, "rotation:<8 hex>", "high", 24h)`.
  - `TestVerdictDiffereNavigateur` : même cas mais X charge `/static/app.css` (`ressource=true`) à t+1 s → aucun ban ;
    `epargnees` incrémenté. **Couvre la Review Focus 4**, y compris une adresse unique (NAT) qui envoie la page
    puis ses ressources.
  - `TestVerdictImmediat` : `Verdict:"immediat"` → ban dès `Observe`, sans attendre.
  - `TestModePropose` : mode `propose` → campagne établie et écrite dans l'état, aucun `BanFor`.
  - `TestGardeFous` : adresse privée, adresse dans `Protegees`, robot vérifié (faux `Crawlers`) → jamais de `BanFor`.
  - `TestRelaisJamaisBanni` : adresse classée `relais_vie_privee`, et adresse présente dans la liste de sorties Tor
    (fichier injecté) → jamais de `BanFor` ; sans liste Tor, l'état porte `"tor_garde": false`.
  - `TestPlafondHoraire` : `MaxParHeure:3` → 3 bans puis plus rien dans l'heure.
  - `TestExpiration` : campagne sans nouvelle source pendant 24 h → retirée de l'état.
  - `TestMemoireBornee` : 30 000 signatures distinctes avec `MaxSignatures:20000` → jamais plus de 20 000 suivies.
  - `TestAudit` : établissement et fin écrits dans le fichier `Audit` (une ligne JSON chacun, ajout seul).
  - `TestEtatRelu` : état écrit, nouveau `Rotation` relit les campagnes actives ; état de plus de 24 h ignoré.
- [ ] **Step 2 : vérifier l'échec** — `go test ./cmd/sbxwaf/ -run 'Test.*(Rotation|Verdict|Campagne|Garde|Plafond|Expiration|Memoire|Audit|Etat|Inconnu|Acces|SansUA)'` → FAIL.
- [ ] **Step 3 : implémenter.** `Observe` est O(1), sous un seul mutex court ; aucune E/S sur le chemin de la requête
  (écriture d'état et d'audit dans `Tick`, appelé toutes les 2 s par un ticker). Le hook dans `handler()` passe
  `ressource=staticAsset(rawPath)`, `cookie=r.Header.Get("Cookie")!=""`, `referent=r.Header.Get("Referer")!=""`, et
  n'est pas appelé quand `skip` est vrai (adresse privée). Les ressources d'une adresse sont suivies par adresse (pas
  par signature) : un navigateur peut charger ses CSS avec un navigateur déclaré identique ou non.
- [ ] **Step 4 : vérifier** — `go test ./...` → PASS ; `go vet ./cmd/sbxwaf/` propre.
- [ ] **Step 5 : commit** — `feat(sbxwaf): détecteur de campagnes à rotation, verdict différé (ref #3919)`.

### Task 10 : rejeu hors ligne sur les journaux nginx

**Files :**
- Create : `TNG/cmd/sbxwaf/rotation_rejeu.go`, `TNG/cmd/sbxwaf/rotation_rejeu_test.go`
- Modify : `TNG/cmd/sbxwaf/main.go` (flag `--rotation-rejeu` qui exécute et quitte, comme le mode « corréler » existant l.1374)

**Interfaces :**
- Consumes : `NewRotation`, `Observe`, `Tick` (tâche 9).
- Produces : `func Rejouer(fichiers []string, cfg RotationConfig, a classeur, sortie io.Writer) error` — lit des
  journaux nginx au format combiné (`.log`, `.gz`), rejoue dans l'ordre chronologique avec horloge simulée, mode
  forcé `propose`, et écrit un JSON : campagnes établies (signature, hôte, heure d'établissement, sources, classes),
  adresses qui **auraient été** bannies, adresses épargnées (ressources chargées), et pour chaque campagne le délai
  entre sa première requête et son établissement.

- [ ] **Step 1 : tests qui échouent** :
  - `TestRejeuFormatCombine` : 3 lignes nginx combinées → 3 `Observe` avec IP, UA, hôte (`Host` lu dans la ligne si le
    format le porte, sinon nom du vhost tiré du nom de fichier `<vhost>_access.log`), statique détecté.
  - `TestRejeuCampagneEtDelai` : fichier synthétique de 120 lignes d'une même signature depuis 120 adresses `proxy_loue`
    sur 30 min + 50 lignes d'un navigateur réel avec ressources → 1 campagne établie, délai < 15 min, le navigateur réel
    est dans « épargnées », jamais dans « auraient été bannies ».
- [ ] **Step 2 : vérifier l'échec** — `go test ./cmd/sbxwaf/ -run TestRejeu` → FAIL.
- [ ] **Step 3 : implémenter.**
- [ ] **Step 4 : vérifier** — PASS.
- [ ] **Step 5 : commit** — `feat(sbxwaf): rejeu hors ligne du détecteur de rotation (ref #3919)`.

### Task 11 : empreinte JA4 depuis HAProxy (investigation bornée)

**Files :**
- Modify (si faisable) : `packages/secubox-haproxy/api/main.py` (gabarit près de l.1672), test
  `packages/secubox-haproxy/tests/test_generation_cfg.py`
- Modify (si faisable) : `WAF/systemd/secubox-waf-ng.service` et `WAF/conf/honeypot.conf` (`--ja4-header X-Sbx-JA4`)

- [ ] **Step 1 : vérifier sur la documentation de HAProxy 3.0** (sans toucher gk2) s'il existe un moyen de calculer
  une empreinte du ClientHello en configuration pure (récupérations `ssl_fc_cipherlist_bin`, `ssl_fc_extlist_bin`,
  `ssl_fc_eclist_bin`, `ssl_fc_ecformats_bin`, `tune.ssl.capture-buffer-size`, convertisseur `digest`).
- [ ] **Step 2 : règle de décision** — si oui : en-tête `X-Sbx-JA4` posé par HAProxy après `del-header X-Sbx-JA4`
  sur toute requête entrante, test de génération qui vérifie l'ordre `del-header` puis `set-header`, flag
  `--ja4-header X-Sbx-JA4` dans l'unité et son miroir ; sinon : ne rien modifier, consigner la raison dans la section
  « Écarts » du registre et dans le README de waf-ng. Le détecteur fonctionne dans les deux cas.
- [ ] **Step 3 : vérifier** — `python3 -m pytest packages/secubox-haproxy/tests -q` → PASS (si modifié).
- [ ] **Step 4 : commit** — `feat(haproxy): empreinte TLS transmise au WAF (ref #3919)` ou rien.

### Task 12 : unités, paquets, versions, documentation

**Files :**
- Modify : `WAF/systemd/secubox-waf-ng.service` (ExecStart l.137-155) **et** `WAF/conf/honeypot.conf` (l.31-47, miroir) :
  `--geoip-asn`, `--reseaux-classes`, `--rotation propose`, `--rotation-verdict differe`
- Modify : unité de `sbx-authwatch` et unité de `sbx-actord` (dans `WAF/systemd/`) : `--geoip-asn`, `--reseaux-classes`,
  `--campagnes-etat` (authwatch)
- Modify : `WAF/debian/changelog` (1.44.0-1~trixie1), `packages/secubox-ai/debian/changelog` (2.3.0-1~trixie1),
  `packages/secubox-toolbox-ng/debian/changelog` (0.19.0-1~trixie1) ; `WAF/debian/control` : `Recommends: geoipupdate`
  seulement si la base ASN n'est pas déjà fournie par un paquet dépendu (vérifier) ; secubox-ai : aucune dépendance
  nouvelle.
- Modify : READMEs de waf-ng et secubox-ai (route `/populations`, nouveaux champs, flags, catalogue et sa surcharge)
- Test : `WAF/tests/test_unite_miroir_3919.py`

- [ ] **Step 1 : test qui échoue** — `test_unite_miroir_3919.py` : chaque flag ajouté (`--geoip-asn`,
  `--reseaux-classes`, `--rotation`, `--rotation-verdict`) figure à la fois dans `secubox-waf-ng.service` et dans
  `honeypot.conf`, avec la même valeur ; `--rotation` vaut `propose`.
- [ ] **Step 2 : vérifier l'échec**, puis modifier unités, changelogs, READMEs.
- [ ] **Step 3 : vérifier** — `python3 -m pytest WAF/tests -q` → PASS ; `cd WAF && dpkg-buildpackage -us -uc -b -aarm64 -d`
  et `cd packages/secubox-ai && dpkg-buildpackage -us -uc -b` → paquets produits ; `dpkg-deb -c` du paquet waf-ng
  contient `usr/share/secubox/waf/reseaux-classes.toml` et `usr/share/secubox/www/actor/reperes.js`, celui de
  secubox-ai contient `usr/share/secubox/www/ai/reperes.js`.
- [ ] **Step 4 : commit** — `chore(paquets): unités, versions et docs des populations et de la rotation (ref #3919)`.

### Task 13 : déploiement et validation (contrôleur, pas un sous-agent)

Effets hors du worktree : le contrôleur l'exécute lui-même, selon les règles du projet (publier puis `apt-get install`
par `systemd-run`, sans délai ; `uptime`/`free -m` avant ; waf-ng seul dans sa transaction ; couture vérifiée après).

- [ ] Copier les `.deb` dans le bloc-notes ; publier waf-ng puis secubox-ai sur `apt.secubox.in`.
- [ ] gk2 : installer `secubox-waf-ng` seul ; vérifier `nft BAN` normaux, lignes `waf-threats.log` avec `reseau_classe`,
  `/api/v1/waf/populations` (après 10 min), `/api/v1/actor/campaigns` enrichi, `rotation-etat.json` présent en
  `propose` ; couture 200.
- [ ] Rejeu sur `/var/lib/secubox/waf/rejeu-3919/` : `sbxwaf --rotation-rejeu …` → la collecte Gitea est établie en
  moins de 15 min, aucune adresse LAN/maillage/robot vérifié/navigateur réel dans « auraient été bannies ».
- [ ] Critère 3 de la spec : comparer `/api/v1/waf/populations` à un script de référence indépendant lancé sur les
  mêmes journaux et la même fenêtre (celui de la maquette, `populations-poc.json`, est un point de départ) : écart ≤ 5 %
  sur adresses, réseaux et parts de classes.
- [ ] gk3 : installer `secubox-ai` ; le Radar affiche la liste refaite ; couper l'accès à `/waf/populations` (ou
  attendre un cache absent) affiche « relevé indisponible » sans casser le reste.
- [ ] 48 h en `propose` puis relecture de `rotation-etat.json` **par le propriétaire** ; passage en `auto` seulement
  sur son accord (modifier l'unité **et** `honeypot.conf`).
- [ ] `.claude/HISTORY.md`, `.claude/WIP.md`, issue #3919 (pas de fermeture avant déploiement + un jour sans anomalie).
