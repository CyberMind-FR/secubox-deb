<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Pilotage distant — Livraison L1 « Voir » : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** depuis le maître, voir en continu chaque box (celles du propriétaire et les box clientes Auto-Load) :
identité, mémoire, CPU, processus, services et boucles de redémarrage, paquets, profil, noms et ports exposés,
maillage, mode « mains liées », plus un relevé de performance à la demande — sans SSH, sans console, en lecture seule.

**Architecture :** un agent Go mince sur chaque box (`secubox-pilotage-agent`) ouvre seul, en sortant, un canal
HTTP en interrogation longue vers le maître, par le tunnel `wg-mesh` (box du propriétaire) ou `wg-autoload` (box
clientes) ; il n'écoute rien. Le maître porte `secubox-pilotage` : une application « canal » (côté agents, sur
socket Unix, exposée par nginx sur les seules IP de tunnel du maître, port 8472) et une application
d'administration (`/api/v1/pilotage/`, `require_jwt`). Les messages ont la forme USP (Get, GetSupportedDM, Operate
limité au relevé, Notify) et les chemins du modèle TR-181 `Device:2` plus une extension `X_SECUBOX_`.

**Tech Stack :** Go 1.22 bibliothèque standard seule (`CGO_ENABLED=0`, `-trimpath`), Python 3 / FastAPI / Uvicorn,
SQLite, nginx, nftables, systemd, AppArmor, Debian trixie.

**Spec :** `docs/superpowers/specs/2026-10-28-pilotage-distant-design.md` (décisions 1 à 14, D0, D1, D4, D6, E1,
E2, E4, E6, livraison L1).

## Global Constraints

- Paquets : `packages/secubox-pilotage/` (maître, `Architecture: all`) et `packages/secubox-pilotage-agent/`
  (box, `Architecture: any`) ; version initiale `0.1.0-1~trixie1` ; `debian/compat` 13 ; `Standards-Version: 4.6.2` ;
  `postinst` `systemctl enable --now`, `prerm` `systemctl stop` ; version montée à chaque changement déployé.
- En-tête SPDX CMSD-1.0 sur tout fichier (`scripts/license-headers.py`). Jamais « CyberMind Produits SASU ».
- Agent : Go 1.22, **bibliothèque standard seule** (aucun module tiers, donc pas de `vendor/`), binaire unique
  `/usr/sbin/sbx-pilotage-agent`, construit comme `packages/sbxos-audio-mood/debian/rules` (`GOARCH` par
  `DEB_HOST_ARCH`, `CGO_ENABLED=0`, `GOFLAGS=-trimpath`).
- Agent : **n'ouvre aucun port d'écoute** ; utilisateur dédié `secubox-pilotage-agent` (jamais root) ; AppArmor `enforce` ;
  mémoire propre (PSS + swap) **≤ 20 Mo** mesurée sur gk5 (spec, choix « utilisable en production ») ;
  `MemoryMax=32M`.
- Maître : FastAPI sur sockets Unix `/run/secubox/pilotage.sock` (administration) et
  `/run/secubox/pilotage-canal.sock` (canal) ; jamais de port TCP direct ; utilisateur `secubox-pilotage`.
- Canal : servi par nginx **uniquement** sur l'IP `wg-mesh` du maître (`10.10.0.1`) et son IP `wg-autoload`
  (`10.64.0.1`), port **8472**, règles nft `iifname "wg-mesh" ip saddr 10.10.0.0/24 tcp dport 8472 accept` et
  `iifname "wg-autoload" ip saddr 10.64.0.0/16 tcp dport 8472 accept`, posées avant le `drop` final de
  `inet secubox_filter` comme pour l'annuaire `:8799` (`packages/secubox-annuaire/sbin/secubox-annuaire-maillage`).
  Ce canal ne passe pas par HAProxy/sbxwaf : il ne vit que dans les tunnels (précédents : Auto-Load `:8470`,
  annuaire `:8799`).
- Identité d'une box = son adresse source dans le tunnel (WireGuard lie l'adresse à la clé du pair), transmise par
  nginx en `X-Real-IP` ; l'application canal n'accepte cet en-tête que sur sa socket Unix.
- Toutes les routes d'administration : `require_jwt`. Chaque relevé demandé et chaque refus d'identité sont écrits
  dans `/var/log/secubox/audit.log` (append-only), jamais une valeur secrète.
- L1 est **lecture seule partout**, mode « mains liées » compris : seuls Get, GetSupportedDM, Notify et l'Operate
  `Device.X_SECUBOX_Releve.Mesurer()` (lecture) existent.
- Langue : messages, journaux et commentaires en français, au niveau de densité des fichiers voisins.

## Review Focus

- Maître injoignable ou tunnel coupé : l'agent attend avec un délai croissant (5 s → 300 s), sans boucle CPU ni
  fuite mémoire ; il reprend seul. Test : `TestClientReculeQuandLeMaitreEstAbsent` (Task 5).
- Adresse source inconnue des deux registres, ou box cliente qui lit la file d'une autre : 403, rien n'est servi,
  refus audité. Tests : `test_canal_refuse_une_adresse_inconnue`, `test_canal_cloisonne_les_files` (Task 8).
- Box très chargée (centaines de processus ou d'unités) : sorties bornées (20 processus, 200 unités, message ≤
  256 Kio), pas d'explosion mémoire de l'agent. Test : `TestModeleBorneLesListes` (Task 2).
- `systemctl` lent ou bloqué (D-Bus figé) : délai de 5 s par collecte, réponse partielle avec erreur par chemin,
  l'agent ne se bloque pas. Test : `TestSystemdDelaiDepasse` (Task 2).
- Réponse tardive ou rejouée (agent redémarré, `msg_id` inconnu ou déjà servi) : ignorée sans erreur 500. Test :
  `test_canal_ignore_une_reponse_inconnue` (Task 8).

---

## Structure des fichiers

**Agent** — `packages/secubox-pilotage-agent/`
- `go.mod` : `module github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent`, `go 1.22`.
- `internal/modele/modele.go` : registre des chemins, `Get`, `GetSupportedDM`, bornes.
- `internal/collecte/systeme.go` : identité, `/proc/meminfo`, `/proc/uptime`, `/proc/stat`, processus.
- `internal/collecte/systemd.go`, `paquets.go`, `exposition.go`, `maillage.go`, `pilotage.go` : une source chacun.
- `internal/notifs/notifs.go` : détections (boucle, mémoire, swap, démarrage).
- `internal/releve/releve.go` : relevé de performance sur une durée.
- `internal/canal/client.go` : interrogation longue, envoi des réponses et notifications, recul.
- `cmd/sbx-pilotage-agent/main.go` : configuration par l'environnement, assemblage.
- `debian/` (control, rules, changelog, compat, postinst, prerm), `systemd/secubox-pilotage-agent.service`,
  `apparmor/usr.sbin.sbx-pilotage-agent`, `conf/pilotage-agent.env`, `README.md`.

**Maître** — `packages/secubox-pilotage/`
- `pilotage/identite.py` : adresse source → box (peers.json, projection Auto-Load).
- `pilotage/files.py` : files de requêtes par box, attentes de réponse, cloisonnement.
- `pilotage/stockage.py` : SQLite `/var/lib/secubox/pilotage/pilotage.db`.
- `pilotage/inventaire.py` : relève périodique de chaque box en ligne.
- `api/canal.py` : application canal ; `api/main.py` : application d'administration ; `api/asgi.py` : les deux.
- `sbin/secubox-pilotage-api` (lanceur), `sbin/secubox-pilotage-ecoute` (root : écouteurs nginx + nft).
- `nginx/pilotage-canal.conf.tpl`, `nginx/pilotage.conf` (route `/api/v1/pilotage/`), `systemd/`, `apparmor/`,
  `debian/`, `README.md`, `tests/`.

**Ailleurs**
- `packages/secubox-autoload/sbin/autoloadctl` : commande `exporter-pairs` (Task 7).
- `packages/secubox-aggregator/aggregator/main.py` : `pilotage` dans `DEDICATED_MODULES` (Task 10).
- `packages/secubox-annuaire/www/fleet/index.html` : panneau « Pilotage » (Task 11).
- `scripts/bench/mesure-box.sh` : outil de banc versé au dépôt (Task 12).

---

### Task 1 : Agent — modèle de données et collecte système

**Files :**
- Create : `packages/secubox-pilotage-agent/go.mod`, `internal/modele/modele.go`, `internal/collecte/systeme.go`
- Test : `internal/modele/modele_test.go`, `internal/collecte/systeme_test.go`, données sous `internal/collecte/testdata/`

**Interfaces :**
- Produces :
  - `type Source interface { Nom() string; Lire(ctx context.Context) (map[string]any, error) }` — chaque
    source rend ses paramètres sous leurs chemins complets (`"Device.DeviceInfo.UpTime": 1234`).
  - `func NouveauModele(sources ...Source) *Modele`
  - `func (m *Modele) Get(ctx context.Context, chemins []string) []Resultat` avec
    `type Resultat struct { Chemin string `json:"path"`; Params map[string]any `json:"params,omitempty"`; Erreur string `json:"err,omitempty"` }`
    — un chemin finissant par `.` est un préfixe (objet partiel) ; un chemin inconnu rend `Erreur: "chemin inconnu"`.
  - `func (m *Modele) Supportes() []string` — liste triée des chemins connus (GetSupportedDM).
  - `func NouvelleSourceSysteme(racine string) Source` — `racine` préfixe `/proc` et `/sys` (vide en production).
- Chemins de la source système (valeurs TR-181 : mémoire en Kio, CPU en %) :
  `Device.DeviceInfo.Manufacturer` (« Globalscale », « Raspberry Pi », sinon `sys_vendor`),
  `Device.DeviceInfo.ModelName` (`/proc/device-tree/model` sans `\0`, sinon `/sys/class/dmi/id/product_name`),
  `Device.DeviceInfo.SerialNumber` (adresse MAC de la première carte physique, sans `:`),
  `Device.DeviceInfo.SoftwareVersion` (version dpkg de `secubox-core`, lue par la source paquets, Task 2),
  `Device.DeviceInfo.UpTime`, `Device.DeviceInfo.MemoryStatus.Total`, `.Free`,
  `Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available`, `.X_SECUBOX_SwapTotal`, `.X_SECUBOX_SwapUsed`,
  `Device.DeviceInfo.ProcessStatus.CPUUsage` (moyenne depuis la lecture précédente, 0 à la première),
  `Device.DeviceInfo.ProcessStatus.ProcessNumberOfEntries`,
  `Device.DeviceInfo.ProcessStatus.Process.{i}.PID`, `.Command` (nom `comm`, jamais la ligne de commande : elle
  peut porter un secret), `.Size` (RSS Kio), `.CPUTime` (ms), `.State` — les **20** plus gros RSS seulement.

- [ ] **Step 1 : tests qui échouent**

```go
func TestSystemeLitMemoireEtUptime(t *testing.T) // racine testdata/gk5 : Total=973824, X_SECUBOX_Available=262144, UpTime=2036
func TestSystemeNeDonneJamaisLaLigneDeCommande(t *testing.T) // cmdline de testdata contient "password=x" : absent de toute valeur
func TestModeleBorneLesListes(t *testing.T) // 500 processus dans testdata/charge : 20 entrées Process.{i}, ProcessNumberOfEntries=500
func TestModelePrefixeEtCheminInconnu(t *testing.T) // Get("Device.DeviceInfo.MemoryStatus.") rend 5 params ; Get("Device.Rien") → Erreur "chemin inconnu"
```

- [ ] **Step 2 :** `cd packages/secubox-pilotage-agent && go test ./...` → FAIL (paquets absents).
- [ ] **Step 3 :** implémenter `modele.go` et `systeme.go` (lecture de fichiers seulement, aucun processus lancé).
- [ ] **Step 4 :** `go test ./... && go vet ./...` → PASS.
- [ ] **Step 5 :** commit `feat(pilotage-agent): modèle TR-181 et collecte système (ref #3126)`.

### Task 2 : Agent — sources systemd, paquets, exposition, maillage, pilotage

**Files :**
- Create : `internal/collecte/systemd.go`, `paquets.go`, `exposition.go`, `maillage.go`, `pilotage.go`
- Test : un `_test.go` par fichier, données sous `testdata/`

**Interfaces :**
- Consumes : `Source` (Task 1).
- Produces :
  - `func NouvelleSourceSystemd(lanceur func(ctx context.Context, args ...string) ([]byte, error)) Source` —
    appelle **une seule fois** `systemctl show --property=Id,ActiveState,SubState,NRestarts,Result 'secubox-*' 'nginx.service' 'unbound.service' 'ssh.service' 'nftables.service'`
    avec un délai de **5 s** ; rend `Device.X_SECUBOX_Services.{i}.Name|ActiveState|SubState|NRestarts|Result` (au
    plus **200**) et `Device.X_SECUBOX_Services.FailedNumberOfEntries`.
  - `func NouvelleSourcePaquets(racine string) Source` — lit `/var/lib/dpkg/status` : `Device.X_SECUBOX_Packages.{i}.Name|Version`
    pour `secubox-*` installés (`Status: install ok installed`), et alimente `Device.DeviceInfo.SoftwareVersion`.
  - `func NouvelleSourceExposition(racine string) Source` — `Device.X_SECUBOX_Exposure.Names` (liste des
    `server_name` non génériques de `/etc/nginx/sites-enabled/*`, sans `_` ni `localhost`) et
    `Device.X_SECUBOX_Exposure.Ports` (ports TCP en écoute de `/proc/net/tcp` et `tcp6`, état `0A`) — exigence E4.
  - `func NouvelleSourceMaillage(interfaces func() ([]net.Interface, error)) Source` — `Device.X_SECUBOX_Mesh.Interface`
    (`wg-mesh` ou `wg-autoload`), `.Address`, `.Present` (bool).
  - `func NouvelleSourcePilotage(racine string, version string) Source` — `Device.X_SECUBOX_Pilotage.AgentVersion`,
    `.MainsLiees` (vrai si `/etc/secubox/pilotage/mains-liees` existe), `.Profil` (contenu de
    `/var/lib/secubox/profiles/actif` s'il existe, sinon vide).

- [ ] **Step 1 : tests qui échouent**

```go
func TestSystemdLitLesRelancesEtLesEchecs(t *testing.T) // sortie testdata : secubox-ndpisrvd NRestarts=391 ; FailedNumberOfEntries=1
func TestSystemdDelaiDepasse(t *testing.T)               // lanceur qui dort 10 s : Lire rend une erreur en ≤ 6 s, aucun blocage
func TestPaquetsNeGardeQueSecuboxInstalles(t *testing.T) // status testdata : 24 paquets secubox, aucun « deinstall »
func TestExpositionNomsEtPorts(t *testing.T)             // admin.gk5.secubox.in présent, « _ » absent ; ports 80, 443, 9080
func TestPilotageMainsLiees(t *testing.T)                // fichier présent → true ; absent → false
```

- [ ] **Step 2 :** `go test ./internal/collecte/` → FAIL.
- [ ] **Step 3 :** implémenter les cinq sources (seule `systemd.go` lance un processus, par `lanceur`).
- [ ] **Step 4 :** `go test ./... && go vet ./...` → PASS.
- [ ] **Step 5 :** commit `feat(pilotage-agent): services, paquets, exposition, maillage, mains liées (ref #3126)`.

### Task 3 : Agent — notifications

**Files :**
- Create : `internal/notifs/notifs.go` ; Test : `internal/notifs/notifs_test.go`

**Interfaces :**
- Produces :
  - `type Seuils struct { MemoireMo int; SwapPct int; BoucleRelances int; BoucleFenetre time.Duration }` —
    défauts **200 Mo**, **80 %**, **3 relances**, **10 min** (variables `PILOTAGE_MEMOIRE_SEUIL_MO`,
    `PILOTAGE_SWAP_SEUIL_PCT`, `PILOTAGE_BOUCLE_RELANCES`, `PILOTAGE_BOUCLE_FENETRE_S`).
  - `type Evenement struct { Type string `json:"type"`; Unite string `json:"unit,omitempty"`; Valeur int64 `json:"value,omitempty"`; Instant int64 `json:"ts"` }`
    avec `Type` ∈ `X_SECUBOX_ServiceLoop`, `X_SECUBOX_MemoryLow`, `X_SECUBOX_SwapHigh`, `X_SECUBOX_Boot`.
  - `func NouveauDetecteur(s Seuils, horloge func() time.Time) *Detecteur`
  - `func (d *Detecteur) Observer(params map[string]any) []Evenement` — reçoit le résultat d'un `Get` complet ;
    une condition ne se déclenche qu'**une fois** tant qu'elle dure, et se réarme quand elle cesse ;
    `X_SECUBOX_Boot` une seule fois par démarrage si `UpTime < 600`.

- [ ] **Step 1 : tests qui échouent**

```go
func TestBoucleDetecteeUneFois(t *testing.T)   // NRestarts 10 → 14 en 2 min : 1 événement ServiceLoop ; 14 → 15 : aucun nouveau
func TestBoucleHorsFenetre(t *testing.T)       // 10 → 14 en 30 min : aucun
func TestMemoireBasseSeReArme(t *testing.T)    // 150 Mo → événement ; 300 Mo → rien ; 150 Mo → nouvel événement
func TestSwapHaut(t *testing.T)                // 902/950 Mo → SwapHigh valeur 94
func TestDemarrageUneSeuleFois(t *testing.T)   // UpTime 120 puis 150 : un seul Boot
```

- [ ] **Step 2 :** `go test ./internal/notifs/` → FAIL. **Step 3 :** implémenter. **Step 4 :** PASS.
- [ ] **Step 5 :** commit `feat(pilotage-agent): détection des boucles, mémoire, swap, démarrage (ref #3126)`.

### Task 4 : Agent — relevé de performance à la demande

**Files :**
- Create : `internal/releve/releve.go` ; Test : `internal/releve/releve_test.go`

**Interfaces :**
- Produces :
  - `func Mesurer(ctx context.Context, racine string, duree time.Duration, attendre func(context.Context, time.Duration) error) (Releve, error)`
    — `duree` bornée à **[10 s, 300 s]** ; un seul relevé à la fois (second appel → erreur `relevé déjà en cours`).
  - `type Releve struct { DureeS int; CPUPct int; CtxtParS int64; EcrituresKoS int64; MemDispoMo int; SwapMo int; Top []ProcRel }`,
    `type ProcRel struct { Nom string; CPUPct float64; PSSMo int }` — mêmes grandeurs que `mesure-box.sh`
    (Task 12), `Top` limité à **10**, PSS lu dans `/proc/<pid>/smaps_rollup` quand il est lisible, sinon RSS.

- [ ] **Step 1 : tests qui échouent**

```go
func TestReleveBorneLaDuree(t *testing.T)     // 5 s → 10 s ; 900 s → 300 s (vu par le faux attendre)
func TestReleveCalculeLeCPU(t *testing.T)     // deux /proc/stat de testdata : CPUPct=50
func TestReleveUnSeulALaFois(t *testing.T)    // second appel concurrent → erreur « relevé déjà en cours »
```

- [ ] **Step 2 :** FAIL. **Step 3 :** implémenter. **Step 4 :** PASS.
- [ ] **Step 5 :** commit `feat(pilotage-agent): relevé de performance à la demande (ref #3126)`.

### Task 5 : Agent — client du canal

**Files :**
- Create : `internal/canal/client.go` ; Test : `internal/canal/client_test.go` (serveur `httptest`)

**Interfaces :**
- Consumes : `Modele.Get`, `Modele.Supportes` (Task 1), `releve.Mesurer` (Task 4), `notifs.Evenement` (Task 3).
- Produces :
  - Format des messages (JSON, forme USP) :
    - requête : `{"msg_id": "<hex 16>", "type": "GET"|"GET_SUPPORTED_DM"|"OPERATE", "body": {...}}`,
      GET `{"paths": [...]}`, OPERATE `{"command": "Device.X_SECUBOX_Releve.Mesurer()", "args": {"duree_s": 60}}` ;
    - réponse : `{"msg_id": ..., "type": "GET_RESP"|"GET_SUPPORTED_DM_RESP"|"OPERATE_RESP"|"ERROR", "body": {...}}`,
      ERROR `{"err": "<message>"}` ; toute autre commande OPERATE → ERROR `commande refusée (L1 : lecture seule)` ;
    - notification : `{"type": "NOTIFY", "body": {"event": <Evenement>}}`.
  - Routes appelées (préfixe `http://<maître>:8472/canal/v1`) : `POST /bonjour` `{"agent_version","boot_id","modele"}`,
    `GET /requetes?attente=25` (200 liste, ou 204), `POST /reponses` (liste), `POST /notifs` (liste).
  - `type Config struct { Maitre string; IPSource string; Attente time.Duration; ReculMin, ReculMax time.Duration; TailleMax int }`
    — défauts `Attente` 25 s, recul **5 s → 300 s** (doublement), `TailleMax` **256 Kio** (réponse tronquée au-delà :
    les listes `{i}` sont coupées et `"tronque": true` est ajouté).
  - `func NouveauClient(c Config, m *modele.Modele, operer func(ctx context.Context, cmd string, args map[string]any) (any, error)) *Client`
  - `func (c *Client) Tourner(ctx context.Context, notifs <-chan notifs.Evenement) error` — la connexion sortante
    est liée à `IPSource` (adresse du tunnel) par `net.Dialer.LocalAddr` ; ne rend la main qu'à l'annulation du ctx.
    Avec `IPAddressAllow` de l'unité (Task 6), c'est ce qui tient l'exigence D1 en L1 : l'agent ne joint le
    contrôleur que par le pair WireGuard qui porte l'adresse du maître ; la vérification explicite de la clé de
    l'ancre (`ancre-maitre.json`), qui demande `CAP_NET_ADMIN`, est reportée à L2 (ctl root).

- [ ] **Step 1 : tests qui échouent**

```go
func TestClientRepondAUnGet(t *testing.T)                 // le faux maître sert un GET ; reçoit GET_RESP avec le même msg_id
func TestClientRefuseUnOperateNonLecture(t *testing.T)    // OPERATE "Device.Reboot()" → ERROR « commande refusée (L1 : lecture seule) »
func TestClientReculeQuandLeMaitreEstAbsent(t *testing.T) // serveur fermé : délais observés 5,10,20,…,300,300 s (horloge factice), aucun appel en rafale
func TestClientTronqueAuDelaDe256Kio(t *testing.T)        // réponse > 256 Kio → envoyée ≤ 256 Kio avec "tronque": true
func TestClientEnvoieLesNotifications(t *testing.T)       // un Evenement sur le canal → POST /notifs reçu
```

- [ ] **Step 2 :** FAIL. **Step 3 :** implémenter (horloge et attente injectables pour les tests).
- [ ] **Step 4 :** `go test ./... && go vet ./...` → PASS.
- [ ] **Step 5 :** commit `feat(pilotage-agent): canal sortant en interrogation longue (ref #3126)`.

### Task 6 : Agent — binaire, paquet Debian, unité durcie

**Files :**
- Create : `cmd/sbx-pilotage-agent/main.go`, `debian/{control,rules,changelog,compat,postinst,prerm}`,
  `systemd/secubox-pilotage-agent.service`, `apparmor/usr.sbin.sbx-pilotage-agent`, `conf/pilotage-agent.env`,
  `README.md`, `tests/test_paquet_agent.py` (contrôles statiques en pytest, comme les autres paquets).

**Interfaces :**
- Consumes : tout ce qui précède.
- Produces :
  - Configuration par l'environnement (`EnvironmentFile=-/etc/secubox/pilotage-agent.env`) :
    `PILOTAGE_MAITRE` (défaut : `10.10.0.1:8472` si `wg-mesh` porte une adresse en `10.10.0.0/24`, sinon
    `10.64.0.1:8472` si `wg-autoload` porte une adresse en `10.64.0.0/16`, sinon l'agent attend et revérifie
    toutes les 300 s), `PILOTAGE_RELEVE_INTERVALLE_S` (défaut **30**, échantillonnage des notifications) et les
    seuils de Task 3.
  - Unité : `User=secubox-pilotage`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
    `PrivateTmp=yes`, `RestrictAddressFamilies=AF_INET AF_UNIX`, `IPAddressDeny=any`,
    `IPAddressAllow=10.10.0.1 10.64.0.1 localhost`, `MemoryMax=32M`, `Restart=on-failure`, `RestartSec=10`,
    `ReadOnlyPaths=/`, aucune capacité.
  - `postinst` : `adduser --system --no-create-home --group secubox-pilotage` si absent,
    `install -d -m 0755 /etc/secubox/pilotage`, chargement AppArmor, `systemctl enable --now`.

- [ ] **Step 1 : tests qui échouent** (`tests/test_paquet_agent.py`)

```python
def test_unite_durcie():           # les directives ci-dessus présentes, aucune "Listen", aucun "CAP_"
def test_regles_construisent_sans_cgo():  # rules : CGO_ENABLED = 0, -trimpath, GOARCH depuis DEB_HOST_ARCH
def test_aucune_dependance_go_tierce():   # go.mod sans bloc require
def test_apparmor_enforce_sans_reseau_entrant():  # profil sans "network inet stream" en écoute (bind/listen absents)
```

- [ ] **Step 2 :** `pytest -q packages/secubox-pilotage-agent/tests` → FAIL.
- [ ] **Step 3 :** écrire `main.go` (assemblage, signal SIGTERM → arrêt propre) et le paquet.
- [ ] **Step 4 :** pytest PASS ; `go test ./...` PASS ; `dpkg-buildpackage -b -us -uc` en amd64 sur le poste, et
  en arm64 **en natif sur gk2** (dans `/data/build/`, comme secubox-ndpid-engine : un `-aarm64` croisé buterait
  sur `dh_strip`) → les deux `.deb` produits ; `ss -ltnp` sur une box de test : aucune socket du binaire.
- [ ] **Step 5 :** commit `feat(pilotage-agent): binaire, paquet et unité durcie (ref #3126)`.

### Task 7 : Auto-Load — projection publique des pairs

**Files :**
- Modify : `packages/secubox-autoload/sbin/autoloadctl` (sous-commande `exporter-pairs`, appelée à la fin de `tunnel-sync`)
- Test : `packages/secubox-autoload/tests/test_exporter_pairs_3126.py`

**Interfaces :**
- Produces : `/var/lib/secubox/autoload/pairs-publics.json` (root, **0644**, écrit par renommage atomique) :
  `{"version": 1, "pairs": [{"adresse": "10.64.0.9", "client": "lgm", "lot": ..., "serie": ..., "profil": ..., "abonnement": "actif"|"suspendu"|"revoque"}]}`
  — **aucune** clé, empreinte ni jeton ; seulement les pairs non retirés dont le jeton est réclamé.

- [ ] **Step 1 : tests qui échouent**

```python
def test_projection_sans_secret(tmp_path):        # base de test avec jeton et clé : ni "cle_pub", ni "empreinte", ni valeur de jeton dans le JSON
def test_projection_relie_adresse_et_client(tmp_path):  # 10.64.0.9 → client "lgm", abonnement "actif"
def test_tunnel_sync_exporte(tmp_path):           # tunnel-sync appelle exporter-pairs (fichier présent après)
```

- [ ] **Step 2 :** FAIL. **Step 3 :** implémenter (lecture en `mode=ro` comme `Pairs(lecture_seule=True)`).
- [ ] **Step 4 :** suite secubox-autoload verte. **Step 5 :** monter la version, commit
  `feat(autoload): projection publique des pairs pour le pilotage (ref #3126)`.

### Task 8 : Maître — identité, files et application canal

**Files :**
- Create : `packages/secubox-pilotage/pilotage/identite.py`, `pilotage/files.py`, `api/canal.py`
- Test : `tests/test_identite.py`, `tests/test_files.py`, `tests/test_canal.py`

**Interfaces :**
- Consumes : `peers.json` (`/var/lib/secubox/p2p/peers.json` : `name`, `mesh_ip`), la projection de Task 7.
- Produces :
  - `@dataclass(frozen=True) class Box: nom: str; adresse: str; reseau: Literal["maillage","autoload"]; client: Optional[str]; abonnement: Optional[str]`
  - `def box_par_adresse(adresse: str, peers: Path, pairs_autoload: Path) -> Optional[Box]` — `10.10.0.0/24` →
    peers.json ; `10.64.0.0/16` → projection (nom = `"<client>-<adresse>"` si pas de série, sinon la série) ;
    abonnement `revoque` → `None`.
  - `class Files` : `deposer(box: str, requete: dict) -> asyncio.Future`, `async attendre_requetes(box: str, delai: float) -> list[dict]`,
    `livrer_reponse(box: str, reponse: dict) -> bool` (False si `msg_id` inconnu ou d'une autre box), expiration
    des requêtes non servies à **30 s**.
  - `def creer_app_canal(files: Files, identifier: Callable[[str], Optional[Box]], stockage, audit) -> FastAPI` —
    routes `POST /canal/v1/bonjour`, `GET /canal/v1/requetes`, `POST /canal/v1/reponses`, `POST /canal/v1/notifs` ;
    l'adresse vient de `X-Real-IP` ; corps refusé au-delà de **256 Kio** (413).

- [ ] **Step 1 : tests qui échouent**

```python
def test_identite_maillage_et_autoload(tmp_path):       # 10.10.0.10 → "gk5" ; 10.64.0.9 → client "lgm" ; 10.64.0.99 révoqué → None
def test_canal_refuse_une_adresse_inconnue():           # X-Real-IP 10.10.0.200 → 403 ; audit "pilotage_identite_refusee"
def test_canal_cloisonne_les_files():                   # requête déposée pour gk5 : la box lgm ne la reçoit jamais ; réponse de lgm au msg_id de gk5 → ignorée
def test_canal_ignore_une_reponse_inconnue():           # msg_id inconnu → 200 {"ignore": 1}, jamais 500
def test_canal_attente_longue_rend_204():               # aucune requête : 204 après le délai demandé (borné à 25 s)
def test_canal_refuse_un_corps_trop_gros():             # 300 Kio → 413
```

- [ ] **Step 2 :** `pytest -q packages/secubox-pilotage/tests` → FAIL.
- [ ] **Step 3 :** implémenter (tout en asyncio, aucune requête bloquante dans la boucle).
- [ ] **Step 4 :** PASS. **Step 5 :** commit `feat(pilotage): identité par le tunnel, files cloisonnées, canal (ref #3126)`.

### Task 9 : Maître — stockage, relève périodique, API d'administration

**Files :**
- Create : `pilotage/stockage.py`, `pilotage/inventaire.py`, `api/main.py`, `api/asgi.py`
- Test : `tests/test_stockage.py`, `tests/test_inventaire.py`, `tests/test_api.py`

**Interfaces :**
- Consumes : `Files`, `Box` (Task 8).
- Produces :
  - SQLite `/var/lib/secubox/pilotage/pilotage.db` (0640 `secubox-pilotage`) : tables
    `boites(nom PK, adresse, reseau, client, abonnement, agent_version, mains_liees, vu_le)`,
    `inventaire(nom, chemin, valeur_json, releve_le, PRIMARY KEY(nom, chemin))`,
    `evenements(id PK, nom, type, unite, valeur, survenu_le, recu_le)` ; événements gardés **30 jours**.
  - `class Inventaire` : toutes les **60 s**, pour chaque box vue depuis moins de 90 s, dépose un GET `["Device."]`
    et enregistre le résultat ; une box non vue depuis 90 s passe « hors ligne ».
  - Routes (préfixe monté `/api/v1/pilotage`, toutes `require_jwt`) :
    `GET /boxes` (liste : nom, réseau, client, en ligne, vu_le, agent_version, mains_liees, mémoire dispo Mo,
    swap utilisé %, CPU %, services en échec, boucles des dernières 24 h),
    `GET /boxes/{nom}` (inventaire complet), `GET /boxes/{nom}/lire?chemin=Device.X.` (Get en direct, délai 15 s, 504
    au-delà), `POST /boxes/{nom}/releve` `{"duree_s": 60}` (Operate relevé ; audit `pilotage_releve_demande`),
    `GET /evenements?nom=&depuis=`.
  - `def construire() -> tuple[FastAPI, FastAPI]` dans `api/asgi.py` (administration, canal), même patron que
    `packages/secubox-autoload/api/asgi.py`.

- [ ] **Step 1 : tests qui échouent**

```python
def test_boxes_exige_un_jwt(client):              # sans jeton → 401
def test_boxes_resume_l_inventaire(client):        # inventaire gk5 en base → swap 66 %, 0 service en échec, mains_liees False
def test_lire_en_direct_et_delai(client):          # agent factice qui ne répond pas → 504 en ≤ 16 s
def test_releve_audite(client):                    # POST /releve → ligne d'audit avec le nom de la box et l'acteur, sans valeur
def test_hors_ligne_apres_90_s(horloge):           # vu_le il y a 91 s → en_ligne False
def test_evenements_purges_apres_30_jours(tmp_path)
```

- [ ] **Step 2 :** FAIL. **Step 3 :** implémenter. **Step 4 :** PASS.
- [ ] **Step 5 :** commit `feat(pilotage): inventaire, événements et API d'administration (ref #3126)`.

### Task 10 : Maître — paquet, écouteurs de tunnel, nft, agrégateur

**Files :**
- Create : `sbin/secubox-pilotage-api`, `sbin/secubox-pilotage-ecoute`, `nginx/pilotage-canal.conf.tpl`,
  `nginx/pilotage.conf`, `systemd/secubox-pilotage.service`, `apparmor/…`, `debian/*`, `README.md`,
  `menu.d/` (entrée du menu, catégorie « network »)
- Modify : `packages/secubox-aggregator/aggregator/main.py` (`"pilotage"` dans `DEDICATED_MODULES`)
- Test : `tests/test_paquet.py`, `tests/test_ecoute.py`

**Interfaces :**
- Produces :
  - `secubox-pilotage-ecoute` (root, appelé par le `postinst` et par une unité `.path` sur les adresses des
    interfaces) : rend `/etc/nginx/conf.d/secubox-pilotage-canal.conf` avec un `server` par IP de tunnel présente
    (`listen 10.10.0.1:8472;`, `listen 10.64.0.1:8472;`), `proxy_pass http://unix:/run/secubox/pilotage-canal.sock`,
    `proxy_set_header X-Real-IP $remote_addr;`, `proxy_read_timeout 60s;`, `client_max_body_size 256k;` ; retire
    le fichier si `nginx -t` échoue ; pose les deux règles nft (Global Constraints) dans le fichier et à chaud,
    exactement comme `secubox-annuaire-maillage` (insertion avant le `drop`, jamais `nft -f` du fichier entier).
  - `nginx/pilotage.conf` : `location /api/v1/pilotage/` → `pilotage.sock` (chemin normal de l'administration,
    derrière HAProxy → sbxwaf).

- [ ] **Step 1 : tests qui échouent**

```python
def test_ecouteur_seulement_sur_les_ip_de_tunnel(tmp_path):  # rendu : aucune ligne "listen 0.0.0.0" ni "listen 8472"
def test_ecouteur_retire_si_nginx_refuse(tmp_path):           # faux nginx -t en échec → fichier absent
def test_regles_nft_avant_le_drop(tmp_path):                  # les deux règles insérées avant "drop" ; idempotent au second passage
def test_pilotage_dans_dedicated_modules():                   # l'agrégateur ne monte pas pilotage
def test_unite_maitre_durcie():                               # User=secubox-pilotage, NoNewPrivileges, ProtectSystem=strict
```

- [ ] **Step 2 :** FAIL. **Step 3 :** implémenter. **Step 4 :** suites secubox-pilotage et secubox-aggregator vertes.
- [ ] **Step 5 :** commit `feat(pilotage): paquet, écouteurs de tunnel et règles nft (ref #3126)`.

### Task 11 : Page Flotte — panneau « Pilotage »

**Files :**
- Modify : `packages/secubox-annuaire/www/fleet/index.html` (nouveau panneau après « Pairs du transport wg-mesh »)
- Test : `packages/secubox-annuaire/tests/test_fleet_pilotage_3126.py`

**Interfaces :**
- Consumes : `GET /api/v1/pilotage/boxes` (Task 9).
- Produces : panneau masqué si le module est absent ou la liste vide (même règle que les panneaux Auto-Load et
  wg-mesh) ; une ligne par box : nom, réseau (maillage / client « <client> »), en ligne, mémoire dispo, swap %, CPU %,
  services en échec, boucles 24 h, pastille « mains liées » ; rafraîchi toutes les **30 s** (suspendu onglet masqué) ;
  valeurs posées par `createElement`/`textContent`, jamais en HTML (règle XSS-strict de la page) ; charte Aurora.

- [ ] **Step 1 : tests qui échouent**

```python
def test_panneau_appelle_l_api_pilotage():        # la page référence /api/v1/pilotage/boxes
def test_panneau_sans_innerhtml_pour_les_donnees(): # aucune affectation innerHTML avec une donnée de l'API dans le bloc pilotage
def test_panneau_masque_si_module_absent():        # le code masque le panneau sur 404 ou liste vide
```

- [ ] **Step 2 :** FAIL. **Step 3 :** implémenter. **Step 4 :** PASS ; monter la version de secubox-annuaire.
- [ ] **Step 5 :** commit `feat(fleet): panneau Pilotage (ref #3126)`.

### Task 12 : Banc, déploiement, mesure du budget

**Files :**
- Create : `scripts/bench/mesure-box.sh` (copie de l'outil du banc du 2026-10-28, présent dans le scratchpad de
  session et sur gk5 en `/root/banc/mesure-box.sh`, sha256 `1a671412…`), section dans `scripts/bench/README.md`
- Modify : `.claude/HISTORY.md`, `.claude/WIP.md`, `.claude/MIGRATION-MAP.md` (nouveaux modules)

- [ ] **Step 1 :** construire et publier par `scripts/apt-publier.sh` : `secubox-pilotage` (all), `secubox-pilotage-agent`
  (arm64 et amd64), `secubox-autoload`, `secubox-aggregator`, `secubox-annuaire` (versions montées).
- [ ] **Step 2 :** gk2 : `apt-get install secubox-pilotage` (un seul redémarrage de l'agrégateur, groupé) ;
  vérifier `ss -ltn` : 8472 seulement sur 10.10.0.1 et 10.64.0.1 ; `curl --unix-socket /run/secubox/pilotage.sock`
  sans jeton → 401.
- [ ] **Step 3 :** gk5 (box du propriétaire) puis lgm-ebin (box cliente) : `apt-get install secubox-pilotage-agent` ;
  sur gk2, `GET /api/v1/pilotage/boxes` (jeton admin) montre les deux en ligne, lgm-ebin avec `client: "lgm"`.
- [ ] **Step 4 :** sur gk5 : `bash /root/banc/mesure-box.sh --duree 300 --etiquette pilotage-agent` ; la PSS de
  `secubox-pilotage-agent` doit être **≤ 20 Mo** ; `ss -ltnp | grep sbx-pilotage` vide.
- [ ] **Step 5 :** provoquer une boucle (unité de test `Restart=always` qui sort en 1) sur gk5 : un événement
  `X_SECUBOX_ServiceLoop` arrive sur gk2 en moins de 2 min ; retirer l'unité.
- [ ] **Step 6 :** `POST /boxes/gk5/releve {"duree_s": 60}` : relevé rendu, ligne d'audit présente.
- [ ] **Step 7 :** HISTORY.md (entrée datée), WIP.md (L1 fait, suivant L2), MIGRATION-MAP.md ; commit
  `docs(suivi): pilotage L1 déployé (ref #3126)` ; PR vers master.
