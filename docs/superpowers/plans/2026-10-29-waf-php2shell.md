<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Analyseur multipart et signatures PHP2Shell dans sbxwaf — plan d'implémentation

> **Pour les agents :** sous-skill requis : superpowers:subagent-driven-development (recommandé) ou superpowers:executing-plans, tâche par tâche. Les étapes utilisent des cases (`- [ ]`).

**Objectif :** sbxwaf repère, en mode `detect`, les envois multipart caractéristiques de PHP2Shell (CVE-2026-109618 et CVE-2026-109619) sur les vhosts PHP, sans tampon ajouté ni blocage, et le journalise avec la gravité réelle.

**Architecture :**
- Sur un vhost PHP, pour un client hors du réseau local, une capture bornée copie le préfixe du corps multipart pendant que le proxy le relaie.
- Une fois la réponse rendue, un analyseur pur compte les parties et extrait les indicateurs structurels.
- Le moteur de règles évalue des signatures structurelles déclarées dans `waf-rules.json`, hors du parcours regex « première correspondance gagne ».
- Les détections partent au journal des menaces (puis vers actord) sans jamais toucher au ban, à nft ni à l'escalade.

**Pile :** Go 1.22 (`mime/multipart`, `vendor/`, `CGO_ENABLED=0`), Python 3 (scripts `waf-rules-sync`, `waf-profils-fusion`), paquet Debian `secubox-waf-ng`.

**Spécification :** `docs/superpowers/specs/2026-10-29-waf-php2shell-design.md` (audit, plan A à D, § 8 décisions arrêtées).

## Contraintes globales

- `SBX` = `packages/secubox-toolbox-ng/cmd/sbxwaf/`, `NG` = `packages/secubox-waf-ng/`. sbxwaf est construit par le paquet **secubox-waf-ng** (pas par toolbox-ng).
- Tests Go, depuis `packages/secubox-toolbox-ng` : `GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local go test -count=1 ./cmd/sbxwaf/`. Ajouter `-race` pour les tâches 4 et 5. Aucune dépendance nouvelle : bibliothèque standard seulement.
- Tests Python : `/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python -m pytest packages/secubox-waf-ng/composants/waf/tests/ -q` depuis la racine du worktree.
- Mode `detect` seulement. Une détection structurelle n'appelle jamais `s.ban.Record`, `appliquerBan`, nft, ni le compteur d'escalade. Elle ne bloque jamais : la décision tombe après la réponse.
- Le corps relayé au backend n'est jamais modifié ; aucun tampon ajouté avant le relais.
- Seuils provisoires : profondeur de nom **12**, nombre de parties **50**. Chaque signature à seuil porte `"seuil": "provisoire, non sourcé (2026-10-29)"`.
- Le journal ne contient jamais le corps, ni un nom de fichier, ni la valeur d'un champ : des compteurs et des booléens seulement.
- Aucune mention de CrowdSec dans le code ou la documentation touchés, sauf pour retirer celle de `SBX/main.go:193`.
- En-tête SPDX CMSD-1.0 sur tout fichier créé (modèle : en-tête de `SBX/vhostprofiles.go`). Commentaires et messages en français, comme le code voisin.
- Commits : `type(portée): message (ref #3257)`, terminés par la ligne `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Jamais de push ni de connexion à une box.
- Version : `secubox-waf-ng` passe de `1.30.7-1~trixie1` à `1.31.0-1~trixie1`. Vérifier d'abord avec `head -1 packages/secubox-waf-ng/debian/changelog` que master n'a pas déjà monté la version ; sinon prendre la mineure suivante.

## Points d'attention pour la relecture

1. **Backend qui répond sans lire le corps** (413, redirection, coupure) : pas de panique ni de course de données (`-race`) ; aucune ligne si aucun octet n'a été lu ; sinon `multipart-tronque`, jamais `php2shell` sur un préfixe vide. Test : tâche 4, `TestMultipartBackendNeLitPas`.
2. **Gros envoi légitime** (pièce jointe Roundcube de plusieurs Mo) : corps relayé intact, mémoire bornée à la fenêtre, une seule ligne `multipart-tronque` de gravité `audit` (projetée à 10), aucune détection. Test : tâche 4, `TestMultipartGrosEnvoiTronque`.
3. **Content-Type à la frontière Go/PHP** (`multipart/form-data, x`, majuscules, boundary entre guillemets contenant `;`, `name=` sans guillemets) : classé et lu comme PHP le ferait ; sinon `malforme` journalisé, jamais ignoré. Tests : tâche 1, `TestEstMultipartPHP`, `TestBoundaryPHP`, `TestAnalyserMultipartDispositionLaxiste`.
4. **Rechargement à chaud de `waf-rules.json`** (seuil changé, catégorie désactivée) : pris en compte à la requête suivante, sans redémarrage. Test : tâche 2, `TestStructurelRechargementAChaud`.
5. **Box dont l'opérateur a modifié `vhost_profiles.json`** : la mise à jour ajoute `php_services` et le service `roundcube` sans toucher ses valeurs. Test : tâche 3, `test_fusion_garde_php_services_de_la_box`.

---

### Tâche 1 : analyseur multipart pur

**Fichiers :**
- Créer : `SBX/multipart.go`
- Tests : `SBX/multipart_test.go` (tests, `FuzzAnalyserMultipart`, `BenchmarkAnalyserMultipart`)

**Interfaces :**
- Consomme : rien.
- Produit (même paquet `main`) :

```go
type StatutMultipart string

const (
	MultipartAnalyse  StatutMultipart = "analyse"
	MultipartTronque  StatutMultipart = "tronque"
	MultipartMalforme StatutMultipart = "malforme"
	MultipartLimite   StatutMultipart = "limite"
)

const partiesMaxDefaut = 2000
const nomProgressPHP = "PHP_SESSION_UPLOAD_PROGRESS"

type LimitesMultipart struct{ PartiesMax int } // 0 → partiesMaxDefaut

type ResultatMultipart struct {
	Statut                StatutMultipart
	Parties               int
	PartiesFichier        int
	ProfondeurMax         int  // nombre de '[' du nom le plus imbriqué
	LongueurNomMax        int  // en octets
	Progress              bool // un champ nommé exactement PHP_SESSION_UPLOAD_PROGRESS
	FichiersApresProgress int  // parties fichier vues APRÈS ce champ
	FilenamePHP           bool // un filename contient "<?php" (insensible à la casse)
	FilenameObjet         bool // un filename contient "|O:"
}

func estMultipartPHP(contentType string) bool
func boundaryPHP(contentType string) (string, bool)
func analyserMultipart(prefixe []byte, contentType string, tronque bool, lim LimitesMultipart) ResultatMultipart
func (r ResultatMultipart) Signaux() map[string]int
```

Règles fixées par la spécification (§ 6.1, 6.2, 6.3) et par la lecture de PHP (`main/SAPI.c`, `main/rfc1867.c`) :
- `estMultipartPHP` : passer en minuscules, couper au premier `;`, `,` ou espace (comme `SAPI.c`), comparer à `multipart/form-data`.
- `boundaryPHP` :
  1. chercher `boundary` sensible à la casse, sinon insensible ;
  2. puis le `=` suivant ;
  3. une valeur qui commence par `"` va jusqu'au `"` suivant (absent → `false`) ; sinon elle s'arrête au premier `,` ou `;` ;
  4. une valeur vide → `false`.
- `analyserMultipart` :
  - pas de boundary → `MultipartMalforme` ;
  - parcours `multipart.NewReader(bytes.NewReader(prefixe), boundary).NextRawPart()`, sans lire ni conserver le contenu des parties (jamais `ReadForm`, jamais `FileName()`, qui applique `filepath.Base`) ;
  - `io.EOF` → `MultipartAnalyse` ; autre erreur → `MultipartTronque` si `tronque`, sinon `MultipartMalforme` ;
  - au moment de compter la partie `PartiesMax + 1`, s'arrêter avec `MultipartLimite` et `Parties == PartiesMax`.
- Disposition : extracteur laxiste à la manière de PHP. Découper `Content-Disposition` sur `;`. Clés `name` et `filename` (`filename*` compte comme `filename`), insensibles à la casse. Valeur sans guillemets ou entre guillemets, `\"` et `\\` déséchappés. Une partie avec un paramètre `filename`, même vide, est une partie fichier.
- `Signaux()` rend les clés `parties`, `fichiers`, `profondeur`, `nom_max`, `fichiers_apres_progress`.

- [ ] **Étape 1 : écrire les tests qui échouent.** Assistant de test `corpsMultipart(boundary string, parties []partieTest, lf bool) []byte`, avec `partieTest{nom, filename string; fichier bool; contenu string}`. Tests :

```go
func TestEstMultipartPHP(t *testing.T) // table :
// "multipart/form-data; boundary=x"→true, "Multipart/Form-Data;boundary=x"→true,
// "multipart/form-data, x"→true, "multipart/form-data x"→true, "multipart/form-dataX"→false,
// "multipart/mixed; boundary=x"→false, "application/x-www-form-urlencoded"→false, ""→false
func TestBoundaryPHP(t *testing.T) // table :
// `multipart/form-data; boundary=abc`→("abc",true) ; `…; boundary="a;b"`→("a;b",true) ;
// `…; BOUNDARY=Q`→("Q",true) ; `…; boundary=abc; charset=utf-8`→("abc",true) ;
// `…; boundary=abc,def`→("abc",true) ; `…; boundary="abc`→("",false) ;
// `multipart/form-data`→("",false) ; `…; boundary=`→("",false)
func TestAnalyserMultipartExploitProgress(t *testing.T)
// progress puis 3 fichiers → Statut analyse, Parties 4, PartiesFichier 3, Progress true, FichiersApresProgress 3
func TestAnalyserMultipartProgressApresFichiers(t *testing.T) // 2 fichiers puis progress → FichiersApresProgress 0, Progress true
func TestAnalyserMultipartImbrique(t *testing.T)
// progress + 900 fichiers `files[R%05d][a][a][a]` → Parties 901, PartiesFichier 900, ProfondeurMax 4, Statut analyse
func TestAnalyserMultipartTronque(t *testing.T)       // même corps coupé à la moitié, tronque=true → Statut tronque, 1 ≤ Parties < 901
func TestAnalyserMultipartCoupeSansTronque(t *testing.T) // coupé, tronque=false → Statut malforme
func TestAnalyserMultipartLimite(t *testing.T)        // 901 parties, PartiesMax 500 → Statut limite, Parties 500
func TestAnalyserMultipartSansBoundary(t *testing.T)  // Content-Type sans boundary → Statut malforme, Parties 0
func TestAnalyserMultipartLF(t *testing.T)            // fins de ligne LF seules → Statut analyse, comptes identiques au CRLF
func TestAnalyserMultipartFilename(t *testing.T)
// filename="<?PHP x" → FilenamePHP ; filename="a|O:8:" → FilenameObjet ;
// contenu de fichier "<?php" avec filename "photo.jpg" → les deux false
func TestAnalyserMultipartDispositionLaxiste(t *testing.T)
// `form-data; name=PHP_SESSION_UPLOAD_PROGRESS` (sans guillemets) → Progress true ;
// `form-data; name="x"; filename=` → PartiesFichier 1
func TestAnalyserMultipartEnvoiLegitime(t *testing.T)
// 1 champ texte + 1 fichier → Statut analyse, Parties 2, PartiesFichier 1, ProfondeurMax 0, Progress false
func FuzzAnalyserMultipart(f *testing.F) // ne panique jamais ; Parties ≤ PartiesMax ; Statut parmi les 4 valeurs
func BenchmarkAnalyserMultipart(b *testing.B) // corps de TestAnalyserMultipartImbrique
```

- [ ] **Étape 2 : lancer les tests.** `go test -count=1 -run 'Multipart|BoundaryPHP' ./cmd/sbxwaf/`. Attendu : échec de compilation, symboles non définis.
- [ ] **Étape 3 : écrire `SBX/multipart.go`** selon les interfaces et les règles ci-dessus.
- [ ] **Étape 4 : relancer.** Même commande, puis `go test -count=1 -run '^$' -fuzz FuzzAnalyserMultipart -fuzztime 30s ./cmd/sbxwaf/`, puis la suite complète. Attendu : tout passe, aucun échec du fuzz.
- [ ] **Étape 5 : commit.** `feat(sbxwaf): analyseur multipart borné à la manière de PHP (ref #3257)`

### Tâche 2 : signatures structurelles dans le moteur de règles

**Fichiers :**
- Modifier : `SBX/rules.go` (types `compiledCategory`, `rulesData`, chargeur `loadRulesJSON`, `Integrite`)
- Tests : `SBX/structurel_test.go`

**Interfaces :**
- Consomme : `ResultatMultipart` (tâche 1).
- Produit :

```go
type signatureStructurelle struct {
	id, check, severity, cve, confidence string
	params map[string]int
}
// compiledCategory gagne : structurelles []signatureStructurelle

type DetectionStructurelle struct {
	Categorie string
	RuleID    string
	Severity  string // celle de la signature, sinon celle de la catégorie
	CVE       string
}

func (r *Rules) EvaluerStructurel(res ResultatMultipart) []DetectionStructurelle
```

Forme JSON dans une catégorie : `"structural": [{"id", "check", "params": {nom: entier}, "severity" (facultatif), "cve", "source", "confidence", "seuil" (facultatif), "desc"}]`. Champs inconnus ignorés. Contrôles connus et paramètres requis (déclenchement à `>=`) :

| `check` | Paramètre | Déclenche si |
|---|---|---|
| `upload_progress_fichiers` | `fichiers_apres_min` (≥ 1) | `Progress && FichiersApresProgress >= fichiers_apres_min` |
| `parties_nombre` | `parties_min` (≥ 1) | `Parties >= parties_min` |
| `noms_profondeur` | `profondeur_min` (≥ 1) | `ProfondeurMax >= profondeur_min` |
| `filename_charge` | aucun | `FilenamePHP \|\| FilenameObjet` |

- Chaque entrée `structural` d'une catégorie activée compte dans `declares`.
- Une entrée rejetée est nommée dans `rejetes` (son `id`, sinon `<catégorie>#<index>`) : contrôle inconnu, paramètre absent ou `< 1`, `id` vide, ou catégorie dont le mode n'est pas `detect` (l'analyse en flux ne peut pas bloquer).
- `Integrite()` compte les signatures structurelles chargées dans `charges`.
- `EvaluerStructurel` parcourt les catégories activées dans l'ordre du fichier, puis les signatures dans l'ordre ; il rend toutes celles qui déclenchent.
- Les signatures structurelles n'entrent jamais dans `MatchDetail`.

- [ ] **Étape 1 : écrire les tests qui échouent.** Les corpus sont écrits dans `t.TempDir()`, comme `integrite_test.go`.

```go
func TestStructurelChargeEtCompte(t *testing.T)
// php2shell detect : 4 signatures valides + 1 check "inconnu" (id "x-1") + 1 sans params (id "x-2")
// → charges == motifs + 4 ; declares == motifs + 6 ; rejetes contient "x-1" et "x-2"
func TestStructurelHorsDetectRejete(t *testing.T) // catégorie mode block avec structural → ses ids dans rejetes, EvaluerStructurel vide
func TestEvaluerStructurelSeuils(t *testing.T)
// parties_min 50 : Parties 49 → rien, 50 → "php2shell-002" ; profondeur_min 12 : 11 → rien, 12 → "php2shell-003" ;
// fichiers_apres_min 2 : Progress+1 → rien, Progress+2 → "php2shell-001" ; Progress false + 5 → rien ;
// FilenameObjet → "php2shell-004" ; Severity de la signature si renseignée, sinon de la catégorie
func TestEvaluerStructurelCategorieDesactivee(t *testing.T) // enabled false → nil
func TestStructurelNeMasquePasMatchDetail(t *testing.T)
// php2shell placée AVANT sqli : MatchDetail("GET", "/", "q=union select 1", "", "ua", true, nil) → cat "sqli", hit
func TestStructurelRechargementAChaud(t *testing.T)
// parties_min 50 → 10, nouvelle mtime, Maybe() → Parties 10 déclenche
```

- [ ] **Étape 2 : lancer.** `go test -count=1 -run 'Structurel' ./cmd/sbxwaf/`. Attendu : échec de compilation.
- [ ] **Étape 3 : implémenter** dans `SBX/rules.go`. Les paramètres JSON sont lus comme nombres et convertis en `int` ; un non-entier rejette la signature.
- [ ] **Étape 4 : relancer** les tests ciblés, puis la suite complète (`TestIntegrite*` compris). Attendu : tout passe.
- [ ] **Étape 5 : commit.** `feat(sbxwaf): signatures structurelles chargées ou rejetées nommément (ref #3257)`

### Tâche 3 : vhosts PHP déclarés

**Fichiers :**
- Modifier : `SBX/vhostprofiles.go` (`fichierProfils`, `VhostProfiles`, chargeur)
- Modifier : `NG/composants/waf/config/vhost_profiles.json`
- Modifier : `NG/composants/waf/scripts/waf-profils-fusion` (`fusionne` et son appelant)
- Tests : `SBX/vhostprofiles_php_test.go`, `NG/composants/waf/tests/test_waf_profils_fusion.py`

**Interfaces :**
- Produit : `func (v *VhostProfiles) estPHP(host string) bool`. Récepteur nil → `false`. Hôte normalisé comme les autres méthodes du fichier (minuscules, sans port).
- `fichierProfils` gagne `PHPServices []string \`json:"php_services"\``. Clé absente → aucun vhost PHP. Un nom de service inconnu est ignoré avec un `log.Printf` ; le fichier reste valide.
- `fusionne(livre, vivant)` rend `(neuf, services_ajoutes, vhosts_ajoutes, php_ajoutes)`. `php_services` de la box reçoit, à la fin et dans l'ordre livré, les noms livrés absents dont le service existe après fusion ; aucun nom n'est retiré. La ligne d'audit nomme les ajouts PHP ; code 10 si quelque chose a été ajouté.
- Fichier livré : `"php_services": ["nextcloud", "roundcube"]`, service `"roundcube": {"legit_paths": []}`, vhost `"webmail.gk2.secubox.in": "roundcube"`.

- [ ] **Étape 1 : écrire les tests qui échouent.**

```go
func TestVhostProfilesEstPHP(t *testing.T)
// php_services ["nextcloud"], vhost nc.example → estPHP("NC.example:443") true ; estPHP("autre.example") false
func TestVhostProfilesEstPHPNil(t *testing.T)           // (*VhostProfiles)(nil).estPHP("x") == false
func TestVhostProfilesPHPServiceInconnu(t *testing.T)   // php_services ["fantome"] → chargement sans erreur, estPHP false partout
func TestVhostProfilesLivreChargeAvecPHP(t *testing.T)  // le fichier livré se charge ; estPHP("webmail.gk2.secubox.in") et estPHP("nc.gk2.secubox.in") vrais
```

```python
def test_fusion_ajoute_php_services(): ...          # box sans clé → ["nextcloud", "roundcube"], code 10
def test_fusion_garde_php_services_de_la_box(): ... # box ["nextcloud", "perso"] → ["nextcloud", "perso", "roundcube"]
def test_fusion_php_service_inconnu_ignore(): ...   # livré ["fantome"] sans service → non ajouté
def test_fusion_rien_a_faire_php(): ...             # box déjà complète → code 0, fichier non réécrit
```

Adapter les tests existants à la nouvelle forme du tuple.
- [ ] **Étape 2 : lancer** les tests Go ciblés et Python. Attendu : échecs (méthode et clé absentes).
- [ ] **Étape 3 : implémenter** les trois fichiers.
- [ ] **Étape 4 : relancer**, puis les deux suites complètes. Attendu : tout passe.
- [ ] **Étape 5 : commit.** `feat(waf): vhosts PHP déclarés dans vhost_profiles, fusion des php_services (ref #3257)`

### Tâche 4 : capture en flux, câblage et journal

**Fichiers :**
- Créer : `SBX/capture.go`
- Modifier : `SBX/main.go` (champ du `Server`, gestionnaire, `main()`) ; `SBX/threatlog.go` (`ThreatRecord`, `logEntry`, `sevToInt`)
- Tests : `SBX/capture_test.go`, `SBX/multipart_handler_test.go` (même manière de monter un `Server` et un backend `httptest` que les tests existants de `main_test.go`)

**Interfaces :**
- Consomme : `estMultipartPHP`, `analyserMultipart`, `LimitesMultipart{}`, `ResultatMultipart.Signaux()` (tâche 1) ; `EvaluerStructurel` (tâche 2) ; `estPHP` (tâche 3).
- Produit :

```go
type captureCorps struct { /* mu sync.Mutex ; src io.ReadCloser ; buf []byte ; max int ; lus int64 ; eof, fige bool ; err error */ }
func nouvelleCapture(src io.ReadCloser, max int) *captureCorps
func (c *captureCorps) Read(p []byte) (int, error) // relaie tel quel ; copie au plus max octets tant que non figé
func (c *captureCorps) Close() error
func (c *captureCorps) figer() (prefixe []byte, lus int64, complet bool) // complet = eof && err == nil && lus == len(prefixe)

const capturesMultipartMax = 16
// Server gagne : capturesMultipart chan struct{} (nil = pas de limite, pour les tests) ; main() : make(chan struct{}, capturesMultipartMax)

type requeteMultipart struct{ ip, host, method, path, ua, contentType string }
func (s *Server) analyserCaptureMultipart(capt *captureCorps, req requeteMultipart)

// ThreatRecord gagne : Mode string ; Signaux map[string]int
// logEntry gagne : Mode `json:"mode,omitempty"` ; Signals `json:"signals,omitempty"`
// sevToInt("audit") == 10 (était 40 par le cas par défaut) ; les autres valeurs inchangées
```

**Câblage** dans le bloc `if s.rules != nil`, après le calcul de `ip` et `rawPath` et le bloc anti-robots, avant `skip :=`. Condition : `s.vhostProfiles.estPHP(r.Host) && !privateCIDR(ip) && r.Body != nil && r.Body != http.NoBody && estMultipartPHP(Content-Type)`. Elle ne dépend PAS de `ncBypass`, `isTrustedHost` ni `staticAsset` (spécification § 8, point 3).
- Si `capturesMultipart` est plein (prise non bloquante) : une ligne `Category/Action "multipart-limite"`, `Severity "audit"`, `Signaux {"concurrence": 16}`, puis rien d'autre ; la requête suit son cours.
- Sinon :
  1. `capt := nouvelleCapture(r.Body, int(fenêtre))`, avec fenêtre = `s.maxBodyInspect` (ou `defaultMaxBodyInspect`) ;
  2. `r.Body = capt` ;
  3. `defer s.analyserCaptureMultipart(capt, req)`.

  Le `defer` couvre les deux appels `proxy.ServeHTTP` et le cache média.
- Les chemins existants du corps restent tels quels. Le multipart reste « binaire » pour les regex : le préfixe n'est jamais passé à `MatchDetail`.

**`analyserCaptureMultipart`** :
1. Figer la capture, puis libérer le jeton du sémaphore.
2. Si `lus == 0`, ne rien faire.
3. Sinon : `res := analyserMultipart(prefixe, ct, !complet, LimitesMultipart{})`.
4. Pour chaque `DetectionStructurelle` : une ligne `Category: d.Categorie`, `Severity: d.Severity`, `RuleID: d.RuleID`, `Action: "detect"`, `Mode: "detect"`, `Signaux: res.Signaux()`, plus un `log.Printf("sbxwaf: DETECT %s rule=%s host=%s path=%s ip=%s parties=%d", …)`.
5. Si `res.Statut != MultipartAnalyse` : une ligne `Category/Action "multipart-" + statut`, `Severity "audit"`, `Signaux`.

Aucun appel au ban, à nft ni à l'escalade.

**Correctif du chemin texte existant** (spécification A2, § 1.2, `main.go:575-599`) :
- lire `fenêtre + 1` octets ;
- `body-inspect-truncated` seulement si plus de `fenêtre` octets ont été lus, ou si la lecture a rendu une erreur autre que `io.EOF` ; l'erreur n'est plus ignorée ;
- `MatchDetail` reçoit au plus `fenêtre` octets ;
- le `MultiReader` rejoue tout ce qui a été lu, suivi du reste.

- [ ] **Étape 1 : écrire les tests qui échouent.** Adresse cliente publique (par exemple `203.0.113.7`, posée comme le font les tests existants), vhost PHP déclaré par un `VhostProfiles` de test, corps de la tâche 1.

```go
func TestCaptureRelaieIntactEtBorne(t *testing.T) // 3 Mio lus au travers → octets identiques, prefixe 1 Mio, lus 3 Mio, complet false
func TestCaptureComplete(t *testing.T)            // 10 Ko → complet true, prefixe == corps
func TestCaptureFigeeIgnoreLaSuite(t *testing.T)  // figer() puis Read → la lecture relaie encore, prefixe inchangé ; sans course sous -race
func TestMultipartPHPDetecteProgressSansBloquer(t *testing.T)
// progress + 2 fichiers → backend reçoit un corps de même sha256, réponse 200 du backend ;
// journal : 1 ligne category "php2shell", rule_id "php2shell-001", action "detect", mode "detect", signals.parties == 3 ;
// l'adresse n'a aucun enregistrement de ban, aucun appel nft
func TestMultipartNonPHPPasAnalyse(t *testing.T)   // même corps, vhost non PHP → aucune ligne php2shell ni multipart-*
func TestMultipartLANExempte(t *testing.T)         // adresse 192.168.1.10 → aucune ligne
func TestMultipartNcBypassAnalyse(t *testing.T)    // vhost PHP, chemin /index.php/login/v2/ → ligne php2shell
func TestMultipartGrosEnvoiTronque(t *testing.T)   // 1 fichier de 3 Mio → backend reçoit 3 Mio intacts ; 1 ligne multipart-tronque severity "audit" ; aucune php2shell
func TestMultipartBackendNeLitPas(t *testing.T)    // backend rend 413 sans lire → pas de panique ; aucune ligne php2shell
func TestMultipartConcurrenceLimite(t *testing.T)  // sémaphore de capacité 1 déjà pris → ligne multipart-limite, requête relayée intacte
func TestMultipartRegexInchangee(t *testing.T)     // multipart contenant "union select" sur vhost PHP → pas de 403
func TestSevToIntAudit(t *testing.T)               // sevToInt("audit") == 10 ; "critical" 90 ; "inconnu" 40
func TestThreatLogModeEtSignaux(t *testing.T)      // une ligne porte "mode" et "signals" ; une ligne sans eux n'a pas ces clés
func TestCorpsTexteExactementFenetrePasTronque(t *testing.T) // corps JSON de exactement 1 Mio → aucune ligne body-inspect-truncated, backend reçoit tout
func TestCorpsTexteFenetrePlusUnTronque(t *testing.T)        // 1 Mio + 1 → une ligne body-inspect-truncated, backend reçoit tout
func TestCorpsTexteErreurLectureJournalisee(t *testing.T)    // lecteur en erreur après 10 octets → une ligne body-inspect-truncated
```

- [ ] **Étape 2 : lancer.** `go test -count=1 -race -run 'Capture|Multipart|SevToInt|ModeEtSignaux|CorpsTexte' ./cmd/sbxwaf/`. Attendu : échec de compilation.
- [ ] **Étape 3 : implémenter** `capture.go`, puis `threatlog.go`, puis le câblage et le champ dans `main.go`.
- [ ] **Étape 4 : relancer**, puis la suite complète avec `-race` et `go vet ./cmd/sbxwaf/`. Attendu : tout passe ; les tests existants `corpsbinaire_test.go`, `skipbody_test.go`, `inspect_test.go` et `main_test.go` restent verts.
- [ ] **Étape 5 : commit.** `feat(sbxwaf): capture multipart en flux sur les vhosts PHP, détections en mode detect (ref #3257)`

### Tâche 5 : corpus, synchronisation, documentation, version

**Fichiers :**
- Modifier : `NG/composants/waf/config/waf-rules.json`
- Modifier : `NG/composants/waf/scripts/waf-rules-sync` (`fusionne`)
- Modifier : `SBX/main.go:193` (commentaire), `NG/docs/CUTOVER.md` (section corps, lignes 196 à 229), `NG/README.md`, `NG/debian/changelog`
- Tests : `SBX/corpus_livre_test.go`, `NG/composants/waf/tests/test_waf_rules_sync.py`

**Interfaces :**
- Consomme : le schéma `structural` (tâche 2) et le câblage (tâche 4).

Catégorie à ajouter en **dernière** position de `categories` :

```json
"php2shell": {
  "name": "PHP2Shell (CVE-2026-109618, CVE-2026-109619)",
  "severity": "critical", "mode": "detect", "enabled": true, "patterns": [],
  "structural": [
    {"id": "php2shell-001", "check": "upload_progress_fichiers", "params": {"fichiers_apres_min": 2},
     "severity": "critical", "cve": "CVE-2026-109619", "confidence": "haute",
     "desc": "PHP_SESSION_UPLOAD_PROGRESS suivi d'au moins deux parties fichier (la seconde déclenche l'use-after-free)"},
    {"id": "php2shell-002", "check": "parties_nombre", "params": {"parties_min": 50},
     "severity": "high", "cve": "CVE-2026-109618", "confidence": "moyenne", "seuil": "provisoire, non sourcé (2026-10-29)",
     "desc": "Nombre anormal de parties (sources : 149 parties t[], ~900 parties en moins de 1 Mo)"},
    {"id": "php2shell-003", "check": "noms_profondeur", "params": {"profondeur_min": 12},
     "severity": "high", "cve": "CVE-2026-109618", "confidence": "moyenne", "seuil": "provisoire, non sourcé (2026-10-29)",
     "desc": "Noms de champ imbriqués profondément (files[R00001][a][a][a]…)"},
    {"id": "php2shell-004", "check": "filename_charge", "params": {},
     "severity": "critical", "cve": "CVE-2026-109618, CVE-2026-109619", "confidence": "haute",
     "desc": "Nom de fichier contenant <?php ou |O: (Splunk)"}
  ]
}
```

Chaque signature porte aussi `"source"` : la liste des quatre URL de la spécification (Datadog Security Labs, Akamai, Splunk Research, tracker Debian), recopiées du prompt du propriétaire. `_meta` : `version` `1.6.0`, `updated` `2026-10-29`, `changelog` d'une phrase sur la catégorie `php2shell` (detect, structurelle, seuils provisoires).

`waf-rules-sync` : `_meta` de la copie livrée remplace celui de la box. Les autres clés hors `categories` gardent la règle actuelle.

- [ ] **Étape 1 : écrire les tests qui échouent.**

```go
func TestCorpusLivreSansRejet(t *testing.T)
// LoadRules("../../../secubox-waf-ng/composants/waf/config/waf-rules.json") → rejetes vide ;
// EvaluerStructurel(résultat de l'exploit de la tâche 1) contient "php2shell-001" et "php2shell-002"
func TestCorpusLivrePhp2shellEnDernier(t *testing.T) // la dernière catégorie du fichier est "php2shell", mode "detect"
```

```python
def test_sync_propage_meta(): ...   # box _meta 1.5.2, livré 1.6.0 → résultat _meta.version == "1.6.0"
def test_sync_garde_generees(): ... # le comportement existant reste vrai (catégorie generated conservée)
```

- [ ] **Étape 2 : lancer.** Tests Go ciblés et Python. Attendu : échecs (catégorie absente, `_meta` non propagé).
- [ ] **Étape 3 : écrire** le corpus, le correctif de `waf-rules-sync`, le commentaire de `main.go:193` sans CrowdSec, puis la documentation :
  - `CUTOVER.md` : le multipart est capturé en flux sur les vhosts PHP ; statuts `multipart-*` ; gravité `audit` = 10 ;
  - README : catégorie `php2shell`, `php_services`, retour arrière par `"enabled": false` à chaud.
- [ ] **Étape 4 : écrire l'entrée de changelog** `1.31.0-1~trixie1`, datée du jour. Elle porte toutes les tâches et le retour arrière.
- [ ] **Étape 5 : relancer** les deux suites complètes (Go avec `-race`, Python), puis `python3 -m json.tool` sur les deux JSON modifiés. Attendu : tout passe.
- [ ] **Étape 6 : commit.** `feat(waf): catégorie php2shell 1.6.0, _meta propagé, secubox-waf-ng 1.31.0 (ref #3257)`

---

## Après la branche (contrôleur, hors sous-agents)

1. Ouvrir les issues annexes de la spécification (§ 8, point 6), une par constat.
2. Construire le paquet arm64, publier par `scripts/apt-publier.sh` après fusion, puis faire le canari :
   - gk1 d'abord, en `detect` ;
   - observer les lignes `php2shell` et `multipart-*`, le CPU et la mémoire de sbxwaf ;
   - puis gk2.

   Retour arrière : `"enabled": false` sur la catégorie (rechargement à chaud), ou le paquet précédent par apt.
3. Mesurer sur le parc la distribution réelle des parties et des profondeurs, pour remplacer les seuils provisoires.
