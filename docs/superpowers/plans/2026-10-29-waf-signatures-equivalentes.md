<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Signatures équivalentes à PHP2Shell dans sbxwaf (#3273) — plan d'implémentation

> **Pour les agents :** sous-skill requis : superpowers:subagent-driven-development (recommandé) ou superpowers:executing-plans, tâche par tâche. Les étapes utilisent des cases (`- [ ]`).

**Objectif :** sbxwaf repère, en mode `detect`, les sondes et attaques équivalentes à PHP2Shell visant Roundcube, Nextcloud et PHP (R-RC1 à R-RC3, R-IMG1, R-IMG2, R-NC1, R-NC2, R-PHP1 à R-PHP4, C1 à C5, étiquettes d'outil), et transmet chaque constat à actord avec sa gravité réelle, sans jamais bloquer ni bannir.

**Architecture :**
- Le moteur de signatures structurelles de #3257 (`EvaluerStructurel` sur un `ResultatMultipart`) devient un moteur sur une **entrée PHP** (`EntreePHP`) : chemin, méthode, paramètres de requête normalisés comme PHP, en-têtes utiles, et, si capturé, le corps urlencoded, multipart, XML ou les 64 premiers octets d'un `PUT`.
- L'entrée est préparée avant le relais (lecture d'en-têtes et de la chaîne de requête seulement) ; le corps passe par la capture en flux de #3257, bornée par contrôle ; l'évaluation tombe dans le `defer`, après la réponse.
- Chaque signature déclare son contrôle (`check`), ses paramètres et, au besoin, les services où elle s'applique (`services`). Les nouvelles catégories du corpus sont `roundcube`, `nextcloud` et `php_requete` ; `php2shell` gagne C1 à C4.

**Pile :** Go 1.22, bibliothèque standard seule (`vendor/`, `CGO_ENABLED=0`) ; Python 3 pour `waf-rules-sync` ; paquet Debian `secubox-waf-ng`.

**Spécification (autorité) :** `docs/superpowers/specs/2026-10-29-waf-signatures-equivalentes-design.md`. Interfaces reprises de `docs/superpowers/plans/2026-10-29-waf-php2shell.md` et de ses arbitrages R1 à R16 (`docs/superpowers/plans/2026-10-29-waf-php2shell-arbitrages.md`).

## Contraintes globales

- `SBX` = `packages/secubox-toolbox-ng/cmd/sbxwaf/` ; `NG` = `packages/secubox-waf-ng/`. sbxwaf est construit par le paquet **secubox-waf-ng** depuis le module Go `packages/secubox-toolbox-ng` (`NG/debian/rules:35-40`).
- Tests Go, depuis `packages/secubox-toolbox-ng` (dossier du module) : ciblés `GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local go test -count=1 -race -run '<motif>' ./cmd/sbxwaf/` ; complets `GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local go test -count=1 -race ./...`, puis `go vet ./cmd/sbxwaf/`.
- Tests Python, depuis la racine du worktree : `/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python -m pytest packages/secubox-waf-ng/composants/waf/tests/ -q`.
- **TDD** : chaque étape d'implémentation suit un test qui échoue sur une assertion (ou à la compilation pour un symbole neuf), lancé et vu rouge.
- **Mode `detect` pour toute nouvelle règle** : chaque catégorie qui porte une signature structurelle a `"mode": "detect"` (le chargeur rejette déjà toute autre valeur, `SBX/rules.go:160`). Aucun appel à `s.ban.Record`, `appliquerBan`, nft ni au compteur d'escalade ; aucune réponse modifiée.
- **R12** : tous les clients sont analysés, réseau local et 127.0.0.1 compris ; `ThreatLog.Record` journalise une adresse privée sous `"local"` et ne l'émet jamais vers actord (`SBX/threatlog.go:240-290`). Ne rien ajouter qui contourne ce chemin.
- **Gravité réelle vers actord** : chaque ligne porte la `severity` de sa signature (projetée par `sevToInt`, `critical` = 90, `high` = 75, `medium` = 50, `low` = 25). Une étiquette d'outil ne change jamais la gravité.
- **Aucune lecture de corps au-delà de la fenêtre de #3257** (`fenetreCapture()` = min(`--max-body-inspect`, 1 Mio), `SBX/capture.go:233`), aucun tampon ajouté avant le relais. Coût par contrôle :

| Contrôle | Ce qui est lu | Borne |
|---|---|---|
| Normalisation des noms, R-RC1, R-RC3, C4 (requête) | chaîne de requête | sa longueur ; au plus 64 paramètres retenus |
| R-RC3, C4 (corps) | corps urlencoded capturé | `fenetreCapture()` ; 64 paramètres retenus |
| R-RC2, R-IMG1, R-PHP1, R-PHP4, C2, C3, C5 | préfixe multipart déjà capturé par #3257 | `fenetreCapture()` ; 64 octets par fichier lu ; 64 champs retenus |
| R-IMG2 | 64 premiers octets d'un `PUT` WebDAV | 64 octets, sans jeton |
| R-PHP2 | prologue XML | min(4096, `fenetreCapture()`), sans jeton |
| R-PHP3, R-NC1 (session) | en-têtes `Cookie` | parcours linéaire, rien de stocké |
| R-NC1, R-NC2, C1, étiquettes | méthode, chemin, `Authorization`, `Destination`, `Content-Type`, `Content-Length`, `Transfer-Encoding` | en-têtes seulement |
| R-NC1 (rafale) | compteur par IP | 4096 IP, 64 horodatages par IP |

- **Seuils non sourcés** : toute constante Go ou tout paramètre JSON sans source primaire porte le commentaire ou le champ `"seuil": "provisoire, non sourcé (2026-10-29)"` (même convention que `php2shell-002` et `-003`). Sourcés : 1 020 parties (`max_multipart_body_parts`), 1 000 variables (`max_input_vars`), 70 caractères (RFC 2046 §5.1.1), 5 appels par 1 200 s (nextcloud/server#62091), 64 octets de R-IMG1 (spécification § 3.3).
- Le journal ne contient jamais un corps, un nom de fichier ni la valeur d'un paramètre : des compteurs (`signals`), des booléens et des étiquettes seulement.
- Version : `secubox-waf-ng` passe de `1.31.0-1~trixie1` à **`1.32.0-1~trixie1`**, une seule fois (tâche 8), entrée datée `Thu, 29 Oct 2026 HH:MM:SS +0100`. Vérifier d'abord `head -1 NG/debian/changelog`.
- Jamais de mention de CrowdSec ; jamais de bypass WAF (aucune entrée `waf_bypass`, aucune route hors sbxwaf).
- En-tête SPDX CMSD-1.0 sur tout fichier créé (modèle : `SBX/multipart.go:1-4`). Commentaires et messages en français, comme le code voisin. Chaque fonction qui transcrit PHP cite le fichier et la ligne qu'elle reproduit, comme `SBX/multipart.go`.
- Commits : `type(portée): message (ref #3273)`, terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Jamais de push ni de connexion à une box.

## Points d'attention pour la relecture

1. **Trafic légitime d'un client Nextcloud** (`PROPFIND` sans DTD, `PUT` d'un vrai JPEG, cookies de session, `POST` OCS authentifié) : aucune ligne. Tests : tâche 4, `TestNextcloudTraficLegitimeMuet` ; tâche 5, `TestPHPGeneriquePropfindLegitimeMuet`.
2. **Envoi Roundcube légitime** avec destinataires multi-lignes (`_to`, `_cc`, `_bcc`) et corps `_message` multi-ligne, en urlencoded comme en multipart : aucune ligne. Test : tâche 3, `TestRoundcubeEnvoiLegitimeMuet`.
3. **Encodages hostiles dans les noms et valeurs** (`%zz`, `%4`, octet nul, `[` orphelin, nom vide) : aucune panique, lecture identique à PHP. Tests : tâche 1, `TestURLDecodePHP`, `TestNomPHP`, `FuzzLireParametresPHP`.
4. **En-tête `Cookie` répété sur plusieurs lignes** (HTTP/2 découpe les cookies) : R-PHP3 et la session Nextcloud lisent toutes les lignes. Tests : tâche 1, `TestParcourirCookiesPHP` (deux lignes) ; tâche 4, `TestSessionNextcloud`.
5. **Requête sans corps ou d'une autre méthode** (`GET`, `PUT` en `chunked`, `POST` JSON sans `Content-Length`) : C1 ne se déclenche pas, aucun jeton du sémaphore n'est pris. Tests : tâche 6, `TestCorpsSansLongueur` ; tâche 2, `TestRequetePHPJetonRenduSansCorps`.

---

### Tâche 1 : normalisation PHP des noms (paramètres, cookies)

**Fichiers :**
- Créer : `SBX/nomsphp.go`
- Tests : `SBX/nomsphp_test.go`

**Interfaces :**
- Consomme : rien.
- Produit :

```go
// nomPHP : nom de base que PHP enregistre (main/php_variables.c, php_register_variable_ex, PHP-8.2).
// ok=false quand PHP ignore la variable (nom vide après les étapes ci-dessous).
func nomPHP(brut string) (nom string, ok bool)
// urldecodePHP : php_url_decode (ext/standard/url.c) : « + » → espace, %XX → octet, %
// suivi d'autre chose que deux chiffres hexadécimaux laissé tel quel.
func urldecodePHP(s string) string

type ParametrePHP struct{ Nom, Valeur string } // Nom normalisé, Valeur décodée
type ParametresPHP struct {
	Retenus   []ParametrePHP // seulement les noms de nomsRetenusPHP, au plus parametresRetenusMax, dans l'ordre
	Variables int            // segments non vides séparés par « & » (max_input_vars, C4)
}
const parametresRetenusMax = 64 // provisoire, non sourcé (2026-10-29)
var nomsRetenusPHP = map[string]bool{ /* _from _uid _flag _q _filter _headers _scope _mbox _search
	_subject _replyto _followupto _charset _task _action */ }
func lireParametresPHP(brut string) ParametresPHP
func (p ParametresPHP) Valeurs(nom string) []string // toutes les occurrences, dans l'ordre
// parcourirCookiesPHP : php_default_treat_data, PARSE_COOKIE (main/php_variables.c) : chaque
// ligne coupée sur « ; », blancs de tête (isspace) sautés, nom jusqu'au premier « = »
// (ligne entière sinon), nom NON décodé (PHP ≥ 8.0), puis nomPHP. f reçoit le nom brut
// (blancs de tête retirés) et le nom normalisé ; rien n'est stocké.
func parcourirCookiesPHP(lignes []string, f func(brut, nom string))
```

Algorithme de `nomPHP`, à confronter ligne à ligne au fichier `main/php_variables.c` de la branche PHP-8.2 (le récupérer, citer son sha256 dans l'en-tête du fichier, comme `SBX/multipart.go:24-27`) :
1. couper au premier octet nul ;
2. sauter les espaces (octet `' '` seulement) de tête ;
3. parcourir : `' '` et `'.'` deviennent `'_'` ; au premier `'['`, arrêter ;
4. base vide → `("", false)` ;
5. après ce `'['` : s'il existe un `']'` plus loin, le nom est la base ; sinon le `'['` devient `'_'` et la suite est recopiée **telle quelle** (sans conversion des points).

`lireParametresPHP` : découpe sur `&` ; segment sans `=` → valeur vide ; nom décodé par `urldecodePHP` puis `nomPHP` ; valeur décodée seulement si le nom est retenu.

- [ ] **Étape 1 : écrire les tests qui échouent.**

```go
func TestNomPHP(t *testing.T) // table brut → (nom, ok) :
// "_from"→("_from",true) ; ".from"→("_from",true) ; " _from"→("_from",true) ; "a.b c"→("a_b_c",true) ;
// "_from[]"→("_from",true) ; "_from[x]"→("_from",true) ; "_[Host-x"→("__Host-x",true) ;
// "a[b.c"→("a_b.c",true) ; "[from"→("",false) ; "_fr\x00om"→("_fr",true) ; ""→("",false) ; "   "→("",false)
func TestURLDecodePHP(t *testing.T)
// "a+b"→"a b" ; "%41"→"A" ; "%zz"→"%zz" ; "%4"→"%4" ; "%0d%0a"→"\r\n" ; "%00"→"\x00"
func TestLireParametresPHP(t *testing.T)
// "_task=settings&.from=edit-%21x&&q=1&_uid" → Variables 4 ; Valeurs("_from") == ["edit-!x"] ;
// Valeurs("_task") == ["settings"] ; Valeurs("q") == nil (non retenu) ; Valeurs("_uid") == [""]
// "_uid=1&_uid=2" → Valeurs("_uid") == ["1","2"]
func TestLireParametresPHPPlafond(t *testing.T) // 100 × "_uid=1" → len(Retenus) == 64, Variables == 100
func TestParcourirCookiesPHP(t *testing.T)
// lignes ["a=1; _[Host-x=y", " b.c=2"] → paires (brut, nom) dans l'ordre :
// ("a","a"), ("_[Host-x","__Host-x"), ("b.c","b_c") ; ["%5F%5BHost-x=1"] → ("%5F%5BHost-x","%5F%5BHost-x")
func FuzzLireParametresPHP(f *testing.F) // ne panique jamais ; len(Retenus) <= 64 ; Variables >= len(Retenus)
```

- [ ] **Étape 2 : lancer.** `go test -count=1 -run 'NomPHP|URLDecodePHP|ParametresPHP|CookiesPHP' ./cmd/sbxwaf/`. Attendu : échec de compilation, symboles non définis.
- [ ] **Étape 3 : écrire `SBX/nomsphp.go`** selon les interfaces et l'algorithme ci-dessus.
- [ ] **Étape 4 : relancer**, puis `go test -count=1 -run '^$' -fuzz FuzzLireParametresPHP -fuzztime 30s ./cmd/sbxwaf/`, puis la suite complète. Attendu : tout passe.
- [ ] **Étape 5 : commit.** `feat(sbxwaf): noms de paramètres et de cookies normalisés comme PHP (ref #3273)`

### Tâche 2 : socle — entrée PHP, moteur par service, capture urlencoded, câblage

**Fichiers :**
- Créer : `SBX/entreephp.go`
- Modifier : `SBX/rules.go` (`signatureStructurelle`, `structurelJSON`, `compileStructurel`, `declenche`, `EvaluerStructurel`) ; `SBX/vhostprofiles.go` (`estPHP` → `servicePHP`) ; `SBX/capture.go` (`analyserCaptureMultipart` remplacée) ; `SBX/main.go:525-560` (bloc PHP2SHELL)
- Tests : `SBX/entreephp_test.go` ; adapter `SBX/capture_test.go` (`TestAnalyseCapturePaniqueRattrapee`, `TestAnalyseCaptureNonRelayeeMuette`)

**Interfaces :**
- Consomme : `lireParametresPHP`, `ParametresPHP` (tâche 1) ; `analyserMultipart`, `ResultatMultipart.Signaux()`, `nouvelleCapture`, `prendreCapture`, `rendreCapture`, `limiteCaptureAtteinte`, `journaliserMultipart`, `requeteMultipart`, `fenetreCapture` (#3257).
- Produit :

```go
// vhostprofiles.go — service = nom du service déclaré PHP ; "" pour un hôte PHP reconnu par
// un motif php_hotes seulement. estPHP(host) devient `_, ok := v.servicePHP(host); return ok`.
func (v *VhostProfiles) servicePHP(host string) (service string, php bool)

// entreephp.go
type genreCorps int
const (
	corpsAucun genreCorps = iota
	corpsMultipart
	corpsUrlencoded
	corpsXML   // branche ajoutée par la tâche 5
	corpsDebut // branche ajoutée par la tâche 4 (64 premiers octets d'un PUT)
)
type EntreePHP struct {
	Service   string             // servicePHP ; "" = hôte par motif : toutes les familles s'appliquent
	Methode   string             // r.Method tel quel
	Chemin    string             // r.URL.Path (décodé)
	Requete   ParametresPHP      // r.URL.RawQuery
	Corps     *ParametresPHP     // corps urlencoded capturé, sinon nil
	Multipart *ResultatMultipart // corps multipart analysé, sinon nil
	// les tâches 3 à 7 ajoutent leurs champs ici (voir leurs Interfaces)
}
func estUrlencodedPHP(contentType string) bool // même coupe que estMultipartPHP, comparé à application/x-www-form-urlencoded
func (s *Server) nouvelleEntreePHP(r *http.Request, service string) *EntreePHP
func (s *Server) corpsACapturer(r *http.Request, e *EntreePHP) (genre genreCorps, plafond int, jeton bool)
func completerCorps(e *EntreePHP, genre genreCorps, prefixe []byte, contentType string, complet bool)
func (e *EntreePHP) Signaux() map[string]int // Multipart.Signaux() si présent, plus les clés des tâches suivantes
func (s *Server) analyserRequetePHP(capt *captureCorps, genre genreCorps, e *EntreePHP, rm requeteMultipart, relaye, jeton bool)

// rules.go
// signatureStructurelle gagne : services []string ; structurelJSON gagne : Services []string `json:"services"`
func (s signatureStructurelle) declenche(e *EntreePHP) bool // contrôles multipart : faux si e.Multipart == nil
func (r *Rules) EvaluerPHP(e *EntreePHP) []DetectionStructurelle
// EvaluerStructurel(res) est gardée : return r.EvaluerPHP(&EntreePHP{Multipart: &res})
```

Règles :
- Filtre de service dans `EvaluerPHP` : `services` vide → toujours ; sinon `e.Service == ""` ou `e.Service` dans la liste.
- `corpsACapturer` : sans corps (`nil`, `http.NoBody`) → `(corpsAucun, 0, false)`. Multipart → `(corpsMultipart, fenetreCapture(), true)`. Urlencoded → `(corpsUrlencoded, fenetreCapture(), true)`. Sinon `corpsAucun`.
- `completerCorps` : multipart → `Multipart = analyserMultipart(prefixe, ct, !complet, LimitesMultipart{})` ; urlencoded → `Corps = lireParametresPHP(string(prefixe))`.
- `analyserRequetePHP` reprend `analyserCaptureMultipart` (`SBX/capture.go:182-226`) : jeton rendu en `defer` si `jeton` ; `recover` journalisé `"sbxwaf: ERREUR analyse PHP host=… path=… ip=… : …"` avec la pile ; capture figée si non nil ; rien si `!relaye` ou `s.rules == nil` ; `completerCorps` seulement si `capt != nil && lus > 0` ; une ligne par `DetectionStructurelle` (`Action "detect"`, `Mode modeDetect`, `Signaux: e.Signaux()`) et un `log.Printf("sbxwaf: DETECT %s rule=%s host=%s path=%s ip=%s", …)` ; ligne d'état `multipart-<statut>` (gravité `audit`) si `e.Multipart != nil` et statut différent de `analyse`.
- **Câblage** (`SBX/main.go`, à la place du bloc PHP2SHELL, même position, mêmes commentaires sur R12 et ncBypass) : si `s.rules.aDesStructurelles()` et `servicePHP(r.Host)` dit PHP → `e := s.nouvelleEntreePHP(r, service)` ; `genre, plafond, jeton := s.corpsACapturer(r, e)` ; si `jeton && !s.prendreCapture()` → `s.limiteCaptureAtteinte(rm)`, puis `genre, jeton = corpsAucun, false` (les contrôles sans corps restent évalués) ; si `genre != corpsAucun` → `capt := nouvelleCapture(r.Body, plafond, r.ContentLength)` et `r.Body = capt` ; enfin `defer func() { s.analyserRequetePHP(capt, genre, e, rm, relaye, jeton) }()`.

- [ ] **Étape 1 : écrire les tests qui échouent.**

```go
func TestServicePHP(t *testing.T)
// profil : services nextcloud et roundcube, vhost nc.example → nextcloud, php_services les deux, php_hotes ["^webmail\\."]
// servicePHP("NC.example:443") == ("nextcloud", true) ; ("webmail.autre") == ("", true) ; ("x.example") == ("", false) ;
// (*VhostProfiles)(nil).servicePHP("x") == ("", false)
func TestEstUrlencodedPHP(t *testing.T)
// "application/x-www-form-urlencoded"→true ; "Application/X-WWW-Form-Urlencoded; charset=UTF-8"→true ;
// "application/x-www-form-urlencodedX"→false ; "multipart/form-data; boundary=x"→false ; ""→false
func TestNouvelleEntreePHP(t *testing.T)
// GET http://webmail.example/?_task=mail&.from=x, service "roundcube" → Service "roundcube", Methode "GET",
// Chemin "/", Requete.Valeurs("_from") == ["x"], Corps == nil, Multipart == nil
func TestCorpsACapturer(t *testing.T)
// POST multipart → (corpsMultipart, fenetreCapture(), true) ; POST urlencoded → (corpsUrlencoded, fenetreCapture(), true) ;
// GET sans corps → (corpsAucun, 0, false) ; POST application/json → (corpsAucun, 0, false)
func TestCompleterCorpsUrlencoded(t *testing.T) // "_uid=1&_uid=2&a=b" → Corps.Variables 3, Corps.Valeurs("_uid") == ["1","2"]
func TestCompleterCorpsMultipart(t *testing.T)  // corpsExploit() → Multipart.Parties 4, Multipart.Progress true
func TestEvaluerPHPFiltreServices(t *testing.T)
// signature filename_charge, "services": ["roundcube"] ; Multipart.FilenamePHP true :
// Service "nextcloud" → aucune ; "roundcube" → 1 ; "" → 1
func TestStructurelServicesMalTypeRejete(t *testing.T) // "services": "roundcube" (chaîne) → son id dans rejetes
func TestRequetePHPUrlencodedRelayeIntact(t *testing.T)
// banc de nouveauBancMultipart, sémaphore de capacité 1 : deux POST urlencoded de 2 Mio sur nc.example
// → le backend reçoit chaque fois un corps de même sha256 ; len(s.capturesMultipart) == 0 après chacun ;
// aucune ligne multipart-concurrence
func TestRequetePHPJetonRenduSansCorps(t *testing.T) // GET sur nc.example, sémaphore capacité 1 → len == 0 après, aucune ligne
```

Adapter : `TestAnalyseCapturePaniqueRattrapee` appelle `s.analyserRequetePHP(nil, corpsMultipart, nil, requeteMultipart{host: "nc.example"}, true, true)` (entrée nil : panique) et attend `"ERREUR analyse PHP"` ; `TestAnalyseCaptureNonRelayeeMuette` appelle `analyserRequetePHP(capt, corpsMultipart, &EntreePHP{}, rm, false, true)`.

- [ ] **Étape 2 : lancer.** `go test -count=1 -race -run 'ServicePHP|UrlencodedPHP|EntreePHP|CorpsACapturer|CompleterCorps|EvaluerPHP|ServicesMalType|RequetePHP|AnalyseCapture' ./cmd/sbxwaf/`. Attendu : échec de compilation.
- [ ] **Étape 3 : implémenter** `entreephp.go`, puis `rules.go`, `vhostprofiles.go`, `capture.go`, enfin le câblage de `main.go`.
- [ ] **Étape 4 : relancer**, puis la suite complète avec `-race` et `go vet`. Attendu : tout passe, y compris `multipart_handler_test.go`, `capture_cablage_test.go`, `structurel_test.go`, `corpus_livre_test.go`, `vhostprofiles_php_test.go` inchangés.
- [ ] **Étape 5 : commit.** `feat(sbxwaf): entrée PHP, signatures par service, capture urlencoded (ref #3273)`

### Tâche 3 : Roundcube (R-RC1, R-RC2, R-RC3, markasjunk, R-IMG1)

**Fichiers :**
- Créer : `SBX/roundcube.go`, `SBX/magique.go`
- Modifier : `SBX/multipart.go` (`ResultatMultipart`, boucle d'`analyserMultipart`, commentaire « CE QUI EST VOLONTAIREMENT ÉVITÉ ») ; `SBX/rules.go` (`parametreRequis`, `declenche`) ; `SBX/entreephp.go`
- Tests : `SBX/roundcube_test.go`, `SBX/magique_test.go`, ajouts à `SBX/multipart_test.go`

**Interfaces :**
- Consomme : `nomPHP`, `ParametrePHP`, `parametresRetenusMax`, `nomsRetenusPHP` (tâche 1) ; `EntreePHP`, `EvaluerPHP` (tâche 2).
- Produit :

```go
// magique.go
const magiqueOctets = 64 // spécification § 3.3 (R-IMG1)
// magiqueNonRaster cherche dans debut[:min(len, 64)], marqueurs texte insensibles à la casse ASCII.
// Rend "eps" (\xC5\xD0\xD3\xC6), "ps" (%!PS), "pdf" (%PDF-), "mvg" (push graphic-context),
// "svg" (<svg, ou <?xml suivi plus loin de <image), sinon "". Ordre de test : eps, ps, pdf, mvg, svg.
func magiqueNonRaster(debut []byte) string

// roundcube.go
func fromInvalideRoundcube(v string) (invalide, bang bool) // v vide → (false,false) ; retire ^(add|edit)- puis exige ^[A-Za-z0-9_.-]+$ ; bang = reste commence par '!'
func crlfDans(v string) bool                 // \r, \n ou \x00
func drapeauInvalideRoundcube(v string) bool // un octet de [\x00-\x20\x7f(){"*%] (commit 242c6d6)
var nomsIMAPRoundcube = []string{"_uid", "_flag", "_q", "_filter", "_headers", "_scope", "_mbox", "_search"}
var nomsEnvoiRoundcube = []string{"_subject", "_from", "_replyto", "_followupto", "_charset"}

// multipart.go — ResultatMultipart gagne :
//   FilenameSession bool           // filename retenu contient '|' ET correspond à [abdisNO]:[0-9;]
//   NonRaster       bool           // un fichier LU (ni sauté, ni filename vide) a magiqueNonRaster != ""
//   Champs          []ParametrePHP // champs ordinaires dont nomPHP(name) est retenu, valeur copiée, au plus parametresRetenusMax
// entreephp.go
func (e *EntreePHP) valeurs(nom string) []string        // Requete, puis Corps, puis Multipart.Champs
func (e *EntreePHP) valeursRequete(nom string) []string // Requete seulement
// Signaux gagne la clé "from_bang" (1 si un _from de la requête est invalide et commence par '!')
```

Contrôles ajoutés à `parametreRequis` (tous sans paramètre) :

| `check` | Déclenche si |
|---|---|
| `rc_from_invalide` | une valeur de `valeursRequete("_from")` donne `invalide` |
| `filename_session` | `Multipart != nil && Multipart.FilenameSession` |
| `rc_crlf_imap` | une valeur de `valeurs(n)`, n dans `nomsIMAPRoundcube`, a `crlfDans` ; ou une valeur de `_flag` a `drapeauInvalideRoundcube` |
| `rc_crlf_envoi` | une valeur de `valeurs(n)`, n dans `nomsEnvoiRoundcube`, a `crlfDans` (`_to`, `_cc`, `_bcc`, `_message` exclus) |
| `rc_markasjunk_uid_requete` | `Methode` POST (sans casse), `valeursRequete("_uid")` non vide, et une valeur de `valeurs("_action")` commence par `plugin.markasjunk` |
| `rc_image_non_raster` | `Multipart.NonRaster` et (`_action` = `upload-photo`, ou `_task` = `settings` et `_action` = `upload`), lus par `valeurs` |

- [ ] **Étape 1 : écrire les tests qui échouent.** Corpus de test : catégorie `roundcube`, mode `detect`, `"services": ["roundcube"]` sur chaque signature, ids `rc-001` (`rc_from_invalide`, critical), `rc-002` (`filename_session`, high), `rc-003` (`rc_crlf_imap`, high), `rc-004` (`rc_crlf_envoi`, medium), `rc-005` (`rc_markasjunk_uid_requete`, low), `rc-006` (`rc_image_non_raster`, high).

```go
func TestMagiqueNonRaster(t *testing.T)
// "<svg xmlns=\"http://www.w3.org/2000/svg\">"→"svg" ; "<?xml version=\"1.0\"?>\n<image href=\"x\"/>"→"svg" ;
// "%!PS-Adobe-3.0"→"ps" ; "\xC5\xD0\xD3\xC6\x20\x00"→"eps" ; "%PDF-1.7"→"pdf" ; "push graphic-context\nviewbox 0 0 1 1"→"mvg" ;
// "\x89PNG\r\n\x1a\n"→"" ; "\xFF\xD8\xFF\xE0"→"" ; 70 espaces puis "<svg"→""
func TestFromInvalideRoundcube(t *testing.T)
// "edit-identity"→(false,false) ; "add-identity"→(false,false) ; "123"→(false,false) ; ""→(false,false) ;
// "edit-!\";i:0;O:16:\"Crypt_GPG_Engine\":"→(true,true) ; "e\xc0d\xc1i\xc2t"→(true,false) ; "edit-"→(true,false) ; "a b"→(true,false)
func TestCrlfEtDrapeauRoundcube(t *testing.T)
// crlfDans : "1\r\nA LOGOUT"→true, "1:*"→false, "a\x00"→true ;
// drapeauInvalideRoundcube : "read"→false, "read)"→true, "a b"→true, "x%"→true, "\x7f"→true, "flagged"→false
func TestAnalyserMultipartFilenameSession(t *testing.T)
// filename `x|b:0;preferences_time|b:0;preferences|s:179:"a:3:{i:0;s:57:".png` → FilenameSession true, FilenameObjet false ;
// "photo|2024.png" → false ; "a:1;.png" → false
func TestAnalyserMultipartNonRaster(t *testing.T)
// fichier "a.png" de contenu "<svg>…" → NonRaster true ; contenu PNG → false ; filename "" et contenu "<svg>" → false
func TestAnalyserMultipartChamps(t *testing.T)
// champ "_action"="upload-photo" et champ "x"="y" → Champs == [{"_action","upload-photo"}] ;
// 100 champs "_uid" → len(Champs) == 64
func TestRoundcubeSignatures(t *testing.T) // EvaluerPHP sur des EntreePHP construites, Service "roundcube" :
// requête "_task=settings&_action=upload&_from=edit-!%22;i:0;O:16:%22Crypt_GPG_Engine%22:" → ["rc-001"], Signaux()["from_bang"] == 1
// requête "_task=settings&.from=edit-%21x" → ["rc-001"] ; "_from=edit-identity" → []
// corps urlencoded "_uid=1%0d%0aA001+LOGOUT" → ["rc-003"] ; "_flag=read)" → ["rc-003"]
// corps "_subject=a%0db" → ["rc-004"] ; "_to=a%0Ab&_cc=c%0Ad&_message=l1%0Al2" → []
// POST requête "_task=mail&_action=plugin.markasjunk.junk&_uid=5" → ["rc-005"] ; même chose en GET → []
// multipart requête "_task=addressbook&_action=upload-photo", fichier SVG → ["rc-006"] ;
// requête "_task=mail&_action=upload", fichier PDF ou SVG → [] ; champ multipart "_action"="upload-photo" + SVG → ["rc-006"]
// chacune des requêtes déclenchantes avec Service "nextcloud" → []
func TestRoundcubeEnvoiLegitimeMuet(t *testing.T)
// POST urlencoded puis multipart : _to "a@x\r\nb@y", _cc et _bcc multi-lignes, _subject "Bonjour", _from "1",
// _message "l1\r\nl2", _task=mail, _action=send → aucune détection
func TestRoundcubeFromJournaliseSansBloquer(t *testing.T) // banc HTTP, profil vhost webmail.example → roundcube
// GET webmail.example/?_task=settings&_action=upload&_from=edit-!x depuis ipPublique → réponse du backend 200 ;
// une ligne category "roundcube", rule_id "rc-001", severity "critical", action "detect", mode "detect" ;
// verifierSansSanction(ipPublique) ; enveloppe émise (patron de TestCaptureLANJamaisEmiseVersActord) avec "severity":90 ;
// même requête depuis 192.168.1.10 → ligne client_ip "local", rien d'émis pour elle
```

- [ ] **Étape 2 : lancer.** `go test -count=1 -race -run 'Magique|Roundcube|FilenameSession|NonRaster|MultipartChamps' ./cmd/sbxwaf/`. Attendu : échec de compilation.
- [ ] **Étape 3 : implémenter** `magique.go`, `roundcube.go`, puis l'analyseur. Dans `analyserMultipart` : `Champs` dans la branche « champ ordinaire » (`SBX/multipart.go:647-657`) ; `NonRaster` sur `prefixe[pos0:pos0+min(blen, 64)]` de la première `m.lire` d'un fichier lu (`SBX/multipart.go:695`) ; `FilenameSession` à côté de `FilenameObjet` (`:686`). Mettre à jour le commentaire d'en-tête : seules les valeurs des champs retenus sont copiées, jamais journalisées. Puis `rules.go` et `entreephp.go`.
- [ ] **Étape 4 : relancer**, puis la suite complète (`-race`), le fuzz `FuzzAnalyserMultipart` 30 s et `go vet`. Attendu : tout passe.
- [ ] **Étape 5 : commit.** `feat(sbxwaf): signatures Roundcube R-RC1 à R-RC3 et R-IMG1 en mode detect (ref #3273)`

### Tâche 4 : Nextcloud (R-NC1, R-NC2, R-IMG2)

**Fichiers :**
- Créer : `SBX/nextcloud.go`
- Modifier : `SBX/vhostprofiles.go` (`fichierProfils`, `VhostProfiles`, chargeur) ; `SBX/entreephp.go` (champs, branche `corpsDebut`, mise à jour du compteur dans `analyserRequetePHP`) ; `SBX/main.go` (champ du `Server`, `main()`) ; `SBX/rules.go`
- Tests : `SBX/nextcloud_test.go`, ajouts à `SBX/vhostprofiles_php_test.go`

**Interfaces :**
- Consomme : `magiqueNonRaster`, `magiqueOctets` (tâche 3) ; `parcourirCookiesPHP` (tâche 1) ; `EntreePHP`, `corpsACapturer`, `analyserRequetePHP` (tâche 2).
- Produit :

```go
// vhostprofiles.go — fichierProfils gagne : FederationVhosts []string `json:"federation_vhosts"` (clé absente = aucun)
func (v *VhostProfiles) federationUtilisee(host string) bool // hôte normalisé ; nil → false

// nextcloud.go
const federationPeriode = 1200 * time.Second // nextcloud/server#62091, FederationRateLimit(limit: 5, period: 1200)
const federationIPMax = 4096                 // provisoire, non sourcé (2026-10-29)
const federationGarde = 64                   // horodatages gardés par IP ; provisoire, non sourcé (2026-10-29)
type compteurFenetre struct { /* mu sync.Mutex ; periode time.Duration ; garde, ipMax int ; parIP map[string][]time.Time */ }
func nouveauCompteurFenetre(periode time.Duration, garde, ipMax int) *compteurFenetre
// noter ajoute t pour ip et rend le nombre d'appels de ip dans ]t-periode, t], plafonné à garde.
// Carte pleine : purge des IP sans horodatage récent ; encore pleine → l'IP n'est pas suivie, rend 1.
func (c *compteurFenetre) noter(ip string, t time.Time) int
func cheminPartageFedere(chemin string) bool // /ocm/shares, /index.php/ocm/shares, /ocs/v1.php/cloud/shares, /ocs/v2.php/cloud/shares, un « / » final toléré
func sessionNextcloud(lignesCookie []string) bool // cookie nc_session_id, nc_token, nc_username, oc_sessionPassphrase, ou nom ^oc[a-z0-9]{10}$
func proxyAgenda(methode, chemin string) (uid string, ok bool) // PROPPATCH (sans casse) et ^/remote\.php/dav/principals/users/([^/]+)/calendar-proxy-(read|write)/?$
func utilisateurBasic(authorization string) (string, bool)     // « Basic » (sans casse) + base64 standard, partie avant le premier ':'
func extensionRaster(nom string) bool                          // jpg, jpeg, png, gif, webp, sans casse
// putWebDAVPremierSegment : PUT (sans casse) sur /remote.php/dav/files/… → dernier segment ;
// sur /remote.php/dav/uploads/<u>/<id>/<n> avec n décimal de valeur <= 1 → dernier segment du chemin de Destination.
func putWebDAVPremierSegment(methode, chemin, destination string) (nomCible string, ok bool)

// EntreePHP gagne : Federation, PartageFedereAnonyme bool ; AppelsFederes int ;
//                   ProxyAgenda, ProxyAgendaAutrui bool ; PutRaster bool ; MagiqueDebut string
// Server gagne : appelsFederes *compteurFenetre (nil = AppelsFederes reste 0) ;
//                main() : nouveauCompteurFenetre(federationPeriode, federationGarde, federationIPMax)
// Signaux gagne la clé "appels_federes" (si > 0)
```

Règles :
- `nouvelleEntreePHP` remplit `Federation`, `PartageFedereAnonyme` (POST sans casse, `cheminPartageFedere(Chemin)`, `Authorization` vide, `!sessionNextcloud(r.Header.Values("Cookie"))`), `ProxyAgenda`, `ProxyAgendaAutrui` (Basic présent et utilisateur ≠ uid, comparaison sans casse ; uid décodé par le chemin déjà décodé), `PutRaster` (`putWebDAVPremierSegment` ok et `extensionRaster`).
- `corpsACapturer` : `PutRaster` → `(corpsDebut, min(magiqueOctets, fenetreCapture()), false)` — sans jeton. `completerCorps` : `corpsDebut` → `MagiqueDebut = magiqueNonRaster(prefixe)`.
- `analyserRequetePHP` : si `PartageFedereAnonyme` et `s.appelsFederes != nil`, `AppelsFederes = noter(rm.ip, time.Now())` avant l'évaluation.

| `check` | Paramètre | Déclenche si |
|---|---|---|
| `nc_partage_federe` | aucun | `PartageFedereAnonyme && !Federation` |
| `nc_partage_federe_rafale` | `appels_min` | `PartageFedereAnonyme && Federation && AppelsFederes >= appels_min` |
| `nc_proxy_agenda` | aucun | `ProxyAgenda && !ProxyAgendaAutrui` |
| `nc_proxy_agenda_autrui` | aucun | `ProxyAgendaAutrui` |
| `nc_put_non_raster` | aucun | `PutRaster && MagiqueDebut != ""` |

- [ ] **Étape 1 : écrire les tests qui échouent.** Corpus de test : catégorie `nextcloud`, `"services": ["nextcloud"]`, ids `nc-001` (`nc_partage_federe`, medium), `nc-002` (`nc_partage_federe_rafale`, `appels_min` 6, high), `nc-003` (`nc_proxy_agenda`, medium), `nc-004` (`nc_proxy_agenda_autrui`, high), `nc-005` (`nc_put_non_raster`, medium).

```go
func TestVhostProfilesFederation(t *testing.T) // ["NC.example"] → federationUtilisee("nc.example:443") ; clé absente → false ; nil → false
func TestCheminPartageFedere(t *testing.T)
// les quatre chemins → true ; "/ocm/shares/" → true ; "/ocs/v2.php/cloud/shares/12" → false ; "/OCM/shares" → false
func TestSessionNextcloud(t *testing.T)
// ["ocabcdef1234=x"] → true ; ["a=1", "nc_session_id=1"] (deux lignes) → true ; ["oc_sessionPassphrase=p"] → true ;
// ["ocabc=1"] → false ; ["foo=1"] → false ; nil → false
func TestCompteurFenetre(t *testing.T)
// 6 appels de 1.2.3.4 à t0…t0+5 s → le 6e rend 6 ; appel à t0+1201 s → 5 ; ipMax 2 : 3e IP → 1 et carte <= 2 IP
func TestProxyAgenda(t *testing.T)
// ("PROPPATCH", "/remote.php/dav/principals/users/alice/calendar-proxy-write") → ("alice", true) ;
// ("proppatch", "…/calendar-proxy-read/") → ok ; ("PROPFIND", même chemin) → false
func TestUtilisateurBasic(t *testing.T) // "Basic "+base64("bob:pw") → ("bob", true) ; "Bearer x" → false ; "Basic %%%" → false
func TestPutWebDAVPremierSegment(t *testing.T)
// ("PUT", "/remote.php/dav/files/alice/x/photo.JPG", "") → ("photo.JPG", true) ;
// ("PUT", "/remote.php/dav/uploads/alice/123/1", "https://nc/remote.php/dav/files/alice/a.png") → ("a.png", true) ;
// chunk "00001" → ok ; chunk "2" → false ; ("GET", …files…) → false
func TestNextcloudPartageFedere(t *testing.T) // banc HTTP, nc.example sans fédération
// POST /ocm/shares anonyme → 1 ligne nc-001 severity "medium" ; avec Authorization → aucune ; avec cookie nc_session_id → aucune
func TestNextcloudPartageFedereRafale(t *testing.T) // federation_vhosts ["nc.example"]
// 5 POST /ocs/v2.php/cloud/shares depuis ipPublique → aucune ligne ; 6e → 1 ligne nc-002 severity "high", signals.appels_federes == 6 ;
// 1 POST depuis 203.0.113.8 → aucune ligne
func TestNextcloudProxyAgenda(t *testing.T)
// PROPPATCH …/users/alice/calendar-proxy-write, Basic alice → exactement une ligne nc-003 ; Basic bob → exactement une ligne nc-004
func TestNextcloudPutNonRaster(t *testing.T)
// PUT /remote.php/dav/files/alice/a.png, corps "%!PS-Adobe-3.0…" de 3 Mio → ligne nc-005, backend reçoit les 3 Mio intacts ;
// PUT a.png d'un vrai PNG → aucune ; PUT doc.pdf "%PDF-1.7" → aucune
func TestNextcloudPutSansJeton(t *testing.T) // sémaphore capacité 1 déjà pris → ligne nc-005, aucune ligne multipart-concurrence
func TestNextcloudTraficLegitimeMuet(t *testing.T)
// PROPFIND /remote.php/dav/files/alice/ (XML sans DTD), PUT d'un JPEG, GET /ocs/v2.php/cloud/user avec cookie ocabcdef1234,
// POST /ocs/v2.php/cloud/shares avec Authorization → aucune ligne au journal
```

- [ ] **Étape 2 : lancer.** `go test -count=1 -race -run 'Federation|PartageFedere|SessionNextcloud|CompteurFenetre|ProxyAgenda|UtilisateurBasic|PutWebDAV|Nextcloud' ./cmd/sbxwaf/`. Attendu : échec de compilation.
- [ ] **Étape 3 : implémenter** `nextcloud.go`, `vhostprofiles.go`, `entreephp.go`, `rules.go`, puis le champ et l'initialisation dans `main.go`.
- [ ] **Étape 4 : relancer**, puis la suite complète (`-race`) et `go vet`. Attendu : tout passe.
- [ ] **Étape 5 : commit.** `feat(sbxwaf): signatures Nextcloud R-NC1, R-NC2 et R-IMG2 en mode detect (ref #3273)`

### Tâche 5 : PHP générique (R-PHP1 à R-PHP4)

**Fichiers :**
- Créer : `SBX/phpgenerique.go`
- Modifier : `SBX/multipart.go` (`LongueurFrontiere`, statut) ; `SBX/entreephp.go` (branche `corpsXML`, champs) ; `SBX/rules.go`
- Tests : `SBX/phpgenerique_test.go`, ajouts à `SBX/multipart_test.go`

**Interfaces :**
- Consomme : `parcourirCookiesPHP` (tâche 1) ; `EntreePHP`, `corpsACapturer`, `completerCorps` (tâche 2) ; contrôle existant `parties_nombre`.
- Produit :

```go
const prologueXMLMax = 4096   // provisoire, non sourcé (2026-10-29) — spécification § 3.7
const frontiereRFC2046 = 70   // RFC 2046 §5.1.1
var methodesDAV = map[string]bool{"PROPFIND": true, "PROPPATCH": true, "REPORT": true, "SEARCH": true, "LOCK": true, "MKCOL": true, "MKCALENDAR": true}
func estXMLPHP(methode, contentType string) bool // méthode (en majuscules) dans methodesDAV, ou type coupé comme estMultipartPHP égal à application/xml ou text/xml
// prologueAvecDTD : si debut commence par un BOM UTF-16 (FF FE ou FE FF), ne garder qu'un octet sur deux
// (l'octet non nul) ; le prologue va jusqu'au premier '<' suivi d'une lettre, de '_' ou de ':' (élément racine) ;
// vrai s'il contient <!DOCTYPE ou <!ENTITY, sans casse.
func prologueAvecDTD(debut []byte) bool
// cookieFauxPrefixe : un cookie dont le nom normalisé commence par __Host- ou __Secure- alors que le nom brut non.
func cookieFauxPrefixe(lignes []string) bool
// ResultatMultipart gagne : LongueurFrontiere int (len de la frontière rendue par boundaryPHP, posée avant tout retour)
// analyserMultipart : LongueurFrontiere > frontiereRFC2046 et statut final « analyse » → statut « malforme » ; les compteurs restent ceux de PHP
// EntreePHP gagne : DTDXML bool ; CookieFauxPrefixe bool
// Signaux gagne la clé "frontiere" (si Multipart et LongueurFrontiere > 0)
```

- `corpsACapturer` : `estXMLPHP` et corps présent → `(corpsXML, min(prologueXMLMax, fenetreCapture()), false)`, vérifié **avant** urlencoded et après multipart. `completerCorps` : `corpsXML` → `DTDXML = prologueAvecDTD(prefixe)`.
- `nouvelleEntreePHP` : `CookieFauxPrefixe = cookieFauxPrefixe(r.Header.Values("Cookie"))`.
- R-PHP1 n'ajoute pas de code : signature `parties_nombre` avec `parties_min` 1021 (le plafond d'analyse est `partiesMaxDefaut` = 2000, `SBX/multipart.go:64`).

| `check` | Paramètre | Déclenche si |
|---|---|---|
| `xml_dtd_prologue` | aucun | `DTDXML` |
| `cookie_prefixe_normalise` | aucun | `CookieFauxPrefixe` |
| `frontiere_longueur` | `longueur_min` | `Multipart != nil && Multipart.LongueurFrontiere >= longueur_min` |

- [ ] **Étape 1 : écrire les tests qui échouent.** Corpus de test : catégorie `php_requete`, sans `services`, ids `php-001` (`parties_nombre`, `parties_min` 1021, high, CVE-2023-0662), `php-002` (`xml_dtd_prologue`, high, CVE-2023-3823), `php-003` (`cookie_prefixe_normalise`, medium, CVE-2024-2756), `php-004` (`frontiere_longueur`, `longueur_min` 71, medium, CVE-2024-8925), `php-005` (`frontiere_longueur`, `longueur_min` 5121, high, CVE-2024-8925).

```go
func TestEstXMLPHP(t *testing.T)
// ("PROPFIND", "") → true ; ("propfind", "") → true ; ("POST", "text/xml; charset=utf-8") → true ; ("POST", "application/xml") → true ;
// ("POST", "application/json") → false ; ("GET", "") → false
func TestPrologueAvecDTD(t *testing.T)
// `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "https://x/"> %remote; %intern; %trick;]><d:propfind xmlns:d="DAV:"/>` → true ;
// `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop/></d:propfind>` → false ; `<d:propfind/><!DOCTYPE x>` → false ;
// " \n<!-- c --><!doctype x><r/>" → true ; la PoC encodée en UTF-16LE avec BOM → true
func TestCookieFauxPrefixe(t *testing.T)
// ["_[Host-x=y"] → true ; ["__Host-nc_sameSiteCookiestrict=true"] → false ; ["a=1", " .[Secure-z=1"] → true ;
// ["__Host-x=1; _.Host-y=2"] → true ; ["x=1"] → false
func TestAnalyserMultipartLongueurFrontiere(t *testing.T)
// frontière de 70 caractères, 2 parties → Statut analyse, LongueurFrontiere 70 ;
// 71 → Statut malforme, Parties 2 ; 5200 → Statut malforme, LongueurFrontiere 5200, Parties 0
func TestPHPGeneriqueSignatures(t *testing.T) // EvaluerPHP
// multipart de 1021 parties texte (< 1 Mio) → contient "php-001" ; 1020 → ne contient pas "php-001" ;
// frontière 71 → ["php-004"] ; 5121 → ["php-004", "php-005"] ; CookieFauxPrefixe → ["php-003"] ; DTDXML → ["php-002"]
func TestPHPGeneriquePropfindDTDJournalise(t *testing.T) // banc HTTP, nc.example
// PROPFIND avec la PoC de 10 Kio → 1 ligne php-002 severity "high" ; backend reçoit les 10 Kio intacts ; aucun jeton pris
func TestPHPGeneriquePropfindLegitimeMuet(t *testing.T) // PROPFIND XML sans DTD, cookie __Host-nc_sameSiteCookielax → aucune ligne
```

- [ ] **Étape 2 : lancer.** `go test -count=1 -race -run 'XMLPHP|PrologueAvecDTD|CookieFauxPrefixe|LongueurFrontiere|PHPGenerique' ./cmd/sbxwaf/`. Attendu : échec de compilation.
- [ ] **Étape 3 : implémenter** `phpgenerique.go`, l'analyseur, `entreephp.go`, `rules.go`.
- [ ] **Étape 4 : relancer**, puis la suite complète (`-race`), le fuzz `FuzzAnalyserMultipart` 30 s, `go vet`. Attendu : tout passe ; `TestAnalyserMultipart*` existants inchangés (leurs frontières font moins de 71 caractères).
- [ ] **Étape 5 : commit.** `feat(sbxwaf): contrôles PHP R-PHP1 à R-PHP4 en mode detect (ref #3273)`

### Tâche 6 : compléments C1 à C5

**Fichiers :**
- Modifier : `SBX/multipart.go` (`entetes`, `ResultatMultipart`) ; `SBX/entreephp.go` ; `SBX/rules.go`
- Tests : `SBX/complements_test.go`, ajouts à `SBX/multipart_test.go`

**Interfaces :**
- Consomme : `EntreePHP`, `estUrlencodedPHP` (tâche 2) ; `ParametresPHP.Variables` (tâche 1).
- Produit :

```go
// ResultatMultipart gagne :
//   EntetesPartieMax int // maximum, sur les parties, du nombre de lignes non vides du bloc d'en-têtes (continuations comprises)
//   FichiersVides    int // parties avec un paramètre filename vide (sautées ou non)
func corpsSansLongueur(r *http.Request) bool // POST (sans casse), multipart ou urlencoded (estMultipartPHP, estUrlencodedPHP),
                                             // et r.ContentLength < 0 ou "chunked" dans r.TransferEncoding
// EntreePHP gagne : SansLongueur bool (posé par nouvelleEntreePHP)
// Signaux gagne : "entetes_partie_max", "fichiers_vides" (si Multipart), "variables" (max de Requete.Variables et Corps.Variables)
```

| `check` | Paramètre | Déclenche si | Source |
|---|---|---|---|
| `corps_sans_longueur` | aucun | `SansLongueur` | C1 |
| `entetes_partie` | `entetes_min` | `Multipart.EntetesPartieMax >= entetes_min` | C2, provisoire |
| `fichiers_vides` | `vides_min` | `Multipart.FichiersVides >= vides_min` | C3, provisoire |
| `variables_nombre` | `variables_min` | `Requete.Variables >= variables_min` ou `Corps.Variables >= variables_min` | C4, `max_input_vars` |
| `upload_progress_present` | aucun | `Multipart.Progress` | C5 |

- [ ] **Étape 1 : écrire les tests qui échouent.** Corpus de test : `php2shell` gagne `php2shell-005` (`corps_sans_longueur`, high), `-006` (`entetes_partie`, `entetes_min` 9, high), `-007` (`fichiers_vides`, `vides_min` 21, high), `-008` (`variables_nombre`, `variables_min` 1001, medium) ; `php_requete` gagne `php-006` (`upload_progress_present`, medium, CVE-2026-115560).

```go
func TestCorpsSansLongueur(t *testing.T)
// POST multipart ContentLength -1 → true ; POST urlencoded TransferEncoding ["chunked"] → true ; POST multipart ContentLength 10 → false ;
// PUT multipart ContentLength -1 → false ; POST application/json ContentLength -1 → false ; GET → false
func TestAnalyserMultipartEntetesPartie(t *testing.T) // une partie à 12 lignes d'en-tête → EntetesPartieMax 12 ; envoi légitime (CD + CT) → 2
func TestAnalyserMultipartFichiersVides(t *testing.T) // 25 parties filename="" → FichiersVides 25, PartiesFichier 25
func TestComplementsSignatures(t *testing.T) // EvaluerPHP
// EntetesPartieMax 9 → contient php2shell-006 ; 8 → non ; FichiersVides 21 → php2shell-007 ; 20 → non ;
// corps urlencoded de 1001 variables → php2shell-008 ; 1000 → non ; requête de 1001 variables → php2shell-008 ;
// Progress et 0 fichier → ["php-006"] (pas php2shell-001)
func TestCorpsChunkedSansLongueurJournalise(t *testing.T) // banc HTTP
// POST multipart sur nc.example, corps io.MultiReader (ContentLength -1) → ligne php2shell-005 severity "high", backend reçoit tout
```

- [ ] **Étape 2 : lancer.** `go test -count=1 -race -run 'SansLongueur|EntetesPartie|FichiersVides|Complements' ./cmd/sbxwaf/`. Attendu : échec de compilation.
- [ ] **Étape 3 : implémenter** : compteur de lignes dans `entetes()` (`SBX/multipart.go:333-365`, toute ligne lue non vide), `FichiersVides` dans la branche fichier (`:688-692`) ; puis `entreephp.go` et `rules.go`.
- [ ] **Étape 4 : relancer**, puis la suite complète (`-race`), fuzz 30 s, `go vet`. Attendu : tout passe.
- [ ] **Étape 5 : commit.** `feat(sbxwaf): compléments PHP2Shell C1 à C5 en mode detect (ref #3273)`

### Tâche 7 : étiquettes d'outil

**Fichiers :**
- Créer : `SBX/etiquettesphp.go`
- Modifier : `SBX/entreephp.go` (champs, lignes de `analyserRequetePHP`) ; `SBX/rules.go`
- Tests : `SBX/etiquettesphp_test.go`

**Interfaces :**
- Consomme : `boundaryPHP` (#3257) ; `urldecodePHP` (tâche 1) ; `EntreePHP`, `analyserRequetePHP` (tâche 2).
- Produit :

```go
const (
	etiquettePoC49113 = "poc-cve-2025-49113"   // frontière contenant a_rule_for_WAF_to_block_fool_exploitation
	etiquetteSondeCGI = "sonde-php-cgi"        // sondePHPCGI(rawQuery)
	etiquetteOwnCloud = "sonde-owncloud"       // chemin contenant /apps/graphapi/ (sans casse), ou paramètre de requête
	                                           // ou en-tête OC-Signature / OC-Credential (sans casse)
	etiquetteFPM11043 = "sonde-cve-2019-11043" // chemin brut contenant %0a ou %0d (sans casse)
)
// sondePHPCGI : après urldecodePHP, « allow_url_include » (sans casse) précédé d'un jeton -d ou \xADd
// (soft hyphen, CVE-2024-4577) en début de chaîne ou après un blanc ou « & ».
func sondePHPCGI(rawQuery string) bool
func etiquettesOutilPHP(r *http.Request, rawPath string) []string // ordre : poc, cgi, owncloud, 11043 ; nil si aucune
// EntreePHP gagne : Etiquettes []string ; SondePHPCGI bool (posés par nouvelleEntreePHP)
// Chaque ligne de détection de la requête : Traits += "outil:<étiquette>" pour chaque étiquette ;
// Tool = Etiquettes[0] si rm.tool est vide. La gravité n'est jamais modifiée.
```

Contrôle : `sonde_php_cgi` (aucun paramètre), déclenche si `SondePHPCGI`. C'est la seule étiquette qui vaut un signal seule (arbitrage du contrôleur) ; les autres n'en produisent jamais.

- [ ] **Étape 1 : écrire les tests qui échouent.** Corpus de test : `php_requete` gagne `php-007` (`sonde_php_cgi`, medium, CVE-2024-4577, CVE-2012-1823).

```go
func TestSondePHPCGI(t *testing.T)
// "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input" → true ; "%ADd+allow_url_include=1" → true ;
// "%2dd+allow_url_include=1" → true ; "a=1&-d+allow_url_include=1" → true ; "q=allow_url_include" → false ; "" → false
func TestEtiquettesOutilPHP(t *testing.T)
// Content-Type "multipart/form-data; boundary=------a_rule_for_WAF_to_block_fool_exploitation" → ["poc-cve-2025-49113"] ;
// chemin "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php" → ["sonde-owncloud"] ;
// requête "OC-Credential=x&OC-Signature=y" → ["sonde-owncloud"] ; chemin brut "/index.php%0a" → ["sonde-cve-2019-11043"] ;
// requête ordinaire → nil
func TestEtiquetteSeuleSansLigne(t *testing.T) // banc HTTP
// POST multipart bénin avec la frontière de la PoC sur webmail.example → aucune ligne ;
// GET /apps/graphapi/…/GetPhpInfo.php sur nc.example → aucune ligne ; GET /index.php%0a sur nc.example → aucune ligne
func TestEtiquetteAggraveLaDetection(t *testing.T)
// requête de la PoC 49113 sur webmail.example (frontière PoC, _from invalide, filename de session) →
// lignes rc-001 et rc-002, chacune avec behavior_traits contenant "outil:poc-cve-2025-49113", tool "poc-cve-2025-49113",
// severity "critical" et "high" inchangées
func TestSondePHPCGISignalMoyen(t *testing.T)
// GET nc.example/index.php?-d+allow_url_include%3d1 → 1 ligne php-007 severity "medium", tool "sonde-php-cgi" ;
// même requête sur un vhost non PHP → aucune ligne php-007
```

- [ ] **Étape 2 : lancer.** `go test -count=1 -race -run 'SondePHPCGI|EtiquettesOutil|Etiquette' ./cmd/sbxwaf/`. Attendu : échec de compilation.
- [ ] **Étape 3 : implémenter** `etiquettesphp.go`, puis les champs et les lignes dans `entreephp.go`, puis `rules.go`.
- [ ] **Étape 4 : relancer**, puis la suite complète (`-race`) et `go vet`. Attendu : tout passe ; `TestCaptureLignesPortentJA4EtOutil` reste vert (un outil identifié par l'UA prime sur l'étiquette).
- [ ] **Étape 5 : commit.** `feat(sbxwaf): étiquettes d'outil aggravantes et sonde PHP-CGI (ref #3273)`

### Tâche 8 : intégration — catalogue, synchronisation, profils, documentation, version

**Fichiers :**
- Modifier : `NG/composants/waf/config/waf-rules.json` ; `NG/composants/waf/config/vhost_profiles.json` ; `NG/README.md` (paragraphe PHP2Shell, ligne 29) ; `NG/docs/CUTOVER.md` (section corps) ; `NG/debian/changelog`
- Tests : `SBX/corpus_livre_test.go`, `NG/composants/waf/tests/test_waf_rules_sync.py`

**Interfaces :**
- Consomme : tous les contrôles des tâches 2 à 7 ; `waf-rules-sync` tel quel (R14, R16 : seul un `"enabled": false` de la box est gardé ; `NG/composants/waf/scripts/waf-rules-sync:45-75`).

Corpus livré :
- `_meta` : `version` `1.7.0`, `updated` `2026-10-29`, `changelog` d'une phrase (catégories `roundcube`, `nextcloud`, `php_requete`, compléments `php2shell-005` à `-008`, tout en `detect`, seuils provisoires étiquetés) placée devant le texte 1.6.0.
- Trois catégories `roundcube`, `nextcloud`, `php_requete` insérées **juste avant** `php2shell` (qui reste dernière), chacune `"mode": "detect"`, `"enabled": true`, `"patterns": []`, `"structural"` avec exactement les ids, contrôles, paramètres et gravités fixés aux tâches 3 à 7 ; `"services": ["roundcube"]` ou `["nextcloud"]` sur chaque signature des deux premières ; `php2shell` gagne `-005` à `-008` (tâche 6).
- Chaque signature porte `cve`, `confidence`, `desc` (une phrase, sans valeur de requête réelle) et `source` (liste des URL de la spécification § 7 qui la fondent). `seuil: "provisoire, non sourcé (2026-10-29)"` sur `php2shell-006` et `-007`.

`vhost_profiles.json` : `"federation_vhosts": []` et `"_comment_federation_vhosts"` (fédération utilisée : lister l'hôte ; absent = chaque partage fédéré anonyme est un signal moyen ; relu au démarrage). `waf-profils-fusion` n'a rien à changer : une clé absente vaut liste vide.

- [ ] **Étape 1 : écrire les tests qui échouent.**

```go
func TestCorpusLivreSansRejet(t *testing.T) // existant, étendu : rejetes vide ; ids attendus tous chargés :
// rc-001…rc-006, nc-001…nc-005, php-001…php-007, php2shell-001…php2shell-008
func TestCorpusLivreDetecteLesReferences(t *testing.T) // EvaluerPHP avec le corpus livré, une EntreePHP par cas :
// requête de la PoC 49113 (Service "roundcube") → rc-001 et rc-002 ; POST /ocm/shares anonyme (Service "nextcloud") → nc-001 ;
// PROPFIND PoC GHSA-3qrf → php-002 ; cookie "_[Host-x" → php-003 ; 1021 parties → php-001 ; frontière 71 → php-004 ;
// chunked multipart → php2shell-005 ; Progress seul → php-006 ; -d allow_url_include → php-007
func TestCorpusLivreStructurellesEnDetect(t *testing.T) // toute catégorie qui a "structural" a "mode": "detect"
func TestCorpusLivreSeuilsProvisoiresEtiquetes(t *testing.T) // php2shell-002, -003, -006, -007 ont seuil == "provisoire, non sourcé (2026-10-29)"
func TestCorpusLivrePhp2shellEnDernier(t *testing.T) // existant, inchangé
func TestVhostProfilesLivreChargeAvecPHP(t *testing.T) // existant, étendu : le fichier livré se charge ; federationUtilisee("nc.gk2.secubox.in") == false ;
// servicePHP("webmail.gk2.secubox.in") == ("roundcube", true)
```

```python
def test_sync_nouvelles_categories_posees_actives(): ...
# box sans roundcube/nextcloud/php_requete, livré 1.7.0 → les trois présentes, enabled True, _meta.version == "1.7.0"
def test_sync_garde_false_de_la_box_sur_roundcube(): ...
# box roundcube enabled False → résultat False, et ecarts_enabled le signale
def test_sync_true_de_la_box_suit_le_livre_sur_nextcloud(): ...
# box nextcloud enabled True, livré False → False
```

- [ ] **Étape 2 : lancer** les tests Go ciblés (`-run 'CorpusLivre|VhostProfilesLivre'`) et Python. Attendu : échecs (catégories et ids absents).
- [ ] **Étape 3 : écrire** le corpus et `vhost_profiles.json`, puis `python3 -m json.tool` sur les deux fichiers.
- [ ] **Étape 4 : documenter.** README (paragraphe PHP2Shell) : les trois catégories et leurs contrôles en une ligne chacun, `services`, `federation_vhosts`, ce qui est lu par contrôle (tableau des contraintes globales), étiquettes d'outil aggravantes (`behavior_traits` `outil:*`), retour arrière par `"enabled": false` par catégorie (rechargement à chaud ; sans aucune catégorie structurelle active, aucune capture). `CUTOVER.md` : capture urlencoded (jeton), XML (4096 octets) et début de `PUT` (64 octets, sans jeton).
- [ ] **Étape 5 : changelog.** Entrée `secubox-waf-ng (1.32.0-1~trixie1) trixie; urgency=medium`, signée `-- Gérald Kerma <devel@cybermind.fr>  Thu, 29 Oct 2026 <heure> +0100`, postérieure à 12:00:00 : une puce par tâche, les seuils provisoires, le retour arrière.
- [ ] **Étape 6 : relancer** les deux suites complètes (Go `go test -count=1 -race ./...` depuis `packages/secubox-toolbox-ng`, Python), `go vet ./cmd/sbxwaf/`, `grep -rni crowdsec` sur les fichiers touchés. Attendu : tout passe, aucune occurrence.
- [ ] **Étape 7 : commit.** `feat(waf): catalogue roundcube, nextcloud, php_requete 1.7.0, secubox-waf-ng 1.32.0 (ref #3273)`

---

## Après la branche (contrôleur, hors sous-agents)

1. Construire le paquet arm64, publier après fusion, canari gk1 puis gk2 en `detect` ; observer les lignes `roundcube`, `nextcloud`, `php_requete`, `php2shell-005` à `-008`, le CPU et la mémoire de sbxwaf.
2. Étalonner sur le trafic réel les seuils provisoires (9 en-têtes, 21 champs vides, 4096 octets de prologue, 4096 IP) et mesurer `_to`, `_cc`, `_bcc` (spécification § 6, point 10).
3. Rappel de la spécification : Roundcube `1.6.5+dfsg-1+deb12u12` reste vulnérable à 113386, 114720, 114724, 114725 et 114727 ; ces signatures repèrent, elles ne corrigent pas.

## Questions ouvertes (décisions prises par l'auteur du plan, à confirmer)

1. **Hôte PHP reconnu par motif seulement** (`php_hotes`, sans vhost explicite) : *mon choix*, `Service ""`, donc toutes les familles (Roundcube et Nextcloud) s'y appliquent. Une sonde Roundcube contre un alias `nextcloud.*` produit alors une ligne ; l'autre choix (familles applicatives coupées) aveuglerait les box sans vhost déclaré.
2. **Exemple de contournement `?[from=`** de la règle transversale : selon ma lecture de `php_variables.c`, PHP **ignore** un nom qui commence par `[` (base vide). Le test `TestNomPHP` fige donc `"[from"` → `("", false)` ; l'implémenteur confronte au fichier source avant d'écrire le test. `.from` reste bien un contournement de `_from`.
3. **Occurrences multiples** d'un même paramètre : *mon choix*, R-RC1 et R-RC3 examinent toutes les occurrences (PHP ne garde que la dernière) ; plus sensible, sans faux positif ajouté.
4. **`_from` vide** : *mon choix*, aucun signal (Roundcube le rejette, mais rien ne le relie à une attaque).
5. **Gravités non fixées par la spécification** (*mes choix*) : R-RC3 `high` pour `_headers`, `_scope`, `_mbox`, `_search` (paramètres IMAP comme `_q`) ; markasjunk `low` (« faible poids ») ; R-PHP1 `high` (CVSS 7.5) ; C1, C2, C3 `high` (comme `php2shell-002` et `-003`) ; C4 `medium` ; C5 `medium` (avis complet non paru) ; sonde PHP-CGI `medium` (arbitrage du contrôleur).
6. **R-PHP4 et le statut** : la spécification dit « statut `malforme` » au-delà de 70 caractères. *Mon choix* : le statut passe à `malforme` mais les compteurs restent ceux de PHP (qui lit la requête jusqu'à 5 116 octets de frontière), pour ne pas perdre les autres signatures.
7. **R-IMG1** : action lue dans la requête, le corps urlencoded **ou** un champ multipart retenu (`_task`, `_action`) — *mon choix*, d'où le relevé borné des champs ordinaires (`Champs`, 64 au plus) dans l'analyseur ; marqueurs texte sans casse.
8. **R-IMG2** : « premier segment » = dernier élément de `/remote.php/dav/uploads/…` de valeur décimale ≤ 1 ; extension lue dans `Destination` ; `jpeg` ajouté à la liste raster — *mes choix*.
9. **R-NC1** : session Nextcloud = cookie `nc_session_id`, `nc_token`, `nc_username`, `oc_sessionPassphrase` ou nom d'instance `^oc[a-z0-9]{10}$` ; un `/` final toléré sur les chemins exacts ; compteur borné à 4096 IP et 64 horodatages ; réglage « fédération utilisée » = `federation_vhosts` dans `vhost_profiles.json` — *mes choix*.
10. **R-NC2** : une seule ligne par requête (`high` si l'utilisateur Basic diffère du `<uid>`, sinon `medium`), comparaison sans casse. Un client qui se connecte par courriel (identifiant ≠ uid) donnera un `high` à tort : accepté en `detect`, à mesurer.
11. **Captures sans jeton** (XML ≤ 4096 octets, début de `PUT` ≤ 64 octets) : *mon choix*, hors du sémaphore de 16, pour qu'un client de synchronisation Nextcloud qui envoie de longs `PUT` ne prive pas la capture multipart ; mémoire bornée par connexion.
12. **Requête non relayée** (403 d'une règle regex, ban, cache média) : aucune ligne des nouvelles signatures, comme pour #3257 — la ligne regex fait foi.
13. **Étiquettes d'outil** : « aggravante » = trait `outil:<étiquette>` envoyé à actord et champ `tool` si vide ; jamais de hausse de gravité (contrainte « gravité réelle »).
14. **C2** : chaque ligne non vide du bloc d'en-têtes d'une partie compte, continuations comprises ; **C4** : chaînes de requête et corps comptés séparément, comme PHP (`$_GET`, `$_POST`).

### Tâche 9 : interface du WAF — les filtres PHP visibles dans la page (demande du propriétaire, 29/10/2026)

Le propriétaire a cherché les nouveaux filtres dans `https://admin.gk2.secubox.in/waf/#vue` : #3257 n'a livré que le moteur. La catégorie `php2shell` de `waf-rules.json` apparaît dans l'onglet « Menaces », mais l'analyse structurelle (multipart et entrée PHP) n'a ni carte ni compteur.

**Fichiers :**
- Modifier : `packages/secubox-waf-ng/composants/waf/api/main.py` (`/detections`, nouvelle route `/php/signaux`)
- Modifier : `packages/secubox-waf-ng/composants/waf/www/waf/menaces.html` (carte des détections) et `www/waf/attaquants.html` (signature PHP par adresse)
- Test : `packages/secubox-waf-ng/composants/waf/tests/test_detection_php_3273.py`

**Interfaces :**
- Consomme : les lignes du journal des menaces écrites par `ThreatLog.Record` (`packages/secubox-toolbox-ng/cmd/sbxwaf/threatlog.go`, champ `category` et le nom de règle des tâches 2 à 7) ; `vhost_profiles.json` (vhosts PHP explicites et motifs, `federation_vhosts` de la tâche 4).
- Produit :
  - dans `/detections`, une entrée `{"id": "analyse_php", "nom": "Analyse des requêtes PHP", "mode": "detect", "classes": [vhosts armés], "actif": <mesuré>, "detail": "<n> signaux en 24 h"}` ;
  - `GET /php/signaux` (`require_lecture`) → `{"fenetre_h": 24, "familles": {"php2shell": n, "roundcube": n, "nextcloud": n, "php_requete": n, "outil": n}, "regles": {"<règle>": n}, "vhosts": {"<hôte>": n}}`, calculé en tâche de fond avec un cache fichier (`.claude/reference/PERF-CACHE.md`), jamais en lisant le journal à chaque requête.
- Aucune adresse privée n'est rendue (R12 : elles sont déjà journalisées « local »), aucun corps ni aucune valeur de paramètre.

- [ ] **Étape 1 : tests qui échouent** — `test_detections_contient_analyse_php` (entrée présente, `mode == "detect"`, vhosts armés lus dans un `vhost_profiles.json` de test) ; `test_php_signaux_compte_par_famille_sur_24h` (journal de test : 3 lignes php2shell, 2 roundcube dont une de plus de 24 h → `php2shell == 3`, `roundcube == 1`) ; `test_php_signaux_exige_une_session` (sans jeton → 401) ; `test_php_signaux_lit_le_cache` (le journal n'est pas relu à chaque appel).
- [ ] **Étape 2 :** lancer, constater l'échec sur une assertion.
- [ ] **Étape 3 :** implémenter l'API, puis la carte de `menaces.html` et la colonne de `attaquants.html`, dans le style des pages refondues (`.claude/AURORA-REFERENCE.md`, `.claude/WEBUI-PANEL-GUIDELINES.md`) ; données réelles seulement, état « inconnu » si le cache manque.
- [ ] **Étape 4 :** `…/.venv/bin/python -m pytest packages/secubox-waf-ng/composants/waf/tests -q` → tout vert.
- [ ] **Étape 5 :** commit `feat(waf): filtres PHP visibles dans la page du WAF (ref #3273)` ; l'entrée de changelog 1.32.0 de la tâche 8 mentionne l'interface.
