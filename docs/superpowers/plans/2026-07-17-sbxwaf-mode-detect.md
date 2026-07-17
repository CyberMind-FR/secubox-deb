# sbxwaf — mode `detect` — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Permettre à une catégorie de règles WAF de **matcher sans bloquer** — comptée et journalisée, requête laissée passer, aucun bannissement.

**Architecture:** Un champ `mode` par catégorie dans `waf-rules.json`, parsé en `compiledCategory`, remonté par `Rules.Match`, et honoré à l'unique site d'appel dans `main.go`. `mode` absent ⇒ `block` : les 17 catégories existantes ne changent pas d'un iota.

**Tech Stack:** Go (paquet `cmd/sbxwaf` de `secubox-toolbox-ng`), tests `go test`. Aucune dépendance nouvelle.

**Spec:** `docs/superpowers/specs/2026-07-17-sbxwaf-mode-detect-design.md`

## Global Constraints

- **`mode` absent ⇒ `block`.** Décision structurante : un défaut `detect` désarmerait silencieusement tout le WAF — une panne de sécurité muette. Même raisonnement que `Enabled *bool` (pointeur, `nil` = absent = `true`) déjà en place à `rules.go:144`.
- **Valeur inconnue (`"monitor"`, `"xyz"`) ⇒ `block` + log d'erreur bruyant.** Fail-**closed**. Ne jamais désactiver ni passer en `detect` sur un mode mal orthographié : un typo ne doit pas retirer une protection.
- **Chaîne vide `""` et `null` ⇒ `block`**, silencieusement (c'est « absent », pas une erreur) — cohérent avec `if sev == "" { sev = "medium" }` à `rules.go:186`.
- **`enabled: false` prime sur `mode`** : la catégorie n'est pas évaluée du tout, coût nul.
- **Un match en `detect` ne déclenche AUCUN effet de bord** : pas de ban, pas d'appel CrowdSec, pas de décision nft, pas de compteur de bannissement. Invariant central : une catégorie en `detect` est aussi inoffensive qu'un `enabled: false`, à la journalisation près.
- **`ThreatRecord.Action`** vaut aujourd'hui `"warning"` ou `"banned"` (`threatlog.go:46`). `detect` ajoute la valeur **`"detect"`** — sans quoi les statistiques mélangeraient « bloqué » et « aurait bloqué », et le compteur de menaces (198k) deviendrait un mensonge.
- **Go, stdlib uniquement.** Pas de nouvelle dépendance.
- **Déploiement** : `cp` échoue (« text file busy ») → **`mv`** ; **jamais** `kill -HUP` → `systemctl restart secubox-waf-ng`. sbxwaf est en frontal de TOUS les vhosts publics.
- Commits terminés par `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`. Aucune référence à Claude.

---

## Structure des fichiers

```
packages/secubox-toolbox-ng/cmd/sbxwaf/
├── rules.go        # MODIFIER : categoryJSON.Mode, compiledCategory.mode, Match rend le mode
├── rules_test.go   # MODIFIER : défaut block, valeur inconnue, detect
├── main.go         # MODIFIER : l'unique site d'appel (ligne ~376) — chemin detect
├── main_test.go    # MODIFIER : detect laisse passer + ne bannit pas
└── threatlog.go    # MODIFIER : commentaire de Action (la valeur "detect")
```

Un seul site d'appel de `Match` (`main.go:376`) — le rayon de souffle est contenu.

---

### Task 1 : Parser `mode` (défaut `block`, fail-closed)

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxwaf/rules.go`
- Test: `packages/secubox-toolbox-ng/cmd/sbxwaf/rules_test.go`

**Interfaces:**
- Consomme : rien.
- Produit : `compiledCategory.mode string` (toujours `"block"` ou `"detect"`, jamais vide) ; les constantes `modeBlock = "block"` et `modeDetect = "detect"`.

- [ ] **Step 1 : écrire les tests qui échouent**

Ajouter à `cmd/sbxwaf/rules_test.go` :

```go
// writeRules writes a waf-rules.json with the given categories body and returns its path.
func writeRulesFile(t *testing.T, categories string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "waf-rules.json")
	body := `{"_meta":{"version":"test"},"categories":` + categories + `}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	return p
}

// catMode returns the compiled mode for category id, or "" if absent.
func catMode(r *Rules, id string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.current.cats {
		if c.id == id {
			return c.data.mode
		}
	}
	return ""
}

// A category with no "mode" MUST block. This is the most important test in the
// file: a detect default would silently disarm all 17 existing categories.
func TestModeAbsentDefaultsToBlock(t *testing.T) {
	p := writeRulesFile(t, `{"sqli":{"name":"SQLi","severity":"critical",
		"patterns":[{"id":"sqli-001","pattern":"union select","desc":"x"}]}}`)
	r := LoadRules(p)
	if got := catMode(r, "sqli"); got != modeBlock {
		t.Fatalf("absent mode: got %q, want %q", got, modeBlock)
	}
}

func TestModeBlockExplicit(t *testing.T) {
	p := writeRulesFile(t, `{"sqli":{"name":"SQLi","mode":"block",
		"patterns":[{"id":"sqli-001","pattern":"union select","desc":"x"}]}}`)
	if got := catMode(LoadRules(p), "sqli"); got != modeBlock {
		t.Fatalf("got %q, want %q", got, modeBlock)
	}
}

func TestModeDetectIsParsed(t *testing.T) {
	p := writeRulesFile(t, `{"cve_2024":{"name":"CVE","mode":"detect",
		"patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"x"}]}}`)
	if got := catMode(LoadRules(p), "cve_2024"); got != modeDetect {
		t.Fatalf("got %q, want %q", got, modeDetect)
	}
}

// A typo must NOT disarm the category and must NOT become detect: fail closed.
func TestModeUnknownFailsClosedToBlock(t *testing.T) {
	for _, bad := range []string{"monitor", "dryrun", "BLOCK ", "xyz"} {
		p := writeRulesFile(t, `{"sqli":{"name":"SQLi","mode":"`+bad+`",
			"patterns":[{"id":"sqli-001","pattern":"union select","desc":"x"}]}}`)
		r := LoadRules(p)
		if got := catMode(r, "sqli"); got != modeBlock {
			t.Fatalf("mode %q: got %q, want %q (must fail closed)", bad, got, modeBlock)
		}
		// And the category must still be evaluated — a typo must not remove protection.
		if _, _, hit := r.Match("GET", "/x", "q=union+select", "", ""); !hit {
			t.Fatalf("mode %q: category was dropped; a typo must not disable a rule", bad)
		}
	}
}

// "" and null are "absent", not errors.
func TestModeEmptyAndNullDefaultToBlock(t *testing.T) {
	for _, body := range []string{`"mode":"",`, `"mode":null,`} {
		p := writeRulesFile(t, `{"sqli":{"name":"SQLi",`+body+`
			"patterns":[{"id":"sqli-001","pattern":"union select","desc":"x"}]}}`)
		if got := catMode(LoadRules(p), "sqli"); got != modeBlock {
			t.Fatalf("%s got %q, want %q", body, got, modeBlock)
		}
	}
}

// enabled:false wins over mode — the category is not evaluated at all.
func TestEnabledFalseWinsOverMode(t *testing.T) {
	p := writeRulesFile(t, `{"sqli":{"name":"SQLi","enabled":false,"mode":"detect",
		"patterns":[{"id":"sqli-001","pattern":"union select","desc":"x"}]}}`)
	r := LoadRules(p)
	if got := catMode(r, "sqli"); got != "" {
		t.Fatalf("disabled category should not be loaded at all, got mode %q", got)
	}
	if _, _, hit := r.Match("GET", "/x", "q=union+select", "", ""); hit {
		t.Fatal("disabled category must not match")
	}
}
```

Vérifier que `rules_test.go` importe `os`, `path/filepath` et `testing` ; les ajouter si absents.

- [ ] **Step 2 : lancer — doit échouer**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-toolbox-ng
go test ./cmd/sbxwaf/ -run 'TestMode|TestEnabledFalseWins' 2>&1 | tail -5
```
Attendu : échec de compilation — `undefined: modeBlock`, `undefined: modeDetect`, et `c.data.mode` inconnu.

- [ ] **Step 3 : implémenter**

Dans `cmd/sbxwaf/rules.go`, après le bloc d'imports, ajouter les constantes :

```go
// Rule evaluation modes for a category.
//
//	modeBlock  — a match blocks the request (the historical, only behaviour).
//	modeDetect — a match is counted and logged, the request PASSES, and nothing
//	             is banned. Lets an operator try a rule against real traffic
//	             before arming it.
//
// A category with no "mode" is modeBlock. A detect default would silently turn
// the whole WAF into an observer — a mute security outage.
const (
	modeBlock  = "block"
	modeDetect = "detect"
)
```

Dans `type compiledCategory struct` (~ligne 76), ajouter le champ :

```go
type compiledCategory struct {
	name     string
	severity string
	mode     string // modeBlock | modeDetect — never empty after loadFile
	patterns []compiledPattern
}
```

Dans `categoryJSON` (~ligne 143), ajouter le champ — **pointeur**, comme `Enabled`, pour distinguer absent de vide :

```go
	type categoryJSON struct {
		Name     string        `json:"name"`
		Severity string        `json:"severity"`
		Enabled  *bool         `json:"enabled"` // pointer: nil means absent (default true)
		Mode     *string       `json:"mode"`    // pointer: nil means absent (default block)
		Patterns []patternJSON `json:"patterns"`
	}
```

Juste après le bloc `// Default severity.` (~ligne 185), ajouter la résolution du mode :

```go
		// Resolve the evaluation mode. Absent, null or "" ⇒ block: the 17
		// shipped categories carry no "mode" and must keep blocking.
		//
		// An UNKNOWN value also ⇒ block, loudly. Fail closed: a typo like
		// "monitor" must never silently drop a protection nor downgrade it to
		// observation. This is the same instinct as Enabled's pointer default.
		mode := modeBlock
		if cat.Mode != nil && *cat.Mode != "" {
			switch *cat.Mode {
			case modeBlock, modeDetect:
				mode = *cat.Mode
			default:
				log.Printf("sbxwaf/rules: category %q has unknown mode %q — falling back to %q (known modes: %q, %q)",
					catID, *cat.Mode, modeBlock, modeBlock, modeDetect)
			}
		}
```

Et renseigner le champ dans le littéral `compiledCategory` (~ligne 189) :

```go
		cc := compiledCategory{
			name:     cat.Name,
			severity: sev,
			mode:     mode,
		}
```

- [ ] **Step 4 : lancer — doit passer**

```bash
go test ./cmd/sbxwaf/ -run 'TestMode|TestEnabledFalseWins' -v 2>&1 | tail -12
```
Attendu : `ok` — 6 tests PASS.

- [ ] **Step 5 : non-régression complète du paquet**

```bash
go test ./cmd/sbxwaf/ 2>&1 | tail -3
```
Attendu : `ok` — aucune régression (notamment `TestRulesDefaultEnabledTrue`).

- [ ] **Step 6 : prouver que les tests peuvent échouer**

Remplacer temporairement `mode := modeBlock` par `mode := modeDetect`, relancer :
```bash
go test ./cmd/sbxwaf/ -run TestModeAbsentDefaultsToBlock 2>&1 | tail -3
```
Attendu : **FAIL**. Restaurer, reconfirmer PASS. Consigner les deux observations dans le rapport. Un test qui ne peut pas échouer n'est pas un test.

- [ ] **Step 7 : commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbxwaf/rules.go packages/secubox-toolbox-ng/cmd/sbxwaf/rules_test.go
git commit -m "feat(sbxwaf): parse a per-category mode (default block, fail closed)

Absent, empty or null mode means block: the 17 shipped categories carry no
mode and must keep blocking. An unknown value also means block, loudly — a
typo like 'monitor' must never silently drop a protection nor downgrade it to
observation.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 2 : Honorer `detect` — matcher, journaliser, laisser passer, ne rien bannir

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxwaf/rules.go` (signature de `Match`)
- Modify: `packages/secubox-toolbox-ng/cmd/sbxwaf/main.go` (~ligne 376, unique site d'appel)
- Modify: `packages/secubox-toolbox-ng/cmd/sbxwaf/threatlog.go` (commentaire de `Action`)
- Test: `packages/secubox-toolbox-ng/cmd/sbxwaf/main_test.go`

**Interfaces:**
- Consomme : `modeBlock`, `modeDetect`, `compiledCategory.mode` (Task 1).
- Produit : `Rules.Match(method, rawPath, rawQuery, body, ua string) (cat, sev, mode string, hit bool)` — **la signature change** : `mode` est inséré avant `hit`. Unique appelant : `main.go`.

- [ ] **Step 1 : écrire les tests qui échouent**

Ajouter à `cmd/sbxwaf/main_test.go` :

```go
// A detect category matches but the request MUST pass through, and NOTHING may
// be banned. A detect category must be as harmless as enabled:false, minus the
// log line.
func TestDetectModeLetsRequestThroughAndDoesNotBan(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"cve_2024":{"name":"CVE","severity":"critical","mode":"detect",
		"patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"F5 RCE"}]}}`)

	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream reached"))
	}))
	defer upstream.Close()

	s := newTestServer(t, upstream.URL, rulesPath)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mgmt/tm/util/bash", nil)
	s.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("detect mode returned 403; it must let the request through")
	}
	if !upstreamHit {
		t.Fatal("detect mode did not reach the upstream; the request was swallowed")
	}
	if s.ban != nil && s.ban.Count(testClientIP) != 0 {
		t.Fatalf("detect mode incremented the ban counter (%d); detect must never punish",
			s.ban.Count(testClientIP))
	}
}

// The same pattern in block mode must still block — the detect path must not
// leak into the default behaviour.
func TestBlockModeStillBlocks(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"cve_2024":{"name":"CVE","severity":"critical","mode":"block",
		"patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"F5 RCE"}]}}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must never be reached in block mode")
	}))
	defer upstream.Close()

	s := newTestServer(t, upstream.URL, rulesPath)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/mgmt/tm/util/bash", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("block mode: got %d, want 403", rec.Code)
	}
}

// A category with no mode must block — non-regression for the 17 shipped ones.
func TestAbsentModeStillBlocks(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"cve_2024":{"name":"CVE","severity":"critical",
		"patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"F5 RCE"}]}}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must never be reached when mode is absent (defaults to block)")
	}))
	defer upstream.Close()

	s := newTestServer(t, upstream.URL, rulesPath)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/mgmt/tm/util/bash", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("absent mode: got %d, want 403", rec.Code)
	}
}

// The threat record must say "detect" — otherwise stats conflate "blocked" with
// "would have blocked" and the 198k threat counter becomes a lie.
func TestDetectModeLogsActionDetect(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "threats.jsonl")
	rulesPath := writeRulesFile(t, `{"cve_2024":{"name":"CVE","severity":"critical","mode":"detect",
		"patterns":[{"id":"cve-1","pattern":"/mgmt/tm/util/bash","desc":"F5 RCE"}]}}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	s := newTestServer(t, upstream.URL, rulesPath)
	s.threatLog = NewThreatLog(logPath)

	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/mgmt/tm/util/bash", nil))

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("threat log not written: %v", err)
	}
	if !strings.Contains(string(raw), `"detect"`) {
		t.Fatalf("threat record must carry action=detect, got: %s", raw)
	}
	if strings.Contains(string(raw), `"banned"`) || strings.Contains(string(raw), `"warning"`) {
		t.Fatalf("detect must not be logged as warning/banned, got: %s", raw)
	}
}
```

**Note à l'implémenteur** : `newTestServer(t, upstreamURL, rulesPath)` et `testClientIP` peuvent ne pas exister sous ce nom dans `main_test.go`. **Lire le fichier d'abord** et réutiliser le harnais existant (nom et signature réels) plutôt que d'en inventer un ; adapter ces tests au harnais, sans changer ce qu'ils affirment. Réutiliser `writeRulesFile` de Task 1 (même paquet).

- [ ] **Step 2 : lancer — doit échouer**

```bash
go test ./cmd/sbxwaf/ -run 'TestDetectMode|TestBlockModeStill|TestAbsentModeStill' 2>&1 | tail -5
```
Attendu : échec de compilation (`Match` rend 3 valeurs, pas 4) ou FAIL (detect renvoie 403).

- [ ] **Step 3 : implémenter — `Match` remonte le mode**

Dans `cmd/sbxwaf/rules.go`, changer la signature (~ligne 287) et les retours :

```go
// Match reports whether any enabled category matches the request, and in which
// mode. `mode` is modeBlock or modeDetect and is only meaningful when hit is
// true; the caller decides what to do with it.
func (r *Rules) Match(method, rawPath, rawQuery, body, ua string) (cat, sev, mode string, hit bool) {
```

Adapter les `return` de la fonction :
- l'early return `if cur == nil` : `return "", "", "", false`
- le return du match : ajouter `c.data.mode` en 3ᵉ position
- le return final (aucun match) : `return "", "", "", false`

- [ ] **Step 4 : implémenter — le chemin `detect` dans `main.go`**

À `main.go:376`, remplacer l'appel et la garde :

```go
				cat, sev, mode, hit := s.rules.Match(
					r.Method,
					rawPath,
					r.URL.RawQuery,
					string(bodyBytes),
					r.Header.Get("User-Agent"),
				)
				if hit && mode == modeDetect {
					// Observe only: count it, log it, let it through. A detect
					// category must be as harmless as enabled:false, minus the
					// log line — so NO ban, NO CrowdSec report, NO nft decision.
					if s.threatLog != nil {
						s.threatLog.Append(ThreatRecord{
							ClientIP: clientIP,
							Host:     r.Host,
							Method:   r.Method,
							Path:     rawPath,
							Category: cat,
							Severity: sev,
							RuleID:   "",
							Action:   "detect",
							UA:       r.Header.Get("User-Agent"),
						})
					}
					hit = false // fall through to the normal proxy path
				}
				if hit {
```

**Note à l'implémenteur** : `clientIP` et le champ `RuleID` doivent reprendre **exactement** ce que fait le chemin bloquant existant juste en dessous (lire les lignes qui suivent `if hit {`). Ne pas inventer la façon dont l'IP client est calculée ni comment `RuleID` est renseigné — copier le motif en place.

- [ ] **Step 5 : documenter la valeur dans `threatlog.go`**

À `threatlog.go:46`, corriger le commentaire :

```go
	Action   string // "detect" | "warning" | "banned"
```

- [ ] **Step 6 : lancer — doit passer**

```bash
go test ./cmd/sbxwaf/ 2>&1 | tail -3
```
Attendu : `ok` — tout le paquet, sans régression.

- [ ] **Step 7 : prouver que les tests peuvent échouer**

Supprimer temporairement la ligne `hit = false` du chemin detect, relancer :
```bash
go test ./cmd/sbxwaf/ -run TestDetectModeLetsRequestThroughAndDoesNotBan 2>&1 | tail -3
```
Attendu : **FAIL** (403 au lieu du passage). Restaurer, reconfirmer PASS. Consigner les deux observations.

- [ ] **Step 8 : commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbxwaf/
git commit -m "feat(sbxwaf): honour detect mode — match, log, pass, never ban

Match now reports the category mode; main.go's single call site treats a detect
hit as observation: the threat record is written with action=detect and the
request continues to the upstream. No ban, no CrowdSec report, no nft decision —
a detect category is as harmless as enabled:false, minus the log line.

action=detect keeps stats honest: without it, 'blocked' and 'would have blocked'
would be indistinguishable.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 3 : Déployer sur gk2 et prouver sur du trafic réel

**Files:** aucun (déploiement).

**Interfaces:** consomme le binaire construit depuis Tasks 1-2.

⚠️ **sbxwaf est en frontal de TOUS les vhosts publics de la box** (Nextcloud, PeerTube, Gitea, billets, admin…). Une régression coupe tout. La box tourne 118 services à load ~5-11 sur 4 cœurs.

- [ ] **Step 1 : construire pour arm64**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-toolbox-ng
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags=-s -o /tmp/sbxwaf ./cmd/sbxwaf
file /tmp/sbxwaf
```
Attendu : `ELF 64-bit LSB executable, ARM aarch64`.

- [ ] **Step 2 : relever l'état AVANT**

```bash
ssh root@192.168.1.200 'echo "waf: $(systemctl is-active secubox-waf-ng)"; \
  cp /usr/sbin/sbxwaf /tmp/sbxwaf.bak.pre-detect && echo "binaire sauvegardé"; \
  curl -sk -o /dev/null -w "admin https -> %{http_code}\n" https://admin.gk2.secubox.in/ --resolve admin.gk2.secubox.in:443:127.0.0.1'
```
Attendu : `active`, sauvegarde faite, `200`.

- [ ] **Step 3 : déployer**

```bash
scp /tmp/sbxwaf root@192.168.1.200:/tmp/sbxwaf.new
ssh root@192.168.1.200 'mv /tmp/sbxwaf.new /usr/sbin/sbxwaf && chmod 755 /usr/sbin/sbxwaf && \
  systemctl restart secubox-waf-ng && sleep 3 && systemctl is-active secubox-waf-ng'
```
`mv`, **jamais** `cp` (« text file busy »). `systemctl restart`, **jamais** `kill -HUP`.
Attendu : `active`.

- [ ] **Step 4 : prouver la non-régression sur du trafic réel**

```bash
ssh root@192.168.1.200 'for h in admin.gk2.secubox.in billets.gk2.secubox.in; do
  curl -sk -o /dev/null -w "  $h -> %{http_code}\n" https://$h/ --resolve $h:443:127.0.0.1
done
echo "--- une attaque connue est-elle toujours bloquée ? ---"
curl -sk -o /dev/null -w "  sqli -> %{http_code} (attendu 403)\n" \
  "https://admin.gk2.secubox.in/?q=union+select+1" --resolve admin.gk2.secubox.in:443:127.0.0.1
echo "--- patterns chargés ---"
journalctl -u secubox-waf-ng -n 5 --no-pager | grep -i "loaded.*patterns"'
```
Attendu : les vhosts en `200`, le SQLi en **403** (les catégories sans `mode` bloquent toujours), et le log confirme 149 patterns / 17 catégories.

- [ ] **Step 5 : prouver le mode `detect` en vrai**

Basculer `cve_2024` en `detect` — la catégorie dont les 6 patterns visent PAN-OS/Ivanti/F5, absents de cette box :

```bash
ssh root@192.168.1.200 'cp /etc/secubox/waf/waf-rules.json /etc/secubox/waf/waf-rules.json.bak.pre-detect
python3 - <<PY
import json
p = "/etc/secubox/waf/waf-rules.json"
d = json.load(open(p))
d["categories"]["cve_2024"]["mode"] = "detect"
json.dump(d, open(p, "w"), indent=2, ensure_ascii=False)
print("cve_2024 -> mode detect")
PY
sleep 3   # rechargement à chaud (watcher)
echo "--- un pattern cve_2024 doit maintenant PASSER (et être journalisé) ---"
curl -sk -o /dev/null -w "  /mgmt/tm/util/bash -> %{http_code} (attendu != 403)\n" \
  "https://admin.gk2.secubox.in/mgmt/tm/util/bash" --resolve admin.gk2.secubox.in:443:127.0.0.1
echo "--- le journal porte-t-il action=detect ? ---"
tail -3 /var/log/secubox/waf-threats.jsonl 2>/dev/null | grep -o "\"action\":\"[a-z]*\"" | tail -2
echo "--- le SQLi (sans mode) bloque-t-il toujours ? ---"
curl -sk -o /dev/null -w "  sqli -> %{http_code} (attendu 403)\n" \
  "https://admin.gk2.secubox.in/?q=union+select+1" --resolve admin.gk2.secubox.in:443:127.0.0.1'
```
Attendu : le pattern `cve_2024` **passe** (≠ 403) et apparaît avec `"action":"detect"` ; le SQLi **bloque toujours** (403).

⚠️ Le chemin exact du journal de menaces est le `--threat-log` de l'unit : le lire avec
`systemctl show secubox-waf-ng -p ExecStart` plutôt que supposer `/var/log/secubox/waf-threats.jsonl`.

- [ ] **Step 6 : rendre l'état initial**

```bash
ssh root@192.168.1.200 'mv /etc/secubox/waf/waf-rules.json.bak.pre-detect /etc/secubox/waf/waf-rules.json && sleep 3
curl -sk -o /dev/null -w "  cve_2024 rearmé -> %{http_code} (attendu 403)\n" \
  "https://admin.gk2.secubox.in/mgmt/tm/util/bash" --resolve admin.gk2.secubox.in:443:127.0.0.1'
```
Attendu : `403` — la démonstration ne laisse aucun résidu. Ne PAS laisser `cve_2024` en `detect` : c'est une décision d'exploitation, elle appartient à l'utilisateur.

- [ ] **Step 7 : consigner**

Reporter dans le rapport : les codes AVANT/APRÈS de chaque vhost, la preuve `detect` (passage + `action=detect`), la preuve de non-régression (SQLi 403), et le retour à l'état initial.

---

## Auto-revue du plan

**Couverture du spec** :

| Exigence du spec | Tâche |
|---|---|
| Champ `mode` par catégorie | 1 |
| `mode` absent ⇒ `block` (non-régression des 17) | 1 (Step 1 : `TestModeAbsentDefaultsToBlock`), 2 (`TestAbsentModeStillBlocks`) |
| `""` / `null` ⇒ `block` silencieux | 1 |
| Valeur inconnue ⇒ `block` + log bruyant (fail-closed) | 1 |
| `enabled:false` prime | 1 |
| Match `detect` : compté, journalisé, **laisse passer** | 2 |
| `detect` ne bannit **jamais** | 2 (assertion sur le compteur de ban) |
| `ThreatRecord.Action = "detect"` | 2 (+ commentaire `threatlog.go`) |
| Rechargement à chaud d'un changement de `mode` | 3 (Step 5 : bascule à chaud, `sleep 3`, sans redémarrage) |
| Tests capables d'échouer (mutation) | 1 (Step 6), 2 (Step 7) |
| Déploiement `mv` + `systemctl restart` | 3 |

Hors périmètre, donc absent (et c'est voulu) : `mode` par pattern, promotion automatique `detect`→`block`, nettoyage des 149 patterns, génération de règles depuis les CVE.

**Placeholders** : aucun — chaque étape porte son code et sa commande exacte. Deux « notes à l'implémenteur » demandent explicitement de **lire le code existant** (harnais de `main_test.go`, calcul de `clientIP`/`RuleID`) plutôt que d'inventer : c'est une instruction, pas un trou.

**Cohérence des types** : `modeBlock`/`modeDetect` (Task 1) sont consommés par Task 2 ; `compiledCategory.mode` (Task 1) est lu par `Match` (Task 2) ; la nouvelle signature `Match(...) (cat, sev, mode string, hit bool)` est déclarée en Task 2 et n'a qu'un seul appelant (`main.go:376`), modifié dans la même tâche.
