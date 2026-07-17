# sbxwaf — mode `escalate` — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ajouter un mode de catégorie `escalate` : observer et laisser passer les premières sondes d'une IP (comme `detect`), puis la bannir réellement (cscli → nft) une fois qu'elle a sondé N fois dans une fenêtre longue.

**Architecture:** `escalate` compose les deux comportements déjà livrés (`detect` = passe+journalise, `block` = 403+cscli), gatés sur un **compteur `Ban` séparé** (fenêtre longue, seuil propre) distinct de celui du mode `block`. Aucune logique de ban ni de report nouvelle.

**Tech Stack:** Go (`cmd/sbxwaf` de `secubox-toolbox-ng`), `go test`. Aucune dépendance nouvelle.

**Spec:** `docs/superpowers/specs/2026-07-17-sbxwaf-mode-escalate-design.md`

## Global Constraints

- **`escalate` n'utilise JAMAIS `s.ban`** (le compteur du mode `block`). Il a sa propre instance `s.escalateBan`. Mélanger les deux ferait « 1 SQLi bloqué + 2 sondes = ban » — deux signaux confondus, ce que le spec interdit.
- **La branche `escalate` est self-contained** : elle ne « tombe » PAS dans le bloc `if hit { … s.ban.Record … }` existant, qui incrémenterait le compteur `block`. Son action de ban (403 + `crowdsec.Report` + `writeBan` + threatLog `banned`) est faite dans la branche, sur `escalateBan`.
- **`mode` absent / `""` / `null` ⇒ `block`** ; **valeur inconnue ⇒ `block` + log bruyant** (fail-closed). Les 17 catégories livrées ne changent pas.
- **`escalateBan == nil` ⇒ la catégorie `escalate` se comporte comme `detect`** (observe, ne banne jamais). Fail-open côté ban : l'absence de compteur ne transforme pas l'observation en blocage.
- **Journal honnête (PR #872)** : les sondes observées portent `Action: "detect"` (exclues du compteur « bloqué ») ; le ban porte `Action: "banned"` (compté).
- **Défauts** : `--escalate-window` = **24h**, `--escalate-threshold` = **3**.
- **Déploiement** : `cp` échoue (« text file busy ») → **`mv`** ; **jamais** `kill -HUP` → `systemctl restart secubox-waf-ng`. sbxwaf est en frontal de TOUS les vhosts publics.
- Go, stdlib uniquement. Commits terminés par `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`. Aucune référence à Claude.

---

## Structure des fichiers

```
packages/secubox-toolbox-ng/cmd/sbxwaf/
├── rules.go        # MODIFIER : ajouter modeEscalate au switch de résolution
├── rules_test.go   # MODIFIER : parsing "escalate"
├── main.go         # MODIFIER : champ escalateBan, flags, branche escalate + helper
└── main_test.go    # MODIFIER : observe-avant-seuil, ban-au-seuil, compteur séparé, nil
```

Un seul site d'appel de `Match` (`main.go:383`) — le rayon de souffle est contenu.

---

### Task 1 : Parser le mode `escalate`

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxwaf/rules.go`
- Test: `packages/secubox-toolbox-ng/cmd/sbxwaf/rules_test.go`

**Interfaces:**
- Consomme : `modeBlock`, `modeDetect` (livrés).
- Produit : la constante `modeEscalate = "escalate"` ; une catégorie `mode: "escalate"` compile en `compiledCategory.mode == modeEscalate`.

- [ ] **Step 1 : écrire les tests qui échouent**

Ajouter à `cmd/sbxwaf/rules_test.go` (réutilise `writeRulesFile` et `catMode`, déjà présents) :

```go
func TestModeEscalateIsParsed(t *testing.T) {
	p := writeRulesFile(t, `{"probes":{"name":"Absent-product probes","severity":"high","mode":"escalate",
		"patterns":[{"id":"f5-1","pattern":"/mgmt/tm/util/bash","desc":"F5 RCE probe"}]}}`)
	if got := catMode(LoadRules(p), "probes"); got != modeEscalate {
		t.Fatalf("got %q, want %q", got, modeEscalate)
	}
}

// escalate must be a first-class known mode — an unknown value still fails
// closed to block, and "escalate" must NOT be treated as unknown.
func TestModeEscalateIsNotTreatedAsUnknown(t *testing.T) {
	p := writeRulesFile(t, `{"probes":{"name":"P","mode":"escalate",
		"patterns":[{"id":"f5-1","pattern":"/mgmt/tm/util/bash","desc":"x"}]}}`)
	r := LoadRules(p)
	if got := catMode(r, "probes"); got == modeBlock {
		t.Fatal("escalate fell through to block — it must be recognised, not treated as an unknown value")
	}
	// The category is still evaluated (a probe hits).
	if _, _, _, hit := r.Match("GET", "/mgmt/tm/util/bash", "", "", ""); !hit {
		t.Fatal("escalate category was dropped")
	}
}
```

- [ ] **Step 2 : lancer — doit échouer**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-toolbox-ng
go test ./cmd/sbxwaf/ -run 'TestModeEscalate' 2>&1 | tail -5
```
Attendu : échec de compilation — `undefined: modeEscalate`.

- [ ] **Step 3 : implémenter**

Dans `cmd/sbxwaf/rules.go`, ajouter `modeEscalate` à la déclaration des constantes de mode (à côté de `modeBlock`/`modeDetect`) :

```go
const (
	modeBlock    = "block"
	modeDetect   = "detect"
	modeEscalate = "escalate"
)
```

(Si les constantes sont déclarées individuellement plutôt qu'en bloc, ajouter `modeEscalate = "escalate"` dans le même style — lire le fichier avant d'éditer.)

Puis, dans le switch de résolution du mode (~ligne 213), ajouter `modeEscalate` aux valeurs connues et à la liste du message d'erreur :

```go
			switch *cat.Mode {
			case modeBlock, modeDetect, modeEscalate:
				mode = *cat.Mode
			default:
				log.Printf("sbxwaf/rules: category %q has unknown mode %q — falling back to %q (known modes: %q, %q, %q)",
					catID, *cat.Mode, modeBlock, modeBlock, modeDetect, modeEscalate)
			}
```

- [ ] **Step 4 : lancer — doit passer**

```bash
go test ./cmd/sbxwaf/ -run 'TestModeEscalate' -v 2>&1 | tail -8
```
Attendu : `ok` — 2 tests PASS.

- [ ] **Step 5 : non-régression + preuve par mutation**

```bash
go test ./cmd/sbxwaf/ 2>&1 | tail -2
```
Attendu : `ok`, aucune régression (`TestModeUnknownFailsClosedToBlock` etc. toujours verts).

Preuve par mutation : retirer temporairement `modeEscalate` de la clause `case` (le laisser tomber dans `default`), relancer `TestModeEscalateIsParsed` → **FAIL** (il devient `block`). Restaurer, reconfirmer PASS. Consigner les deux observations.

- [ ] **Step 6 : commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbxwaf/rules.go packages/secubox-toolbox-ng/cmd/sbxwaf/rules_test.go
git commit -m "feat(sbxwaf): recognise the escalate mode value

escalate is a first-class known mode alongside block/detect. Absent/unknown
still fail closed to block; escalate itself must not be treated as unknown.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 2 : Le chemin `escalate` — compteur séparé, observe puis banne

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxwaf/main.go`
- Test: `packages/secubox-toolbox-ng/cmd/sbxwaf/main_test.go`

**Interfaces:**
- Consomme : `modeEscalate` (Task 1) ; `Ban` / `NewBan(window, threshold)` / `Ban.Record(ip, now) → (count, banned)` ; `CscliReporter` via `s.crowdsec` ; `writeBan(w)` ; `ThreatRecord` / `s.threatLog.Record` ; `Server` (`main.go:119`).
- Produit : le champ `Server.escalateBan *Ban` ; les flags `--escalate-window` / `--escalate-threshold` ; la branche `escalate` dans le handler.

- [ ] **Step 1 : écrire les tests qui échouent**

Ajouter à `cmd/sbxwaf/main_test.go`. Réutiliser le harnais existant : `newDetectTestServer(t, backendURL, rulesPath)`, `detectTestReq(clientIP)`, `s.handler()`, `writeRulesFile`. **Lire ces helpers d'abord** — ne pas en inventer.

`newDetectTestServer` construit un `Server` avec `ban: NewBan(300s, 3)` mais **sans** `escalateBan`. Ces tests l'injectent après construction : `s.escalateBan = NewBan(time.Hour, 3)`.

```go
// escalate observes the first N-1 probes: they PASS (like detect) and do NOT
// ban. Only the Nth probe from the same IP bans.
func TestEscalateObservesThenBansAtThreshold(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"probes":{"name":"P","severity":"high","mode":"escalate",
		"patterns":[{"id":"f5-1","pattern":"/mgmt/tm/util/bash","desc":"F5 probe"}]}}`)

	backendHits := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)
	s.escalateBan = NewBan(time.Hour, 3) // threshold 3
	handler := s.handler()

	// Probes 1 and 2: observed, pass through, backend reached.
	for i := 1; i <= 2; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, detectTestReq("203.0.113.60"))
		if rec.Code == http.StatusForbidden {
			t.Fatalf("probe %d: got 403, escalate must observe (pass) before the threshold", i)
		}
	}
	if backendHits != 2 {
		t.Fatalf("expected 2 observed probes to reach the backend, got %d", backendHits)
	}
	if s.escalateBan.Count("203.0.113.60") < 2 {
		t.Fatal("escalate did not count the observed probes")
	}

	// Probe 3: threshold reached → ban (403).
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, detectTestReq("203.0.113.60"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("probe 3 (threshold): got %d, want 403 (ban)", rec.Code)
	}
}

// escalate must NOT touch the block counter (s.ban): the two signals are
// separate. Probing an escalate category must not advance s.ban.
func TestEscalateUsesItsOwnCounterNotTheBlockBan(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"probes":{"name":"P","severity":"high","mode":"escalate",
		"patterns":[{"id":"f5-1","pattern":"/mgmt/tm/util/bash","desc":"F5 probe"}]}}`)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)
	s.escalateBan = NewBan(time.Hour, 3)
	handler := s.handler()

	handler.ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.61"))
	handler.ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.61"))

	if s.ban != nil && s.ban.Count("203.0.113.61") != 0 {
		t.Fatalf("escalate advanced the block counter s.ban (%d); the counters must be separate",
			s.ban.Count("203.0.113.61"))
	}
	if s.escalateBan.Count("203.0.113.61") != 2 {
		t.Fatalf("escalate counter = %d, want 2", s.escalateBan.Count("203.0.113.61"))
	}
}

// With no escalate counter, an escalate category behaves like detect: it
// observes and never bans — never like block.
func TestEscalateWithNilCounterBehavesLikeDetect(t *testing.T) {
	rulesPath := writeRulesFile(t, `{"probes":{"name":"P","severity":"high","mode":"escalate",
		"patterns":[{"id":"f5-1","pattern":"/mgmt/tm/util/bash","desc":"F5 probe"}]}}`)
	reached := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)
	s.escalateBan = nil // no counter
	handler := s.handler()

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, detectTestReq("203.0.113.62"))
		if rec.Code == http.StatusForbidden {
			t.Fatalf("nil escalate counter must observe (pass), never ban; got 403 on probe %d", i+1)
		}
	}
	if !reached {
		t.Fatal("nil escalate counter: request was swallowed")
	}
}

// The ban at threshold logs action="banned" (counted as a block); the observed
// probes log action="detect" (excluded from the block counters).
func TestEscalateLogsDetectWhileObservingAndBannedAtThreshold(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "threats.jsonl")
	rulesPath := writeRulesFile(t, `{"probes":{"name":"P","severity":"high","mode":"escalate",
		"patterns":[{"id":"f5-1","pattern":"/mgmt/tm/util/bash","desc":"F5 probe"}]}}`)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newDetectTestServer(t, backend.URL, rulesPath)
	s.escalateBan = NewBan(time.Hour, 2) // threshold 2 for a short test
	s.threatLog = NewThreatLog(logPath)
	handler := s.handler()

	handler.ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.63")) // observe → "detect"
	handler.ServeHTTP(httptest.NewRecorder(), detectTestReq("203.0.113.63")) // threshold → "banned"

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("threat log not written: %v", err)
	}
	if !strings.Contains(string(raw), `"detect"`) {
		t.Fatalf("observed probe must log action=detect, got: %s", raw)
	}
	if !strings.Contains(string(raw), `"banned"`) {
		t.Fatalf("threshold probe must log action=banned, got: %s", raw)
	}
}
```

- [ ] **Step 2 : lancer — doit échouer**

```bash
go test ./cmd/sbxwaf/ -run 'TestEscalate' 2>&1 | tail -5
```
Attendu : échec de compilation (`s.escalateBan` inconnu).

- [ ] **Step 3 : implémenter — champ + flags + construction**

Dans `type Server struct` (~ligne 128, à côté de `ban *Ban`), ajouter :

```go
	// escalateBan counts hits on `escalate`-mode categories in a SEPARATE
	// sliding window (long, e.g. 24h) from `ban`. escalate observes (passes,
	// logs "detect") until this counter says banned, then bans via crowdsec.
	// Nil means escalate behaves like detect (observe, never ban).
	escalateBan *Ban
```

Dans `main()`, à côté des autres flags (~ligne 592+) :

```go
	escalateWindow := flag.Duration("escalate-window", 24*time.Hour,
		"sliding window for escalate-mode categories (a slow scanner needs a long window)")
	escalateThreshold := flag.Int("escalate-threshold", 3,
		"probes within the escalate window before an IP is banned")
```

Dans la construction du `Server` (~ligne 676, à côté de `ban: NewBan(...)`), ajouter :

```go
		escalateBan: NewBan(*escalateWindow, *escalateThreshold),
```

- [ ] **Step 4 : implémenter — la branche `escalate` dans le handler**

À `main.go`, juste après le bloc `if hit && mode == modeDetect { … }` et **avant** `if hit {` (le chemin block), insérer :

```go
				if hit && mode == modeEscalate {
					// Observe first, ban a persistent scanner. Uses a SEPARATE
					// counter (escalateBan) so probes for absent products never
					// mix with the block-mode ban signal. Self-contained: it does
					// NOT fall through to the block path below, which would double
					// count into s.ban.
					if s.escalateBan == nil {
						// No counter → observe like detect, never ban.
						s.logEscalate(r, ip, rawPath, cat, sev, "detect")
						hit = false
					} else if _, banned := s.escalateBan.Record(ip, time.Now().Unix()); banned {
						// Threshold crossed: ban for real, exactly as the block
						// path's ban branch does — but gated on escalateBan.
						s.logEscalate(r, ip, rawPath, cat, sev, "banned")
						if s.crowdsec != nil {
							go s.crowdsec.Report(ip, cat, sev)
						}
						writeBan(w)
						return
					} else {
						// Still observing: log and let it through.
						s.logEscalate(r, ip, rawPath, cat, sev, "detect")
						hit = false
					}
				}
```

Ajouter le helper (près du handler, ou en méthode sur `*Server`) — factorise l'écriture du threat record, identique aux deux branches sauf `action` :

```go
// logEscalate writes one threat record for an escalate-mode hit. `action` is
// "detect" while observing and "banned" once the threshold is crossed.
func (s *Server) logEscalate(r *http.Request, ip, rawPath, cat, sev, action string) {
	if s.threatLog == nil {
		return
	}
	s.threatLog.Record(ThreatRecord{
		ClientIP: ip,
		Host:     r.Host,
		Method:   r.Method,
		Path:     rawPath,
		Category: cat,
		Severity: sev,
		RuleID:   "",
		Action:   action,
		UA:       r.Header.Get("User-Agent"),
	})
}
```

**Note à l'implémenteur** : lire les lignes autour de `if hit && mode == modeDetect` pour reprendre EXACTEMENT le nom de la variable IP (`ip`), de `rawPath`, et la façon dont `r` est disponible dans ce scope. Ne pas inventer.

- [ ] **Step 5 : lancer — doit passer**

```bash
go test ./cmd/sbxwaf/ 2>&1 | tail -3
```
Attendu : `ok` — tout le paquet, les 4 tests escalate verts, aucune régression.

- [ ] **Step 6 : race + vet**

```bash
go test -race ./cmd/sbxwaf/ 2>&1 | tail -2
go vet ./cmd/sbxwaf/ 2>&1 | tail -1 && echo "vet ✓"
```
Attendu : `ok` (le champ `escalateBan` est un `*Ban` déjà mutex-protégé), vet propre.

- [ ] **Step 7 : preuve par mutation**

Remplacer temporairement, dans la branche `escalate`, `s.escalateBan.Record` par `s.ban.Record`, relancer :
```bash
go test ./cmd/sbxwaf/ -run TestEscalateUsesItsOwnCounterNotTheBlockBan 2>&1 | tail -3
```
Attendu : **FAIL** (le compteur `block` avance). Restaurer, reconfirmer PASS. Puis retirer la ligne `hit = false` de la branche « still observing » → `TestEscalateObservesThenBansAtThreshold` FAIL (403 dès la 1re sonde). Restaurer. Consigner les deux observations.

- [ ] **Step 8 : commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbxwaf/main.go packages/secubox-toolbox-ng/cmd/sbxwaf/main_test.go
git commit -m "feat(sbxwaf): escalate path — observe on a separate counter, then ban

A separate escalateBan (default 24h/3, --escalate-window/--escalate-threshold)
counts hits on escalate-mode categories. Below the threshold the request passes
and logs action=detect (like detect); at the threshold it bans exactly as the
block path does (crowdsec.Report + writeBan) — but gated on escalateBan, never
s.ban, so the slow-scanner signal never mixes with the block ban. A nil
escalateBan degrades to detect (observe, never ban), never to block.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 3 : Déployer sur gk2 et prouver sur du trafic réel

**Files:** aucun (déploiement).

⚠️ **sbxwaf est en frontal de TOUS les vhosts publics.** Une régression coupe tout. Juger par les codes HTTP (valides sous charge), avec retry — la box peut être à load élevé (transcodage). `admin.gk2` contourne le WAF (`webui_direct` + `trustedHosts`) : **tester via `billets.gk2` + un `X-Forwarded-For` public** pour traverser réellement le WAF.

- [ ] **Step 1 : construire pour arm64**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-toolbox-ng
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags=-s -o /tmp/sbxwaf ./cmd/sbxwaf
file /tmp/sbxwaf | grep -o "ARM aarch64"
```
Attendu : `ARM aarch64`.

- [ ] **Step 2 : AVANT — santé + sauvegarde**

```bash
ssh root@192.168.1.200 'systemctl is-active secubox-waf-ng
cp /usr/sbin/sbxwaf /tmp/sbxwaf.bak.pre-escalate && echo "binaire sauvegardé"
curl -sk -o /dev/null -w "billets -> %{http_code}\n" --max-time 15 https://billets.gk2.secubox.in/ --resolve billets.gk2.secubox.in:443:127.0.0.1'
```
Attendu : `active`, sauvegarde faite, `200`.

- [ ] **Step 3 : le nouveau binaire doit passer `--escalate-window`/`--escalate-threshold` — vérifier l'unit**

```bash
ssh root@192.168.1.200 'systemctl show secubox-waf-ng -p ExecStart --value | tr " " "\n" | grep -E "escalate" || echo "  (flags escalate ABSENTS de l unit — défauts 24h/3 utilisés)"'
```
Les défauts (24h/3) s'appliquent si les flags ne sont pas dans l'unit — acceptable pour cette preuve. **Ne pas modifier l'unit** dans ce plan (c'est une décision d'exploitation).

- [ ] **Step 4 : déployer**

```bash
scp /tmp/sbxwaf root@192.168.1.200:/tmp/sbxwaf.new
ssh root@192.168.1.200 'mv /tmp/sbxwaf.new /usr/sbin/sbxwaf && chmod 755 /usr/sbin/sbxwaf && systemctl restart secubox-waf-ng && sleep 3 && systemctl is-active secubox-waf-ng'
```
Attendu : `active`.

- [ ] **Step 5 : non-régression — le block banne toujours**

```bash
ssh root@192.168.1.200 'for i in 1 2 3; do
  curl -sk -o /dev/null -w "  sqli essai $i -> %{http_code}\n" --max-time 20 -H "X-Forwarded-For: 203.0.113.201" "https://billets.gk2.secubox.in/?q=union+select+1" --resolve billets.gk2.secubox.in:443:127.0.0.1
done'
```
Attendu : `403` (au moins sur retry). Les catégories sans `mode` bloquent toujours.

- [ ] **Step 6 : preuve `escalate` live (seuil bas, catégorie de test, à chaud)**

Créer une catégorie `escalate` de test avec un seuil de 2 et un pattern inoffensif, la charger à chaud (hot-reload livré), envoyer 3 sondes depuis une même IP forgée, vérifier passe→ban, puis restaurer. Le seuil du binaire est 24h/3 par défaut ; **pour prouver rapidement sans reconfigurer l'unit, on ne peut pas baisser le seuil binaire à chaud** — donc cette preuve démontre l'observation (les sondes passent et sont journalisées `detect`) et laisse la preuve du *ban au seuil* aux tests unitaires (Task 2), qui l'établissent déterministe­ment.

```bash
ssh root@192.168.1.200 'bash -s' <<'REMOTE'
set -e
cp /etc/secubox/waf/waf-rules.json /etc/secubox/waf/waf-rules.json.bak.esc
FF="--max-time 20 --resolve billets.gk2.secubox.in:443:127.0.0.1"
python3 - <<'PY'
import json
p="/etc/secubox/waf/waf-rules.json"
d=json.load(open(p))
d["categories"]["esc_test"]={"name":"Escalate test","severity":"high","mode":"escalate",
  "patterns":[{"id":"esc-1","pattern":"/__escalate_probe__","desc":"test probe"}]}
json.dump(d, open(p,"w"), indent=2, ensure_ascii=False)
print("  esc_test ajouté en mode escalate (hot-reload)")
PY
sleep 2
echo "=== 3 sondes: doivent PASSER (observation, seuil binaire 3 non atteint en une passe) ==="
for i in 1 2 3; do
  curl -sk -o /dev/null -w "  sonde $i -> %{http_code} (attendu != 403, observé)\n" $FF -H "X-Forwarded-For: 203.0.113.210" "https://billets.gk2.secubox.in/__escalate_probe__"
done
echo "=== le threat log porte-t-il action=detect pour ces sondes ? ==="
TL=$(systemctl show secubox-waf-ng -p ExecStart --value | tr " " "\n" | grep -A1 "threat-log" | tail -1)
tail -8 "${TL:-/var/log/secubox/waf/waf-threats.log}" 2>/dev/null | grep "__escalate_probe__" | grep -o '"action":"[a-z]*"' | tail -3
echo "=== restauration ==="
mv /etc/secubox/waf/waf-rules.json.bak.esc /etc/secubox/waf/waf-rules.json
sleep 2
curl -sk -o /dev/null -w "  esc_test retiré -> catégorie disparue (404 attendu)\n" $FF -H "X-Forwarded-For: 203.0.113.211" "https://billets.gk2.secubox.in/__escalate_probe__"
REMOTE
```
Attendu : les 3 sondes passent (≠403), le threat log porte `"action":"detect"`, la catégorie disparaît après restauration. **Le ban au seuil est prouvé par les tests unitaires** (déterministe, sans dépendre du seuil binaire de prod).

- [ ] **Step 7 : consigner**

Reporter : codes AVANT/APRÈS des vhosts, non-régression SQLi (403), observation escalate (sondes passent + `action=detect`), restauration propre.

---

## Auto-revue du plan

**Couverture du spec** :

| Exigence du spec | Tâche |
|---|---|
| `mode: escalate` reconnu, fail-closed préservé | 1 |
| Compteur SÉPARÉ (2e instance `Ban`) | 2 (Step 3 champ + Step 7 mutation `s.ban` vs `escalateBan`) |
| Fenêtre longue + seuil configurables (défauts 24h/3) | 2 (flags) |
| Observe avant seuil (passe, `action=detect`) | 2 (`TestEscalateObservesThenBansAtThreshold`, `…LogsDetect…`) |
| Ban au seuil (403 + `crowdsec.Report` + `action=banned`) | 2 |
| Ne PAS tomber dans le chemin block (`s.ban`) | 2 (branche self-contained + mutation Step 7) |
| `escalateBan == nil` ⇒ comme `detect` | 2 (`TestEscalateWithNilCounterBehavesLikeDetect`) |
| Journal honnête (detect exclu, banned compté) | 2 (helper `logEscalate` + PR #872) |
| Déploiement `mv` + `systemctl restart` + preuve live | 3 |
| Tests capables d'échouer (mutation) | 1 (Step 5), 2 (Step 7) |

Hors périmètre, donc absent (voulu) : génération de règles (spec B), corrélation ASN/JA4, promotion auto `detect`→`escalate`, câblage des flags dans l'unit systemd (décision d'exploitation).

**Placeholders** : aucun — chaque étape porte son code et sa commande. Deux « notes à l'implémenteur » demandent de **lire le code existant** (harnais `main_test.go`, variables `ip`/`rawPath`/`r` du scope) plutôt que d'inventer — instruction, pas trou.

**Cohérence des types** : `modeEscalate` (Task 1) consommé par Task 2 ; `Server.escalateBan *Ban` (Task 2) est un `*Ban` existant, `Ban.Record`/`Ban.Count` déjà livrés ; la signature de `Match` (`cat, sev, mode, hit`) est celle en place depuis PR #872, non modifiée ici ; le helper `logEscalate` est défini et appelé dans la même tâche.
