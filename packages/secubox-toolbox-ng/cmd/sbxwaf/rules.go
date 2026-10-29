// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — WAF rule engine (waf-rules.json)
//
// Ported from packages/secubox-mitmproxy/addons/secubox_waf.py:
//   - load_rules (~line 727): parse categories, compile patterns case-insensitively
//   - check_request (~line 758): match against decoded path / query / body / UA
//
// JSON shape (packages/secubox-waf/config/waf-rules.json):
//
//	{
//	  "categories": {
//	    "<cat_id>": {
//	      "name":     string,
//	      "severity": "low"|"medium"|"high"|"critical",   // default "medium"
//	      "enabled":  bool,                                // default true
//	      "patterns": [{"id": string, "pattern": string, "desc": string}, ...]
//	    }
//	  }
//	}
//
// Loading semantics (mirrors Python):
//   - A category where enabled == false is skipped entirely.
//   - Each "pattern" string is compiled as "(?i)"+pattern (case-insensitive).
//     Go uses RE2; patterns that fail to compile (e.g., lookaheads, backrefs)
//     are SKIPPED with a log.Printf — not fatal (mirrors Python's except re.error: pass).
//   - Severity is per-category; every pattern in the category inherits it.
//
// Match semantics (mirrors Python check_request):
//   - Match(method, rawPath, rawQuery, body, ua) accepts RAW (URL-encoded)
//     path and query strings; it applies unquote_plus-equivalent decoding
//     internally before scanning, matching Python's urllib.parse.unquote_plus
//     behaviour ('+' → space, then percent-unescape).
//   - The scan target is: decoded(path) + " " + decoded(query) + " " + body + " " + ua,
//     all lowercased, concatenated with spaces (mirrors Python's scan_text).
//   - Pattern iteration: categories in insertion order, patterns within each
//     category in insertion order. First match wins; returns cat, sev, hit=true.
//     No match → "", "", false.
//
// Hot-reload: mirrors routes.go — reload.NewWatcher(throttle=0, target) with
// throttle=0 so tests that call Maybe() trigger an immediate reload.  Production
// code can layer its own rate gate (same pattern as Routes.Maybe()).
//
// RE2 vs Python regex gap (checked against packages/secubox-waf/config/waf-rules.json):
//
//	CETTE AFFIRMATION A ETE FAUSSE (#1310). Cinq motifs CVE — trois cve_voip,
//	deux cve_xmpp — utilisaient `\u0000`, que RE2 ne connait pas : ils etaient
//	SILENCIEUSEMENT IGNORES, ecrits et livres mais ne protegeant rien. Corriges
//	en `\x00` (regles 1.5.2).
//
//	La lecon n'est pas l'echappement, c'est le SILENCE : le filet de securite
//	journalise au demarrage puis se tait, et un motif absent ne se distingue
//	pas d'un motif qui ne matche jamais. Un compte de motifs charges compare
//	au compte de motifs declares rendrait l'ecart visible — c'est le vrai
//	correctif, il reste a faire.
package main

import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"regexp"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reload"
)

// Rule evaluation modes for a category.
//
//	modeBlock  — a match blocks the request (the historical, only behaviour).
//	modeDetect — a match is counted and logged, the request PASSES, and nothing
//	             is banned. Lets an operator try a rule against real traffic
//	             before arming it.
//	modeEscalate — a match is observed first; after N occurrences from the same
//	              source within a time window, the source is banned. Intermediate
//	              protection: observe persistent scanners, block them, but allow
//	              transient false positives.
//
// A category with no "mode" is modeBlock. A detect default would silently turn
// the whole WAF into an observer — a mute security outage.
const (
	modeBlock    = "block"
	modeDetect   = "detect"
	modeEscalate = "escalate"
)

// compiledPattern holds a compiled regex and its metadata.
type compiledPattern struct {
	id   string
	re   *regexp.Regexp
	desc string
	// severity is inherited from the parent category at compile time.
	severity string
}

// compiledCategory is one loaded WAF category with all its compiled patterns.
type compiledCategory struct {
	name     string
	severity string
	mode     string // modeBlock | modeDetect — never empty after loadFile
	patterns []compiledPattern
	// structurelles : signatures lues sur le ResultatMultipart de l'analyseur
	// (#3257). Jamais consultees par MatchDetail.
	structurelles []signatureStructurelle
}

// signatureStructurelle est une signature qui ne lit pas le texte de la
// requete mais la STRUCTURE d'un envoi multipart. params porte les seuils
// (entiers >= 1) du controle nomme par check.
type signatureStructurelle struct {
	id, check, severity, cve, confidence string
	params                               map[string]int
	// services (#3273) : services PHP visés ; vide = tous. Un hôte PHP reconnu
	// par motif (service "") est toujours visé.
	services []string
}

// DetectionStructurelle est le constat d'une signature structurelle. Severity
// est celle de la signature, sinon celle de la categorie.
type DetectionStructurelle struct {
	Categorie string
	RuleID    string
	Severity  string
	CVE       string
}

// parametreRequis donne, par controle connu, le parametre entier obligatoire
// ("" : aucun). Un controle absent de cette table est inconnu donc rejete.
var parametreRequis = map[string]string{
	"upload_progress_fichiers": "fichiers_apres_min",
	"parties_nombre":           "parties_min",
	"noms_profondeur":          "profondeur_min",
	"filename_charge":          "",
}

// structurelJSON : champs inconnus ignores ; "source" (liste d'URL, ou tout
// autre type) n'est volontairement pas declare, pour qu'un type inattendu ne
// fasse jamais echouer le chargement.
type structurelJSON struct {
	ID         string                     `json:"id"`
	Check      string                     `json:"check"`
	Params     map[string]json.RawMessage `json:"params"`
	Severity   string                     `json:"severity"`
	CVE        string                     `json:"cve"`
	Confidence string                     `json:"confidence"`
	Services   []string                   `json:"services"`
}

// compileStructurel valide une entree "structural". Une erreur rend un motif
// de rejet, jamais un echec du fichier.
func compileStructurel(brut json.RawMessage, mode string) (signatureStructurelle, string, error) {
	var sj structurelJSON
	if err := json.Unmarshal(brut, &sj); err != nil {
		// Un champ mal typé ("services": "roundcube") n'arrête pas le
		// décodage des autres (encoding/json) : l'id lu nomme le rejet.
		return signatureStructurelle{}, sj.ID, err
	}
	if sj.ID == "" {
		return signatureStructurelle{}, "", errStructurel("id vide")
	}
	if mode != modeDetect {
		return signatureStructurelle{}, sj.ID, errStructurel("categorie en mode " + mode + " : l'analyse en flux ne peut que detecter")
	}
	requis, connu := parametreRequis[sj.Check]
	if !connu {
		return signatureStructurelle{}, sj.ID, errStructurel("controle inconnu " + strconv.Quote(sj.Check))
	}
	params := make(map[string]int, len(sj.Params))
	for nom, v := range sj.Params {
		n, err := strconv.Atoi(strings.TrimSpace(string(v)))
		if err != nil {
			return signatureStructurelle{}, sj.ID, errStructurel("parametre " + nom + " non entier")
		}
		params[nom] = n
	}
	if requis != "" {
		if n, ok := params[requis]; !ok || n < 1 {
			return signatureStructurelle{}, sj.ID, errStructurel("parametre " + requis + " absent ou < 1")
		}
	}
	return signatureStructurelle{
		id: sj.ID, check: sj.Check, severity: sj.Severity, cve: sj.CVE,
		confidence: sj.Confidence, params: params, services: sj.Services,
	}, sj.ID, nil
}

type errStructurel string

func (e errStructurel) Error() string { return string(e) }

// declenche applique le controle a l'entree PHP (seuils a >=). Les controles
// multipart sont faux sans corps multipart analyse.
func (s signatureStructurelle) declenche(e *EntreePHP) bool {
	if e.Multipart == nil {
		return false
	}
	res := *e.Multipart
	switch s.check {
	case "upload_progress_fichiers":
		return res.Progress && res.FichiersApresProgress >= s.params["fichiers_apres_min"]
	case "parties_nombre":
		return res.Parties >= s.params["parties_min"]
	case "noms_profondeur":
		return res.ProfondeurMax >= s.params["profondeur_min"]
	case "filename_charge":
		return res.FilenamePHP || res.FilenameObjet
	}
	return false
}

// rulesData is the hot-swappable payload — a slice of categories in the order
// they were loaded from JSON (Go 1.22+ map iteration is random, so we preserve
// order via a separate ordered slice rather than a map, matching Python which
// iterates dict items in insertion order).
type rulesData struct {
	// ordered list of (cat_id, compiledCategory) pairs.
	cats []struct {
		id   string
		data compiledCategory
	}

	// DECLARES vs CHARGES — l'ecart qui n'existait nulle part (#1317).
	//
	// Le chargeur comptait les motifs COMPILES et journalisait chaque rejet,
	// une fois, au demarrage. Puis il se taisait. Or un motif rejete et un
	// motif qui n'attrape jamais rien produisent EXACTEMENT la meme chose :
	// zero prise, zero ligne, zero alerte. Rien ne les separait.
	//
	// C'est ce silence qui a laisse cinq motifs CVE inertes — ecrits, relus,
	// livres, versionnes — sans que personne ne s'en apercoive (#1310). Les
	// corriger sans rendre l'ecart MESURABLE, c'etait accepter de recommencer
	// au prochain.
	declares int
	rejetes  []string
}

// Rules is a hot-reloadable, RW-locked WAF rule set.
// Create with LoadRules; call Match on the hot path; call Maybe() to pick up
// on-disk changes (throttle=0 → eager, same as Routes).
type Rules struct {
	mu      sync.RWMutex
	current *rulesData

	// watcher handles mtime tracking + Apply callbacks.
	watcher *reload.Watcher
}

// loadRulesJSON parses waf-rules.json and compiles all enabled patterns.
// Returns an empty (never-matching) rulesData on any parse/file error.
// Individual patterns that fail to compile are skipped with a log.Printf.
func loadRulesJSON(path string) *rulesData {
	data := &rulesData{}

	raw, err := os.ReadFile(path)
	if err != nil {
		// Missing file is best-effort — return empty rules (always-miss).
		return data
	}

	// Parse outer wrapper: expect {"categories": {...}}.
	// We use a two-level decode: outer is map[string]json.RawMessage so we can
	// handle the optional "_meta" key without failing.
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil {
		log.Printf("sbxwaf/rules: parse %s outer: %v", path, err)
		return data
	}

	catRaw, ok := outer["categories"]
	if !ok {
		// No "categories" key — treat as empty.
		return data
	}

	// Parse categories as map[string]json.RawMessage to preserve per-category
	// raw bytes while we iterate.  Order is randomised by Go's map; to preserve
	// deterministic ordering (and match Python's dict insertion order on >=3.7),
	// we use a json.Decoder to iterate tokens in order.
	type patternJSON struct {
		ID      string `json:"id"`
		Pattern string `json:"pattern"`
		Desc    string `json:"desc"`
	}
	type categoryJSON struct {
		Name     string        `json:"name"`
		Severity string        `json:"severity"`
		Enabled  *bool         `json:"enabled"` // pointer: nil means absent (default true)
		Mode     *string       `json:"mode"`    // pointer: nil means absent (default block)
		Patterns []patternJSON `json:"patterns"`
		// Brut : une forme inattendue est rejetee nommement plus bas, elle ne
		// doit pas faire sauter la categorie entiere (ses motifs regex).
		Structural json.RawMessage `json:"structural"`
	}

	// Use a simple ordered parse: json.Decoder over the categories object,
	// reading key-value pairs in order.
	dec := json.NewDecoder(strings.NewReader(string(catRaw)))

	// Consume the opening '{'.
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		log.Printf("sbxwaf/rules: categories is not a JSON object in %s", path)
		return data
	}

	total := 0
	for dec.More() {
		// Read category ID key.
		keyTok, err := dec.Token()
		if err != nil {
			break
		}
		catID, ok := keyTok.(string)
		if !ok {
			continue
		}

		// Decode the category value.
		var cat categoryJSON
		if err := dec.Decode(&cat); err != nil {
			log.Printf("sbxwaf/rules: skipping category %q: %v", catID, err)
			continue
		}

		// Default: enabled=true when the field is absent.
		if cat.Enabled != nil && !*cat.Enabled {
			continue
		}

		// Default severity.
		sev := cat.Severity
		if sev == "" {
			sev = "medium"
		}

		// Resolve the evaluation mode. Absent, null or "" ⇒ block: the 17
		// shipped categories carry no "mode" and must keep blocking.
		//
		// An UNKNOWN value also ⇒ block, loudly. Fail closed: a typo like
		// "monitor" must never silently drop a protection nor downgrade it to
		// observation. This is the same instinct as Enabled's pointer default.
		mode := modeBlock
		if cat.Mode != nil && *cat.Mode != "" {
			switch *cat.Mode {
			case modeBlock, modeDetect, modeEscalate:
				mode = *cat.Mode
			default:
				log.Printf("sbxwaf/rules: category %q has unknown mode %q — falling back to %q (known modes: %q, %q, %q)",
					catID, *cat.Mode, modeBlock, modeBlock, modeDetect, modeEscalate)
			}
		}

		cc := compiledCategory{
			name:     cat.Name,
			severity: sev,
			mode:     mode,
		}
		if cc.name == "" {
			cc.name = catID
		}

		for _, p := range cat.Patterns {
			if p.Pattern == "" {
				continue
			}
			// Compte AVANT la tentative : un motif declare le reste, qu'il
			// compile ou non. C'est la difference entre les deux nombres qui
			// porte l'information.
			data.declares++
			// Case-insensitive prefix, matching Python re.compile(pat, re.IGNORECASE).
			re, err := regexp.Compile("(?i)" + p.Pattern)
			if err != nil {
				log.Printf("sbxwaf/rules: category %q pattern %q failed to compile (skipped): %v", catID, p.ID, err)
				// L'IDENTIFIANT, PAS SEULEMENT LE COMPTE. Savoir qu'il en
				// manque cinq sans savoir lesquels ne permet pas d'agir.
				data.rejetes = append(data.rejetes, catID+"/"+p.ID)
				continue
			}
			cc.patterns = append(cc.patterns, compiledPattern{
				id:       p.ID,
				re:       re,
				desc:     p.Desc,
				severity: sev,
			})
			total++
		}

		// Signatures structurelles (#3257) : chacune est chargee ou rejetee
		// NOMMEMENT, jamais ignoree. Une erreur locale ne touche ni les autres
		// signatures ni les motifs regex.
		if len(cat.Structural) > 0 && string(cat.Structural) != "null" {
			var entrees []json.RawMessage
			if err := json.Unmarshal(cat.Structural, &entrees); err != nil {
				log.Printf("sbxwaf/rules: category %q structural is not a list (rejected): %v", catID, err)
				data.declares++
				data.rejetes = append(data.rejetes, catID+"#structural")
			}
			for i, brut := range entrees {
				data.declares++
				sig, id, err := compileStructurel(brut, mode)
				if err != nil {
					nom := catID + "#" + strconv.Itoa(i)
					if id != "" {
						nom = catID + "/" + id
					}
					log.Printf("sbxwaf/rules: category %q structural %s rejected: %v", catID, nom, err)
					data.rejetes = append(data.rejetes, nom)
					continue
				}
				if sig.severity == "" {
					sig.severity = sev
				}
				cc.structurelles = append(cc.structurelles, sig)
			}
		}

		data.cats = append(data.cats, struct {
			id   string
			data compiledCategory
		}{id: catID, data: cc})
	}

	log.Printf("sbxwaf/rules: loaded %d patterns in %d categories from %s", total, len(data.cats), path)
	if len(data.rejetes) > 0 {
		// « ALERTE » et non « info » : des motifs ecrits et livres ne
		// protegent rien. Le message porte les identifiants pour qu'on puisse
		// aller les corriger sans les rechercher.
		log.Printf("sbxwaf/rules: ALERTE — %d motifs DECLARES, %d CHARGES : %d NE PROTEGENT RIEN (%s)",
			data.declares, total, len(data.rejetes), strings.Join(data.rejetes, ", "))
	}
	return data
}

// LoadRules parses path as a waf-rules.json file and returns a *Rules ready
// for Match.  A missing or unreadable file yields an empty (always-miss) Rules —
// the caller will get hit=false until a valid file appears and Maybe() reloads it.
func LoadRules(path string) *Rules {
	r := &Rules{}

	// Initial load.
	r.current = loadRulesJSON(path)

	// Register hot-reload target.  throttle=0 so Maybe() fires immediately in
	// tests; production can wrap with its own rate gate (mirrors Routes.Maybe()).
	target := reload.Target{
		Path:      path,
		LastMtime: reload.StatMtime(path),
		Load: func(p string) any {
			return loadRulesJSON(p)
		},
		Apply: func(v any) {
			newData := v.(*rulesData)
			r.mu.Lock()
			r.current = newData
			r.mu.Unlock()
		},
	}
	r.watcher = reload.NewWatcher(0, target)
	return r
}

// Maybe triggers a hot-reload check — stats the rules file and atomically
// swaps the compiled rule set if the mtime changed.  Cheap when nothing
// changed (one stat + one time compare).  Call from the request hot path or
// from a ticker.  Mirrors Routes.Maybe().
func (r *Rules) Maybe() {
	r.watcher.Maybe()
}

// unquotePlus mirrors Python's urllib.parse.unquote_plus:
// replace '+' with ' ', then percent-unescape.
// We apply this to both path and query before scanning.
func unquotePlus(s string) string {
	// Replace '+' with space first (unquote_plus semantic).
	s = strings.ReplaceAll(s, "+", " ")
	// Then percent-unescape. url.PathUnescape handles %XX sequences; it is
	// equivalent to urllib.parse.unquote for the remaining percent-encoded chars.
	decoded, err := url.PathUnescape(s)
	if err != nil {
		// On malformed percent-encoding, return best-effort (as-is after + swap).
		return s
	}
	return decoded
}

// Match checks the request against all compiled WAF rules (all modes). See the
// package doc for scan-target and iteration semantics. Equivalent to
// MatchModes(..., includeBlock=true).
func (r *Rules) Match(method, rawPath, rawQuery, body, ua string) (cat, sev, mode string, hit bool) {
	return r.MatchModes(method, rawPath, rawQuery, body, ua, true)
}

// MatchModes is Match with a category-mode filter. When includeBlock is false,
// categories in modeBlock are skipped entirely — used by the static-asset fast
// path, where only detect/escalate (path-fingerprint) categories run so a
// legitimate static asset can never be newly blocked. Otherwise identical to
// Match (same decoding, same scan target, first-match-wins in category order).
func (r *Rules) MatchModes(method, rawPath, rawQuery, body, ua string, includeBlock bool) (cat, sev, mode string, hit bool) {
	return r.MatchExcept(method, rawPath, rawQuery, body, ua, includeBlock, nil)
}

// MatchExcept is MatchModes with an extra category-id exclusion set. Any
// category whose id is in `exclure` is skipped entirely.
//
// Phase G (#1080) uses it as a SAFETY RE-CHECK. When a request's first hit is
// a SUPPRESSIBLE reconnaissance category on a legitimate vhost path, the same
// request could ALSO carry an injection that first-match-wins masked (the recon
// category matched the path before the injection category was reached). Before
// suppressing, the caller re-runs MatchExcept excluding the suppressible
// categories: if a real (injection) rule still trips, the request is NOT merely
// legitimate recon and must be acted on rather than let through. A nil exclure
// makes this identical to MatchModes.
func (r *Rules) MatchExcept(method, rawPath, rawQuery, body, ua string, includeBlock bool, exclure map[string]bool) (cat, sev, mode string, hit bool) {
	cat, sev, mode, _, hit = r.MatchDetail(method, rawPath, rawQuery, body, ua, includeBlock, exclure)
	return cat, sev, mode, hit
}

// MatchDetail is MatchExcept plus the ID OF THE PATTERN that fired.
//
// POURQUOI CETTE METHODE EXISTE (#1313). Le moteur SAIT quel motif a touche —
// la boucle tient `p` dans la main — et jetait l'information : `Match` ne
// rendait que (categorie, severite, mode). Le journal de menaces ecrivait donc
// `"rule_id": ""` sur toute detection de chemin, en dur, a trois endroits.
//
// CE QUE CA COUTAIT. Une ligne de journal disait « product_absent_probes » sans
// dire LEQUEL des motifs de la categorie avait decide. Impossible, en lisant le
// journal, de savoir si un motif sert encore, s'il fait des faux positifs, ou
// s'il n'a jamais rien attrape depuis qu'on l'a ecrit — c'est exactement ce qui
// a permis a cinq motifs CVE de rester inertes sans que rien ne le signale
// (#1310), et ce qui m'a oblige a rejouer les regex a la main pour savoir ce
// qui attrapait quoi.
//
// Le dossier technique ANSSI promet « explicabilite des decisions de blocage ».
// Une decision qu'on ne peut pas rattacher a sa regle n'est pas explicable.
//
// LA SIGNATURE DES TROIS AUTRES EST INCHANGEE, deliberement : 25 appels de test
// en dependent, et les faire bouger pour un champ supplementaire aurait melange
// un changement de fond avec du bruit de refonte.
func (r *Rules) MatchDetail(method, rawPath, rawQuery, body, ua string, includeBlock bool, exclure map[string]bool) (cat, sev, mode, ruleID string, hit bool) {
	decodedPath := unquotePlus(rawPath)
	decodedQuery := unquotePlus(rawQuery)
	scanParts := []string{decodedPath, decodedQuery, body, ua}

	// Variante normalisée (voir replierchemin.go). Elle est AJOUTÉE, jamais
	// substituée : tout ce que le décodage simple attrapait aujourd'hui
	// continue d'être attrapé, et on ne gagne que des prises. La quasi-totalité
	// du trafic ne produit aucune variante et ne paie donc rien.
	if v := varianteNormalisee(rawPath, decodedPath); v != "" {
		scanParts = append(scanParts, v)
	}
	if v := varianteNormalisee(rawQuery, decodedQuery); v != "" {
		scanParts = append(scanParts, v)
	}

	scanText := strings.ToLower(strings.Join(scanParts, " "))

	r.mu.RLock()
	cur := r.current
	r.mu.RUnlock()

	if cur == nil {
		return "", "", "", "", false
	}

	for _, c := range cur.cats {
		if !includeBlock && c.data.mode == modeBlock {
			continue
		}
		if exclure[c.id] {
			continue
		}
		for _, p := range c.data.patterns {
			if p.re.MatchString(scanText) {
				return c.id, p.severity, c.data.mode, p.id, true
			}
		}
	}
	return "", "", "", "", false
}

// Integrite rend l'ecart entre motifs DECLARES et motifs CHARGES (#1317).
//
// POURQUOI UNE METHODE, ET PAS SEULEMENT UN LOG. Une ligne de journal passe
// une fois au demarrage puis disparait dans le flot. L'ecart, lui, PERSISTE
// tant que le fichier de regles n'est pas corrige : il doit pouvoir etre
// interroge a tout moment — par /healthz, par la carlette WAF, par un test.
//
// `rejetes` porte les identifiants et pas seulement le compte : savoir qu'il
// manque cinq motifs sans savoir lesquels ne permet pas d'agir.
func (r *Rules) Integrite() (declares, charges int, rejetes []string) {
	r.mu.RLock()
	cur := r.current
	r.mu.RUnlock()
	if cur == nil {
		return 0, 0, nil
	}
	for _, c := range cur.cats {
		charges += len(c.data.patterns) + len(c.data.structurelles)
	}
	return cur.declares, charges, append([]string(nil), cur.rejetes...)
}

// aDesStructurelles dit si au moins une signature structurelle est chargée dans
// une catégorie active (relecture finale I2a). Sans elle, la capture multipart
// n'est pas posée : `"enabled": false` arrête aussi la capture et les lignes
// multipart-*, au démarrage comme après un rechargement à chaud. Nil-safe.
func (r *Rules) aDesStructurelles() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	cur := r.current
	r.mu.RUnlock()
	if cur == nil {
		return false
	}
	for _, c := range cur.cats {
		if len(c.data.structurelles) > 0 {
			return true
		}
	}
	return false
}

// visePHP dit si la signature s'applique au service de l'entree : liste
// vide = tous les services ; service "" (hote PHP par motif) = toujours.
func (s signatureStructurelle) visePHP(service string) bool {
	if len(s.services) == 0 || service == "" {
		return true
	}
	for _, v := range s.services {
		if v == service {
			return true
		}
	}
	return false
}

// EvaluerStructurel evalue un seul resultat multipart, sans service (#3257).
func (r *Rules) EvaluerStructurel(res ResultatMultipart) []DetectionStructurelle {
	return r.EvaluerPHP(&EntreePHP{Multipart: &res})
}

// EvaluerPHP rend toutes les signatures structurelles qui declenchent sur
// l'entree : categories activees dans l'ordre du fichier, puis signatures dans
// l'ordre, filtrees par service. Pur et sans effet de bord ; ne bloque rien
// (mode detect seulement).
func (r *Rules) EvaluerPHP(e *EntreePHP) []DetectionStructurelle {
	r.mu.RLock()
	cur := r.current
	r.mu.RUnlock()
	if cur == nil {
		return nil
	}
	var out []DetectionStructurelle
	for _, c := range cur.cats {
		for _, s := range c.data.structurelles {
			if s.visePHP(e.Service) && s.declenche(e) {
				out = append(out, DetectionStructurelle{
					Categorie: c.id, RuleID: s.id, Severity: s.severity, CVE: s.cve,
				})
			}
		}
	}
	return out
}
