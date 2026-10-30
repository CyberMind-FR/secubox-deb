// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

// Contrat maître → agent (#3126, N5 / M14 de la relecture finale L1, R-L2-38).
//
// Les requêtes de testdata/contrat/maitre/ sont produites par le VRAI contrôleur du maître
// (packages/secubox-pilotage/tests/test_contrat_maitre.py). Elles sont rejouées ici contre le vrai client du canal, le vrai
// exécuteur des actions (ctl simulé : sudo n'existe pas en test, l'argv reçu est vérifié) et le vrai opérateur du relevé.
// Ce que l'agent émet en retour pour L2 (OPERATE_RESP des actions, réponse du relevé de performance, notifications
// OperationProgress, OperationDone, HandsTied, Consent, Support) est figé dans testdata/contrat/agent-l2/, que le maître
// rejoue contre son vrai canal, son vrai stockage et ses vraies routes. Une fixture altérée fait échouer les deux côtés.
//
//	SECUBOX_CONTRAT_MAJ=1 go test ./cmd/sbx-pilotage-agent -run TestContratRequetesDuMaitre

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/canal"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/collecte"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/operations"
)

const (
	dossierMaitre  = "../../internal/canal/testdata/contrat/maitre"
	dossierAgentL2 = "../../internal/canal/testdata/contrat/agent-l2"
	instantContrat = 1793000000
	supportContrat = "5e55105000000001"
	consentContrat = "00000000000000c1"
	// I4 (R-L2-47) : fin d'un reboot enregistrée par le ctl avant le redémarrage de la box, relue au démarrage de l'agent
	// (fins-recentes) et renvoyée au maître.
	jobRattrape = "00000000f1500001"
)

// attenteMaitre : ce que l'agent doit faire de chaque requête du maître. ctl : argv du ctl après « -n <ctl> » (vide :
// aucune action) ; etat : état de l'OPERATE_RESP.
type attenteMaitre struct {
	reponse, ctl, etat string
	entree             bool // le code de Rejoindre passe sur l'entrée standard du ctl, jamais dans l'argv
}

var attendusMaitre = map[string]attenteMaitre{
	"get_inventaire":             {reponse: "GET_RESP"},
	"get_lire":                   {reponse: "GET_RESP"},
	"get_supported_dm":           {reponse: "GET_SUPPORTED_DM_RESP"},
	"operate_releve":             {reponse: "OPERATE_RESP"},
	"operate_reboot":             {"OPERATE_RESP", "--acteur alice reboot", "accepte", false},
	"operate_maj_paquets":        {"OPERATE_RESP", "--acteur alice maj-paquets", "accepte", false},
	"operate_service_demarrer":   {"OPERATE_RESP", "--acteur alice service demarrer secubox-hub.service", "accepte", false},
	"operate_service_arreter":    {"OPERATE_RESP", "--acteur alice service arreter secubox-hub.service", "accepte", false},
	"operate_service_redemarrer": {"OPERATE_RESP", "--acteur alice service redemarrer secubox-hub.service", "accepte", false},
	"operate_renommer":           {"OPERATE_RESP", "--acteur alice renommer gk9", "accepte", false},
	"operate_renouveler":         {"OPERATE_RESP", "--acteur alice renouveler-secrets", "accepte", false},
	"operate_support_ouvrir":     {"OPERATE_RESP", "--acteur alice support ouvrir " + supportContrat + " 30", "consentement", false},
	"operate_support_fermer":     {"OPERATE_RESP", "--acteur alice support fermer " + supportContrat, "accepte", false},
	"operate_rejoindre":          {"OPERATE_RESP", "maillage-rejoindre", "accepte", true},
}

type fixtureMaitre struct {
	nom     string
	Route   string          `json:"route"`
	Requete json.RawMessage `json:"requete"`
}

func lireFixturesMaitre(t *testing.T) []fixtureMaitre {
	t.Helper()
	chemins, _ := filepath.Glob(filepath.Join(dossierMaitre, "*.json"))
	sort.Strings(chemins)
	var out []fixtureMaitre
	for _, c := range chemins {
		b, err := os.ReadFile(c)
		if err != nil {
			t.Fatal(err)
		}
		var f fixtureMaitre
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatalf("%s : %v", c, err)
		}
		f.nom = strings.TrimSuffix(filepath.Base(c), ".json")
		out = append(out, f)
	}
	return out
}

// ctlContrat simule le ctl root derrière sudo : il note l'argv (et l'entrée standard) et répond comme le vrai ctl. Le
// job d'une action est tiré de son argv : une réponse dit donc quelle commande l'agent a réellement passée.
type ctlContrat struct {
	mu      sync.Mutex
	appels  []string
	entrees []string
}

func jobDe(argv string) string {
	n := 0
	for _, c := range argv {
		n = (n*31 + int(c)) & 0xffff
	}
	return fmt.Sprintf("00000000c0de%04x", n)
}

func (c *ctlContrat) repondre(args []string) ([]byte, error) {
	if len(args) < 3 || args[0] != "-n" || args[1] != operations.CheminCtl {
		return nil, errors.New("argv sudo inattendu")
	}
	verbe := args[2:]
	switch {
	case verbe[0] == "etat-operation":
		return []byte(fmt.Sprintf(`{"ok":true,"job":%q,"etat":"termine","resultat":"succes","rc":0}`, verbe[1])), nil
	case verbe[0] == "fins-recentes" && len(verbe) == 1:
		return []byte(`{"ok":true,"fins":[{"job":"` + jobRattrape + `","verbe":"reboot","resultat":"succes","rc":0}]}`), nil
	}
	argv := strings.Join(verbe, " ")
	c.mu.Lock()
	c.appels = append(c.appels, argv)
	c.mu.Unlock()
	nu := strings.TrimPrefix(argv, "--acteur alice ")
	switch {
	case strings.HasPrefix(nu, "support ouvrir "):
		return []byte(fmt.Sprintf(`{"ok":false,"refus":"consentement requis","support":%q}`, strings.Fields(nu)[2])), nil
	case strings.HasPrefix(nu, "support fermer "):
		return []byte(fmt.Sprintf(`{"ok":true,"support":%q,"etat":"ferme"}`, strings.Fields(nu)[2])), nil
	}
	return []byte(fmt.Sprintf(`{"ok":true,"job":%q}`, jobDe(argv))), nil
}

// maitreContrat : faux maître HTTP qui sert le lot de requêtes une fois et note ce que le client poste.
type maitreContrat struct {
	mu       sync.Mutex
	lot      []byte
	servi    bool
	reponses map[string]json.RawMessage // msg_id -> élément posté
	notifs   []json.RawMessage          // éléments NOTIFY postés
}

func (m *maitreContrat) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/canal/v1/bonjour", func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) })
	mux.HandleFunc("/canal/v1/requetes", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		servi := m.servi
		m.servi = true
		m.mu.Unlock()
		if servi {
			time.Sleep(20 * time.Millisecond)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write(m.lot)
	})
	noter := func(dest func([]json.RawMessage)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			var l []json.RawMessage
			if json.Unmarshal(b, &l) == nil {
				m.mu.Lock()
				dest(l)
				m.mu.Unlock()
			}
			_, _ = w.Write([]byte(`{"ignore":0}`))
		}
	}
	mux.HandleFunc("/canal/v1/reponses", noter(func(l []json.RawMessage) {
		for _, e := range l {
			var x struct {
				MsgID string `json:"msg_id"`
			}
			if json.Unmarshal(e, &x) == nil {
				m.reponses[x.MsgID] = e
			}
		}
	}))
	mux.HandleFunc("/canal/v1/notifs", noter(func(l []json.RawMessage) { m.notifs = append(m.notifs, l...) }))
	return mux
}

// etatsLocaux : deux lectures successives du verbe `etat` du ctl (forme réelle), observées par les vraies bascules :
// mains liées et support ouvert au premier état, puis une décision de consentement.
var etatsLocaux = []string{
	`{"ok":true,"mains_liees":true,"consentements":[{"id":"` + consentContrat + `","etat":"en_attente"}],` +
		`"support":{"id":"` + supportContrat + `","etat":"ouvert","fin":1793001800}}`,
	`{"ok":true,"mains_liees":true,"consentements":[{"id":"` + consentContrat + `","etat":"accepte"}],` +
		`"support":{"id":"` + supportContrat + `","etat":"ouvert","fin":1793001800}}`,
}

type resultatContrat struct {
	msgIDs   map[string]string // fixture -> msg_id servi
	reponses map[string]json.RawMessage
	notifs   []json.RawMessage
	appels   []string
	entrees  []string
}

// rejouerMaitre sert les requêtes du maître au vrai client de l'agent et rend ce qu'il a fait et émis.
func rejouerMaitre(t *testing.T, fixtures []fixtureMaitre) resultatContrat {
	t.Helper()
	res := resultatContrat{msgIDs: map[string]string{}}
	var lot []map[string]json.RawMessage
	for i, f := range fixtures {
		var rq map[string]json.RawMessage
		if err := json.Unmarshal(f.Requete, &rq); err != nil {
			t.Fatalf("%s : requête illisible : %v", f.nom, err)
		}
		id := fmt.Sprintf("%016x", 0xd0+i)
		res.msgIDs[f.nom] = id
		rq["msg_id"] = json.RawMessage(fmt.Sprintf("%q", id))
		lot = append(lot, rq)
	}
	brut, _ := json.Marshal(lot)
	fm := &maitreContrat{lot: brut, reponses: map[string]json.RawMessage{}}
	srv := httptest.NewServer(fm.handler())
	defer srv.Close()

	horloge := func() time.Time { return time.Unix(instantContrat, 0) }
	ev := make(chan notifs.Evenement, 64)
	// Bascules locales : le vrai interprète de l'état du ctl et les vraies bascules (ce que fait veiller).
	b := notifs.NouvellesBascules(horloge)
	for _, s := range etatsLocaux {
		e, err := operations.LireEtat([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range b.Observer(e) {
			ev <- n
		}
	}
	ctl := &ctlContrat{}
	boite := operations.NouvelleBoite(operations.MaxResultats)
	ex := operations.Nouveau(operations.Config{
		Ctl: func(ctx context.Context, args ...string) ([]byte, error) { return ctl.repondre(args) },
		CtlEntree: func(ctx context.Context, entree []byte, args ...string) ([]byte, error) {
			ctl.mu.Lock()
			ctl.entrees = append(ctl.entrees, string(entree))
			ctl.mu.Unlock()
			return ctl.repondre(args)
		},
		Systemctl: func(ctx context.Context, args ...string) ([]byte, error) { return []byte("inactive\ninactive\n"), nil },
		Progression: func(e notifs.Evenement) {
			select {
			case ev <- e:
			default: // file pleine : la notification manquera, verifierMaitre et les fixtures le verront
			}
		},
		Resultats: boite,
		Pas:       5 * time.Millisecond,
		Horloge:   horloge,
	})
	m := modele.NouveauModele(collecte.NouvelleSourceSysteme(racineTest))
	cl := canal.NouveauClient(canal.Config{
		Maitre:    strings.TrimPrefix(srv.URL, "http://"),
		Attente:   time.Second,
		Version:   "0.0.0-contrat",
		BootID:    "00000000-0000-4000-8000-000000000000",
		Ancre:     func(context.Context) canal.Verdict { return canal.AncreOK },
		Agir:      ex.Operer,
		Resultats: boite,
		// comme main.go : à la première ancre vérifiée, les fins récentes du ctl repartent (I4)
		ApresAncre: func(ctx context.Context) { ex.Rattraper(ctx) },
	}, m, operateur(racineTest, func(context.Context, time.Duration) error { return nil }))
	ctx, arreter := context.WithCancel(context.Background())
	fini := make(chan struct{})
	go func() { _ = cl.Tourner(ctx, ev); close(fini) }()

	// Attendus : une réponse par requête, puis les notifications de L2 : 3 bascules (mains liées, support, consentement),
	// la fin rattrapée au démarrage (I4) et, pour chaque job accepté, sa progression « lancee » et « terminee » et sa fin.
	echeance := time.Now().Add(10 * time.Second)
	for time.Now().Before(echeance) {
		fm.mu.Lock()
		jobs, complet := 0, len(fm.reponses) == len(fixtures)
		for _, r := range fm.reponses {
			var e struct {
				Body struct {
					Etat string `json:"etat"`
					Job  string `json:"job"`
				} `json:"body"`
			}
			if json.Unmarshal(r, &e) == nil && e.Body.Etat == "accepte" && e.Body.Job != "" {
				jobs++
			}
		}
		fini := complet && len(fm.notifs) >= 3+1+3*jobs
		fm.mu.Unlock()
		if fini {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	arreter()
	<-fini
	ex.Attendre()
	fm.mu.Lock()
	defer fm.mu.Unlock()
	ctl.mu.Lock()
	defer ctl.mu.Unlock()
	res.reponses, res.notifs, res.appels, res.entrees = fm.reponses, fm.notifs, ctl.appels, ctl.entrees
	return res
}

type enveloppe struct {
	MsgID string                     `json:"msg_id"`
	Type  string                     `json:"type"`
	Body  map[string]json.RawMessage `json:"body"`
}

// verifierMaitre : chaque requête du maître a produit la réponse et l'action attendues ; nil si le contrat tient.
func verifierMaitre(fixtures []fixtureMaitre, res resultatContrat) error {
	var errs []error
	vus := map[string]bool{}
	for _, f := range fixtures {
		a, ok := attendusMaitre[f.nom]
		if !ok {
			errs = append(errs, fmt.Errorf("%s : fixture sans attente côté agent", f.nom))
			continue
		}
		vus[f.nom] = true
		var e enveloppe
		if err := json.Unmarshal(res.reponses[res.msgIDs[f.nom]], &e); err != nil {
			errs = append(errs, fmt.Errorf("%s : aucune réponse de l'agent", f.nom))
			continue
		}
		if e.Type != a.reponse {
			errs = append(errs, fmt.Errorf("%s : réponse %s (%s), %s attendue", f.nom, e.Type, e.Body["err"], a.reponse))
			continue
		}
		switch {
		case e.Type == "GET_RESP" && len(e.Body["results"]) < 3:
			errs = append(errs, fmt.Errorf("%s : GET_RESP sans résultat", f.nom))
		case e.Type == "GET_SUPPORTED_DM_RESP" && !bytes.Contains(e.Body["paths"], []byte("Device.DeviceInfo.UpTime")):
			errs = append(errs, fmt.Errorf("%s : modèle sans Device.DeviceInfo.UpTime", f.nom))
		case f.nom == "operate_releve" && !bytes.Contains(e.Body["output"], []byte(`"mem_dispo_mo"`)):
			errs = append(errs, fmt.Errorf("%s : relevé sans sortie", f.nom))
		}
		if a.ctl == "" {
			continue
		}
		var etat, job string
		_ = json.Unmarshal(e.Body["etat"], &etat)
		_ = json.Unmarshal(e.Body["job"], &job)
		appele := false
		for _, x := range res.appels {
			appele = appele || x == a.ctl
		}
		if etat != a.etat || !appele {
			errs = append(errs, fmt.Errorf("%s : etat %q (%s), ctl appelé avec %q : %v", f.nom, etat, e.Body["raison"], a.ctl, appele))
		}
		if a.etat == "accepte" && !strings.Contains(a.ctl, " support ") && job != jobDe(a.ctl) {
			errs = append(errs, fmt.Errorf("%s : job %q, %q attendu (autre commande passée au ctl ?)", f.nom, job, jobDe(a.ctl)))
		}
		if a.entree {
			var rq struct {
				Body struct {
					Args map[string]string `json:"args"`
				} `json:"body"`
			}
			_ = json.Unmarshal(f.Requete, &rq)
			code := rq.Body.Args["code"]
			if len(res.entrees) != 1 || res.entrees[0] != code+"\n" {
				errs = append(errs, fmt.Errorf("%s : le code n'est pas passé sur l'entrée standard du ctl", f.nom))
			}
			for _, x := range res.appels {
				if code != "" && strings.Contains(x, code) {
					errs = append(errs, fmt.Errorf("%s : code dans l'argv du ctl", f.nom))
				}
			}
		}
	}
	for nom := range attendusMaitre {
		if !vus[nom] {
			errs = append(errs, fmt.Errorf("%s : fixture du maître absente", nom))
		}
	}
	return errors.Join(errs...)
}

type fixtureAgent struct {
	Route   string          `json:"route"`
	Requete json.RawMessage `json:"requete,omitempty"` // la requête du maître (fixture maitre/) à laquelle répond l'agent
	Envoi   json.RawMessage `json:"envoi"`             // élément posté (réponse) ou liste postée (notifications)
}

// notifsDe : éléments NOTIFY postés dont l'événement satisfait garder, triés (job, pct, type) pour des fixtures stables.
func notifsDe(l []json.RawMessage, garder func(map[string]any) bool) json.RawMessage {
	type cle struct {
		job, typ string
		pct      float64
	}
	var choisis []json.RawMessage
	var cles []cle
	for _, n := range l {
		var x struct {
			Body struct {
				Event map[string]any `json:"event"`
			} `json:"body"`
		}
		if json.Unmarshal(n, &x) != nil || !garder(x.Body.Event) {
			continue
		}
		job, _ := x.Body.Event["job"].(string)
		pct, _ := x.Body.Event["pct"].(float64)
		typ, _ := x.Body.Event["type"].(string)
		choisis, cles = append(choisis, n), append(cles, cle{job, typ, pct})
	}
	idx := make([]int, len(choisis))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := cles[idx[a]], cles[idx[b]]
		if x.job != y.job {
			return x.job < y.job
		}
		if x.pct != y.pct {
			return x.pct < y.pct
		}
		return x.typ < y.typ
	})
	out := make([]json.RawMessage, len(idx))
	for i, j := range idx {
		out[i] = choisis[j]
	}
	b, _ := json.Marshal(out)
	return b
}

func fixturesAgentL2(fixtures []fixtureMaitre, res resultatContrat) map[string]fixtureAgent {
	out := map[string]fixtureAgent{}
	for _, f := range fixtures {
		if a := attendusMaitre[f.nom]; a.reponse == "OPERATE_RESP" {
			out["reponse_"+f.nom] = fixtureAgent{Route: "/canal/v1/reponses", Requete: f.Requete, Envoi: res.reponses[res.msgIDs[f.nom]]}
		}
	}
	type_ := func(t string) func(map[string]any) bool { return func(e map[string]any) bool { return e["type"] == t } }
	jobReboot := jobDe(attendusMaitre["operate_reboot"].ctl)
	out["notify_operation_progress"] = fixtureAgent{Route: "/canal/v1/notifs", Envoi: notifsDe(res.notifs, func(e map[string]any) bool {
		return e["type"] == notifs.TypeOperationProgress && e["job"] == jobReboot
	})}
	out["notify_operation_done"] = fixtureAgent{Route: "/canal/v1/notifs", Envoi: notifsDe(res.notifs, func(e map[string]any) bool {
		return e["type"] == notifs.TypeOperationDone && e["job"] != jobRattrape
	})}
	out["notify_operation_done_rattrapee"] = fixtureAgent{Route: "/canal/v1/notifs", Envoi: notifsDe(res.notifs, func(e map[string]any) bool {
		return e["type"] == notifs.TypeOperationDone && e["job"] == jobRattrape
	})}
	out["notify_hands_tied"] = fixtureAgent{Route: "/canal/v1/notifs", Envoi: notifsDe(res.notifs, type_(notifs.TypeMainsLiees))}
	out["notify_consent"] = fixtureAgent{Route: "/canal/v1/notifs", Envoi: notifsDe(res.notifs, type_(notifs.TypeConsentement))}
	out["notify_support"] = fixtureAgent{Route: "/canal/v1/notifs", Envoi: notifsDe(res.notifs, type_(notifs.TypeSupport))}
	return out
}

func TestContratRequetesDuMaitre(t *testing.T) {
	fixtures := lireFixturesMaitre(t)
	if len(fixtures) != len(attendusMaitre) {
		t.Fatalf("%d fixtures du maître dans %s, %d attendues", len(fixtures), dossierMaitre, len(attendusMaitre))
	}
	res := rejouerMaitre(t, fixtures)
	if err := verifierMaitre(fixtures, res); err != nil {
		t.Fatalf("l'agent ne fait plus ce que le maître demande :\n%v", err)
	}
	l2 := fixturesAgentL2(fixtures, res)
	// ce que les fixtures doivent montrer, sans quoi le contrat de L2 ne couvre plus le cas
	for nom, sous := range map[string]string{
		"notify_operation_progress": `"etape":"lancee"`, "notify_operation_done": `"rc":0`, "notify_hands_tied": `"etat":"on"`,
		"notify_operation_done_rattrapee": `"job":"` + jobRattrape + `"`,
		"notify_consent":                  `"decision":"accepte"`, "notify_support": `"fin":"`, "reponse_operate_releve": `"top":`,
		"reponse_operate_support_ouvrir": `"etat":"consentement"`,
	} {
		if !bytes.Contains(l2[nom].Envoi, []byte(sous)) {
			t.Fatalf("%s ne contient pas %s : %.300s", nom, sous, l2[nom].Envoi)
		}
	}
	maj := os.Getenv("SECUBOX_CONTRAT_MAJ") == "1"
	if maj {
		if err := os.MkdirAll(dossierAgentL2, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for nom, fx := range l2 {
		b, err := json.MarshalIndent(fx, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, '\n')
		chemin := filepath.Join(dossierAgentL2, nom+".json")
		if maj {
			if err := os.WriteFile(chemin, b, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if actuel, err := os.ReadFile(chemin); err != nil || !bytes.Equal(actuel, b) {
			t.Errorf("fixture %s périmée ou absente (%v) : l'agent n'émet plus ce que le maître rejoue ; "+
				"SECUBOX_CONTRAT_MAJ=1 go test ./cmd/sbx-pilotage-agent -run TestContratRequetesDuMaitre, puis les tests du maître", chemin, err)
		}
	}
	if presentes, _ := filepath.Glob(filepath.Join(dossierAgentL2, "*.json")); !maj && len(presentes) != len(l2) {
		t.Errorf("%d fixtures dans %s, %d attendues (fixture orpheline ?)", len(presentes), dossierAgentL2, len(l2))
	}
}

// Une requête du maître altérée (paramètre renommé, commande changée) n'est plus comprise par l'agent : le contrat échoue.
func TestContratRequeteAltereeEchoue(t *testing.T) {
	for _, alteration := range []struct{ fixture, avant, apres string }{
		{"operate_service_redemarrer", `"unite"`, `"unit"`},
		{"operate_reboot", `Device.Reboot()`, `Device.Redemarrer()`},
		{"operate_support_ouvrir", `"duree_min": 30`, `"duree_min": "30"`},
		{"get_lire", `"paths"`, `"chemins"`},
	} {
		t.Run(alteration.fixture, func(t *testing.T) {
			fixtures := lireFixturesMaitre(t)
			trouve := false
			for i := range fixtures {
				if fixtures[i].nom == alteration.fixture {
					avant := fixtures[i].Requete
					fixtures[i].Requete = bytes.Replace(avant, []byte(alteration.avant), []byte(alteration.apres), 1)
					trouve = !bytes.Equal(avant, fixtures[i].Requete)
				}
			}
			if !trouve {
				t.Fatalf("altération %q introuvable dans %s", alteration.avant, alteration.fixture)
			}
			if err := verifierMaitre(fixtures, rejouerMaitre(t, fixtures)); err == nil {
				t.Fatal("fixture altérée acceptée : le contrat ne protège rien")
			}
		})
	}
}
