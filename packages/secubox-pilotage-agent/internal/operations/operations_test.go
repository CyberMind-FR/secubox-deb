// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package operations

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

// fauxCtl remplace `sudo` : il note chaque argv et rend la sortie choisie par repondre.
type fauxCtl struct {
	mu       sync.Mutex
	appels   [][]string
	repondre func(args []string) ([]byte, error)
}

func (f *fauxCtl) lancer(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.appels = append(f.appels, append([]string(nil), args...))
	r := f.repondre
	f.mu.Unlock()
	if r == nil {
		return []byte(`{"ok": true, "job": "0123456789abcdef"}` + "\n"), nil
	}
	return r(args)
}

func (f *fauxCtl) nb() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.appels)
}

func (f *fauxCtl) dernier() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.appels) == 0 {
		return nil
	}
	return f.appels[len(f.appels)-1]
}

// executeurTest : ctl et systemctl factices, aucun suivi d'unité (systemctl rend l'unité active à jamais).
func executeurTest(ctl *fauxCtl) *Executeur {
	return Nouveau(Config{
		Ctl:       ctl.lancer,
		Systemctl: func(context.Context, ...string) ([]byte, error) { return []byte("active\ninactive\n"), nil },
		Resultats: NouvelleBoite(0),
		Pas:       time.Hour,
	})
}

// TestOperateInconnuRefuse : une commande hors de la liste fermée, ou des paramètres mal typés, inconnus ou hors
// motif, donnent « refuse » sans jamais appeler le ctl.
func TestOperateInconnuRefuse(t *testing.T) {
	ctl := &fauxCtl{}
	e := executeurTest(ctl)
	ctx := context.Background()
	cas := []struct {
		cmd  string
		args map[string]any
	}{
		{"Device.FactoryReset()", nil},
		{"Device.Reboot", nil},
		{"Device.X_SECUBOX_Releve.Mesurer()", map[string]any{"duree_s": 10.0}}, // pas une action : le canal la traite
		{"Device.X_SECUBOX_Maillage.Rejoindre()", map[string]any{"code": "1234"}},
		{"device.reboot()", nil},
		{"Device.Reboot()", map[string]any{"force": true}},
		{"Device.X_SECUBOX_Packages.MettreAJour()", map[string]any{"paquets": "nginx"}},
		{"Device.X_SECUBOX_Services.Agir()", map[string]any{"unite": "secubox-foo.service"}},
		{"Device.X_SECUBOX_Services.Agir()", map[string]any{"unite": "secubox-foo.service", "action": "tuer"}},
		{"Device.X_SECUBOX_Services.Agir()", map[string]any{"unite": "nginx.service", "action": "restart"}},
		{"Device.X_SECUBOX_Services.Agir()", map[string]any{"unite": "secubox-foo.service; reboot", "action": "restart"}},
		{"Device.X_SECUBOX_Services.Agir()", map[string]any{"unite": "secubox-Foo.service", "action": "stop"}},
		{"Device.X_SECUBOX_Services.Agir()", map[string]any{"unite": 3.0, "action": "stop"}},
		{"Device.X_SECUBOX_Services.Agir()", map[string]any{"unite": "secubox-foo.service", "action": "stop", "x": 1.0}},
		{"Device.X_SECUBOX_Nom.Renommer()", map[string]any{"nom": "Box_1"}},
		{"Device.X_SECUBOX_Nom.Renommer()", map[string]any{"nom": "-box"}},
		{"Device.X_SECUBOX_Nom.Renommer()", map[string]any{"nom": strings.Repeat("a", 64)}},
		{"Device.X_SECUBOX_Nom.Renommer()", nil},
		{"Device.X_SECUBOX_Secrets.Renouveler()", map[string]any{"tout": true}},
		{"Device.X_SECUBOX_Support.Ouvrir()", map[string]any{"id": "../s1"}},
		{"Device.X_SECUBOX_Support.Ouvrir()", map[string]any{"id": "s1", "duree_min": 0.0}},
		{"Device.X_SECUBOX_Support.Ouvrir()", map[string]any{"id": "s1", "duree_min": 241.0}},
		{"Device.X_SECUBOX_Support.Ouvrir()", map[string]any{"id": "s1", "duree_min": 30.5}},
		{"Device.X_SECUBOX_Support.Ouvrir()", map[string]any{"id": "s1", "duree_min": "30"}},
		{"Device.X_SECUBOX_Support.Ouvrir()", map[string]any{"duree_min": 30.0}},
		{"Device.X_SECUBOX_Support.Fermer()", map[string]any{"id": "s1", "duree_min": 30.0}},
		{"Device.X_SECUBOX_Support.Fermer()", map[string]any{"id": ""}},
	}
	for _, c := range cas {
		r := e.Operer(ctx, c.cmd, c.args, "gk2admin")
		if r.Etat != Refuse || r.Raison == "" || r.Job != "" {
			t.Errorf("%s %v : refus attendu, reçu %+v", c.cmd, c.args, r)
		}
	}
	if n := ctl.nb(); n != 0 {
		t.Fatalf("le ctl ne doit jamais être appelé pour une commande refusée par l'agent (%d appels)", n)
	}
}

// TestTraductionVersLeCtl : chaque commande de la liste fermée donne l'argv exact du ctl, précédé de --acteur quand
// le login du maître est valable (R-L2-14) ; un login invalide ou absent n'est pas transmis.
func TestTraductionVersLeCtl(t *testing.T) {
	ctl := &fauxCtl{}
	e := executeurTest(ctl)
	ctx := context.Background()
	cas := []struct {
		cmd    string
		args   map[string]any
		acteur string
		argv   string
	}{
		{"Device.Reboot()", nil, "gk2admin", "-n /usr/sbin/secubox-pilotagectl --acteur gk2admin reboot"},
		{"Device.Reboot()", map[string]any{}, "", "-n /usr/sbin/secubox-pilotagectl reboot"},
		{"Device.X_SECUBOX_Packages.MettreAJour()", nil, "Admin", "-n /usr/sbin/secubox-pilotagectl maj-paquets"},
		{"Device.X_SECUBOX_Secrets.Renouveler()", nil, "_ops.x-1", "-n /usr/sbin/secubox-pilotagectl --acteur _ops.x-1 renouveler-secrets"},
		{"Device.X_SECUBOX_Services.Agir()", map[string]any{"unite": "secubox-lyrion.service", "action": "restart"}, "a b",
			"-n /usr/sbin/secubox-pilotagectl service redemarrer secubox-lyrion.service"},
		{"Device.X_SECUBOX_Services.Agir()", map[string]any{"unite": "secubox-lyrion.service", "action": "start"}, "",
			"-n /usr/sbin/secubox-pilotagectl service demarrer secubox-lyrion.service"},
		{"Device.X_SECUBOX_Services.Agir()", map[string]any{"unite": "secubox-foo@bar.timer", "action": "stop"}, "",
			"-n /usr/sbin/secubox-pilotagectl service arreter secubox-foo@bar.timer"},
		{"Device.X_SECUBOX_Services.Agir()", map[string]any{"unite": "secubox-lyrion.service", "action": "arreter"}, "",
			"-n /usr/sbin/secubox-pilotagectl service arreter secubox-lyrion.service"},
		{"Device.X_SECUBOX_Nom.Renommer()", map[string]any{"nom": "box-2"}, "gk2admin",
			"-n /usr/sbin/secubox-pilotagectl --acteur gk2admin renommer box-2"},
		// Tâche 4 : la durée (bornée ici, revalidée par le ctl) est transmise ; absente, 30 min.
		{"Device.X_SECUBOX_Support.Ouvrir()", map[string]any{"id": "s-01", "duree_min": 240.0}, "",
			"-n /usr/sbin/secubox-pilotagectl support ouvrir s-01 240"},
		{"Device.X_SECUBOX_Support.Ouvrir()", map[string]any{"id": "s-01", "duree_min": 1.0}, "",
			"-n /usr/sbin/secubox-pilotagectl support ouvrir s-01 1"},
		{"Device.X_SECUBOX_Support.Ouvrir()", map[string]any{"id": "s-01"}, "",
			"-n /usr/sbin/secubox-pilotagectl support ouvrir s-01 30"},
		{"Device.X_SECUBOX_Support.Fermer()", map[string]any{"id": "s-01"}, strings.Repeat("a", 65),
			"-n /usr/sbin/secubox-pilotagectl support fermer s-01"},
	}
	for _, c := range cas {
		r := e.Operer(ctx, c.cmd, c.args, c.acteur)
		if r.Etat != Accepte || r.Job != "0123456789abcdef" {
			t.Errorf("%s : accepte attendu, reçu %+v", c.cmd, r)
		}
		if got := strings.Join(ctl.dernier(), " "); got != c.argv {
			t.Errorf("%s : argv %q, attendu %q", c.cmd, got, c.argv)
		}
	}
}

// TestOperateRefuseSousMainsLiees : sous mains liées, le ctl refuse ; l'agent rend « refuse » avec la raison du ctl
// (R-L2-1) et ne suit aucune opération.
func TestOperateRefuseSousMainsLiees(t *testing.T) {
	ctl := &fauxCtl{repondre: func([]string) ([]byte, error) {
		return []byte(`{"ok": false, "refus": "mains liées"}` + "\n"), nil
	}}
	var progres atomic.Int32
	e := Nouveau(Config{Ctl: ctl.lancer, Resultats: NouvelleBoite(0), Pas: time.Millisecond,
		Systemctl:   func(context.Context, ...string) ([]byte, error) { return []byte("inactive\ninactive\n"), nil },
		Progression: func(notifs.Evenement) { progres.Add(1) }})
	for _, cmd := range []string{"Device.Reboot()", "Device.X_SECUBOX_Packages.MettreAJour()", "Device.X_SECUBOX_Secrets.Renouveler()"} {
		r := e.Operer(context.Background(), cmd, nil, "gk2admin")
		if r.Etat != Refuse || r.Raison != "mains liées" || r.Job != "" {
			t.Fatalf("%s : refus « mains liées » attendu, reçu %+v", cmd, r)
		}
	}
	e.Attendre()
	if progres.Load() != 0 || e.cfg.Resultats.Taille() != 0 {
		t.Fatalf("aucun suivi pour une action refusée : progressions=%d résultats=%d", progres.Load(), e.cfg.Resultats.Taille())
	}
	if c := Corps(Reponse{Etat: Refuse, Raison: "mains liées"}); c["etat"] != "refuse" || c["raison"] != "mains liées" || c["job"] != "" {
		t.Fatalf("corps de l'OPERATE_RESP inattendu : %v", c)
	}
}

// TestOperateCliente_Consentement : sur une box cliente, le ctl répond « consentement requis » → etat
// « consentement » ; une fois l'accord donné en local, la demande identique suivante est acceptée (R-L2-10).
func TestOperateCliente_Consentement(t *testing.T) {
	var accord atomic.Bool
	ctl := &fauxCtl{repondre: func([]string) ([]byte, error) {
		if accord.Load() {
			return []byte(`{"ok": true, "job": "00000000000000aa"}`), nil
		}
		return []byte(`{"ok": false, "refus": "consentement requis", "consentement": "fedcba9876543210"}`), nil
	}}
	e := executeurTest(ctl)
	args := map[string]any{"unite": "secubox-lyrion.service", "action": "restart"}
	r := e.Operer(context.Background(), "Device.X_SECUBOX_Services.Agir()", args, "gk2admin")
	if r.Etat != Consentement || r.Raison != "consentement requis" || r.Job != "" {
		t.Fatalf("etat consentement attendu, reçu %+v", r)
	}
	accord.Store(true)
	r = e.Operer(context.Background(), "Device.X_SECUBOX_Services.Agir()", args, "gk2admin")
	if r.Etat != Accepte || r.Job != "00000000000000aa" {
		t.Fatalf("accepte attendu après l'accord, reçu %+v", r)
	}
}

// TestSortiesDuCtl : tout ce qui n'est pas une réponse attendue du ctl vaut « refuse » (fermé par défaut) ; un
// refus « opération en cours » garde le job en cours.
func TestSortiesDuCtl(t *testing.T) {
	cas := []struct {
		sortie string
		err    error
		etat   Etat
		job    string
		raison string
	}{
		{`{"ok": false, "refus": "opération en cours", "job": "0123456789abcdef"}`, nil, Refuse, "0123456789abcdef", "opération en cours"},
		{`{"ok": false, "refus": "unité protégée"}`, nil, Refuse, "", "unité protégée"},
		{`{"ok": false, "refus": "ancre non vérifiée"}`, nil, Refuse, "", "ancre non vérifiée"},
		{`{"ok": true, "job": "../x"}`, nil, Refuse, "", "réponse du ctl incohérente"},
		{`{"ok": true}`, nil, Refuse, "", "réponse du ctl incohérente"},
		{`{"ok": "true", "job": "0123456789abcdef"}`, nil, Refuse, "", "réponse du ctl incohérente"},
		{`{"ok": true, "job": "0123456789abcdef"} {"ok": true}`, nil, Refuse, "", "réponse du ctl incohérente"},
		{`{"ok": false}`, nil, Refuse, "", "réponse du ctl incohérente"},
		{`pas du json`, nil, Refuse, "", "réponse du ctl incohérente"},
		{``, errors.New("sudo : code 1"), Refuse, "", "action impossible (ctl en erreur)"},
		{`{"ok": false, "refus": "a\u0007b` + strings.Repeat("x", 300) + `"}`, nil, Refuse, "", "ab" + strings.Repeat("x", maxRaison-2)},
	}
	for _, c := range cas {
		ctl := &fauxCtl{repondre: func([]string) ([]byte, error) { return []byte(c.sortie), c.err }}
		r := executeurTest(ctl).Operer(context.Background(), "Device.Reboot()", nil, "")
		if r.Etat != c.etat || r.Job != c.job || r.Raison != c.raison {
			t.Errorf("sortie %.60q : %+v, attendu %s/%q/%q", c.sortie, r, c.etat, c.job, c.raison)
		}
	}
}

// suiviTest : systemctl rend l'unité active tant que fini est faux ; etat-operation rend la fin donnée.
func suiviTest(t *testing.T, fin string) (*Executeur, *fauxCtl, *atomic.Bool, *[]notifs.Evenement, *sync.Mutex) {
	t.Helper()
	var fini atomic.Bool
	var mu sync.Mutex
	var progres []notifs.Evenement
	ctl := &fauxCtl{repondre: func(args []string) ([]byte, error) {
		if args[len(args)-2] == "etat-operation" {
			return []byte(fin), nil
		}
		return []byte(`{"ok": true, "job": "0123456789abcdef"}`), nil
	}}
	e := Nouveau(Config{
		Ctl: ctl.lancer,
		Systemctl: func(_ context.Context, args ...string) ([]byte, error) {
			want := "show -p ActiveState --value -- secubox-pilotage-op-0123456789abcdef.service secubox-pilotage-op-0123456789abcdef.timer"
			if got := strings.Join(args, " "); got != want {
				return nil, fmt.Errorf("argv systemctl inattendu %q", got)
			}
			if fini.Load() {
				return []byte("inactive\ninactive\n"), nil
			}
			return []byte("active\ninactive\n"), nil
		},
		Progression: func(ev notifs.Evenement) { mu.Lock(); progres = append(progres, ev); mu.Unlock() },
		Resultats:   NouvelleBoite(0),
		Pas:         2 * time.Millisecond,
		Horloge:     func() time.Time { return time.Unix(1793000000, 0) },
	})
	return e, ctl, &fini, &progres, &mu
}

// TestSuiviProgressionEtFin : une opération acceptée est suivie par `systemctl show` (sans sudo) : progression
// lancée → en cours → terminée, puis, l'unité finie, le ctl donne le code (etat-operation) et
// X_SECUBOX_OperationDone {job, rc, resume} part dans la boîte des résultats.
func TestSuiviProgressionEtFin(t *testing.T) {
	e, ctl, fini, progres, mu := suiviTest(t,
		`{"ok": true, "job": "0123456789abcdef", "etat": "termine", "verbe": "maj-paquets", "resultat": "echec", "rc": 100}`)
	r := e.Operer(context.Background(), "Device.X_SECUBOX_Packages.MettreAJour()", nil, "gk2admin")
	if r.Etat != Accepte {
		t.Fatalf("accepte attendu : %+v", r)
	}
	attendreQue(t, "en cours", func() bool { mu.Lock(); defer mu.Unlock(); return len(*progres) >= 2 })
	fini.Store(true)
	attendreQue(t, "résultat", func() bool { return e.cfg.Resultats.Taille() == 1 })
	e.Attendre()
	mu.Lock()
	etapes := []string{}
	for _, p := range *progres {
		if p.Type != notifs.TypeOperationProgress || p.Job != "0123456789abcdef" || p.Pct == nil {
			t.Fatalf("progression malformée : %+v", p)
		}
		etapes = append(etapes, fmt.Sprintf("%s:%d", p.Etape, *p.Pct))
	}
	mu.Unlock()
	if strings.Join(etapes, " ") != "lancee:0 en_cours:50 terminee:100" {
		t.Fatalf("étapes inattendues : %v", etapes)
	}
	evs, _ := e.cfg.Resultats.Prendre(16)
	d := evs[0]
	if d.Type != notifs.TypeOperationDone || d.Job != "0123456789abcdef" || d.RC == nil || *d.RC != 100 ||
		d.Resume != "maj-paquets : échec (code 100)" || d.Instant != 1793000000 {
		t.Fatalf("fin inattendue : %+v", d)
	}
	if got := strings.Join(ctl.dernier(), " "); got != "-n /usr/sbin/secubox-pilotagectl etat-operation 0123456789abcdef" {
		t.Fatalf("lecture de la fin par le ctl : %q", got)
	}
}

// TestSuiviFinInconnue : l'unité a disparu sans fin enregistrée → après quelques essais, rc -1, « résultat inconnu ».
func TestSuiviFinInconnue(t *testing.T) {
	e, ctl, fini, _, _ := suiviTest(t, `{"ok": true, "job": "0123456789abcdef", "etat": "inconnu"}`)
	fini.Store(true)
	e.Operer(context.Background(), "Device.Reboot()", nil, "")
	e.Attendre()
	evs, _ := e.cfg.Resultats.Prendre(16)
	if len(evs) != 1 || *evs[0].RC != -1 || evs[0].Resume != "reboot : résultat inconnu" {
		t.Fatalf("fin inconnue attendue : %+v", evs)
	}
	if n := ctl.nb(); n != 1+essaisFin {
		t.Fatalf("1 lancement + %d lectures attendus, %d appels", essaisFin, n)
	}
}

// TestSuiviSArreteALAnnulation : l'arrêt de l'agent interrompt le suivi sans résultat inventé.
func TestSuiviSArreteALAnnulation(t *testing.T) {
	e, _, _, _, _ := suiviTest(t, `{}`)
	ctx, annule := context.WithCancel(context.Background())
	e.Operer(ctx, "Device.X_SECUBOX_Packages.MettreAJour()", nil, "")
	time.Sleep(20 * time.Millisecond)
	annule()
	e.Attendre()
	if n := e.cfg.Resultats.Taille(); n != 0 {
		t.Fatalf("aucun résultat attendu après l'annulation, %d", n)
	}
}

// TestBoiteGardeAuPlus50 : au-delà de 50 résultats non remis, le plus ancien est évincé et journalisé ; Remis ne
// retire que ce qui a été pris (un dépôt pendant l'envoi reste dans la boîte).
func TestBoiteGardeAuPlus50(t *testing.T) {
	var journal bytes.Buffer
	ancien := log.Writer()
	log.SetOutput(&journal)
	defer log.SetOutput(ancien)
	b := NouvelleBoite(0)
	for i := 0; i < 51; i++ {
		b.Deposer(notifs.Evenement{Type: notifs.TypeOperationDone, Job: fmt.Sprintf("%016x", i)})
	}
	if b.Taille() != MaxResultats || MaxResultats != 50 {
		t.Fatalf("50 résultats gardés attendus, %d", b.Taille())
	}
	if !strings.Contains(journal.String(), "0000000000000000") {
		t.Fatalf("l'éviction doit être journalisée avec le job : %q", journal.String())
	}
	evs, seq := b.Prendre(16)
	if len(evs) != 16 || evs[0].Job != "0000000000000001" {
		t.Fatalf("les plus anciens d'abord : %d, %+v", len(evs), evs[0])
	}
	// pendant l'envoi, un dépôt évince le plus ancien (déjà pris) : Remis retire les 15 autres pris, pas le nouveau
	b.Deposer(notifs.Evenement{Type: notifs.TypeOperationDone, Job: "ffffffffffffffff"})
	b.Remis(seq)
	if b.Taille() != 50-15 {
		t.Fatalf("après remise, %d restants, attendu %d", b.Taille(), 50-15)
	}
	evs, _ = b.Prendre(100)
	if evs[len(evs)-1].Job != "ffffffffffffffff" || evs[0].Job != "0000000000000011" {
		t.Fatalf("ordre ou contenu inattendu : %s … %s", evs[0].Job, evs[len(evs)-1].Job)
	}
	select {
	case <-b.Signal():
	default:
		t.Fatal("un dépôt doit réveiller l'envoi")
	}
}

func attendreQue(t *testing.T, quoi string, cond func() bool) {
	t.Helper()
	for fin := time.Now().Add(3 * time.Second); time.Now().Before(fin); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("délai dépassé : %s", quoi)
}

// TestSuiviSystemctlEnEchecBorne (M4, R-L2-28) : systemctl show en échec sans fin (bus injoignable) → après
// maxErreursShow erreurs consécutives, « résultat inconnu » est déposé et l'emplacement de suivi est libéré.
func TestSuiviSystemctlEnEchecBorne(t *testing.T) {
	var appels atomic.Int32
	ctl := &fauxCtl{}
	e := Nouveau(Config{Ctl: ctl.lancer, Pas: time.Millisecond, Resultats: NouvelleBoite(0),
		Systemctl: func(context.Context, ...string) ([]byte, error) {
			appels.Add(1)
			return nil, errors.New("systemctl : code 1")
		}})
	ctx, annule := context.WithTimeout(context.Background(), 2*time.Second) // sans borne, le suivi ne finirait jamais
	defer annule()
	e.Operer(ctx, CmdMettreAJour, nil, "")
	e.Attendre()
	evs, _ := e.cfg.Resultats.Prendre(16)
	if len(evs) != 1 || *evs[0].RC != -1 || evs[0].Resume != "maj-paquets : résultat inconnu" {
		t.Fatalf("« résultat inconnu » attendu : %+v", evs)
	}
	if n := appels.Load(); n != maxErreursShow || maxErreursShow != 12 {
		t.Fatalf("%d lectures, attendu 12", n)
	}
	if s := e.suivis.Load(); s != 0 {
		t.Fatalf("emplacement de suivi non libéré : %d", s)
	}
}

// TestSupportSansJob (tâche 4) : le support ne lance rien. Ouvrir rend « consentement » (en attente de l'accord du
// détenteur) ; fermer rend « accepte » SANS job et rien n'est suivi ; un ok sans job hors support reste incohérent.
func TestSupportSansJob(t *testing.T) {
	reponses := map[string]string{
		"ouvrir": `{"ok": false, "refus": "consentement requis", "support": "s-01"}`,
		"fermer": `{"ok": true, "support": "s-01", "etat": "ferme"}`,
	}
	// argv : -n <ctl> --acteur gk2admin support <op> …
	ctl := &fauxCtl{repondre: func(a []string) ([]byte, error) { return []byte(reponses[a[5]] + "\n"), nil }}
	var progres atomic.Int32
	e := Nouveau(Config{Ctl: ctl.lancer, Resultats: NouvelleBoite(0), Pas: time.Millisecond,
		Systemctl:   func(context.Context, ...string) ([]byte, error) { return []byte("inactive\ninactive\n"), nil },
		Progression: func(notifs.Evenement) { progres.Add(1) }})
	r := e.Operer(context.Background(), CmdSupportOuvrir, map[string]any{"id": "s-01", "duree_min": 45.0}, "gk2admin")
	if r.Etat != Consentement || r.Job != "" {
		t.Fatalf("ouvrir : %+v", r)
	}
	r = e.Operer(context.Background(), CmdSupportFermer, map[string]any{"id": "s-01"}, "gk2admin")
	if r.Etat != Accepte || r.Job != "" || r.Raison != "" {
		t.Fatalf("fermer : %+v", r)
	}
	e.Attendre()
	if progres.Load() != 0 {
		t.Fatalf("aucun suivi attendu, %d progressions", progres.Load())
	}
	for _, s := range []string{`{"ok": true}`, `{"ok": true, "etat": "ferme"}`, `{"ok": true, "support": "S 1"}`} {
		if r := lireReponse([]byte(s)); r.Etat != Refuse {
			t.Errorf("%s : refus attendu, %+v", s, r)
		}
	}
}
