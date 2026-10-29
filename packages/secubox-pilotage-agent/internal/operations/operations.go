// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package operations traite les Operate d'action de L2 (#3126) : liste fermée de commandes, paramètres validés
// par l'agent AVANT tout appel, traduits en un argv du ctl root (`sudo -n /usr/sbin/secubox-pilotagectl …`), qui
// reste la frontière de sécurité et décide de la politique (mains liées, box cliente, consentement, ancre).
//
// La réponse est immédiate (OPERATE_RESP {etat, job, raison}) ; une opération acceptée est ensuite suivie par
// `systemctl show` sans sudo (progression : lancée, en cours, terminée) puis, l'unité finie, par le verbe de
// lecture `etat-operation <job>` du ctl, qui donne le code de sortie. La fin
// (X_SECUBOX_OperationDone {job, rc, resume}) va dans une Boite : gardée tant qu'elle n'est pas remise au maître
// (au plus 50), renvoyée à la reconnexion.
package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

// Commandes acceptées (liste fermée). Le relevé (Device.X_SECUBOX_Releve.Mesurer()) reste traité par le canal.
const (
	CmdReboot        = "Device.Reboot()"
	CmdMettreAJour   = "Device.X_SECUBOX_Packages.MettreAJour()"
	CmdServices      = "Device.X_SECUBOX_Services.Agir()"
	CmdRenommer      = "Device.X_SECUBOX_Nom.Renommer()"
	CmdRenouveler    = "Device.X_SECUBOX_Secrets.Renouveler()"
	CmdSupportOuvrir = "Device.X_SECUBOX_Support.Ouvrir()"
	CmdSupportFermer = "Device.X_SECUBOX_Support.Fermer()"
)

// RaisonAncre est le refus du ctl quand aucune ancre n'est vérifiée de son côté (R-L2-21) : le canal force alors
// une revérification (M3, R-L2-28).
const RaisonAncre = "ancre non vérifiée"

// Bornes et réglages.
const (
	CheminCtl    = "/usr/sbin/secubox-pilotagectl"
	MaxResultats = 50              // résultats non remis gardés en mémoire
	PasDefaut    = 5 * time.Second // sondage de l'unité d'une opération suivie
	maxSuivis    = 32              // opérations suivies en même temps
	maxRaison    = 120             // octets de la raison d'un refus
	essaisFin    = 3               // lectures de la fin d'une unité disparue avant « résultat inconnu »
	// erreurs consécutives de systemctl show (bus injoignable) avant « résultat inconnu » : 1 min au pas de 5 s
	maxErreursShow = 12
	prefixeOp      = "secubox-pilotage-op-"
	dureeSupport   = 30 // minutes, défaut d'une session de support (maximum 240)
	dureeSupMax    = 240
)

var (
	reUnite   = regexp.MustCompile(`^secubox-[a-z0-9][a-z0-9@.-]{0,62}\.(service|timer)$`)
	reNom     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reSupport = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	reJob     = regexp.MustCompile(`^[0-9a-f]{16}$`)
	reActeur  = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,63}$`) // même motif que le ctl (R-L2-14)
	// Le maître peut envoyer l'action en anglais (vocabulaire systemd) ou en français (verbes du ctl).
	actionsService = map[string]string{"demarrer": "demarrer", "arreter": "arreter", "redemarrer": "redemarrer",
		"start": "demarrer", "stop": "arreter", "restart": "redemarrer"}
	actifs = map[string]bool{"active": true, "activating": true, "deactivating": true, "reloading": true, "refreshing": true}
)

// Etat est l'état rendu dans l'OPERATE_RESP.
type Etat string

// États de l'OPERATE_RESP (R-L2-1 : « consentement requis » du ctl → Consentement ; tout autre refus → Refuse).
const (
	Accepte      Etat = "accepte"
	Consentement Etat = "consentement"
	Refuse       Etat = "refuse"
)

// Reponse est la réponse immédiate à un Operate d'action.
type Reponse struct {
	Etat   Etat
	Job    string // opération lancée, ou opération en cours qui bloque la demande ; vide sinon
	Raison string // refus du ctl, ou de l'agent ; vide pour une demande acceptée
}

// Lanceur exécute un programme fixé (sudo, systemctl) avec ces arguments et rend sa sortie standard.
type Lanceur func(ctx context.Context, args ...string) ([]byte, error)

// Config règle l'exécuteur.
type Config struct {
	Ctl         Lanceur                // sudo : reçoit "-n", CheminCtl, … (argv exact du sudoers)
	Systemctl   Lanceur                // systemctl sans sudo : lecture de l'état de l'unité (bus système)
	Progression func(notifs.Evenement) // progression (non bloquante ; perdue si la file est pleine)
	Resultats   *Boite                 // fins d'opération, gardées jusqu'à leur remise
	Pas         time.Duration          // intervalle de sondage de l'unité (5 s)
	Horloge     func() time.Time
}

// Executeur valide, lance par le ctl et suit les opérations.
type Executeur struct {
	cfg    Config
	suivi  sync.WaitGroup
	suivis atomic.Int32
}

// Nouveau prépare l'exécuteur ; Resultats nil : une boîte de 50 est créée.
func Nouveau(c Config) *Executeur {
	if c.Pas <= 0 {
		c.Pas = PasDefaut
	}
	if c.Horloge == nil {
		c.Horloge = time.Now
	}
	if c.Resultats == nil {
		c.Resultats = NouvelleBoite(0)
	}
	if c.Progression == nil {
		c.Progression = func(notifs.Evenement) {}
	}
	return &Executeur{cfg: c}
}

// Corps rend le corps de l'OPERATE_RESP : {"etat", "job", "raison"}, les trois clés toujours présentes.
func Corps(r Reponse) map[string]any {
	return map[string]any{"etat": string(r.Etat), "job": r.Job, "raison": r.Raison}
}

// Attendre attend la fin des suivis (après l'annulation de leur contexte).
func (e *Executeur) Attendre() { e.suivi.Wait() }

func refus(raison string) Reponse { return Reponse{Etat: Refuse, Raison: raison} }

// Operer valide la commande, appelle le ctl et rend la réponse immédiate ; une opération acceptée est suivie en
// tâche de fond jusqu'à sa fin ou l'annulation de ctx. acteur : login de l'administrateur du maître, transmis au
// ctl (--acteur) seulement s'il a la forme d'un login ; jamais un motif de refus.
func (e *Executeur) Operer(ctx context.Context, cmd string, args map[string]any, acteur string) Reponse {
	verbe, err := Traduire(cmd, args)
	if err != nil {
		return refus(err.Error())
	}
	argv := []string{"-n", CheminCtl}
	if reActeur.MatchString(acteur) {
		argv = append(argv, "--acteur", acteur)
	}
	argv = append(argv, verbe...)
	sortie, err := e.cfg.Ctl(ctx, argv...)
	if err != nil {
		log.Printf("operations : %s : ctl en erreur (%v)", verbe[0], err)
		return refus("action impossible (ctl en erreur)")
	}
	r := lireReponse(sortie)
	if r.Etat == Accepte {
		e.suivre(ctx, r.Job, verbe[0])
	}
	return r
}

// Traduire rend l'argv du ctl d'une commande de la liste fermée, ou une erreur (refus de l'agent) : commande
// inconnue, paramètre manquant, inconnu, mal typé ou hors motif.
func Traduire(cmd string, args map[string]any) ([]string, error) {
	cles := func(obligatoires []string, facultatives ...string) error {
		permises := map[string]bool{}
		for _, k := range append(obligatoires, facultatives...) {
			permises[k] = true
		}
		for k := range args {
			if !permises[k] {
				return fmt.Errorf("argument inconnu pour %s", cmd)
			}
		}
		for _, k := range obligatoires {
			if _, ok := args[k]; !ok {
				return fmt.Errorf("argument manquant pour %s : %s", cmd, k)
			}
		}
		return nil
	}
	chaine := func(k string, re *regexp.Regexp) (string, error) {
		s, ok := args[k].(string)
		if !ok || !re.MatchString(s) {
			return "", fmt.Errorf("argument invalide : %s", k)
		}
		return s, nil
	}
	sansArgument := func(verbe string) ([]string, error) {
		if err := cles(nil); err != nil {
			return nil, err
		}
		return []string{verbe}, nil
	}
	switch cmd {
	case CmdReboot:
		return sansArgument("reboot")
	case CmdMettreAJour:
		return sansArgument("maj-paquets")
	case CmdRenouveler:
		return sansArgument("renouveler-secrets")
	case CmdServices:
		if err := cles([]string{"unite", "action"}); err != nil {
			return nil, err
		}
		unite, err := chaine("unite", reUnite)
		if err != nil {
			return nil, err
		}
		a, _ := args["action"].(string)
		op, ok := actionsService[a]
		if !ok {
			return nil, fmt.Errorf("argument invalide : action")
		}
		return []string{"service", op, unite}, nil
	case CmdRenommer:
		if err := cles([]string{"nom"}); err != nil {
			return nil, err
		}
		nom, err := chaine("nom", reNom)
		if err != nil {
			return nil, err
		}
		return []string{"renommer", nom}, nil
	case CmdSupportOuvrir, CmdSupportFermer:
		op := "fermer"
		var facultatives []string
		if cmd == CmdSupportOuvrir {
			op, facultatives = "ouvrir", []string{"duree_min"}
		}
		if err := cles([]string{"id"}, facultatives...); err != nil {
			return nil, err
		}
		id, err := chaine("id", reSupport)
		if err != nil {
			return nil, err
		}
		if v, ok := args["duree_min"]; ok {
			// Durée bornée (défaut 30 min, au plus 4 h) ; validée ici, transmise au ctl avec la session (tâche 4).
			f, ok := v.(float64)
			if !ok || f != float64(int(f)) || f < 1 || f > dureeSupMax {
				return nil, fmt.Errorf("argument invalide : duree_min (entier de 1 à %d, défaut %d)", dureeSupMax, dureeSupport)
			}
		}
		return []string{"support", op, id}, nil
	}
	return nil, fmt.Errorf("commande inconnue")
}

// lireReponse interprète la sortie du ctl : un seul objet JSON. {"ok": true, "job"} → accepte ;
// {"ok": false, "refus": "consentement requis"} → consentement ; autre refus → refuse avec sa raison (et le job
// d'une opération en cours). Toute autre forme : refusée (fermé par défaut).
func lireReponse(b []byte) Reponse {
	incoherente := refus("réponse du ctl incohérente")
	var r map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&r); err != nil || dec.More() {
		return incoherente
	}
	var job, motif string
	if raw, ok := r["job"]; ok && (json.Unmarshal(raw, &job) != nil || !reJob.MatchString(job)) {
		return incoherente
	}
	switch string(r["ok"]) {
	case "true":
		if job == "" {
			return incoherente
		}
		return Reponse{Etat: Accepte, Job: job}
	case "false":
		if json.Unmarshal(r["refus"], &motif) != nil || motif == "" {
			return incoherente
		}
		if motif == "consentement requis" {
			return Reponse{Etat: Consentement, Raison: motif}
		}
		return Reponse{Etat: Refuse, Job: job, Raison: imprimable(motif)}
	}
	return incoherente
}

// imprimable garde les caractères imprimables d'une raison, au plus maxRaison octets, sans couper un caractère.
func imprimable(s string) string {
	var b strings.Builder
	for _, c := range s {
		if !unicode.IsPrint(c) {
			continue
		}
		if b.Len()+utf8.RuneLen(c) > maxRaison {
			break
		}
		b.WriteRune(c)
	}
	return b.String()
}

// suivre lance le suivi de l'opération job (verbe du ctl), borné à maxSuivis en même temps.
func (e *Executeur) suivre(ctx context.Context, job, verbe string) {
	if e.suivis.Add(1) > maxSuivis {
		e.suivis.Add(-1)
		log.Printf("operations : %s lancée sans suivi (déjà %d opérations suivies)", job, maxSuivis)
		e.fin(job, -1, verbe+" : suivi impossible (trop d'opérations suivies)")
		return
	}
	e.suivi.Add(1)
	go func() {
		defer e.suivi.Done()
		defer e.suivis.Add(-1)
		e.boucler(ctx, job, verbe)
	}()
}

func (e *Executeur) progression(job, etape string, pct int) {
	p := pct
	e.cfg.Progression(notifs.Evenement{Type: notifs.TypeOperationProgress, Job: job, Etape: etape, Pct: &p,
		Instant: e.cfg.Horloge().Unix()})
}

func (e *Executeur) fin(job string, rc int, resume string) {
	r := rc
	e.cfg.Resultats.Deposer(notifs.Evenement{Type: notifs.TypeOperationDone, Job: job, RC: &r, Resume: resume,
		Instant: e.cfg.Horloge().Unix()})
}

// boucler sonde l'unité (service, et minuterie d'un reboot différé) jusqu'à sa fin, puis lit le code au ctl.
// L'annulation de ctx (arrêt de l'agent, reboot de la box) l'interrompt sans inventer de résultat.
func (e *Executeur) boucler(ctx context.Context, job, verbe string) {
	e.progression(job, "lancee", 0)
	enCours := false
	essais, erreurs := 0, 0
	minuteur := time.NewTimer(e.cfg.Pas)
	defer minuteur.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-minuteur.C:
		}
		minuteur.Reset(e.cfg.Pas)
		actif, err := e.actif(ctx, job)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// M4 : un bus injoignable ne garde pas l'emplacement de suivi à vie.
			if erreurs++; erreurs >= maxErreursShow {
				log.Printf("operations : état de %s illisible %d fois de suite (%v), résultat inconnu", job, erreurs, err)
				e.fin(job, -1, verbe+" : résultat inconnu")
				return
			}
			log.Printf("operations : état de %s illisible (%v), nouvel essai", job, err)
			continue
		}
		erreurs = 0
		if actif {
			if !enCours {
				enCours = true
				e.progression(job, "en_cours", 50)
			}
			continue
		}
		// L'unité n'est plus active (et --collect l'a peut-être ramassée) : le ctl a enregistré sa fin (_fin).
		termine, succes, rc, err := e.lireFin(ctx, job)
		switch {
		case err == nil && termine:
			e.progression(job, "terminee", 100)
			e.fin(job, rc, resume(verbe, succes, rc))
			return
		case ctx.Err() != nil:
			return
		}
		if essais++; essais >= essaisFin {
			log.Printf("operations : fin de %s introuvable après %d lectures", job, essais)
			e.fin(job, -1, verbe+" : résultat inconnu")
			return
		}
	}
}

// actif lit, sans sudo, l'état du service et de la minuterie de l'opération.
func (e *Executeur) actif(ctx context.Context, job string) (bool, error) {
	u := prefixeOp + job
	b, err := e.cfg.Systemctl(ctx, "show", "-p", "ActiveState", "--value", "--", u+".service", u+".timer")
	if err != nil {
		return false, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if actifs[strings.TrimSpace(l)] {
			return true, nil
		}
	}
	return false, nil
}

// lireFin demande au ctl la fin enregistrée de job (verbe de lecture etat-operation, audité). termine faux : en
// cours ou inconnue. rc vaut -1 quand le code n'est pas un nombre (signal).
func (e *Executeur) lireFin(ctx context.Context, job string) (termine, succes bool, rc int, err error) {
	b, err := e.cfg.Ctl(ctx, "-n", CheminCtl, "etat-operation", job)
	if err != nil {
		return false, false, 0, err
	}
	var r struct {
		OK       *bool  `json:"ok"`
		Job      string `json:"job"`
		Etat     string `json:"etat"`
		Resultat string `json:"resultat"`
		RC       *int   `json:"rc"`
	}
	if json.Unmarshal(bytes.TrimSpace(b), &r) != nil || r.OK == nil || !*r.OK || r.Job != job {
		return false, false, 0, fmt.Errorf("réponse du ctl incohérente")
	}
	if r.Etat != "termine" || (r.Resultat != "succes" && r.Resultat != "echec") {
		return false, false, 0, nil
	}
	rc = -1
	if r.RC != nil && *r.RC >= 0 && *r.RC <= 255 {
		rc = *r.RC
	}
	return true, r.Resultat == "succes", rc, nil
}

// resume : texte court, sans secret ni sortie d'apt.
func resume(verbe string, succes bool, rc int) string {
	switch {
	case succes:
		return verbe + " : succès"
	case rc >= 0:
		return fmt.Sprintf("%s : échec (code %d)", verbe, rc)
	}
	return verbe + " : échec (interrompu)"
}

// Boite garde les fins d'opération non remises au maître, au plus max (le plus ancien est évincé et journalisé).
// Prendre et Remis travaillent par numéro de dépôt : un dépôt fait pendant un envoi n'est jamais retiré par erreur.
type Boite struct {
	mu     sync.Mutex
	file   []depot
	seq    uint64
	max    int
	signal chan struct{}
}

type depot struct {
	seq uint64
	ev  notifs.Evenement
}

// NouvelleBoite crée une boîte de max résultats (MaxResultats si max <= 0).
func NouvelleBoite(max int) *Boite {
	if max <= 0 {
		max = MaxResultats
	}
	return &Boite{max: max, signal: make(chan struct{}, 1)}
}

// Deposer ajoute un résultat et réveille l'envoi.
func (b *Boite) Deposer(ev notifs.Evenement) {
	b.mu.Lock()
	b.seq++
	b.file = append(b.file, depot{b.seq, ev})
	if len(b.file) > b.max {
		log.Printf("operations : résultat de %s évincé, non remis (plus de %d résultats en attente)", b.file[0].ev.Job, b.max)
		b.file = append([]depot(nil), b.file[1:]...)
	}
	b.mu.Unlock()
	b.Reveiller()
}

// Reveiller signale qu'un envoi est à tenter (dépôt, reconnexion) ; jamais bloquant.
func (b *Boite) Reveiller() {
	select {
	case b.signal <- struct{}{}:
	default:
	}
}

// Signal est lu par la goroutine qui remet les résultats.
func (b *Boite) Signal() <-chan struct{} { return b.signal }

// Taille rend le nombre de résultats en attente.
func (b *Boite) Taille() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.file)
}

// Prendre rend (sans les retirer) au plus n résultats, les plus anciens d'abord, et le numéro du dernier.
func (b *Boite) Prendre(n int) ([]notifs.Evenement, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n = min(n, len(b.file))
	out := make([]notifs.Evenement, n)
	var dernier uint64
	for i, d := range b.file[:n] {
		out[i], dernier = d.ev, d.seq
	}
	return out, dernier
}

// Remis retire les résultats remis : ceux dont le numéro est au plus seq (une seule remise chacun).
func (b *Boite) Remis(seq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	i := 0
	for i < len(b.file) && b.file[i].seq <= seq {
		i++
	}
	b.file = append([]depot(nil), b.file[i:]...)
}
