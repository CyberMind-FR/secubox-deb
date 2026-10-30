// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package canal est le seul code réseau de l'agent : un client HTTP sortant en
// interrogation longue vers le maître, par le tunnel WireGuard. L'agent
// n'écoute sur aucun port ; tout ce qui vient du réseau est borné et validé
// (taille, nombre, forme) avant usage.
//
// Ancre (D1, #3126 L2) : quand Config.Ancre est posée, elle est rappelée au
// démarrage puis toutes les PeriodeAncre (1 h). Aucun Operate n'est traité
// tant qu'elle n'a pas rendu AncreOK. AncreAbsente (aucune ancre posée sur la
// box, R-L2-19) garde le canal en lecture comme en L1 ; un lot d'Operate refusés
// redemande la vérification au ctl, qui audite « ancre absente », au plus une
// fois par lot et par minute (R-L2-24). Une ancre absente après une
// vérification réussie vaut AncreIllisible (M1). AncreDifferente
// ou AncreIllisible coupent le canal : rien ne part vers le maître (bonjour,
// sondage, réponses, notifications) ; la reconnexion suivante qui réussit
// notifie la coupure au maître (X_SECUBOX_AnchorFailed).
//
// Actions (L2, tâche 3) : avec l'ancre vérifiée, un Operate d'action passe à Config.Agir (l'exécuteur du paquet
// operations, qui appelle le ctl root) et reçoit tout de suite un OPERATE_RESP {etat, job, raison}. Les fins
// d'opération (X_SECUBOX_OperationDone) attendent dans Config.Resultats : une goroutine les remet par /notifs et
// les retire seulement après un 2xx ; un envoi manqué est retenté avec recul, et chaque bonjour (reconnexion) le
// relance tout de suite.
//
// Pilotage HTTP (L5, tâche 3) : un message HTTP passe au relais local (Config.CheminRelais) en tâche de fond, avec
// une portée recalculée par l'agent (Config.PorteeAdmin) ; sa HTTP_RESP part seule par POST /http. Voir http.go.
package canal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/operations"
)

// Valeurs par défaut et bornes.
const (
	AttenteDefaut   = 25 * time.Second
	ReculMinDefaut  = 5 * time.Second
	ReculMaxDefaut  = 300 * time.Second
	TailleMaxDefaut = 256 << 10
	PeriodeAncreDef = time.Hour
	reverifRefus    = time.Minute // au plus une revérification (ligne d'audit) par lot de refus et par minute

	portCanal      = "8472"
	prefixe        = "/canal/v1"
	maxRequetes    = 32 // requêtes traitées par sondage
	maxChemins     = 64 // chemins par GET
	maxCheminLong  = 256
	maxLotNotifs   = 16
	maxNotifsAtt   = 64 // notifications gardées si le maître est injoignable
	maxErreurLong  = 200
	delaiPost      = 15 * time.Second
	delaiConnexion = 5 * time.Second
	commandeMesure = "Device.X_SECUBOX_Releve.Mesurer()"
	dureeDefautS   = 60
	dureeMinS      = 10
	dureeMaxS      = 300
	planchCycle    = time.Second // un cycle sans requête revenu plus vite est suivi de cette pause
	maxEntetes     = 16 << 10
)

const (
	msgRefus        = "commande refusée (L1 : lecture seule)"
	msgAncreAbsente = "ancre absente : action refusée (lecture seule)"
)

var (
	reMsgID   = regexp.MustCompile(`^[0-9a-f]{16}$`)
	errTaille = errors.New("réponse du maître trop volumineuse")
	errAncre  = errors.New("ancre du maître non vérifiée : canal coupé")
)

// Verdict est le résultat de la vérification de l'ancre (sortie du ctl).
type Verdict string

// Verdicts possibles ; tout ce qui n'est pas AncreOK ou AncreAbsente coupe le canal.
const (
	AncreOK         Verdict = "ok"         // le pair du maître a la clé de l'ancre
	AncreAbsente    Verdict = "absente"    // aucune ancre posée : lecture seule, aucune action
	AncreDifferente Verdict = "differente" // autre clé : canal coupé
	AncreIllisible  Verdict = "illisible"  // ancre, wg ou ctl illisible : canal coupé
)

// Config règle le client. Les champs à zéro prennent leur valeur par défaut.
type Config struct {
	Maitre    string        // adresse du maître dans le tunnel : « hôte » ou « hôte:port » (8472 par défaut)
	IPSource  string        // adresse du tunnel liée en sortie (LocalAddr) ; vide = aucune liaison
	Attente   time.Duration // durée d'attente d'un sondage (25 s)
	ReculMin  time.Duration // premier recul après erreur (5 s)
	ReculMax  time.Duration // plafond du recul (300 s)
	TailleMax int           // taille maximale d'un message de réponse (256 Kio)
	Version   string        // version de l'agent annoncée à /bonjour
	BootID    string        // identifiant de démarrage de la box annoncé à /bonjour
	// Ancre vérifie que le pair WireGuard du maître porte la clé ancrée (le ctl
	// root, `ancre-verifier`) et rend son verdict ; nil : aucune vérification
	// (tests du canal).
	Ancre        func(ctx context.Context) Verdict
	PeriodeAncre time.Duration // intervalle des revérifications de l'ancre (1 h)
	// Agir traite un Operate d'action (L2) ; nil : toute commande autre que le relevé est refusée (L1).
	Agir func(ctx context.Context, cmd string, args map[string]any, acteur string) operations.Reponse
	// Resultats : fins d'opération à remettre au maître, renvoyées à la reconnexion ; nil : aucune.
	Resultats *operations.Boite
	// ApresAncre est appelée une fois, à la première vérification réussie de l'ancre (avant le premier bonjour) :
	// l'agent y renvoie les fins récentes enregistrées par le ctl (I4, R-L2-47) ; nil : rien.
	ApresAncre func(ctx context.Context)
	// CheminRelais : socket du relais local (L5, /run/secubox/pilotage-relais.sock) ; vide : tout message HTTP est
	// refusé (501). Exige Ancre, comme Agir.
	CheminRelais string
	// PorteeAdmin dit si la box permet la portée admin MAINTENANT (mains libres et box du propriétaire, ou box cliente
	// pendant un support accepté) ; voir PorteeLocale. nil : jamais admin. La portée du maître ne peut que réduire.
	PorteeAdmin func(ctx context.Context) bool
	// Joignable (L5 tâche 7, facultatif) reçoit, après chaque tour, si le maître a répondu (page d'état locale).
	// Appelée par la seule goroutine de Tourner ; elle ne doit pas bloquer.
	Joignable func(ok bool)
	DelaiHTTP time.Duration // délai d'un appel au relais (DelaiHTTPDefaut)
	// HTTPSimultanes : messages HTTP traités à la fois (HTTPSimultanesDefaut) ; au-delà, 503 tout de suite.
	HTTPSimultanes int
	// JournalDebug : journalise aussi chaque lecture HTTP réussie (sinon : écritures et refus seulement, R-L5-21 M5).
	JournalDebug bool
}

// Client interroge le maître et lui répond.
type Client struct {
	cfg     Config
	m       *modele.Modele
	operer  func(ctx context.Context, cmd string, args map[string]any) (any, error)
	http    *http.Client
	base    string
	dormir  func(ctx context.Context, d time.Duration) error // injectable pour les tests
	reprise func(d time.Duration) *time.Timer                // minuteur de reprise des notifications, injectable
	suivi   sync.WaitGroup                                   // relevés en tâche de fond, attendus par Tourner
	releve  atomic.Bool                                      // un relevé est en cours
	errCfg  error                                            // configuration invalide : aucune connexion
	horloge func() time.Time                                 // injectable pour les tests
	verdict atomic.Value                                     // Verdict courant ; vide : pas encore vérifiée
	// Lus et écrits par la seule goroutine de Tourner :
	ancreVue time.Time // dernière vérification réussie
	coupure  int64     // instant (Unix) de la coupure à notifier ; 0 : rien à notifier
	dejaOK   bool      // l'ancre a été vérifiée au moins une fois (M1)
	reverif  time.Time // dernière revérification demandée par un refus d'Operate (R-L2-24)
	// L5 : messages HTTP (voir http.go).
	semHTTP    chan struct{}                                       // plafond de concurrence
	gros       chan struct{}                                       // un seul échange de plus de seuilGros à la fois (mémoire)
	posterHTTP func(ctx context.Context, id string, sortie []byte) // remise de la HTTP_RESP, injectable
}

// NouveauClient prépare le client ; rien n'est envoyé avant Tourner.
func NouveauClient(c Config, m *modele.Modele, operer func(ctx context.Context, cmd string, args map[string]any) (any, error)) *Client {
	if c.Attente <= 0 {
		c.Attente = AttenteDefaut
	}
	if c.ReculMin <= 0 {
		c.ReculMin = ReculMinDefaut
	}
	if c.ReculMax < c.ReculMin {
		c.ReculMax = ReculMaxDefaut
		if c.ReculMax < c.ReculMin {
			c.ReculMax = c.ReculMin
		}
	}
	if c.TailleMax <= 0 {
		c.TailleMax = TailleMaxDefaut
	}
	if c.PeriodeAncre <= 0 {
		c.PeriodeAncre = PeriodeAncreDef
	}
	d := &net.Dialer{Timeout: delaiConnexion}
	var errCfg error
	if c.IPSource != "" {
		ip, err := ipSource(c.IPSource)
		if err != nil {
			errCfg = err
		} else {
			d.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}
	tr := &http.Transport{
		Proxy:                  nil, // jamais de proxy d'environnement
		DialContext:            d.DialContext,
		ResponseHeaderTimeout:  c.Attente + 10*time.Second,
		MaxResponseHeaderBytes: maxEntetes,
		MaxIdleConns:           2,
		IdleConnTimeout:        90 * time.Second,
	}
	cl := &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirection refusée")
		},
	}
	if c.DelaiHTTP <= 0 {
		c.DelaiHTTP = DelaiHTTPDefaut
	}
	if c.HTTPSimultanes <= 0 {
		c.HTTPSimultanes = HTTPSimultanesDefaut
	}
	if c.CheminRelais != "" && c.Ancre == nil && errCfg == nil {
		// R-L5-3 : aucun appel au relais sans ancre vérifiée (R-L2-21).
		errCfg = errors.New("relais (CheminRelais) sans vérification d'ancre (Ancre) : configuration refusée, aucune connexion")
	}
	if c.Agir != nil && c.Ancre == nil && errCfg == nil {
		// M5 : des actions sans vérification de l'ancre du maître ne sont jamais servies.
		errCfg = errors.New("actions (Agir) sans vérification d'ancre (Ancre) : configuration refusée, aucune connexion")
	}
	hote := strings.TrimPrefix(c.Maitre, "http://")
	if !strings.Contains(hote, ":") || strings.HasSuffix(hote, "]") {
		hote = net.JoinHostPort(strings.Trim(hote, "[]"), portCanal)
	}
	cli := &Client{cfg: c, m: m, operer: operer, http: cl, base: "http://" + hote + prefixe, dormir: dormirReel, reprise: time.NewTimer, errCfg: errCfg,
		horloge: time.Now, semHTTP: make(chan struct{}, c.HTTPSimultanes), gros: make(chan struct{}, 1)}
	cli.posterHTTP = cli.remettreHTTP
	return cli
}

// ipSource accepte une adresse seule ou sa forme CIDR (« 10.10.0.5/24 »).
func ipSource(s string) (net.IP, error) {
	if ip := net.ParseIP(s); ip != nil {
		return ip, nil
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip, nil
	}
	return nil, fmt.Errorf("ip_source %q invalide : adresse IP ou CIDR attendue, aucune connexion", s)
}

func dormirReel(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Tourner sonde le maître jusqu'à l'annulation de ctx, seul motif de retour.
// Les erreurs réseau, 5xx et délais déclenchent un recul doublé de ReculMin à
// ReculMax, remis à zéro après un sondage réussi. Les notifications reçues sur
// ev partent par lots, sans jamais bloquer le sondage.
func (c *Client) Tourner(ctx context.Context, ev <-chan notifs.Evenement) error {
	var wg sync.WaitGroup
	if ev != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.notifier(ctx, ev)
		}()
	}
	if c.cfg.Resultats != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.remettre(ctx)
		}()
	}
	defer wg.Wait()
	defer c.suivi.Wait() // relevés en tâche de fond

	recul := c.cfg.ReculMin
	reculAncre := c.cfg.ReculMin
	bonjour := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !c.ancreAJour(ctx, &bonjour) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if c.cfg.Joignable != nil {
				c.cfg.Joignable(false) // ancre non vérifiée : le maître n'est pas reconnu
			}
			// Chaque échec est audité par le ctl : le recul monte jusqu'à la période (24 lignes par jour au plus).
			log.Printf("canal : %v (%s), aucun Operate (nouvelle vérification dans %s)", errAncre, c.etatAncre(), reculAncre)
			if e := c.dormir(ctx, reculAncre); e != nil {
				return e
			}
			if reculAncre *= 2; reculAncre > c.cfg.PeriodeAncre {
				reculAncre = c.cfg.PeriodeAncre
			}
			continue
		}
		reculAncre = c.cfg.ReculMin
		debut := time.Now()
		actif, err := c.cycle(ctx, &bonjour)
		if c.cfg.Joignable != nil && ctx.Err() == nil {
			c.cfg.Joignable(err == nil)
		}
		if err == nil {
			recul = c.cfg.ReculMin
			if !actif && time.Since(debut) < planchCycle {
				// le maître répond tout de suite sans rien demander : pas de rafale
				if e := c.dormir(ctx, planchCycle); e != nil {
					return e
				}
			}
			continue
		}
		bonjour = false // le maître a pu redémarrer : on se réannonce
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("canal : %v (nouvel essai dans %s)", err, recul)
		if e := c.dormir(ctx, recul); e != nil {
			return e
		}
		if recul *= 2; recul > c.cfg.ReculMax {
			recul = c.cfg.ReculMax
		}
	}
}

func (c *Client) etatAncre() Verdict {
	v, _ := c.verdict.Load().(Verdict)
	return v
}

func ouvert(v Verdict) bool { return v == AncreOK || v == AncreAbsente }

// verifierAncre appelle le ctl et retient son verdict (seule la goroutine de
// Tourner l'appelle). Rend le verdict.
func (c *Client) verifierAncre(ctx context.Context) Verdict {
	v := c.cfg.Ancre(ctx)
	if !ouvert(v) && v != AncreDifferente {
		v = AncreIllisible // valeur inconnue : fermé par défaut
	}
	if v == AncreAbsente && c.dejaOK {
		// M1 : une ancre vue puis disparue n'est pas une box sans ancre (on l'a retirée) : coupure.
		log.Print("ancre : disparue après une vérification réussie, traitée comme illisible")
		v = AncreIllisible
	}
	premiere := v == AncreOK && !c.dejaOK
	if v == AncreOK {
		c.dejaOK = true
	}
	c.verdict.Store(v)
	if ouvert(v) {
		c.ancreVue = c.horloge()
	}
	if premiere && c.cfg.ApresAncre != nil {
		// I4 : une fois par démarrage, le canal ouvert (les fins déposées partent dès le bonjour)
		c.cfg.ApresAncre(ctx)
	}
	return v
}

// ancreAJour rend vrai si le canal peut servir (ancre vérifiée, ou absente :
// lecture seule) depuis moins de PeriodeAncre, sinon la revérifie. Un verdict
// différente ou illisible coupe le canal : plus rien ne part (sonder et poster
// refusent), les connexions inactives sont fermées, le bonjour sera refait, et
// la coupure est retenue pour être notifiée à la reconnexion.
func (c *Client) ancreAJour(ctx context.Context, bonjour *bool) bool {
	if c.cfg.Ancre == nil {
		return true
	}
	if ouvert(c.etatAncre()) && c.horloge().Sub(c.ancreVue) < c.cfg.PeriodeAncre {
		return true
	}
	if ouvert(c.verifierAncre(ctx)) {
		return true
	}
	if c.coupure == 0 {
		c.coupure = c.horloge().Unix()
	}
	*bonjour = false
	c.http.CloseIdleConnections()
	return false
}

// coupe rend vrai si le canal est coupé (ancre différente, illisible, ou pas
// encore vérifiée).
func (c *Client) coupe() bool {
	return c.cfg.Ancre != nil && !ouvert(c.etatAncre())
}

// cycle fait un tour : bonjour (une fois), sondage, traitement, réponses.
// Il rend vrai si le maître a demandé quelque chose de valable.
func (c *Client) cycle(ctx context.Context, bonjour *bool) (bool, error) {
	if c.errCfg != nil {
		return false, c.errCfg
	}
	if !*bonjour {
		corps := map[string]any{
			"agent_version": c.cfg.Version,
			"boot_id":       c.cfg.BootID,
			"modele":        c.m.Supportes(),
		}
		if err := c.poster(ctx, "/bonjour", corps); err != nil {
			return false, fmt.Errorf("bonjour : %w", err)
		}
		*bonjour = true
		if c.cfg.Resultats != nil {
			c.cfg.Resultats.Reveiller() // (re)connexion : les résultats non remis partent tout de suite
		}
	}
	if c.coupure != 0 {
		// Reconnexion après une coupure faute d'ancre : le maître en est informé
		// (value = instant de la coupure). Non remise : retentée au cycle suivant.
		ev := notifs.Evenement{Type: notifs.TypeAncre, Valeur: c.coupure, Instant: c.horloge().Unix()}
		lot := []map[string]any{{"type": "NOTIFY", "body": map[string]any{"event": ev}}}
		if err := c.poster(ctx, "/notifs", lot); err != nil {
			log.Printf("canal : notification de coupure (ancre) non remise : %v", err)
		} else {
			c.coupure = 0
		}
	}
	brut, err := c.sonder(ctx)
	if err != nil {
		return false, fmt.Errorf("sondage : %w", err)
	}
	if len(brut) == 0 {
		return false, nil
	}
	reps, lances, err := c.traiter(ctx, brut)
	if err != nil {
		return false, err
	}
	actif := len(reps)+lances > 0
	if len(reps) == 0 {
		return actif, nil
	}
	for _, lot := range lotsReponses(reps, c.cfg.TailleMax) {
		if e := c.poster(ctx, "/reponses", json.RawMessage(lot)); e != nil && err == nil {
			err = fmt.Errorf("réponses : %w", e)
		}
	}
	return actif, err
}

// lotsReponses range les réponses en listes JSON dont chacune, crochets
// compris, tient dans max octets (un POST par lot).
func lotsReponses(reps []reponse, max int) [][]byte {
	var lots [][]byte
	cur := []byte{'['}
	for _, r := range reps {
		b, err := json.Marshal(r)
		if err != nil {
			continue
		}
		if len(cur) > 1 && len(cur)+1+len(b)+1 > max {
			lots = append(lots, append(cur, ']'))
			cur = []byte{'['}
		}
		if len(cur) > 1 {
			cur = append(cur, ',')
		}
		cur = append(cur, b...)
	}
	if len(cur) > 1 {
		lots = append(lots, append(cur, ']'))
	}
	return lots
}

// sonder attend une liste de requêtes (200) ou rien (204).
func (c *Client) sonder(ctx context.Context) ([]byte, error) {
	if c.coupe() {
		return nil, errAncre
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Attente+15*time.Second)
	defer cancel()
	url := fmt.Sprintf("%s/requetes?attente=%d", c.base, int(c.cfg.Attente/time.Second))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		max := c.cfg.TailleMax
		if c.cfg.CheminRelais != "" && max < tailleHTTPMax {
			max = tailleHTTPMax // L5 : un message HTTP porte jusqu'à 4 Mio de corps (base64)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
		if err != nil {
			return nil, err
		}
		if len(b) > max {
			return nil, errTaille
		}
		return b, nil
	default:
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("statut HTTP %d", resp.StatusCode)
	}
}

// poster envoie un corps JSON ; tout statut hors 2xx est une erreur.
func (c *Client) poster(ctx context.Context, chemin string, corps any) error {
	if c.coupe() {
		return errAncre // rien ne part vers un pair qui n'est peut-être pas le maître
	}
	b, err := json.Marshal(corps)
	if err != nil {
		return err
	}
	return c.posterBrut(ctx, chemin, bytes.NewReader(b), int64(len(b)))
}

// posterBrut envoie un corps JSON déjà formé (lu une fois, sans copie) ; tout statut hors 2xx est une erreur.
func (c *Client) posterBrut(ctx context.Context, chemin string, corps io.Reader, n int64) error {
	if c.coupe() {
		return errAncre
	}
	ctx, cancel := context.WithTimeout(ctx, delaiPost)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+chemin, corps)
	if err != nil {
		return err
	}
	req.ContentLength = n
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("statut HTTP %d", resp.StatusCode)
	}
	return nil
}

// notifier regroupe les événements (16 par POST) ; en cas d'échec ils sont
// gardés (64 au plus, les plus anciens tombent) et retentés par un minuteur à
// recul doublé de ReculMin à ReculMax, sans attendre l'événement suivant.
func (c *Client) notifier(ctx context.Context, ev <-chan notifs.Evenement) {
	var att []notifs.Evenement
	var minuteur *time.Timer
	var reprise <-chan time.Time
	recul := c.cfg.ReculMin
	defer func() {
		if minuteur != nil {
			minuteur.Stop()
		}
	}()
	ajouter := func(e notifs.Evenement) {
		att = append(att, e)
		if len(att) > maxNotifsAtt {
			att = att[len(att)-maxNotifsAtt:]
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ev:
			if !ok {
				return
			}
			ajouter(e)
		case <-reprise:
			reprise = nil
		}
		for ouvert := true; ouvert; {
			select {
			case e, ok := <-ev:
				if !ok {
					ouvert = false
					break
				}
				ajouter(e)
			default:
				ouvert = false
			}
		}
		if c.vider(ctx, &att) {
			recul = c.cfg.ReculMin
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if minuteur != nil {
			minuteur.Stop()
		}
		minuteur = c.reprise(recul)
		reprise = minuteur.C
		if recul *= 2; recul > c.cfg.ReculMax {
			recul = c.cfg.ReculMax
		}
	}
}

// vider envoie les notifications en attente par lots ; faux au premier échec,
// les lots non remis restant dans att.
func (c *Client) vider(ctx context.Context, att *[]notifs.Evenement) bool {
	for len(*att) > 0 {
		n := min(len(*att), maxLotNotifs)
		lot := make([]map[string]any, n)
		for i, e := range (*att)[:n] {
			lot[i] = map[string]any{"type": "NOTIFY", "body": map[string]any{"event": e}}
		}
		if err := c.poster(ctx, "/notifs", lot); err != nil {
			if ctx.Err() == nil {
				log.Printf("canal : notifications non remises : %v", err)
			}
			return false
		}
		*att = (*att)[n:]
	}
	return true
}

// remettre envoie les fins d'opération de Config.Resultats (lots de 16) ; seule cette goroutine les envoie, et un
// résultat n'est retiré qu'une fois remis (2xx). Échec : nouvel essai par minuteur à recul doublé (ReculMin à
// ReculMax), ou dès le prochain dépôt ou bonjour.
func (c *Client) remettre(ctx context.Context) {
	b := c.cfg.Resultats
	var minuteur *time.Timer
	var reprise <-chan time.Time
	recul := c.cfg.ReculMin
	defer func() {
		if minuteur != nil {
			minuteur.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.Signal():
		case <-reprise:
			reprise = nil
		}
		if c.viderResultats(ctx) {
			recul = c.cfg.ReculMin
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if minuteur != nil {
			minuteur.Stop()
		}
		minuteur = c.reprise(recul)
		reprise = minuteur.C
		if recul *= 2; recul > c.cfg.ReculMax {
			recul = c.cfg.ReculMax
		}
	}
}

// viderResultats remet les résultats en attente ; faux au premier échec (ils restent dans la boîte).
func (c *Client) viderResultats(ctx context.Context) bool {
	b := c.cfg.Resultats
	for {
		evs, seq := b.Prendre(maxLotNotifs)
		if len(evs) == 0 {
			return true
		}
		lot := make([]map[string]any, len(evs))
		for i, e := range evs {
			lot[i] = map[string]any{"type": "NOTIFY", "body": map[string]any{"event": e}}
		}
		if err := c.poster(ctx, "/notifs", lot); err != nil {
			if ctx.Err() == nil {
				log.Printf("canal : %d résultat(s) d'opération non remis, gardés (%v)", b.Taille(), err)
			}
			return false
		}
		b.Remis(seq)
	}
}

// requete est un message du maître, tel que décodé.
type requete struct {
	MsgID string          `json:"msg_id"`
	Type  string          `json:"type"`
	Body  json.RawMessage `json:"body"`
}

type reponse struct {
	MsgID string         `json:"msg_id"`
	Type  string         `json:"type"`
	Body  map[string]any `json:"body"`
}

// traiter décode la liste brute et répond à chaque requête valable. Une liste
// illisible est une erreur (recul) ; une requête sans msg_id correct est
// journalisée puis ignorée. Les relevés partent en tâche de fond : lances les
// compte, leur réponse part seule, plus tard.
func (c *Client) traiter(ctx context.Context, brut []byte) ([]reponse, int, error) {
	var liste []json.RawMessage
	if err := json.Unmarshal(brut, &liste); err != nil {
		return nil, 0, errors.New("liste de requêtes illisible")
	}
	if len(liste) > maxRequetes {
		log.Printf("canal : %d requêtes reçues, %d traitées", len(liste), maxRequetes)
		liste = liste[:maxRequetes]
	}
	var reps []reponse
	lances := 0
	reverifie, sansAppel := false, 0
	for _, r := range liste {
		if ctx.Err() != nil {
			break
		}
		var rq requete
		if err := json.Unmarshal(r, &rq); err != nil || !reMsgID.MatchString(rq.MsgID) {
			log.Printf("canal : requête malformée ignorée")
			continue
		}
		if rq.Type == "OPERATE" {
			if v := c.etatAncre(); c.cfg.Ancre != nil && v != AncreOK {
				if v == AncreAbsente {
					// R-L2-19 : lecture seule ; le refus est audité par le ctl (« ancre absente »), à qui la
					// vérification est redemandée : une ancre posée depuis rend la main aux actions suivantes.
					// R-L2-24 : au plus une fois par lot et par minute (un pair non vérifié n'inonde pas l'audit) ;
					// les autres refus sont seulement comptés dans le journal de l'agent.
					if c.peutReverifier(&reverifie) {
						c.verifierAncre(ctx)
					} else {
						sansAppel++
					}
					reps = append(reps, erreur(rq.MsgID, msgAncreAbsente))
				} else {
					reps = append(reps, erreur(rq.MsgID, errAncre.Error()))
				}
				continue
			}
			rep, run := c.operate(ctx, rq)
			if refusSansAncre(rep) && c.peutReverifier(&reverifie) {
				// M3 : le ctl ne voit pas d'ancre vérifiée alors que l'agent se croit ancré (canal enregistré périmé
				// ou retiré) : revérification forcée, au plus une par lot et par minute (limiteur de R-L2-24).
				log.Print("canal : le ctl refuse faute d'ancre vérifiée, revérification forcée")
				c.verifierAncre(ctx)
			}
			if run == nil {
				reps = append(reps, c.borner(rep))
			} else if c.lancerReleve(ctx, rq.MsgID, run) {
				lances++
			} else {
				reps = append(reps, erreur(rq.MsgID, "relevé déjà en cours"))
			}
			continue
		}
		if rq.Type == TypeHTTP {
			// L5 : appel du relais local en tâche de fond ; la HTTP_RESP part seule (POST /http), plus tard.
			if c.lancerHTTP(ctx, rq.MsgID, rq.Body) {
				lances++
			} else {
				reps = append(reps, reponse{MsgID: rq.MsgID, Type: TypeHTTPResp, Body: sortieRefusMap(http.StatusServiceUnavailable, "agent occupé : trop de requêtes HTTP en cours")})
			}
			continue
		}
		reps = append(reps, c.repondre(ctx, rq))
	}
	if sansAppel > 0 {
		log.Printf("canal : %d Operate refusés (ancre absente) sans revérification auprès du ctl", sansAppel)
	}
	return reps, lances, nil
}

// peutReverifier applique le limiteur des revérifications demandées par un Operate (R-L2-24, M3) : une par lot et
// par minute au plus. Vrai : la revérification est permise et comptée.
func (c *Client) peutReverifier(reverifie *bool) bool {
	maintenant := c.horloge()
	if *reverifie || (!c.reverif.IsZero() && maintenant.Sub(c.reverif) < reverifRefus) {
		return false
	}
	*reverifie, c.reverif = true, maintenant
	return true
}

// refusSansAncre : OPERATE_RESP « refuse » du ctl faute d'ancre vérifiée de son côté.
func refusSansAncre(rep reponse) bool {
	return rep.Type == "OPERATE_RESP" && rep.Body["etat"] == string(operations.Refuse) && rep.Body["raison"] == operations.RaisonAncre
}

// lancerReleve exécute run en tâche de fond, suivie par Tourner, et poste sa
// réponse seule. Faux si un relevé est déjà en cours.
func (c *Client) lancerReleve(ctx context.Context, id string, run func(context.Context) reponse) bool {
	if !c.releve.CompareAndSwap(false, true) {
		return false
	}
	c.suivi.Add(1)
	go func() {
		defer c.suivi.Done()
		defer c.releve.Store(false)
		rep := c.borner(run(ctx))
		if ctx.Err() != nil {
			return
		}
		for _, lot := range lotsReponses([]reponse{rep}, c.cfg.TailleMax) {
			if err := c.poster(ctx, "/reponses", json.RawMessage(lot)); err != nil && ctx.Err() == nil {
				log.Printf("canal : réponse du relevé non remise : %v", err)
			}
		}
	}()
	return true
}

// borner remplace une réponse qui, mise en liste, dépasserait TailleMax.
func (c *Client) borner(rep reponse) reponse {
	if b, err := json.Marshal(rep); err != nil || len(b)+2 > c.cfg.TailleMax {
		return erreur(rep.MsgID, "réponse trop volumineuse")
	}
	return rep
}

func erreur(id, msg string) reponse {
	if len(msg) > maxErreurLong {
		n := maxErreurLong
		for n > 0 && !utf8.RuneStart(msg[n]) {
			n--
		}
		msg = msg[:n]
	}
	return reponse{MsgID: id, Type: "ERROR", Body: map[string]any{"err": msg}}
}

// repondre traite les requêtes à réponse immédiate ; OPERATE passe par traiter.
func (c *Client) repondre(ctx context.Context, rq requete) reponse {
	var rep reponse
	switch rq.Type {
	case "GET":
		var b struct {
			Paths []any `json:"paths"`
		}
		if err := json.Unmarshal(rq.Body, &b); err != nil {
			return erreur(rq.MsgID, "corps GET invalide")
		}
		chemins, err := validerChemins(b.Paths)
		if err != nil {
			return erreur(rq.MsgID, err.Error())
		}
		rep = c.tronquer(rq.MsgID, c.m.Get(ctx, chemins))
	case "GET_SUPPORTED_DM":
		rep = reponse{MsgID: rq.MsgID, Type: "GET_SUPPORTED_DM_RESP", Body: map[string]any{"paths": c.m.Supportes()}}
	default:
		return erreur(rq.MsgID, "type de requête inconnu")
	}
	return c.borner(rep)
}

func validerChemins(l []any) ([]string, error) {
	if len(l) == 0 || len(l) > maxChemins {
		return nil, fmt.Errorf("nombre de chemins invalide (1 à %d)", maxChemins)
	}
	out := make([]string, 0, len(l))
	vus := make(map[string]bool, len(l))
	for _, v := range l {
		s, ok := v.(string)
		if !ok || len(s) > maxCheminLong || !strings.HasPrefix(s, "Device.") {
			return nil, errors.New("chemin invalide")
		}
		if !vus[s] {
			vus[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}

// operate valide un OPERATE. Rend soit une réponse immédiate (refus, argument
// invalide, OPERATE_RESP d'une action) avec run nul, soit la fonction qui fera le relevé.
func (c *Client) operate(ctx context.Context, rq requete) (reponse, func(context.Context) reponse) {
	var b struct {
		Command string         `json:"command"`
		Args    map[string]any `json:"args"`
		Acteur  any            `json:"acteur"` // login de l'administrateur du maître (R-L2-14), validé par l'exécuteur
	}
	if err := json.Unmarshal(rq.Body, &b); err != nil {
		return erreur(rq.MsgID, "corps OPERATE invalide"), nil
	}
	if b.Command != commandeMesure && c.cfg.Agir != nil {
		acteur, _ := b.Acteur.(string)
		r := c.cfg.Agir(ctx, b.Command, b.Args, acteur)
		return reponse{MsgID: rq.MsgID, Type: "OPERATE_RESP", Body: operations.Corps(r)}, nil
	}
	if b.Command != commandeMesure || c.operer == nil {
		return erreur(rq.MsgID, msgRefus), nil
	}
	duree := dureeDefautS
	for k, v := range b.Args {
		f, ok := v.(float64)
		if k != "duree_s" || !ok || f != float64(int(f)) || f < dureeMinS || f > dureeMaxS {
			return erreur(rq.MsgID, fmt.Sprintf("argument invalide (duree_s : entier de %d à %d)", dureeMinS, dureeMaxS)), nil
		}
		duree = int(f)
	}
	return reponse{}, func(ctx context.Context) reponse {
		sortie, err := c.operer(ctx, b.Command, map[string]any{"duree_s": duree})
		if err != nil {
			return erreur(rq.MsgID, err.Error())
		}
		return reponse{MsgID: rq.MsgID, Type: "OPERATE_RESP", Body: map[string]any{"output": sortie}}
	}
}

// tronquer construit la GET_RESP ; au-delà de TailleMax, les entrées de listes
// « {i} » partent, indices les plus hauts d'abord, et « tronque » passe à vrai.
func (c *Client) tronquer(id string, res []modele.Resultat) reponse {
	fait := func(r []modele.Resultat, tronque bool) reponse {
		corps := map[string]any{"results": r}
		if tronque {
			corps["tronque"] = true
		}
		return reponse{MsgID: id, Type: "GET_RESP", Body: corps}
	}
	taille := func(r reponse) int {
		b, err := json.Marshal(r)
		if err != nil {
			return c.cfg.TailleMax + 1
		}
		return len(b) + 2 // crochets de la liste du POST
	}
	if rep := fait(res, false); taille(rep) <= c.cfg.TailleMax {
		return rep
	}
	type entree struct {
		idx  int
		res  int
		cle  string
		pref string
	}
	var groupes []entree
	vus := map[string]bool{}
	for i, r := range res {
		for k := range r.Params {
			if idx, pref, ok := indiceListe(k); ok {
				g := strconv.Itoa(i) + "|" + pref
				if !vus[g] {
					vus[g] = true
					groupes = append(groupes, entree{idx, i, k, pref})
				}
			}
		}
	}
	sort.Slice(groupes, func(a, b int) bool {
		if groupes[a].idx != groupes[b].idx {
			return groupes[a].idx > groupes[b].idx
		}
		return groupes[a].pref < groupes[b].pref
	})
	sans := func(n int) []modele.Resultat {
		coupes := map[string]bool{}
		for _, g := range groupes[:n] {
			coupes[strconv.Itoa(g.res)+"|"+g.pref] = true
		}
		out := make([]modele.Resultat, len(res))
		for i, r := range res {
			out[i] = r
			if len(r.Params) == 0 {
				continue
			}
			p := make(map[string]any, len(r.Params))
			for k, v := range r.Params {
				if _, pref, ok := indiceListe(k); ok && coupes[strconv.Itoa(i)+"|"+pref] {
					continue
				}
				p[k] = v
			}
			out[i].Params = p
		}
		return out
	}
	// plus petit nombre de groupes à couper pour tenir dans la taille
	lo, hi := 1, len(groupes)
	if hi == 0 || taille(fait(sans(hi), true)) > c.cfg.TailleMax {
		return erreur(id, "réponse trop volumineuse")
	}
	for lo < hi {
		mid := (lo + hi) / 2
		if taille(fait(sans(mid), true)) <= c.cfg.TailleMax {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return fait(sans(lo), true)
}

// indiceListe repère le premier segment numérique d'un chemin : son indice et
// le préfixe de liste qui le précède, avec l'indice.
func indiceListe(k string) (int, string, bool) {
	segs := strings.Split(k, ".")
	for i, s := range segs {
		if s == "" || len(s) > 9 {
			continue
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 0 && s[0] != '+' && s[0] != '-' {
			return n, strings.Join(segs[:i+1], "."), true
		}
	}
	return 0, "", false
}
