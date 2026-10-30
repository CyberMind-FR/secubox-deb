// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package canal

// Message HTTP (L5, tâche 3, #3126) : le maître sert les pages d'une box légère et fait passer leurs appels d'API
// par le canal. Requête `{"msg_id", "type": "HTTP", "body": <entrée du relais>}` ; l'agent appelle le relais local
// (/run/secubox/pilotage-relais.sock, un objet JSON par connexion) et rend `{"msg_id", "type": "HTTP_RESP",
// "body": <sortie du relais>}` par POST /canal/v1/http (une réponse par POST : jusqu'à ~5,6 Mo en base64, hors
// du plafond de 256 Kio de /reponses).
//
// La PORTÉE est recalculée ici, jamais crue : `lecture` si les mains sont liées (même vérification que le relais,
// relais.MainsLieesDans) ou si le ctl root ne permet pas l'admin (box cliente sans support ouvert) ; la portée du
// maître ne peut que réduire. Acteur et maître : motifs du vérificateur (relais.Normaliser = _RE_ACTEUR et
// _RE_MAITRE de secubox_core.auth). L'agent ne connaît le maître que par son adresse dans le tunnel, authentifiée
// par l'ancre : il ne peut pas vérifier ces noms, seulement leur forme ; ils ne servent qu'à l'audit des modules.
// Ancre vérifiée exigée (R-L5-3, R-L2-21). Corps ≤ 4 Mio (413), délai du relais + 5 s (504), 4 messages HTTP à la
// fois (503 au-delà), un seul échange de plus de 256 Kio à la fois (mémoire). Journal : méthode, chemin sans
// requête, portées et statut ; jamais un jeton, un corps ni un en-tête.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/relais"
)

const (
	// TypeHTTP et TypeHTTPResp : types du message HTTP sur le canal.
	TypeHTTP     = "HTTP"
	TypeHTTPResp = "HTTP_RESP"
	// HTTPSimultanesDefaut : messages HTTP traités à la fois ; le relais en sert deux, les autres attendent sa place.
	HTTPSimultanesDefaut = 4
	// DelaiHTTPDefaut : le relais borne l'appel au module à 30 s et rend alors son propre 504 ; 5 s de marge.
	DelaiHTTPDefaut = relais.DelaiDefaut + 5*time.Second
	// tailleHTTPMax : un message HTTP (corps de 4 Mio en base64 et champs), dans un sondage comme dans la sortie du
	// relais.
	tailleHTTPMax = (relais.CorpsMax+2)/3*4 + 256<<10
	// seuilGros : au-delà, un échange prend la place unique « gros » (deux copies de 5,6 Mo tiennent sous
	// MemoryMax, pas quatre).
	seuilGros     = 256 << 10
	cheminHTTP    = "/http"
	PorteeLecture = "lecture"
	PorteeAdmin   = "admin"
)

// PorteeLocale assemble la décision « admin permis » de l'agent : mainsLiees est relue à CHAQUE message (drapeau
// root, aucun appel privilégié) ; politique (le ctl root, `politique pilotage-admin`, une ligne sudo) n'est
// relue qu'au plus une fois par `cache`. Mains liées ⇒ jamais admin, quoi que dise le cache.
func PorteeLocale(mainsLiees func() bool, politique func(context.Context) bool, cache time.Duration) func(context.Context) bool {
	var mu sync.Mutex
	var jusqua time.Time
	var permis bool
	return func(ctx context.Context) bool {
		if mainsLiees() {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		if time.Now().Before(jusqua) {
			return permis
		}
		permis = politique(ctx)
		jusqua = time.Now().Add(cache)
		return permis
	}
}

// sortieRefus : une sortie de la forme du relais, {statut, entetes, corps_b64} avec {"detail": motif}.
func sortieRefus(statut int, motif string) []byte {
	corps, _ := json.Marshal(map[string]string{"detail": motif})
	b, _ := json.Marshal(map[string]any{"statut": statut, "entetes": map[string]string{"Content-Type": "application/json"},
		"corps_b64": base64.StdEncoding.EncodeToString(corps)})
	return b
}

func sortieRefusMap(statut int, motif string) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(sortieRefus(statut, motif), &m)
	return m
}

// longueurDecodee : taille exacte du corps une fois décodé (base64 standard avec bourrage).
func longueurDecodee(s string) int {
	n := len(s) / 4 * 3
	if strings.HasSuffix(s, "==") {
		n -= 2
	} else if strings.HasSuffix(s, "=") {
		n--
	}
	return n
}

// lancerHTTP traite le message en tâche de fond (suivie par Tourner) et poste sa réponse seule. Faux si le
// plafond de concurrence est atteint (le maître reçoit alors un 503 dans la liste de réponses).
func (c *Client) lancerHTTP(ctx context.Context, id string, brut json.RawMessage) bool {
	select {
	case c.semHTTP <- struct{}{}:
	default:
		return false
	}
	c.suivi.Add(1)
	go func() {
		defer c.suivi.Done()
		defer func() { <-c.semHTTP }()
		b := brut
		brut = nil // la fermeture ne retient pas le message pendant l'appel (traiterHTTP le libère après décodage)
		sortie := c.traiterHTTP(ctx, b)
		if ctx.Err() != nil {
			return
		}
		c.posterHTTP(ctx, id, sortie)
	}()
	return true
}

// remettreHTTP poste la HTTP_RESP, la sortie du relais insérée telle quelle (aucune copie de plus).
func (c *Client) remettreHTTP(ctx context.Context, id string, sortie []byte) {
	tete := []byte(`{"msg_id":"` + id + `","type":"` + TypeHTTPResp + `","body":`)
	n := int64(len(tete) + len(sortie) + 1)
	r := io.MultiReader(bytes.NewReader(tete), bytes.NewReader(sortie), strings.NewReader("}"))
	if err := c.posterBrut(ctx, cheminHTTP, r, n); err != nil && ctx.Err() == nil {
		log.Printf("canal : réponse HTTP non remise : %v", err)
	}
}

// traiterHTTP rend la sortie du relais (ou un refus de même forme) pour le corps d'un message HTTP.
func (c *Client) traiterHTTP(ctx context.Context, brut json.RawMessage) []byte {
	if c.cfg.CheminRelais == "" {
		return sortieRefus(http.StatusNotImplemented, "pilotage HTTP non pris en charge par cet agent")
	}
	if c.cfg.Ancre != nil && c.etatAncre() != AncreOK {
		return sortieRefus(http.StatusForbidden, "ancre non vérifiée")
	}
	gros := len(brut) > seuilGros
	if gros {
		select {
		case c.gros <- struct{}{}:
			defer func() { <-c.gros }()
		default:
			return sortieRefus(http.StatusServiceUnavailable, "agent occupé : un gros échange est en cours")
		}
	}
	var d relais.Demande
	dec := json.NewDecoder(bytes.NewReader(brut))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil || dec.More() {
		return sortieRefus(http.StatusBadRequest, "demande HTTP illisible")
	}
	brut = nil // la forme JSON n'est plus retenue
	acteur, maitre, err := relais.Normaliser(d.Acteur, d.Maitre)
	if err != nil {
		return sortieRefus(http.StatusBadRequest, err.Error())
	}
	if d.Portee != PorteeLecture && d.Portee != PorteeAdmin {
		return sortieRefus(http.StatusBadRequest, "portee invalide")
	}
	if longueurDecodee(d.CorpsB64) > relais.CorpsMax {
		return sortieRefus(http.StatusRequestEntityTooLarge, "corps trop long (4 Mio au plus)")
	}
	demandee := d.Portee
	portee := PorteeLecture
	if demandee == PorteeAdmin && c.cfg.PorteeAdmin != nil && c.cfg.PorteeAdmin(ctx) {
		portee = PorteeAdmin
	}
	d.Acteur, d.Maitre, d.Portee = acteur, maitre, portee
	sortie := c.appelerRelais(ctx, &d, gros)
	chemin, _, _ := strings.Cut(d.Chemin, "?")
	log.Printf("http : %s %s acteur=%s maitre=%s portee=%s/%s statut=%d", imprimableASCII(d.Methode, 8),
		imprimableASCII(chemin, 200), acteur, maitre, demandee, portee, statutDe(sortie))
	return sortie
}

func statutDe(sortie []byte) int {
	var s struct {
		Statut int `json:"statut"`
	}
	_ = json.Unmarshal(sortie, &s)
	return s.Statut
}

func imprimableASCII(s string, max int) string {
	b := make([]byte, 0, min(len(s), max))
	for i := 0; i < len(s) && len(b) < max; i++ {
		if ch := s[i]; ch > 0x20 && ch < 0x7f {
			b = append(b, ch)
		} else {
			b = append(b, '?')
		}
	}
	return string(b)
}

// ecrireDemande : la demande en JSON, le corps base64 écrit sans seconde copie (les caractères base64 ne
// demandent aucun échappement JSON).
func ecrireDemande(w io.Writer, d *relais.Demande) error {
	corps := d.CorpsB64
	d.CorpsB64 = ""
	b, err := json.Marshal(d)
	d.CorpsB64 = corps
	if err != nil {
		return err
	}
	// `"corps_b64":""` ne peut apparaître qu'à sa place : dans une chaîne JSON, `"` est toujours échappé.
	cle := []byte(`"corps_b64":"`)
	i := bytes.Index(b, cle)
	if i < 0 {
		return errors.New("champ corps_b64 absent")
	}
	i += len(cle)
	bw := bufio.NewWriterSize(w, 64<<10)
	bw.Write(b[:i])
	bw.WriteString(corps)
	bw.Write(b[i:])
	bw.WriteByte('\n')
	return bw.Flush()
}

// appelerRelais : une connexion par demande ; la sortie (un objet JSON) est rendue telle quelle, sinon un refus.
func (c *Client) appelerRelais(ctx context.Context, d *relais.Demande, gros bool) []byte {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.DelaiHTTP)
	defer cancel()
	var dl net.Dialer
	conn, err := dl.DialContext(ctx, "unix", c.cfg.CheminRelais)
	if err != nil {
		if ctx.Err() != nil {
			return sortieRefus(http.StatusGatewayTimeout, "délai du relais dépassé")
		}
		return sortieRefus(http.StatusBadGateway, "relais local injoignable")
	}
	defer conn.Close()
	fin, _ := ctx.Deadline()
	_ = conn.SetDeadline(fin)
	arret := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer arret()
	if err := ecrireDemande(conn, d); err != nil {
		return refusReseau(ctx, err, "relais local : demande non transmise")
	}
	d.CorpsB64 = "" // transmis : libéré pendant l'attente
	// Lecture bornée : 256 Kio d'abord ; au-delà, la place « gros » est exigée (un seul gros échange à la fois).
	l := bufio.NewReaderSize(conn, 64<<10)
	var tampon bytes.Buffer
	n, err := tampon.ReadFrom(io.LimitReader(l, seuilGros))
	if err == nil && n == seuilGros {
		if !gros {
			select {
			case c.gros <- struct{}{}:
				defer func() { <-c.gros }()
			default:
				return sortieRefus(http.StatusServiceUnavailable, "agent occupé : un gros échange est en cours")
			}
		}
		tampon.Grow(64 << 10)
		_, err = tampon.ReadFrom(io.LimitReader(l, tailleHTTPMax-seuilGros+1))
	}
	if err != nil {
		return refusReseau(ctx, err, "relais local : réponse illisible")
	}
	b := bytes.TrimSpace(tampon.Bytes())
	if tampon.Len() > tailleHTTPMax {
		return sortieRefus(http.StatusBadGateway, "relais local : réponse trop longue")
	}
	if len(b) == 0 {
		return sortieRefus(http.StatusBadGateway, "relais local : aucune réponse (accès refusé ?)")
	}
	// Forme vérifiée sans recopier le corps (champ ignoré par le décodeur).
	if s := statutDe(b); !json.Valid(b) || s < 100 || s > 599 {
		return sortieRefus(http.StatusBadGateway, "relais local : réponse mal formée")
	}
	return b
}

func refusReseau(ctx context.Context, err error, motif string) []byte {
	var ne net.Error
	if ctx.Err() != nil || (errors.As(err, &ne) && ne.Timeout()) {
		return sortieRefus(http.StatusGatewayTimeout, "délai du relais dépassé")
	}
	return sortieRefus(http.StatusBadGateway, motif)
}
