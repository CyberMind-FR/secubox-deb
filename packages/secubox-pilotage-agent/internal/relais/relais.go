// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package relais

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// CorpsMax : 4 Mio dans les deux sens (413 au-delà). ÉCART AU BRIEF (8 Mio), R-L5-19 : deux appels
	// simultanés de taille maximale doivent tenir sous MemoryMax=64M (GOMEMLIMIT=48MiB) ; mesuré par
	// TestRelaisMemoireBornee.
	CorpsMax = 4 << 20
	// DelaiDefaut : délai d'un appel au module.
	DelaiDefaut = 30 * time.Second
	// tailleDemandeMax : le JSON d'une demande (corps en base64 + champs).
	tailleDemandeMax = (CorpsMax+2)/3*4 + 64<<10
	// appelsSimultanes : deux appels à la fois au plus (mémoire d'une box légère).
	appelsSimultanes = 2
	// connexionsMax : connexions acceptées à la fois (en cours ou en attente) ; au-delà, elles restent dans la
	// file du noyau, Accept n'est plus appelé.
	connexionsMax = 8
	// DelaiLectureDefaut : une demande doit arriver en entier dans ce délai (une connexion oisive ne garde pas
	// sa place).
	DelaiLectureDefaut = 10 * time.Second
	longueurCheminMax  = 4096
	nombreEntetesMax   = 64
	longueurEnteteMax  = 8192
	// EnteteRelais : posé par le relais seulement ; nginx, HAProxy et l'agrégateur l'effacent.
	EnteteRelais = "X-SecuBox-Pilotage-Relais"
	valeurRelais = "sbx-pilotage-relais"
	prefixeAPI   = "/api/v1/"
)

// Demande : ce que l'agent remet au relais, un objet JSON par connexion.
type Demande struct {
	Methode     string            `json:"methode"`
	Chemin      string            `json:"chemin"`
	Entetes     map[string]string `json:"entetes"`
	CorpsB64    string            `json:"corps_b64"`
	Acteur      string            `json:"acteur"`
	Maitre      string            `json:"maitre"`
	Portee      string            `json:"portee"`
	VersionPage string            `json:"version_page"`
}

// Reponse : ce que le relais rend à l'agent, puis ferme la connexion. Écrite par ecrireReponse, le corps
// encodé en base64 AU FIL de l'écriture (jamais une seconde copie en mémoire).
type Reponse struct {
	Statut   int               `json:"statut"`
	Entetes  map[string]string `json:"entetes"`
	CorpsB64 string            `json:"corps_b64"`

	corps []byte
}

// ecrireReponse : {"statut":…,"entetes":{…},"corps_b64":"…"} puis saut de ligne.
func ecrireReponse(w io.Writer, rep Reponse) error {
	bw := bufio.NewWriterSize(w, 64<<10)
	entetes, err := json.Marshal(rep.Entetes)
	if err != nil {
		return err
	}
	fmt.Fprintf(bw, `{"statut":%d,"entetes":%s,"corps_b64":"`, rep.Statut, entetes)
	enc := base64.NewEncoder(base64.StdEncoding, bw)
	if _, err := enc.Write(rep.corps); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	bw.WriteString("\"}\n")
	return bw.Flush()
}

// Relais : réglages du service (voir cmd/sbx-pilotage-relais pour les valeurs de production).
type Relais struct {
	Cle            ed25519.PrivateKey
	UIDAgent       uint32 // seul compte admis (SO_PEERCRED) : secubox-pilotage-agent
	DossierSockets string // /run/secubox
	// DossierMainsLiees : /etc/secubox-pilotage (root:root 0755, postinst) ; le ctl root y projette
	// `mains-liees`. JAMAIS /etc/secubox/pilotage (compte partagé secubox, R-L5-19).
	DossierMainsLiees string
	UIDRoot           uint32 // propriétaire exigé du dossier et du drapeau (0 en production)
	DelaiLecture      time.Duration
	CheminAudit       string // /var/log/secubox/audit.log (ajout seul, jamais créé ici)
	NomBox            func() string
	Maintenant        func() time.Time
	Delai             time.Duration
	Journal           *log.Logger

	once       sync.Once
	sem        chan struct{}
	connexions chan struct{}
}

// methodesPermises : ni OPTIONS, ni TRACE, ni CONNECT ; la casse est exacte.
var methodesPermises = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// AliasSockets : socket /run/secubox/<clé>.sock dont le code est installé sous un AUTRE dossier
// /usr/lib/secubox/<valeur>/ — `module_courant` (secubox_core.auth) y voit <valeur>, la cible du
// jeton doit l'être aussi. Relevé sur le dépôt (#3126 L5 T2) : secubox-profiles sert `waker`
// (api.waker:app, WorkingDirectory=/usr/lib/secubox/profiles).
var AliasSockets = map[string]string{"waker": "profiles"}

// modulesExclus : MODULES_EXCLUS_PILOTAGE de secubox_core.auth (et tout module `pilotage*`). Le
// vérificateur les refuse déjà ; le relais ne les appelle même pas (défense en profondeur).
var modulesExclus = map[string]bool{
	"auth": true, "vault": true, "portal": true, "assist": true, "premier-pas": true, "users": true,
	"aggregator": true, "pilotage": true, "pilotage-agent": true, "pilotage-canal": true, "pilotage-relais": true,
}

func moduleExclu(nom string) bool { return modulesExclus[nom] || strings.HasPrefix(nom, "pilotage") }

// entetesReponse : en-têtes du module rendus à la page ; jamais Set-Cookie.
var entetesReponse = []string{"Content-Type", "Content-Disposition", "Content-Language", "Cache-Control", "ETag",
	"Last-Modified", "Expires", "Location", "Retry-After", "Vary"}

// refus : une demande refusée par le relais, avec son statut et son motif (audité, sans jeton ni corps).
type refus struct {
	statut int
	motif  string
}

func (r *refus) Error() string { return r.motif }

func refuser(statut int, motif string) *refus { return &refus{statut: statut, motif: motif} }

func (r *Relais) init() {
	r.once.Do(func() {
		r.sem = make(chan struct{}, appelsSimultanes)
		r.connexions = make(chan struct{}, connexionsMax)
		if r.DelaiLecture <= 0 {
			r.DelaiLecture = DelaiLectureDefaut
		}
		if r.Journal == nil {
			r.Journal = log.New(os.Stderr, "", 0)
		}
		if r.Maintenant == nil {
			r.Maintenant = time.Now
		}
		if r.NomBox == nil {
			r.NomBox = NomBoxLocale
		}
		if r.Delai <= 0 {
			r.Delai = DelaiDefaut
		}
	})
}

// Servir accepte les connexions jusqu'à l'annulation de ctx.
func (r *Relais) Servir(ctx context.Context, ln net.Listener) error {
	r.init()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		// Borne des connexions : la place est prise AVANT Accept, rendue à la fermeture.
		select {
		case r.connexions <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		c, err := ln.Accept()
		if err != nil {
			<-r.connexions
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go func() {
			defer func() { <-r.connexions }()
			r.traiter(c)
		}()
	}
}

// uidPair : le compte du processus à l'autre bout (SO_PEERCRED, fixé par le noyau à la connexion).
func uidPair(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("pas une socket Unix")
	}
	brut, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var errCred error
	if err := brut.Control(func(fd uintptr) {
		cred, errCred = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if errCred != nil {
		return 0, errCred
	}
	return cred.Uid, nil
}

func (r *Relais) traiter(c net.Conn) {
	defer c.Close()
	r.init()
	uid, err := uidPair(c)
	if err != nil || uid != r.UIDAgent {
		// Fermeture sans un octet de réponse.
		detail := "uid=?"
		if err == nil {
			detail = fmt.Sprintf("uid=%d", uid)
		}
		r.auditer(nil, &refus{motif: "compte du pair refuse"}, detail)
		return
	}
	r.sem <- struct{}{}
	defer func() { <-r.sem }()
	_ = c.SetReadDeadline(time.Now().Add(r.DelaiLecture))
	_ = c.SetWriteDeadline(time.Now().Add(r.DelaiLecture + r.Delai + 30*time.Second))
	rep := r.executer(c)
	_ = ecrireReponse(c, rep)
}

// lecteurCompte : compte les octets lus, pour distinguer « trop long » (413) de « mal formé » (400).
type lecteurCompte struct {
	r io.Reader
	n int64
}

func (l *lecteurCompte) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.n += int64(n)
	return n, err
}

func reponseRefus(rf *refus) Reponse {
	corps, _ := json.Marshal(map[string]string{"detail": rf.motif})
	return Reponse{Statut: rf.statut, Entetes: map[string]string{"Content-Type": "application/json"}, corps: corps}
}

func (r *Relais) executer(c io.Reader) Reponse {
	d, rf := lireDemande(c)
	if rf == nil {
		var rep Reponse
		rep, rf = r.relayer(d)
		if rf == nil {
			return rep
		}
	}
	r.auditer(d, rf, "")
	return reponseRefus(rf)
}

func lireDemande(c io.Reader) (*Demande, *refus) {
	lc := &lecteurCompte{r: io.LimitReader(c, tailleDemandeMax+1)}
	dec := json.NewDecoder(lc)
	dec.DisallowUnknownFields()
	var d Demande
	if err := dec.Decode(&d); err != nil {
		if lc.n > tailleDemandeMax {
			return nil, refuser(http.StatusRequestEntityTooLarge, "demande trop longue")
		}
		return nil, refuser(http.StatusBadRequest, "demande illisible")
	}
	// Un seul objet par connexion : rien d'autre que des blancs derrière (ce qui est déjà lu).
	reste, _ := io.ReadAll(dec.Buffered())
	if len(bytes.TrimSpace(reste)) != 0 {
		return &d, refuser(http.StatusBadRequest, "donnees apres la demande")
	}
	return &d, nil
}

// analyserChemin : `/api/v1/<module>/<reste>[?requête]` → module, chemin transmis au module (préfixe
// retiré, comme `proxy_pass …:/` de nginx et l'agrégateur) et requête brute. Refusé : tout ce qui
// n'est pas ASCII imprimable, `#`, `\`, segment vide, `.`/`..` (même encodé), `%2F`/`%5C`, échappement
// invalide.
func analyserChemin(chemin string) (module, reste, requete string, rf *refus) {
	invalide := refuser(http.StatusBadRequest, "chemin refuse")
	if len(chemin) > longueurCheminMax || !strings.HasPrefix(chemin, prefixeAPI) {
		return "", "", "", invalide
	}
	for i := 0; i < len(chemin); i++ {
		if c := chemin[i]; c <= 0x20 || c >= 0x7f || c == '#' || c == '\\' {
			return "", "", "", invalide
		}
	}
	p, requete, _ := strings.Cut(chemin, "?")
	if requete != "" {
		valeurs, err := url.ParseQuery(requete)
		if err != nil {
			return "", "", "", invalide
		}
		// %00 et tout caractère de contrôle, même encodés, refusés dans la requête aussi.
		for k, vs := range valeurs {
			for _, v := range append(vs, k) {
				if strings.IndexFunc(v, func(c rune) bool { return c < 0x20 || c == 0x7f }) >= 0 {
					return "", "", "", invalide
				}
			}
		}
	}
	module, reste, ok := strings.Cut(strings.TrimPrefix(p, prefixeAPI), "/")
	if !ok || !reModule.MatchString(module) {
		return "", "", "", invalide
	}
	segments := strings.Split(reste, "/")
	for i, s := range segments {
		if s == "" && i != len(segments)-1 {
			return "", "", "", invalide
		}
		dec, err := url.PathUnescape(s)
		if err != nil || dec == "." || dec == ".." || strings.ContainsAny(dec, "/\\") {
			return "", "", "", invalide
		}
		for j := 0; j < len(dec); j++ {
			if dec[j] < 0x20 || dec[j] == 0x7f {
				return "", "", "", invalide
			}
		}
	}
	return module, "/" + reste, requete, nil
}

func (r *Relais) mainsLiees() bool { return MainsLieesDans(r.DossierMainsLiees, r.UIDRoot, r.Journal) }

// socketModule : le chemin de la socket du module si c'en est une (Lstat : jamais un lien).
func (r *Relais) socketModule(module string) (string, bool) {
	s := filepath.Join(r.DossierSockets, module+".sock")
	st, err := os.Lstat(s)
	return s, err == nil && st.Mode()&fs.ModeSocket != 0
}

func entetesTransmis(recus map[string]string) (http.Header, *refus) {
	h := http.Header{}
	if len(recus) > nombreEntetesMax {
		return nil, refuser(http.StatusBadRequest, "trop d en-tetes")
	}
	for k, v := range recus {
		if len(k)+len(v) > longueurEnteteMax || strings.ContainsAny(k+v, "\r\n\x00") {
			return nil, refuser(http.StatusBadRequest, "en-tete invalide")
		}
		cle := strings.ToLower(k)
		// Seuls Content-Type, Accept, If-* passent ; Authorization, Cookie, X-SecuBox-*, Host… sont effacés.
		if cle == "content-type" || cle == "accept" || strings.HasPrefix(cle, "if-") {
			h.Set(k, v)
		}
	}
	return h, nil
}

func (r *Relais) relayer(d *Demande) (Reponse, *refus) {
	if !methodesPermises[d.Methode] {
		return Reponse{}, refuser(http.StatusBadRequest, "methode refusee")
	}
	module, reste, requete, rf := analyserChemin(d.Chemin)
	if rf != nil {
		return Reponse{}, rf
	}
	acteur, maitre, err := Normaliser(d.Acteur, d.Maitre)
	if err != nil {
		return Reponse{}, refuser(http.StatusBadRequest, err.Error())
	}
	if d.Portee != "lecture" && d.Portee != "admin" {
		return Reponse{}, refuser(http.StatusBadRequest, "portee invalide")
	}
	if base64.StdEncoding.DecodedLen(len(d.CorpsB64)) > CorpsMax+2 {
		return Reponse{}, refuser(http.StatusRequestEntityTooLarge, "corps trop long")
	}
	corps, err := base64.StdEncoding.DecodeString(d.CorpsB64)
	d.CorpsB64 = "" // la forme base64 n'est plus retenue pendant l'appel
	if err != nil {
		return Reponse{}, refuser(http.StatusBadRequest, "corps_b64 invalide")
	}
	if len(corps) > 0 && (d.Methode == "GET" || d.Methode == "HEAD") {
		return Reponse{}, refuser(http.StatusBadRequest, "corps refuse pour une lecture")
	}
	if len(corps) > CorpsMax {
		return Reponse{}, refuser(http.StatusRequestEntityTooLarge, "corps trop long")
	}
	entetes, rf := entetesTransmis(d.Entetes)
	if rf != nil {
		return Reponse{}, rf
	}
	cible := module
	if a, ok := AliasSockets[module]; ok {
		cible = a
	}
	if moduleExclu(module) || moduleExclu(cible) {
		return Reponse{}, refuser(http.StatusForbidden, "module exclu du pilotage")
	}
	portee := d.Portee
	if r.mainsLiees() {
		portee = "lecture"
	}
	if portee == "lecture" && d.Methode != "GET" && d.Methode != "HEAD" {
		motif := "portee lecture"
		if d.Portee == "admin" {
			motif = "mains liees"
		}
		return Reponse{}, refuser(http.StatusLocked, motif)
	}
	sock, ok := r.socketModule(module)
	if !ok {
		return Reponse{}, refuser(http.StatusNotFound, "module sans socket")
	}
	box := r.NomBox()
	if box == "" {
		return Reponse{}, refuser(http.StatusServiceUnavailable, "nom de box illisible")
	}
	jeton, err := Frapper(r.Cle, box, cible, acteur, maitre, portee, r.Maintenant())
	if err != nil {
		return Reponse{}, refuser(http.StatusInternalServerError, "jeton non frappe")
	}
	rep, rf := r.appeler(sock, d.Methode, reste, requete, entetes, corps, jeton)
	if rf == nil {
		r.Journal.Printf("relais : %s %s%s/… module=%s acteur=%s maitre=%s portee=%s statut=%d",
			d.Methode, prefixeAPI, module, cible, acteur, maitre, portee, rep.Statut)
	}
	return rep, rf
}

func (r *Relais) appeler(sock, methode, reste, requete string, entetes http.Header, corps []byte,
	jeton string) (Reponse, *refus) {
	client := &http.Client{
		Timeout: r.Delai,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dl net.Dialer
				return dl.DialContext(ctx, "unix", sock)
			},
			DisableKeepAlives:      true,
			DisableCompression:     true,
			MaxResponseHeaderBytes: 64 << 10,
			Proxy:                  nil,
		},
		// Une redirection est rendue à la page, jamais suivie par le relais.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u := "http://localhost" + reste
	if requete != "" {
		u += "?" + requete
	}
	var lecteur io.Reader
	if len(corps) > 0 {
		lecteur = bytes.NewReader(corps)
	}
	req, err := http.NewRequest(methode, u, lecteur)
	if err != nil {
		return Reponse{}, refuser(http.StatusBadRequest, "chemin refuse")
	}
	req.Header = entetes
	req.Header.Set("Authorization", "Bearer "+jeton)
	req.Header.Set(EnteteRelais, valeurRelais)
	req.Header.Set("User-Agent", valeurRelais)
	resp, err := client.Do(req)
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return Reponse{}, refuser(http.StatusGatewayTimeout, "delai du module depasse")
		}
		return Reponse{}, refuser(http.StatusBadGateway, "module injoignable")
	}
	defer resp.Body.Close()
	b, err := lireCorps(resp.Body, resp.ContentLength)
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return Reponse{}, refuser(http.StatusGatewayTimeout, "delai du module depasse")
		}
		return Reponse{}, refuser(http.StatusBadGateway, "reponse du module illisible")
	}
	if len(b) > CorpsMax {
		return Reponse{}, refuser(http.StatusRequestEntityTooLarge, "reponse du module trop longue")
	}
	out := map[string]string{}
	for _, k := range entetesReponse {
		if v := resp.Header.Values(k); len(v) > 0 {
			out[k] = strings.Join(v, ", ")
		}
	}
	return Reponse{Statut: resp.StatusCode, Entetes: out, corps: b}, nil
}

// lireCorps : CorpsMax+1 octets au plus (l'appelant voit le dépassement). Tampon taillé sur Content-Length
// quand il est connu (+1 pour constater la fin sans croître) ; sinon (chunked, -1 ; R-L5-20 M2) il double à
// partir de 64 Kio mais PLAFONNÉ à CorpsMax+1 : jamais les 8 Mio d'un bytes.Buffer pour 4 Mio lus.
func lireCorps(r io.Reader, connu int64) ([]byte, error) {
	r = io.LimitReader(r, CorpsMax+1)
	capacite := 64 << 10
	if connu >= 0 && connu <= CorpsMax {
		capacite = int(connu) + 1
	}
	b := make([]byte, 0, capacite)
	for {
		if len(b) == cap(b) {
			if cap(b) >= CorpsMax+1 {
				return b, nil
			}
			nb := make([]byte, len(b), min(2*cap(b), CorpsMax+1))
			copy(nb, b)
			b = nb
		}
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err == io.EOF {
			return b, nil
		}
		if err != nil {
			return b, err
		}
	}
}

// ascii : texte venu du client, rendu sûr pour une ligne de journal (ASCII imprimable, borné).
func ascii(s string, max int) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < max; i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b = append(b, c)
		} else {
			b = append(b, '?')
		}
	}
	return string(b)
}

// auditer : chaque REFUS, une ligne JSON dans audit.log (ajout seul, O_NOFOLLOW, jamais créé : le
// fichier appartient au compte secubox) ; si le compte du relais ne peut pas y écrire, la même ligne
// part au journal du service. Jamais le jeton, le corps, la requête (`?…`) ni les en-têtes.
func (r *Relais) auditer(d *Demande, rf *refus, detail string) {
	r.init()
	e := map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339), "module": "pilotage-relais", "evenement": "pilotage_relais",
		"verdict": "refuse", "motif": rf.motif,
	}
	if rf.statut != 0 {
		e["statut"] = rf.statut
	}
	if detail != "" {
		e["detail"] = ascii(detail, 64)
	}
	if d != nil {
		p, _, _ := strings.Cut(d.Chemin, "?")
		e["methode"] = ascii(d.Methode, 16)
		e["chemin"] = ascii(p, 512)
		e["acteur"] = ascii(d.Acteur, 64)
		e["maitre"] = ascii(d.Maitre, 63)
		e["portee"] = ascii(d.Portee, 16)
	}
	ligne, err := json.Marshal(e)
	if err != nil {
		r.Journal.Printf("audit impossible : %v", err)
		return
	}
	if r.CheminAudit != "" {
		fd, err := syscall.Open(r.CheminAudit, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err == nil {
			f := os.NewFile(uintptr(fd), r.CheminAudit)
			_, err = f.Write(append(ligne, '\n'))
			if errClose := f.Close(); err == nil {
				err = errClose
			}
			if err == nil {
				return
			}
		}
		r.Journal.Printf("audit.log non ecrit (%v) : %s", err, ligne)
		return
	}
	r.Journal.Printf("audit : %s", ligne)
}
