// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — leurres de messagerie (#3924)
//
// LE CONTENEUR DE COURRIER EST ARRÊTÉ L'ESSENTIEL DU TEMPS. Ses ports ne
// répondent alors à personne, et les essais d'authentification frauduleux ne
// sont plus vus. Pendant son arrêt — et SEULEMENT pendant — authwatch répond à
// sa place sur 25, 465, 587, 993 et 995 (voir messagerie_bascule.go) ; 110 et
// 143, que la box ne sert pas, sont des leurres permanents.
//
// CE N'EST PAS UN LEURRE COMME LES AUTRES. Sur 3389 personne n'a rien à faire ;
// sur 25, de vrais serveurs de courrier se présentent, et sur 993 le téléphone
// du propriétaire. D'où cinq règles :
//
//   - RIEN N'EST ACCEPTÉ, RIEN N'EST PERDU : toute réponse d'échec est
//     TEMPORAIRE (4xx, [UNAVAILABLE], [SYS/TEMP]) ; jamais un 5xx, jamais un
//     354. L'expéditeur garde son message et le représente.
//   - UNE VISITE N'EST PAS UN SIGNAL. Seule une authentification tentée en est
//     un, et elle ne bannit que si la liste des comptes est chargée et que le
//     compte N'EXISTE PAS : le leurre refuse même le bon mot de passe, son refus
//     ne prouve rien contre un compte réel (ni compteur, ni campagne).
//   - ON NE DEMANDE PAS DE MOT DE PASSE : l'authentification n'est pas annoncée
//     (STARTTLS l'est, et refusé) ; un client bien réglé s'arrête. Dès que le
//     compte est connu, on refuse sans solliciter le secret (PLAIN en deux temps
//     excepté : compte et secret y sont indissociables).
//   - LE MOT DE PASSE N'EXISTE PAS ICI : lu dans un tampon fixe, effacé aussitôt,
//     jamais converti en chaîne, ni journalisé, ni haché, ni rendu. C'est peut-
//     être celui d'un vrai compte — l'exact contraire d'identifiants.go.
//   - LE COMPTE ne s'affiche (masqué) que s'il EXISTE : un nom inconnu peut être
//     un mot de passe tapé dans le mauvais champ. Ni haché, ni envoyé à actord.
//
// 465, 993 et 995 sont chiffrés d'emblée : pas de certificat ici, donc pas de
// poignée de main. On ferme ; l'adresse et la cadence sont comptées, rien
// d'autre, et JAMAIS de ban.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Bornes : ces ports sont exposés à Internet.
const (
	mailLigneMax  = 1024 // octets par ligne (tampon fixe : rien n'est alloué sur annonce)
	mailOctetsMax = 8192 // octets lus par connexion
	mailLitteral  = 512  // littéral IMAP accepté
	mailCommandes = 32   // commandes par connexion
	mailEssaisMax = 3    // authentifications par connexion
	mailCompteMax = 254  // au-delà, ce n'est pas une adresse
	mailParLeurre = 64   // connexions simultanées par leurre
	mailParIP     = 4    // connexions simultanées par adresse, tous leurres confondus
)

const (
	mailEcheanceLigne  = 10 * time.Second // pour une ligne ENTIÈRE
	mailEcheanceTotale = 30 * time.Second // pour la connexion
)

// LeurreMail — un port de messagerie tenu à la place du conteneur.
type LeurreMail struct {
	Nom       string // nom du réglage de la page Modes
	Service   string // service porté au journal ; vide = jamais de signal
	Compte    bool   // connexions comptées par adresse (TLS)
	Categorie string // catégorie du signal : auth_smtp*/auth_imap* (famille « messagerie »)
	Port      int    // port public
	Local     int    // port local de redirection ; 0 = écoute directe sur Port, permanente
	Saturee   string // réponse temporaire quand le plafond est atteint
	dialogue  func(*sessionMail)
}

// LeurresMailRelais remplacent le conteneur pendant son arrêt (redirection nft).
var LeurresMailRelais = []LeurreMail{
	{Nom: "smtp", Port: 25, Local: 18025, Saturee: smtpSature, dialogue: dialogueSMTP25},
	{Nom: "smtps", Compte: true, Port: 465, Local: 18465, dialogue: dialogueTLS},
	{Nom: "submission", Service: "smtp", Categorie: "auth_smtp:leurre", Port: 587, Local: 18587, Saturee: smtpSature, dialogue: dialogueSMTP587},
	{Nom: "imaps", Compte: true, Port: 993, Local: 18993, dialogue: dialogueTLS},
	{Nom: "pop3s", Compte: true, Port: 995, Local: 18995, dialogue: dialogueTLS},
}

// LeurresMailPermanents : ports en clair que la box ne sert pas.
var LeurresMailPermanents = []LeurreMail{
	{Nom: "pop3", Service: "pop3", Categorie: "auth_imap:leurre_pop3", Port: 110, Saturee: pop3Sature, dialogue: dialoguePOP3},
	{Nom: "imap", Service: "imap", Categorie: "auth_imap:leurre", Port: 143, Saturee: imapSature, dialogue: dialogueIMAP},
}

// portsMessagerie : refusés à `--leurres`, dont le régime (ban au premier
// contact, première trame gardée) serait faux ET indiscret sur ces ports.
var portsMessagerie = map[int]bool{25: true, 110: true, 143: true, 465: true, 587: true, 993: true, 995: true}

// servicesMessagerie : services dont identifiants.go ne capture JAMAIS rien.
var servicesMessagerie = map[string]bool{"smtp": true, "smtps": true, "submission": true,
	"imap": true, "imaps": true, "pop3": true, "pop3s": true}

// ── lecture bornée, tampon effacé ───────────────────────────────────────────

var errMailBorne = errors.New("borne de lecture atteinte")

// lecteurMail lit des lignes dans UN tampon fixe qu'il efface lui-même : une
// ligne rendue n'est valable que jusqu'à la lecture suivante. (bufio garderait
// des copies d'un mot de passe hors de portée.)
type lecteurMail struct {
	conn   net.Conn
	tampon [mailLigneMax]byte
	d, f   int // [d:f] : reçu, pas encore rendu
	lus    int
	delai  time.Duration // par ligne
	fin    time.Time     // de la connexion
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// compacte efface ce qui a été rendu et ramène le reste en tête.
func (l *lecteurMail) compacte() {
	n := copy(l.tampon[:], l.tampon[l.d:l.f])
	zero(l.tampon[n:])
	l.d, l.f = 0, n
}

func (l *lecteurMail) echeance() {
	e := time.Now().Add(l.delai)
	if l.fin.Before(e) {
		e = l.fin
	}
	_ = l.conn.SetDeadline(e)
}

// recoit lit une fois du réseau, dans la place restante et le budget.
func (l *lecteurMail) recoit() error {
	place := l.tampon[l.f:]
	if reste := mailOctetsMax - l.lus; len(place) > reste {
		place = place[:reste]
	}
	if len(place) == 0 {
		return errMailBorne
	}
	n, err := l.conn.Read(place)
	l.f += n
	l.lus += n
	if n > 0 {
		return nil
	}
	if err == nil {
		err = io.ErrNoProgress
	}
	return err
}

// ligne rend la ligne suivante sans sa fin. L'échéance vaut pour la ligne
// ENTIÈRE : un octet toutes les 9 s ne la repousse pas.
func (l *lecteurMail) ligne() ([]byte, error) {
	l.compacte()
	l.echeance()
	for {
		if i := bytes.IndexByte(l.tampon[l.d:l.f], '\n'); i >= 0 {
			lig := l.tampon[l.d : l.d+i]
			l.d += i + 1
			return bytes.TrimSuffix(lig, []byte{'\r'}), nil
		}
		if err := l.recoit(); err != nil {
			return nil, err
		}
	}
}

// octets rend exactement n octets (littéral IMAP).
func (l *lecteurMail) octets(n int) ([]byte, error) {
	if n < 0 || n > mailLitteral {
		return nil, errMailBorne
	}
	l.compacte()
	l.echeance()
	for l.f-l.d < n {
		if err := l.recoit(); err != nil {
			return nil, err
		}
	}
	b := l.tampon[l.d : l.d+n]
	l.d += n
	return b, nil
}

func (l *lecteurMail) efface() {
	zero(l.tampon[:])
	l.d, l.f = 0, 0
}

// ── session ─────────────────────────────────────────────────────────────────

// sessionMail : une connexion. Elle ne retient que les COMPTES visés.
type sessionMail struct {
	conn    net.Conn
	lec     lecteurMail
	essais  int
	comptes []string
}

func nouvelleSession(c net.Conn, ligne, totale time.Duration) *sessionMail {
	s := &sessionMail{conn: c}
	s.lec.conn, s.lec.delai = c, ligne
	s.lec.fin = time.Now().Add(totale)
	return s
}

// ecrit n'envoie que des constantes compilées (et l'étiquette IMAP, revalidée).
func (s *sessionMail) ecrit(t string) error {
	s.lec.echeance()
	_, err := io.WriteString(s.conn, t)
	return err
}

// note compte une authentification tentée et retient le compte visé.
func (s *sessionMail) note(compte string) {
	s.essais++
	if compte == "" {
		return
	}
	for _, c := range s.comptes {
		if c == compte {
			return
		}
	}
	if len(s.comptes) < mailEssaisMax {
		s.comptes = append(s.comptes, compte)
	}
}

// compteDe copie un compte : UTF-8 imprimable, sans blanc, 254 octets au plus.
// Tout le reste rend "" — un nom tronqué ou réécrit passerait pour un compte
// INEXISTANT et ferait bannir un utilisateur réel.
func compteDe(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || len(b) > mailCompteMax || !utf8.Valid(b) {
		return ""
	}
	for _, r := range string(b) {
		if !unicode.IsPrint(r) || r == ' ' {
			return ""
		}
	}
	return strings.ToLower(string(b))
}

// decode64 décode dans un tampon neuf ; l'appelant l'efface.
func decode64(src []byte) []byte {
	src = bytes.TrimSpace(src)
	if len(src) > mailLigneMax {
		return nil
	}
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(dst, src)
	if err != nil {
		zero(dst)
		return nil
	}
	return dst[:n]
}

// comptePlain lit le compte d'une réponse SASL PLAIN (authzid NUL authcid NUL
// secret) et efface le reste, source comprise. Toute forme douteuse — champs en
// désordre, secret vide (« compte NUL secret NUL »), authzid différent — rend "" :
// le champ du milieu pourrait être le secret.
func comptePlain(src []byte) string {
	d := decode64(src)
	zero(src)
	defer zero(d)
	p := bytes.Split(d, []byte{0})
	if len(p) != 3 || len(p[2]) == 0 || (len(p[0]) > 0 && !bytes.Equal(p[0], p[1])) {
		return ""
	}
	return compteDe(p[1])
}

// sasl joue PLAIN ou LOGIN jusqu'au COMPTE ; LOGIN n'invite jamais à livrer le
// secret. Une annulation « * » n'est pas un essai ; un autre mécanisme n'est pas
// joué : c'est un essai sans compte.
func (s *sessionMail) sasl(mecanisme, initiale []byte, invite func(string) error) (err error) {
	var b64 string
	switch string(mecanisme) {
	case "PLAIN":
	case "LOGIN":
		b64 = "VXNlcm5hbWU6"
	default:
		s.note("")
		return nil
	}
	plain := b64 == ""
	if len(initiale) == 1 && initiale[0] == '=' {
		initiale = initiale[:0] // réponse initiale vide (RFC 4954)
	}
	if len(initiale) == 0 {
		if err = invite(b64); err != nil {
			return err
		}
		if initiale, err = s.lec.ligne(); err != nil {
			return err
		}
		if len(initiale) == 1 && initiale[0] == '*' {
			return nil
		}
	}
	if plain {
		s.note(comptePlain(initiale))
		return nil
	}
	d := decode64(initiale)
	s.note(compteDe(d))
	zero(d)
	return nil
}

// mot sépare le premier mot du reste, mis en majuscules SUR PLACE : rien de ce que
// dit le client n'est copié pour reconnaître une commande (ce peut être un mot
// de passe envoyé au mauvais moment).
func mot(b []byte) (verbe, reste []byte) {
	b = bytes.TrimLeft(b, " \t")
	i := bytes.IndexAny(b, " \t")
	if i < 0 {
		i = len(b)
	}
	verbe, reste = b[:i], bytes.TrimSpace(b[i:])
	for k, c := range verbe {
		if c >= 'a' && c <= 'z' {
			verbe[k] = c - 'a' + 'A'
		}
	}
	return verbe, reste
}

// ── écoute ──────────────────────────────────────────────────────────────────

// ServeurMail tient les leurres de messagerie : plafonds, signaux, décompte TLS.
type ServeurMail struct {
	signaux chan<- Signal
	lb      *ListeBlanche
	tls     *DecompteTLS
	ligne   time.Duration
	totale  time.Duration

	mu        sync.Mutex
	paniques  int
	parIP     map[string]int
	parLeurre map[string]int
}

func NewServeurMail(signaux chan<- Signal, lb *ListeBlanche) *ServeurMail {
	return &ServeurMail{signaux: signaux, lb: lb, tls: NewDecompteTLS(),
		ligne: mailEcheanceLigne, totale: mailEcheanceTotale,
		parIP: map[string]int{}, parLeurre: map[string]int{}}
}

// reserve compte une connexion ; faux quand un plafond est atteint.
func (m *ServeurMail) reserve(nom, ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.parLeurre[nom] >= mailParLeurre || m.parIP[ip] >= mailParIP {
		return false
	}
	m.parLeurre[nom]++
	m.parIP[ip]++
	return true
}

func (m *ServeurMail) libere(nom, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parLeurre[nom]--
	if m.parIP[ip]--; m.parIP[ip] <= 0 {
		delete(m.parIP, ip)
	}
}

func (m *ServeurMail) ouvertes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, k := range m.parLeurre {
		n += k
	}
	return n
}

// cgnat : 100.64.0.0/10, privé de fait, que net.IP.IsPrivate ne compte pas.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

// exempte : LAN, maillage, pont des conteneurs, liste blanche. Servis, mais ni
// comptés, ni inscrits, ni jugés.
func (m *ServeurMail) exempte(ip string) bool {
	p := net.ParseIP(ip)
	return p == nil || p.IsUnspecified() || cgnat.Contains(p) || m.lb.Contient(ip)
}

// ecouteMail ouvre un port en IPv4 SEULEMENT (les règles ferment les leurres en
// IPv6). Un port déjà tenu par un service échoue : le leurre lui cède la place.
func ecouteMail(ctx context.Context, port int) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp4", fmt.Sprintf(":%d", port))
}

// Sert accepte jusqu'à la fermeture de l'écoute.
func (m *ServeurMail) Sert(ctx context.Context, ln net.Listener, l LeurreMail) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(200 * time.Millisecond) // descripteurs épuisés : le leurre survit
			continue
		}
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if l.Compte && !m.exempte(ip) {
			m.tls.Note(l.Nom, ip, time.Now())
		}
		if !m.reserve(l.Nom, ip) {
			// Plafond : même politesse, en une écriture qui ne bloque pas.
			_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = io.WriteString(conn, l.Saturee)
			_ = conn.Close()
			continue
		}
		go func() {
			defer m.libere(l.Nom, ip)
			defer conn.Close()
			s := nouvelleSession(conn, m.ligne, m.totale)
			defer s.lec.efface()
			// Une panique ferme CETTE connexion, pas la surveillance. Ni sa valeur
			// ni sa pile ne sont écrites : elles peuvent porter des octets reçus.
			defer func() {
				if recover() != nil {
					m.mu.Lock()
					m.paniques++
					m.mu.Unlock()
					log.Printf("sbx-authwatch: leurre %s : panique sur une connexion, fermée", l.Nom)
				}
			}()
			l.dialogue(s)
			// Rupture avant le signal : le ban jetterait aussi nos derniers octets.
			_ = conn.Close()
			m.emet(ctx, l, ip, s)
		}()
	}
}

// emet pousse un signal par COMPTE visé (un seul sans compte lisible). Jamais
// d'`Essais` : le chemin des identifiants en clair n'est pas emprunté. Gravité
// « audit », neutre pour le maillage : la boucle de décision, qui connaît les
// comptes réels, la relève à haute pour un compte inexistant.
func (m *ServeurMail) emet(ctx context.Context, l LeurreMail, ip string, s *sessionMail) {
	if l.Service == "" || s.essais == 0 || m.exempte(ip) {
		return
	}
	comptes := s.comptes
	if len(comptes) == 0 {
		comptes = []string{""}
	}
	for _, c := range comptes {
		sig := Signal{IP: ip, Service: l.Service, Categorie: l.Categorie, Severite: graviteAudit,
			Detail: fmt.Sprintf("authentification sur le leurre %s (port %d)", l.Nom, l.Port),
			Cible:  c, LeurreMail: l.Nom}
		select {
		case m.signaux <- sig:
		case <-ctx.Done():
			return
		}
	}
}

// Permanents ouvre les leurres en clair permanents (110, 143).
func (m *ServeurMail) Permanents(ctx context.Context) {
	for _, l := range LeurresMailPermanents {
		ln, err := ecouteMail(ctx, l.Port)
		if err != nil {
			log.Printf("sbx-authwatch: leurre %s non ouvert, port %d déjà tenu ou refusé : %v", l.Nom, l.Port, err)
			continue
		}
		log.Printf("sbx-authwatch: leurre %s en écoute sur :%d (permanent)", l.Nom, l.Port)
		go func() { <-ctx.Done(); _ = ln.Close() }()
		go m.Sert(ctx, ln, l)
	}
}

// Relais ouvre les ports locaux des leurres de remplacement, rend ceux qui ont
// pu l'être et de quoi les fermer. Un port non ouvert n'est PAS redirigé.
func (m *ServeurMail) Relais(ctx context.Context) ([]LeurreMail, func()) {
	var ouverts []LeurreMail
	var ecoutes []net.Listener
	for _, l := range LeurresMailRelais {
		ln, err := ecouteMail(ctx, l.Local)
		if err != nil {
			log.Printf("sbx-authwatch: leurre %s : port local %d indisponible, non redirigé : %v", l.Nom, l.Local, err)
			continue
		}
		ouverts, ecoutes = append(ouverts, l), append(ecoutes, ln)
		go m.Sert(ctx, ln, l)
	}
	return ouverts, func() {
		for _, ln := range ecoutes {
			_ = ln.Close()
		}
	}
}
