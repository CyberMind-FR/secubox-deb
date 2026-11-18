// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

// IDENTIFIANTS DES ROBOTS — ce qu'ils essaient, qui ils sont (#3728).
//
// Ouverts sur le WAN, les leurres reçoivent des robots de force brute. Le
// régime bannière (banniere.go) ne gardait que la première trame : on savait
// QUI frappait, jamais AVEC QUOI. Ici, pour les protocoles dont l'échange
// d'authentification est en clair (telnet, redis, postgres, HTTP Basic) ou dont
// la première trame porte le compte (RDP), on tient la conversation juste assez
// pour recevoir les identifiants, on les refuse, et on ferme.
//
// LES MOTS DE PASSE SONT JOURNALISÉS EN CLAIR, par décision du propriétaire
// (2026-11-15) : derrière ces ports il n'y a AUCUN service ni AUCUN compte ; tout
// ce qui y arrive est tenté par un robot, et c'est précisément ce qu'on veut
// lire (dictionnaires, rejeu d'un même mot de passe sur plusieurs comptes).
//
// CE QU'ON S'AUTORISE, ET SES BORNES. On s'écartait de « ne jamais interpréter »
// de leurre.go ; l'écart reste étroit :
//   * ce qu'on ÉCRIT est toujours une constante compilée (invites, refus) ;
//   * ce qu'on LIT est borné : échéance de connexion, octets par connexion,
//     longueur de chaque champ, nombre d'essais ; aucune allocation n'est guidée
//     par une longueur annoncée au-delà de ces bornes ;
//   * ce qu'on GARDE passe par propre() : ASCII imprimable, 64 caractères.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// LE BAN ATTEND LA FIN DU DIALOGUE : le ban nft (waf_drop, priorité -100) jette AUSSI la connexion établie, bannir
	// à l'ouverture tuerait la capture. La fenêtre est donc courte : 3 s pour dire un premier octet (un balayeur muet
	// est clos et banni à 3 s), 10 s au total pour qui parle.
	premierOctetEcheance = 3 * time.Second
	dialogueEcheance     = 10 * time.Second
	essaisMax            = 5    // essais gardés par connexion
	champMax             = 64   // caractères gardés par compte, mot de passe, client
	octetsMax            = 4096 // octets lus par connexion, tous échanges confondus
	reveilsMax           = 3    // lignes vides tolérées en telnet avant de fermer
)

// Essai — un couple tenté. L'un des deux peut manquer (RDP ne livre que le
// compte, redis AUTH à un argument que le mot de passe).
type Essai struct {
	Compte     string `json:"compte,omitempty"`
	MotDePasse string `json:"mot_de_passe,omitempty"`
}

// Capture — ce qu'une connexion à un leurre a révélé.
type Capture struct {
	Essais  []Essai
	Client  string // logiciel client déduit du protocole (porté en user_agent)
	Agent   string // « balayeur » | « sondeur » | « force-brute »
	Extrait string // première trame assainie, quand on n'a rien de mieux
	Octets  int
}

// agentDe classe le visiteur : il a tenté des identifiants, il a parlé, ou il
// n'a fait qu'ouvrir le port.
func agentDe(c Capture) string {
	switch {
	case len(c.Essais) > 0:
		return "force-brute"
	case c.Octets > 0:
		return "sondeur"
	default:
		return "balayeur"
	}
}

// Dialogue tient l'échange propre au service et rend la capture. Les services
// sans dialogue connu retombent sur Echange (une bannière, une trame).
func Dialogue(conn net.Conn, service string) (c Capture) {
	_ = conn.SetDeadline(time.Now().Add(premierOctetEcheance))
	defer func() { c.Agent = agentDe(c) }()
	switch service {
	case "telnet":
		return dialogueTelnet(conn)
	case "postgres":
		return dialoguePostgres(conn)
	case "redis":
		return dialogueRedis(conn)
	case "elasticsearch":
		return dialogueHTTP(conn)
	}
	extrait, n, brut := echangeBrut(conn, service)
	c = Capture{Extrait: extrait, Octets: n}
	switch service {
	case "rdp":
		c.Essais, c.Client = analyseRDP(brut)
	case "vnc":
		c.Client = analyseVNC(brut)
	case "mongodb":
		c.Client = analyseMongo(brut)
	}
	return c
}

// propre rend une chaîne SÛRE pour le journal : ASCII imprimable, le reste en
// point, coupée à champMax.
func propre(b []byte) string { return propreN(b, champMax) }

// propreN — propre() avec sa propre longueur maximale.
func propreN(b []byte, max int) string {
	var sb strings.Builder
	for _, x := range b {
		if sb.Len() >= max {
			break
		}
		if x >= 0x20 && x < 0x7f {
			sb.WriteByte(x)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

// lecteur borné : compte les octets lus et refuse d'aller au-delà d'octetsMax. Au
// premier octet reçu, l'échéance passe de premierOctetEcheance à `fin`.
type lecteur struct {
	r    *bufio.Reader
	n    *int
	conn net.Conn
	fin  time.Time
}

func nouveauLecteur(conn net.Conn, taille int, n *int) lecteur {
	return lecteur{bufio.NewReaderSize(conn, taille), n, conn, time.Now().Add(dialogueEcheance)}
}

func (l lecteur) compte(k int) {
	if *l.n == 0 && k > 0 && l.conn != nil {
		_ = l.conn.SetDeadline(l.fin)
	}
	*l.n += k
}

func (l lecteur) octet() (byte, error) {
	if *l.n >= octetsMax {
		return 0, io.ErrShortBuffer
	}
	b, err := l.r.ReadByte()
	if err == nil {
		l.compte(1)
	}
	return b, err
}

func (l lecteur) plein(n int) ([]byte, error) {
	if n < 0 || *l.n+n > octetsMax {
		return nil, io.ErrShortBuffer
	}
	b := make([]byte, n)
	k, err := io.ReadFull(l.r, b)
	l.compte(k)
	return b, err
}

// ligne lit jusqu'à \n, garde au plus `max` octets ; les octets au-delà sont lus et
// jetés. ok=false à la fin du flux (la ligne partielle est rendue).
func (l lecteur) ligne(max int) (string, bool) {
	var b []byte
	for {
		x, err := l.octet()
		if err != nil {
			return propreN(bytes.TrimSpace(b), max), false
		}
		if x == '\n' {
			return propreN(bytes.TrimRight(b, "\r"), max), true
		}
		if len(b) < max {
			b = append(b, x)
		}
	}
}

const ligneLongue = 512 // en-têtes HTTP, commandes redis en ligne

// ── telnet ──────────────────────────────────────────────────────────────────

var (
	telnetMotDePasse = []byte("Password: ")
	telnetRefus      = []byte("\r\nLogin incorrect\r\n\r\nlogin: ")
)

// telnet — lecteur de lignes : négociation (IAC) écartée, ses premiers octets
// gardés dans `iac` (ils signent le client) ; \r\n, \r\0 et \n finissent une
// ligne UNE fois (`cr` retient le \r précédent). Une ligne vide est rendue : un
// robot peut tenter un mot de passe vide.
type telnet struct {
	l   lecteur
	iac []byte
	cr  bool
}

func (tl *telnet) ligne() (string, bool) {
	l, iac := tl.l, &tl.iac
	var b []byte
	for {
		x, err := l.octet()
		if err != nil {
			return propre(b), false
		}
		switch {
		case x == 0xff: // IAC
			cmd, err := l.octet()
			if err != nil {
				return propre(b), false
			}
			garde := func(v ...byte) {
				if len(*iac) < 32 {
					*iac = append(*iac, v...)
				}
			}
			switch {
			case cmd >= 251 && cmd <= 254: // WILL WONT DO DONT <option>
				opt, err := l.octet()
				if err != nil {
					return propre(b), false
				}
				garde(0xff, cmd, opt)
			case cmd == 250: // SB … IAC SE, borné
				garde(0xff, cmd)
				for i := 0; i < 64; i++ {
					y, err := l.octet()
					if err != nil {
						return propre(b), false
					}
					if y == 0xf0 {
						break
					}
				}
			}
		case x == '\n' || x == 0:
			if tl.cr && len(b) == 0 {
				tl.cr = false
				continue
			}
			tl.cr = false
			return propre(b), true
		case x == '\r':
			tl.cr = true
			return propre(b), true
		case x >= 0x20 && x < 0x7f:
			tl.cr = false
			if len(b) < champMax {
				b = append(b, x)
			}
		}
	}
}

func dialogueTelnet(conn net.Conn) (c Capture) {
	tl := &telnet{l: nouveauLecteur(conn, 256, &c.Octets)}
	defer func() { c.Client = clientTelnet(tl.iac) }()
	if _, err := conn.Write(bannieres["telnet"]); err != nil {
		return c
	}
	reveils := 0
	for len(c.Essais) < essaisMax {
		compte, ok := tl.ligne()
		if compte == "" && !ok {
			return c
		}
		if compte == "" { // ligne vide : le robot « réveille » l'invite, quelques fois au plus
			if reveils++; reveils > reveilsMax {
				return c
			}
			if _, err := conn.Write(bannieres["telnet"]); err != nil {
				return c
			}
			continue
		}
		if !ok {
			c.Essais = append(c.Essais, Essai{Compte: compte})
			return c
		}
		if _, err := conn.Write(telnetMotDePasse); err != nil {
			c.Essais = append(c.Essais, Essai{Compte: compte})
			return c
		}
		mdp, ok := tl.ligne()
		c.Essais = append(c.Essais, Essai{Compte: compte, MotDePasse: mdp})
		if !ok {
			return c
		}
		if _, err := conn.Write(telnetRefus); err != nil {
			return c
		}
	}
	return c
}

func clientTelnet(iac []byte) string {
	if len(iac) == 0 {
		return "telnet sans négociation"
	}
	return "telnet négociation " + hex.EncodeToString(iac)
}

// ── postgres ────────────────────────────────────────────────────────────────

var (
	pgPasDeChiffrement = []byte{'N'}
	pgDemandeEnClair   = []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3} // AuthenticationCleartextPassword
	pgRefus            = messagePG('E', "SFATAL\x00VFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00")
)

func messagePG(t byte, corps string) []byte {
	b := []byte{t, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(4+len(corps)))
	return append(b, corps...)
}

// startupPG lit un message sans type (longueur incluse) : demande SSL/GSS ou démarrage.
func startupPG(l lecteur) ([]byte, bool) {
	t, err := l.plein(4)
	if err != nil {
		return nil, false
	}
	n := int(binary.BigEndian.Uint32(t))
	if n < 8 || n > 1024 {
		return nil, false
	}
	corps, err := l.plein(n - 4)
	return corps, err == nil
}

func dialoguePostgres(conn net.Conn) (c Capture) {
	l := nouveauLecteur(conn, 1024, &c.Octets)
	corps, ok := startupPG(l)
	for i := 0; ok && i < 2 && len(corps) == 4; i++ {
		code := binary.BigEndian.Uint32(corps)
		if code != 80877103 && code != 80877104 { // SSLRequest, GSSENCRequest
			break
		}
		if _, err := conn.Write(pgPasDeChiffrement); err != nil {
			return c
		}
		corps, ok = startupPG(l)
	}
	if !ok {
		return c
	}
	if len(corps) < 4 || binary.BigEndian.Uint32(corps[:4]) != 196608 { // protocole 3.0
		c.Client = "postgres protocole inconnu"
		c.Extrait = resumeTrame(corps)
		return c
	}
	p := map[string]string{}
	champs := bytes.Split(corps[4:], []byte{0})
	for i := 0; i+1 < len(champs) && i < 32; i += 2 {
		p[propre(champs[i])] = propre(champs[i+1])
	}
	c.Client = "postgres"
	if a := p["application_name"]; a != "" {
		c.Client += " application_name=" + a
	} else {
		c.Client += " sans application_name"
	}
	if d := p["database"]; d != "" {
		c.Client += " base=" + d
	}
	if _, err := conn.Write(pgDemandeEnClair); err != nil {
		if p["user"] != "" {
			c.Essais = append(c.Essais, Essai{Compte: p["user"]})
		}
		return c
	}
	e := Essai{Compte: p["user"]}
	if t, err := l.octet(); err == nil && t == 'p' {
		if lg, err := l.plein(4); err == nil {
			n := int(binary.BigEndian.Uint32(lg))
			if n >= 4 && n <= 260 {
				if mdp, err := l.plein(n - 4); err == nil {
					e.MotDePasse = propre(bytes.TrimRight(mdp, "\x00"))
				}
			}
		}
	}
	if e.Compte != "" || e.MotDePasse != "" {
		c.Essais = append(c.Essais, e)
	}
	_, _ = conn.Write(pgRefus)
	return c
}

// ── redis ───────────────────────────────────────────────────────────────────

var (
	redisNoAuth  = []byte("-NOAUTH Authentication required.\r\n")
	redisMauvais = []byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n")
)

// commandeRedis lit une commande RESP (*n $len …) ou en ligne (mots séparés).
func commandeRedis(l lecteur) ([]string, bool) {
	tete, ok := l.ligne(ligneLongue)
	if !ok && tete == "" {
		return nil, false
	}
	if !strings.HasPrefix(tete, "*") {
		var args []string
		for _, f := range strings.Fields(tete) {
			args = append(args, propre([]byte(f)))
		}
		return args, ok
	}
	n, err := strconv.Atoi(tete[1:])
	if err != nil || n < 1 || n > 8 {
		return nil, false
	}
	var args []string
	for i := 0; i < n; i++ {
		lg, ok := l.ligne(champMax)
		if !ok || !strings.HasPrefix(lg, "$") {
			return args, false
		}
		k, err := strconv.Atoi(lg[1:])
		if err != nil || k < 0 || k > 512 {
			return args, false
		}
		v, err := l.plein(k + 2)
		if err != nil {
			return args, false
		}
		args = append(args, propre(v[:k]))
	}
	return args, true
}

func dialogueRedis(conn net.Conn) (c Capture) {
	l := nouveauLecteur(conn, 1024, &c.Octets)
	var vues []string
	defer func() {
		if len(vues) > 0 {
			c.Client = "redis " + strings.Join(vues, ",")
		} else {
			c.Client = "redis muet"
		}
	}()
	for i := 0; i < 2*essaisMax && len(c.Essais) < essaisMax; i++ {
		args, ok := commandeRedis(l)
		if len(args) == 0 {
			if !ok {
				return c
			}
			continue
		}
		nom := strings.ToUpper(args[0])
		if len(vues) < 4 {
			vues = append(vues, nom)
		}
		rep := redisNoAuth
		switch {
		case nom == "AUTH" && len(args) == 2:
			c.Essais = append(c.Essais, Essai{MotDePasse: args[1]})
			rep = redisMauvais
		case nom == "AUTH" && len(args) >= 3:
			c.Essais = append(c.Essais, Essai{Compte: args[1], MotDePasse: args[2]})
			rep = redisMauvais
		case nom == "HELLO" && len(args) >= 5 && strings.ToUpper(args[2]) == "AUTH":
			c.Essais = append(c.Essais, Essai{Compte: args[3], MotDePasse: args[4]})
			rep = redisMauvais
		}
		if _, err := conn.Write(rep); err != nil || !ok {
			return c
		}
	}
	return c
}

// ── HTTP (elasticsearch) ────────────────────────────────────────────────────

var httpRefus = []byte("HTTP/1.1 401 Unauthorized\r\n" +
	"WWW-Authenticate: Basic realm=\"security\" charset=\"UTF-8\"\r\n" +
	"Content-Type: application/json; charset=UTF-8\r\nContent-Length: 0\r\n\r\n")

// requeteHTTP lit la ligne de requête et les en-têtes (32 au plus).
func requeteHTTP(l lecteur) (string, map[string]string, bool) {
	premiere, ok := l.ligne(ligneLongue)
	if !ok || premiere == "" {
		return premiere, nil, false
	}
	entetes := map[string]string{}
	for i := 0; i < 32; i++ {
		h, ok := l.ligne(ligneLongue)
		if !ok {
			return premiere, entetes, false
		}
		if h == "" {
			return premiere, entetes, true
		}
		if k, v, trouve := strings.Cut(h, ":"); trouve {
			entetes[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return premiere, entetes, false
}

// basic décode « Authorization: Basic … » (ligne gardée jusqu'à 512 octets).
func basic(v string) (Essai, bool) {
	if !strings.HasPrefix(strings.ToLower(v), "basic ") {
		return Essai{}, false
	}
	brut, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[6:]))
	if err != nil {
		return Essai{}, false
	}
	compte, mdp, _ := bytes.Cut(brut, []byte(":"))
	return Essai{Compte: propre(compte), MotDePasse: propre(mdp)}, true
}

func dialogueHTTP(conn net.Conn) (c Capture) {
	l := nouveauLecteur(conn, 2048, &c.Octets)
	for i := 0; i < essaisMax; i++ {
		premiere, entetes, ok := requeteHTTP(l)
		if premiere == "" {
			return c
		}
		if c.Client == "" {
			c.Extrait = propreN([]byte(premiere), 160)
			if ua := entetes["user-agent"]; ua != "" {
				c.Client = propreN([]byte(ua), 160)
			} else {
				c.Client = "http sans User-Agent"
			}
		}
		if e, oui := basic(entetes["authorization"]); oui {
			c.Essais = append(c.Essais, e)
		}
		if _, err := conn.Write(httpRefus); err != nil || !ok {
			return c
		}
		if lg := entetes["content-length"]; lg != "" && lg != "0" {
			return c // un corps suit : on ne le lit pas, la conversation s'arrête là
		}
	}
	return c
}

// ── analyses d'une première trame (RDP, VNC, Mongo) ─────────────────────────

var protocolesRDP = []struct {
	bit uint32
	nom string
}{{1, "TLS"}, {2, "CredSSP"}, {4, "RDSTLS"}, {8, "CredSSP-EX"}, {0x10, "RDSAAD"}}

// analyseRDP lit la demande de connexion X.224 : compte du cookie mstshash et
// protocoles demandés (RDP_NEG_REQ, 8 derniers octets d'une trame complète).
func analyseRDP(b []byte) ([]Essai, string) {
	var essais []Essai
	var traits []string
	if i := bytes.Index(b, []byte("Cookie: mstshash=")); i >= 0 {
		reste := b[i+len("Cookie: mstshash="):]
		if j := bytes.Index(reste, []byte("\r\n")); j >= 0 {
			reste = reste[:j]
		}
		if compte := propre(reste); compte != "" {
			essais = append(essais, Essai{Compte: compte})
		}
		traits = append(traits, "cookie mstshash")
	} else if bytes.Contains(b, []byte("Cookie: msts=")) {
		traits = append(traits, "jeton de routage")
	}
	if len(b) >= 19 && b[0] == 0x03 && int(binary.BigEndian.Uint16(b[2:4])) == len(b) {
		neg := b[len(b)-8:]
		if neg[0] == 0x01 && neg[2] == 8 && neg[3] == 0 {
			p := binary.LittleEndian.Uint32(neg[4:])
			var noms []string
			for _, x := range protocolesRDP {
				if p&x.bit != 0 {
					noms = append(noms, x.nom)
				}
			}
			if len(noms) == 0 {
				noms = []string{"RDP standard"}
			}
			traits = append(traits, "protocoles "+strings.Join(noms, "+"))
		}
	}
	switch {
	case len(traits) > 0:
		return essais, "rdp " + strings.Join(traits, ", ")
	case len(b) > 0 && b[0] == 0x03:
		return essais, "rdp sans négociation"
	case len(b) > 0:
		return essais, "pas du RDP"
	}
	return essais, ""
}

func analyseVNC(b []byte) string {
	if bytes.HasPrefix(b, []byte("RFB ")) && len(b) >= 11 {
		return "vnc client " + propre(b[:11])
	}
	if len(b) > 0 {
		return "vnc sans version"
	}
	return ""
}

// chaineBSON cherche l'élément chaîne `cle` après `depuis` et rend sa valeur.
func chaineBSON(b []byte, depuis int, cle string) string {
	if depuis < 0 || depuis > len(b) {
		return ""
	}
	motif := append(append([]byte{0x02}, cle...), 0)
	i := bytes.Index(b[depuis:], motif)
	if i < 0 {
		return ""
	}
	i += depuis + len(motif)
	if i+4 > len(b) {
		return ""
	}
	n := int(binary.LittleEndian.Uint32(b[i : i+4]))
	if n < 1 || n > 128 || i+4+n > len(b) {
		return ""
	}
	return propre(bytes.TrimRight(b[i+4:i+4+n], "\x00"))
}

// analyseMongo lit le document « hello » du pilote : nom et version du pilote,
// nom de l'application.
func analyseMongo(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var traits []string
	if d := bytes.Index(b, []byte("driver")); d >= 0 {
		if n := chaineBSON(b, d, "name"); n != "" {
			traits = append(traits, "pilote "+n)
		}
		if v := chaineBSON(b, d, "version"); v != "" {
			traits = append(traits, v)
		}
	}
	if a := bytes.Index(b, []byte("application")); a >= 0 {
		if n := chaineBSON(b, a, "name"); n != "" {
			traits = append(traits, "appli "+n)
		}
	}
	if len(traits) == 0 {
		return "mongo sans pilote déclaré"
	}
	return "mongo " + strings.Join(traits, " ")
}
