package web

// Authentification deleguee a secubox-auth.
//
// UNE SEULE IDENTITE. Quelqu'un qui a deja un compte SecuBox n'a pas a en creer
// un second ici, avec un second mot de passe, pour lire les memes fils.
//
// LE BBS TRANSMET ET OUBLIE. Il ne garde aucune empreinte des comptes SecuBox :
// une seconde copie deviendrait fausse au premier changement, et survivrait a
// une revocation. Un compte ferme la-bas doit etre ferme ici, sans delai et
// sans intervention.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

// authAmont : verifie un couple pseudonyme/mot de passe aupres de SecuBox.
// Rend false sans distinguer « inconnu » de « mauvais mot de passe » — cette
// distinction n'appartient pas au BBS.
type authAmont func(handle, motDePasse string) bool

// clientAuthSocket parle a secubox-auth par sa socket unix.
func clientAuthSocket(socket string) authAmont {
	c := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
	return clientAuthHTTP("http://auth", c)
}

func clientAuthHTTP(base string, c *http.Client) authAmont {
	if c == nil {
		c = &http.Client{Timeout: 8 * time.Second}
	}
	return func(handle, mdp string) bool {
		corps, _ := json.Marshal(map[string]string{"username": handle, "password": mdp})
		req, err := http.NewRequest("POST", base+"/auth/login", bytes.NewReader(corps))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			// INJOIGNABLE = REFUS. Un service d'authentification en panne ne
			// doit pas ouvrir la porte « en attendant » : c'est exactement le
			// moment ou personne ne surveille.
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var rep map[string]any
		if json.NewDecoder(resp.Body).Decode(&rep) != nil {
			return false
		}
		// UN JETON D'ACCES, PAS UN JETON DE MISE EN PLACE. Un compte sans mot
		// de passe rend `setup_required` avec un `setup_token` : le prendre
		// pour une reussite ouvrirait une session a quiconque connait le
		// pseudonyme d'un compte pas encore configure.
		if req, _ := rep["setup_required"].(bool); req {
			return false
		}
		jeton, _ := rep["access_token"].(string)
		return jeton != ""
	}
}

// ── La session SecuBox, reconnue ici (#1369) ────────────────────────────────
//
// UN APPAREIL CONNECTE AU HALL EST CONNECTE A LA BBS. Avant, la BBS ne lisait
// que son propre cookie : un iPhone ouvert au Hall arrivait ici anonyme, sans un
// bouton, et la seule issue etait une seconde connexion avec un mot de passe
// que l'appareil — entre par sa cle — n'a jamais eu.
//
// LA VERIFICATION EST CELLE DE SECUBOX, PAS UNE COPIE. /auth/verify controle la
// signature, l'expiration, la revocation (jti) et l'etat du compte : refaire
// ici la seule signature laisserait passer une session revoquee la-bas.

// sessionSecubox : ce que /auth/verify dit d'un jeton.
type sessionSecubox struct {
	User    string
	Groupes string
	// Bbs : le compte BBS lié à la PERSONNE SBX OS derrière la session
	// (#1456, en-tête Remote-Sbx-Bbs), posé par l'administration SBX OS.
	Bbs string
}

// verifSession interroge secubox-auth. ok=false pour tout refus, y compris
// l'injoignable : on ferme, on ne devine pas.
type verifSession func(jeton string) (sessionSecubox, bool)

func clientVerifSocket(socket string) verifSession {
	c := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
	return clientVerifHTTP("http://auth", c)
}

func clientVerifHTTP(base string, c *http.Client) verifSession {
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	cache := &cacheVerif{m: map[[32]byte]entreeVerif{}}
	return func(jeton string) (sessionSecubox, bool) {
		if jeton == "" {
			return sessionSecubox{}, false
		}
		cle := sha256.Sum256([]byte(jeton))
		if e, ok := cache.lit(cle); ok {
			return e.s, e.ok
		}
		req, err := http.NewRequest("GET", base+"/auth/verify", nil)
		if err != nil {
			return sessionSecubox{}, false
		}
		req.Header.Set("Authorization", "Bearer "+jeton)
		resp, err := c.Do(req)
		if err != nil {
			// Injoignable : refus, et PAS de mise en cache — une panne passagere
			// ne doit pas deconnecter tout le monde pour la duree du cache.
			return sessionSecubox{}, false
		}
		defer resp.Body.Close()
		s := sessionSecubox{User: resp.Header.Get("Remote-User"), Groupes: resp.Header.Get("Remote-Groups"),
			Bbs: resp.Header.Get("Remote-Sbx-Bbs")}
		ok := resp.StatusCode == http.StatusOK && s.User != ""
		cache.pose(cle, entreeVerif{s: s, ok: ok, jusqua: time.Now().Add(dureeCacheVerif)})
		return s, ok
	}
}

// Le cache borne le cout : chaque page affichee appelle qui(). Trente secondes,
// c'est aussi le delai maximal pendant lequel une revocation reste ignoree ici.
const dureeCacheVerif = 30 * time.Second
const tailleCacheVerif = 512

type entreeVerif struct {
	s      sessionSecubox
	ok     bool
	jusqua time.Time
}

type cacheVerif struct {
	mu sync.Mutex
	m  map[[32]byte]entreeVerif
}

func (c *cacheVerif) lit(k [32]byte) (entreeVerif, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok || time.Now().After(e.jusqua) {
		delete(c.m, k)
		return entreeVerif{}, false
	}
	return e, true
}

func (c *cacheVerif) pose(k [32]byte, e entreeVerif) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= tailleCacheVerif {
		c.m = map[[32]byte]entreeVerif{}
	}
	c.m[k] = e
}
