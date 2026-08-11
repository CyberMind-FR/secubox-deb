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
	"encoding/json"
	"net"
	"net/http"
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
