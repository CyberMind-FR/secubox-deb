// Package billets publie un fil du BBS vers le module billets.
//
// LE SENS DE LA DEPENDANCE : le BBS appelle billets, jamais l'inverse. billets
// sait publier ; il n'a pas a savoir qu'un BBS existe. Un module qui tombe ne
// doit pas emporter l'autre.
//
// CE QUE CE CLIENT REFUSE DE FAIRE, ET POURQUOI :
//
//   - publier un fil local. Publier, c'est mettre sur internet : l'erreur ne se
//     rattrape pas, c'est lu, indexe, archive. La garde est ici ET dans
//     l'interface, parce qu'une garde d'interface se contourne en tapant
//     l'adresse.
//
//   - transmettre un message local d'un fil public. C'est le cas difficile de
//     tout le systeme : le fil sort, ce message-la reste.
//
//   - signer avec un secret vide. Un jeton signe avec une valeur par defaut
//     serait accepte par tout service faisant la meme erreur.
package billets

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Message struct {
	Auteur string
	Corps  string
	Public bool
}

type Fil struct {
	ID       int64
	Titre    string
	Public   bool
	Messages []Message
	Retour   string // adresse du fil dans le BBS, pour le lien croise
}

type Resultat struct {
	BilletID string
	URL      string
	Pris     int
	Retenus  int
}

type Client struct {
	Base   string // http://unix ou http://127.0.0.1:PORT
	Socket string // chemin de la socket unix, si l'appel passe par elle
	Secret string // secret HS256 partage (api.jwt_secret)
	HTTP   *http.Client
}

// NewUnix construit un client parlant a billets par sa socket unix.
//
// Socket et non port TCP : un port ecoute pour tout le monde sur la machine,
// une socket obeit aux permissions du systeme de fichiers.
func NewUnix(socket, secret string) *Client {
	return &Client{
		Base:   "http://billets",
		Socket: socket,
		Secret: secret,
		HTTP: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

func (c *Client) Publier(f Fil) (Resultat, error) {
	var r Resultat
	if !f.Public {
		return r, errors.New("fil local : rendez-le public explicitement avant de le publier")
	}
	// DEUX GARDES REDONDANTES pour le secret, ici et dans jeton(). La mutation
	// le montre : retirer l'une laisse l'autre tenir, aucun test ne les
	// distingue. C'est voulu et non un oubli — celle-ci refuse AVANT de
	// construire la charge utile, jeton() refuse avant de signer. Un futur
	// appelant qui appellerait jeton() directement reste couvert.
	if strings.TrimSpace(c.Secret) == "" {
		return r, errors.New("aucun secret de signature configure — publication refusee")
	}

	var b strings.Builder
	for _, m := range f.Messages {
		if !m.Public {
			r.Retenus++
			continue
		}
		r.Pris++
		// L'attribution est portee dans le corps : billets ne connait pas les
		// comptes du BBS, et un texte publie sans ses voix perd son sens.
		fmt.Fprintf(&b, "**%s** — %s\n\n", m.Auteur, strings.TrimSpace(m.Corps))
	}
	if r.Pris == 0 {
		return r, errors.New("aucun message public dans ce fil")
	}
	if f.Retour != "" {
		fmt.Fprintf(&b, "\n---\n\n[Discuter ce billet sur le BBS](%s)\n", f.Retour)
	}

	charge, _ := json.Marshal(map[string]any{
		"title": f.Titre,
		"body":  b.String(),
		"url":   f.Retour,
		// `ref` et non `embed` : le billet renvoie vers la conversation, il ne
		// l'incorpore pas.
		"url_kind": "ref",
		"status":   "published",
	})

	req, err := http.NewRequest("POST", strings.TrimRight(c.Base, "/")+"/admin/api/billets",
		bytes.NewReader(charge))
	if err != nil {
		return r, err
	}
	jeton, err := c.jeton()
	if err != nil {
		return r, err
	}
	req.Header.Set("Authorization", "Bearer "+jeton)
	req.Header.Set("Content-Type", "application/json")

	cl := c.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return r, fmt.Errorf("billets injoignable : %w", err)
	}
	defer resp.Body.Close()
	corps, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		// L'echec REMONTE. Enregistrer le fil comme publie alors que billets a
		// refuse afficherait un lien vers une page inexistante — et personne ne
		// s'en apercevrait avant qu'un lecteur ne clique.
		return r, fmt.Errorf("billets a refuse (%d) : %s", resp.StatusCode,
			strings.TrimSpace(string(corps[:min(len(corps), 200)])))
	}
	var out struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	json.Unmarshal(corps, &out)
	r.BilletID, r.URL = out.ID, out.URL
	return r, nil
}

// jeton forge un JWT HS256 de courte duree.
//
// Court volontairement : il ne sert qu'a UN appel. Un jeton de service valable
// des heures traine dans les journaux et les captures reseau bien apres que
// l'appel qu'il autorisait soit termine.
func (c *Client) jeton() (string, error) {
	if strings.TrimSpace(c.Secret) == "" {
		return "", errors.New("secret de signature absent")
	}
	now := time.Now().Unix()
	entete := b64(`{"alg":"HS256","typ":"JWT"}`)
	charge := b64(fmt.Sprintf(
		`{"sub":"secubox-bbs","role":"sysop","iat":%d,"exp":%d}`, now, now+60))
	sig := hmac.New(sha256.New, []byte(c.Secret))
	sig.Write([]byte(entete + "." + charge))
	return entete + "." + charge + "." +
		base64.RawURLEncoding.EncodeToString(sig.Sum(nil)), nil
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// charge decode la charge utile d'un JWT (utilise par les tests).
func charge(jwt string) ([]byte, error) {
	p := strings.Split(jwt, ".")
	if len(p) != 3 {
		return nil, errors.New("jeton mal forme")
	}
	return base64.RawURLEncoding.DecodeString(p[1])
}
