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
	// Session : le jeton de session SecuBox de L'OPERATEUR qui declenche la
	// publication. Le BBS n'a pas d'identite propre chez billets.
	Session  string
	ID       int64
	Titre    string
	Public   bool
	Messages []Message
	Retour   string // adresse du fil dans le BBS, pour le lien croise
	// Attribuer nomme les auteurs dans le billet. FAUX par defaut : voir
	// l'assemblage du corps ci-dessous.
	Attribuer bool
}

type Resultat struct {
	BilletID string
	URL      string
	Pris     int
	Retenus  int
}

type Client struct {
	Base    string // http://unix ou http://127.0.0.1:PORT
	Socket  string // chemin de la socket unix, si l'appel passe par elle
	Session string // session d'operateur par defaut (essais uniquement)
	HTTP    *http.Client
}

// NewUnix construit un client parlant a billets par sa socket unix.
//
// Socket et non port TCP : un port ecoute pour tout le monde sur la machine,
// une socket obeit aux permissions du systeme de fichiers.
func NewUnix(socket string) *Client {
	return &Client{
		Base:   "http://billets",
		Socket: socket,
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
	// LE BBS N'A PAS D'IDENTITE PROPRE CHEZ BILLETS, et c'est une bonne chose.
	//
	// Le noyau SecuBox exige d'un jeton qu'il porte un `jti` correspondant a
	// une session VIVANTE et un `sub` present dans l'annuaire des comptes. Un
	// jeton de service forge par le BBS ne peut donc pas passer — la garde
	// existe precisement pour empecher qu'un module s'invente une autorite.
	//
	// La publication se fait donc sous l'autorite de L'OPERATEUR : sa session
	// SecuBox est relayee telle quelle. Sans elle, on n'envoie rien.
	session := strings.TrimSpace(f.Session)
	if session == "" {
		session = strings.TrimSpace(c.Session)
	}
	if session == "" {
		return r, errors.New("aucune session SecuBox — connectez-vous a l'administration avant de publier")
	}

	var b strings.Builder
	for _, m := range f.Messages {
		if !m.Public {
			r.Retenus++
			continue
		}
		r.Pris++
		// L'AUTORITE DE L'OPERATEUR EST ANONYMISANTE — c'est le coeur de
		// l'interet du dispositif, pas une omission.
		//
		// Les membres ecrivent a l'interieur sous leur pseudonyme, entre gens
		// qui se connaissent. Ce qui SORT est publie sous l'autorite de celui
		// qui publie. Sans cela, repondre a une question dans un salon
		// reviendrait a accepter d'etre cite nominativement sur internet un
		// jour — ce que personne n'a demande.
		//
		// Nommer reste possible, mais c'est une DECISION explicite.
		if f.Attribuer {
			fmt.Fprintf(&b, "**%s** — %s\n\n", m.Auteur, strings.TrimSpace(m.Corps))
		} else {
			fmt.Fprintf(&b, "%s\n\n", strings.TrimSpace(m.Corps))
		}
	}
	if r.Pris == 0 {
		return r, errors.New("aucun message public dans ce fil")
	}
	if f.Retour != "" {
		fmt.Fprintf(&b, "\n---\n\n[Discuter ce billet sur le BBS](%s)\n", f.Retour)
	}

	// LE CONTRAT DE BILLETS : `body`, `ref_url`, `embed_url`, `style`, `status`.
	//
	// billets est un MICRO-BLOG : il n'a pas de champ titre. Le premier jet
	// envoyait `title` et `url` — des champs qu'il ignore silencieusement. La
	// requete aurait ete acceptee, un billet vide cree, et le BBS aurait
	// enregistre un lien vers lui. Le titre vit donc DANS le corps.
	texte := "## " + strings.TrimSpace(f.Titre) + "\n\n" + b.String()
	charge, _ := json.Marshal(map[string]any{
		"body": texte,
		// `ref_url` et non `embed_url` : le billet RENVOIE vers la
		// conversation, il ne l'incorpore pas. Incorporer un fil de BBS dans
		// une page publique y ferait entrer des pseudonymes et des reponses
		// que personne n'a relus pour cet usage.
		"ref_url": f.Retour,
		"status":  "published",
	})

	req, err := http.NewRequest("POST", strings.TrimRight(c.Base, "/")+"/admin/api/billets",
		bytes.NewReader(charge))
	if err != nil {
		return r, err
	}
	// La session est relayee EN COOKIE, comme le navigateur l'aurait envoyee.
	// billets la valide aupres du noyau exactement comme pour une requete
	// directe : le BBS n'ajoute aucune autorite, il transmet celle qu'on lui a
	// presentee.
	req.Header.Set("Cookie", "secubox_session="+session)
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
