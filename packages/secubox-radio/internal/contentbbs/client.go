// Package contentbbs parle au content spine du BBS (#1166) : un
// ContentObject federe toutes les representations d'un meme contenu source
// (radio, billets, mediatheque…), reliees par leur provenance. Voir
// packages/secubox-bbs/internal/web/api_content.go pour le contrat cote
// serveur — ce client en est le miroir cote appelant.
//
// LE SENS DE LA DEPENDANCE : la radio appelle le BBS, jamais l'inverse. Un
// BBS injoignable ne doit jamais empecher l'antenne de tourner — c'est
// pourquoi CHAQUE ECHEC EST REMONTE A L'APPELANT PLUTOT QUE PANIQUE : c'est a
// la boucle de validation (task B2) de decider qu'un contenu spine manquant
// n'est pas un motif d'arret.
//
// SOCKET UNIX + JWT DE FLOTTE, comme billets/pipeline avant lui
// (internal/billets, internal/pipeline dans secubox-bbs/secubox-socialrelay) :
// jamais de port TCP direct, jamais de secret vide qui signerait un jeton que
// n'importe qui pourrait rejouer.
package contentbbs

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

// Objet : ce qu'on demande au BBS de federer.
type Objet struct {
	Type  string
	Title string
	// Metadata est du JSON DEJA ENCODE (chaine). Vide -> "{}" cote serveur.
	Metadata string
}

// Prov : une provenance de l'objet. La regle d'or du spine (constraints.md) :
// il en faut TOUJOURS au moins une avec Original=true — le serveur la refuse
// sinon, et ce client ne la contourne pas.
type Prov struct {
	SourceURL  string
	SourceType string
	Original   bool
}

// Comment : un point de la timeline d'un ContentObject, tel que rendu par
// GET .../timeline.
type Comment struct {
	ID          int64  `json:"id"`
	Author      string `json:"author"`
	AuthorID    int64  `json:"author_id"`
	OffsetMS    int64  `json:"offset_ms"`
	Body        string `json:"body"`
	BroadcastAt int64  `json:"broadcast_at"`
	CreatedAt   int64  `json:"created_at"`
}

// Client parle au content spine du BBS.
//
// Base/HTTP sont EXPORTES, comme dans billets.Client et ytsas.Client : un test
// pointe Base vers un httptest.NewServer et pose un HTTP.Client sans dialer
// particulier, sans jamais toucher a une socket unix reelle.
type Client struct {
	Base string // "http://bbs" (socket unix) ou l'URL d'un serveur de test
	HTTP *http.Client
	// Secret signe le jeton de flotte (api.jwt_secret, le meme que lit le
	// BBS). VIDE, AUCUN APPEL NE PART — un jeton signe avec une valeur par
	// defaut serait accepte par tout service faisant la meme erreur.
	Secret string
	// Sub est le sujet du jeton ("radio" par defaut) — sert au BBS a savoir
	// quel module de la flotte a parle, pour ses journaux.
	Sub string
}

// New construit un client parlant au BBS par sa socket unix
// (/run/secubox/bbs.sock).
func New(socketPath, jwtSecret string) *Client {
	return &Client{
		Base:   "http://bbs",
		Secret: jwtSecret,
		Sub:    "radio",
		HTTP: &http.Client{
			// 5 s : genereux pour un appel local par socket, borne pour que
			// l'antenne ne reste jamais suspendue derriere un BBS en panne.
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

// Creer ouvre un ContentObject. POST /api/v1/bbs/content. Idempotent cote
// serveur sur la provenance originale.
func (c *Client) Creer(o Objet, prov []Prov) (string, error) {
	meta := strings.TrimSpace(o.Metadata)
	if meta == "" {
		meta = "{}"
	}
	entrees := make([]map[string]any, 0, len(prov))
	for _, p := range prov {
		entrees = append(entrees, map[string]any{
			"source_url": p.SourceURL, "source_type": p.SourceType, "original": p.Original,
		})
	}
	var out struct {
		OK bool   `json:"ok"`
		ID string `json:"id"`
	}
	if err := c.appel(http.MethodPost, "/api/v1/bbs/content", map[string]any{
		"type": o.Type, "title": o.Title, "metadata": json.RawMessage(meta),
		"provenance": entrees,
	}, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// Representation rattache une representation (radio, billets…) a un
// ContentObject deja ouvert. POST .../representation. Idempotent cote
// serveur (UNIQUE content_id,kind,module,ref).
func (c *Client) Representation(id, kind, module, ref string, isCache bool) error {
	var out struct {
		OK bool `json:"ok"`
	}
	return c.appel(http.MethodPost, "/api/v1/bbs/content/"+id+"/representation", map[string]any{
		"kind": kind, "module": module, "ref": ref, "is_cache": isCache, "url": "",
	}, &out)
}

// Event journalise une decision (append-only cote serveur). POST .../event.
func (c *Client) Event(id, kind, actor, payloadJSON string) error {
	pl := strings.TrimSpace(payloadJSON)
	if pl == "" {
		pl = "{}"
	}
	var out struct {
		OK bool `json:"ok"`
	}
	return c.appel(http.MethodPost, "/api/v1/bbs/content/"+id+"/event", map[string]any{
		"kind": kind, "actor": actor, "payload": json.RawMessage(pl),
	}, &out)
}

// Topic ouvre (ou retrouve, idempotent cote serveur) le fil BBS qui porte la
// discussion du ContentObject. POST .../topic -> bbs_topic_id.
func (c *Client) Topic(id string) (int64, error) {
	var out struct {
		OK         bool  `json:"ok"`
		BBSTopicID int64 `json:"bbs_topic_id"`
	}
	if err := c.appel(http.MethodPost, "/api/v1/bbs/content/"+id+"/topic", nil, &out); err != nil {
		return 0, err
	}
	return out.BBSTopicID, nil
}

// Timeline depose un commentaire synchronise sur le ContentObject. POST
// .../timeline.
//
// L'IDENTITE N'EST PLUS FOURNIE PAR CE CLIENT (correctif B4,
// constraints.md/task-B4-report.md) : le BBS est desormais SEUL JUGE de qui
// a poste — un author_id/author fabrique ou releve d'une source non
// authentifiee (ex. le pseudo `sbx_radio` cote client, Math.random()) aurait
// pu attribuer un commentaire persiste au mauvais compte, ou a aucun.
// Ce client se contente de relayer memberToken — le sbx_token PROPRE du
// posteur, distinct du jeton de flotte que jeton() signe pour l'appelant
// (le module radio lui-meme) — dans l'entete X-Sbx-Member. Le serveur
// verifie ce jeton et resout sub -> membre lui-meme
// (packages/secubox-bbs/internal/web/api_content.go, membreDepuisJeton) et
// rend 400 si le jeton est absent, invalide, expire, ou sans compte BBS —
// remonte tel quel plutot que de passer pour un succes.
func (c *Client) Timeline(id, memberToken string, offsetMS int64, body string) error {
	var out struct {
		OK bool `json:"ok"`
	}
	return c.appelAvecEntetes(http.MethodPost, "/api/v1/bbs/content/"+id+"/timeline", map[string]any{
		"offset_ms": offsetMS, "body": body,
	}, &out, map[string]string{"X-Sbx-Member": memberToken})
}

// TimelineDe lit les commentaires d'un ContentObject. GET .../timeline.
func (c *Client) TimelineDe(id string) ([]Comment, error) {
	var out struct {
		OK       bool      `json:"ok"`
		Comments []Comment `json:"comments"`
	}
	if err := c.appel(http.MethodGet, "/api/v1/bbs/content/"+id+"/timeline", nil, &out); err != nil {
		return nil, err
	}
	return out.Comments, nil
}

// appel fait la requete JSON : marshal du corps (si non nil), en-tete
// d'autorisation avec le jeton de flotte, decodage borne de la reponse.
// Regroupe ici pour que chaque methode publique reste un simple mappage
// route<->charge, sans repeter la marche a suivre HTTP.
func (c *Client) appel(methode, chemin string, corps any, out any) error {
	return c.appelAvecEntetes(methode, chemin, corps, out, nil)
}

// appelAvecEntetes est appel, avec des entetes SUPPLEMENTAIRES posees
// APRES Authorization — jamais a sa place. Seule Timeline s'en sert
// aujourd'hui (X-Sbx-Member, le jeton du posteur, distinct du jeton de
// flotte qui identifie le module appelant) ; les autres methodes passent
// `nil` via appel().
func (c *Client) appelAvecEntetes(methode, chemin string, corps any, out any, entetes map[string]string) error {
	jeton, err := c.jeton()
	if err != nil {
		return err
	}
	var r io.Reader
	if corps != nil {
		b, err := json.Marshal(corps)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(methode, strings.TrimRight(c.Base, "/")+chemin, r)
	if err != nil {
		return err
	}
	if corps != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+jeton)
	for k, v := range entetes {
		req.Header.Set(k, v)
	}

	cl := c.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 5 * time.Second}
	}
	res, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("bbs injoignable : %w", err)
	}
	defer res.Body.Close()
	brut, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("bbs a refuse (%d) : %s", res.StatusCode,
			strings.TrimSpace(string(brut[:min(len(brut), 200)])))
	}
	if out == nil || len(brut) == 0 {
		return nil
	}
	return json.Unmarshal(brut, out)
}

// jeton signe un JWT HS256 de service, comme signerJeton dans
// secubox-socialrelay/internal/pipeline et secubox-metanews/internal/web : le
// meme algorithme, le meme secret de flotte (api.jwt_secret), pour que
// l'AUTH DU BBS TRAITE TOUS LES APPELANTS DE LA MEME FACON.
//
// UN SECRET VIDE NE SIGNE RIEN : un deploiement qui a oublie de poser
// api.jwt_secret ne doit pas parler au BBS avec un jeton que n'importe qui
// pourrait reproduire.
func (c *Client) jeton() (string, error) {
	if strings.TrimSpace(c.Secret) == "" {
		return "", errors.New("secret JWT de flotte absent (api.jwt_secret) : appel refuse")
	}
	sub := c.Sub
	if sub == "" {
		sub = "radio"
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	hdr := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now()
	claims, err := json.Marshal(map[string]any{
		"sub": sub, "iss": "secubox-radio",
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	pl := b64(claims)
	mac := hmac.New(sha256.New, []byte(c.Secret))
	mac.Write([]byte(hdr + "." + pl))
	return hdr + "." + pl + "." + b64(mac.Sum(nil)), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
