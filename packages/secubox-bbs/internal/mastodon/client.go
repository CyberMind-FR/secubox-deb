// Package mastodon parle a une instance du fediverse au nom d'UN membre.
//
// LE SENS DE LA DEPENDANCE, comme pour billets : le BBS appelle Mastodon,
// jamais l'inverse. Une instance qui tombe ne doit pas emporter le BBS.
//
// CE QUE CE CLIENT NE FAIT JAMAIS, ET POURQUOI :
//
//   - publier sous une identite qui n'est pas celle du porteur du jeton. Il n'y
//     a pas de jeton d'administration ici : chaque appel porte le jeton d'un
//     membre, obtenu par son propre aller-retour OAuth.
//
//   - deviner un compte a partir d'un pseudonyme. Le compte lie est celui que
//     l'instance NOMME au retour de `verify_credentials`, jamais celui qu'on
//     aurait deduit du nom local.
//
//   - demander plus de droits qu'il n'en faut. La portee est exactement
//     « lire mon compte, ecrire des statuts » : ni lecture des messages prives,
//     ni gestion des abonnements, ni moderation.
package mastodon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Portee : le strict necessaire.
//
// `read:accounts` sert a SAVOIR QUI on vient de lier — sans quoi on afficherait
// un pseudonyme devine. `write:statuses` publie. Rien d'autre n'est demande :
// une portee large serait acceptee sans discuter par le membre, qui clique sur
// un ecran de consentement dont il ne lira pas le detail.
const Portee = "read:accounts write:statuses"

var (
	ErrInstanceRefusee = errors.New("instance refusee")
	ErrPasAutorise     = errors.New("l'instance a refuse le jeton — reliez votre compte")
)

// Client parle a UNE instance.
type Client struct {
	Instance string // hote normalise
	HTTP     *http.Client
}

// Nouveau construit un client vers une instance.
//
// `interne` est l'instance de la maison, telle que les reglages la nomment :
// elle est jointe SANS controle d'adresse, parce qu'elle vit precisement sur le
// reseau local — voir `VerifieHote`.
func Nouveau(instance, interne string) (*Client, error) {
	if err := VerifieHote(instance, interne); err != nil {
		return nil, err
	}
	return &Client{
		Instance: instance,
		HTTP: &http.Client{
			// UNE INSTANCE LENTE NE DOIT PAS RETENIR UNE REQUETE DU BBS. Le
			// demon sert toutes ses pages sur une seule boucle : un appel
			// sortant sans borne y bloquerait tout le monde.
			Timeout: 12 * time.Second,
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				// UNE REDIRECTION EST UN CONTOURNEMENT DU CONTROLE D'ADRESSE :
				// l'hote verifie renverrait vers 127.0.0.1 et l'appel partirait
				// quand meme. On ne suit rien.
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// VerifieHote decide si le serveur a le droit d'appeler cet hote.
//
// LE PROBLEME EST REEL ET SPECIFIQUE A CETTE FONCTIONNALITE : l'instance est
// TAPEE PAR LE MEMBRE. Sans controle, n'importe qui obtiendrait du BBS qu'il
// emette des requetes vers le reseau interne — les services d'administration,
// les sockets d'autres modules, les adresses de metadonnees. C'est la faille
// classique dite SSRF, et elle est ici a portee de formulaire.
//
// MAIS LE REFLEXE « INTERDIRE TOUTE ADRESSE PRIVEE » CASSERAIT LE CAS PRINCIPAL :
// l'instance de la maison est justement sur le reseau local. On distingue donc
// deux situations au lieu d'appliquer une regle unique qui aurait l'air plus
// stricte tout en rendant la fonction inutilisable :
//
//   - l'instance CONFIGUREE par le sysop est jointe telle quelle. Elle n'est pas
//     choisie par le membre, elle est le reglage de la maison ;
//   - toute AUTRE instance doit resoudre vers des adresses publiques, et
//     seulement vers elles.
func VerifieHote(instance, interne string) error {
	h := strings.ToLower(strings.TrimSpace(instance))
	if h == "" {
		return fmt.Errorf("%w : adresse vide", ErrInstanceRefusee)
	}
	if strings.ContainsAny(h, "/\\ @:") {
		return fmt.Errorf("%w : %q n'est pas un nom d'hote", ErrInstanceRefusee, instance)
	}
	// L'instance de la maison : c'est un reglage, pas une saisie de membre.
	if interne != "" && h == strings.ToLower(strings.TrimSpace(interne)) {
		return nil
	}
	adrs, err := net.LookupIP(h)
	if err != nil {
		return fmt.Errorf("%w : %s introuvable", ErrInstanceRefusee, h)
	}
	if len(adrs) == 0 {
		return fmt.Errorf("%w : %s ne resout vers rien", ErrInstanceRefusee, h)
	}
	for _, ip := range adrs {
		if !estPublique(ip) {
			// ON NE DIT PAS VERS QUOI ELLE RESOUT. Le message renseignerait sur
			// la topologie interne qui que ce soit ayant un compte.
			return fmt.Errorf("%w : %s designe une adresse du reseau interne",
				ErrInstanceRefusee, h)
		}
	}
	return nil
}

// estPublique : tout ce qui n'est pas routable sur internet est refuse.
func estPublique(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	// 100.64.0.0/10 (CGNAT, dont Tailscale) n'est pas couvert par IsPrivate.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	return true
}

func (c *Client) url(chemin string) string { return "https://" + c.Instance + chemin }

// App : ce qu'une instance rend a l'enregistrement.
type App struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// EnregistreApp declare le BBS aupres de l'instance. Fait UNE FOIS par instance.
func (c *Client) EnregistreApp(ctx context.Context, nom, siteWeb, retour string) (App, error) {
	var a App
	v := url.Values{
		"client_name":   {nom},
		"redirect_uris": {retour},
		"scopes":        {Portee},
		"website":       {siteWeb},
	}
	if err := c.postForm(ctx, "/api/v1/apps", "", v, &a); err != nil {
		return a, err
	}
	if a.ClientID == "" || a.ClientSecret == "" {
		return a, errors.New("l'instance n'a pas rendu d'identifiants d'application")
	}
	return a, nil
}

// URLAutorisation : l'adresse ou envoyer le membre pour qu'il consente.
func (c *Client) URLAutorisation(clientID, retour, etat string) string {
	v := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {retour},
		"response_type": {"code"},
		"scope":         {Portee},
		"state":         {etat},
		// L'ecran de consentement est REDEMANDE meme si le membre a deja
		// autorise : relier son compte doit etre un acte visible, pas une
		// redirection qui revient toute seule.
		"force_login": {"false"},
	}
	return c.url("/oauth/authorize") + "?" + v.Encode()
}

type jetonRendu struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
}

// EchangeCode transforme le code du retour en jeton personnel.
func (c *Client) EchangeCode(ctx context.Context, clientID, secret, code, retour string) (jeton, portee string, err error) {
	var j jetonRendu
	v := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"redirect_uri":  {retour},
		"code":          {code},
		"scope":         {Portee},
	}
	if err := c.postForm(ctx, "/oauth/token", "", v, &j); err != nil {
		return "", "", err
	}
	if j.AccessToken == "" {
		return "", "", errors.New("l'instance n'a pas rendu de jeton")
	}
	return j.AccessToken, j.Scope, nil
}

// Compte : ce que l'instance dit du porteur du jeton.
type Compte struct {
	ID   string `json:"id"`
	Acct string `json:"acct"`
	URL  string `json:"url"`
}

// QuiSuisJe demande a l'instance QUI est le porteur du jeton.
//
// C'EST LE SEUL ETABLISSEMENT D'IDENTITE DE TOUTE LA PASSERELLE. Le compte lie
// est celui que l'instance nomme ici — jamais celui qu'on aurait deduit du
// pseudonyme local.
func (c *Client) QuiSuisJe(ctx context.Context, jeton string) (Compte, error) {
	var m Compte
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.url("/api/v1/accounts/verify_credentials"), nil)
	if err != nil {
		return m, err
	}
	req.Header.Set("Authorization", "Bearer "+jeton)
	if err := c.faire(req, &m); err != nil {
		return m, err
	}
	if m.ID == "" {
		return m, errors.New("l'instance n'a pas nomme le compte")
	}
	return m, nil
}

// Statut : ce qui est publie.
type Statut struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// Publie ecrit un statut sous l'identite du porteur du jeton.
//
// `visibilite` suit le vocabulaire de Mastodon : public, unlisted, private,
// direct. L'appelant choisit — le BBS ne force pas « public » : republier un
// fil dans son cercle restreint est un usage legitime.
func (c *Client) Publie(ctx context.Context, jeton, texte, visibilite string) (Statut, error) {
	var st Statut
	if strings.TrimSpace(texte) == "" {
		return st, errors.New("statut vide")
	}
	if visibilite == "" {
		visibilite = "public"
	}
	v := url.Values{"status": {texte}, "visibility": {visibilite}}
	err := c.postForm(ctx, "/api/v1/statuses", jeton, v, &st)
	return st, err
}

func (c *Client) postForm(ctx context.Context, chemin, jeton string, v url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(chemin),
		strings.NewReader(v.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if jeton != "" {
		req.Header.Set("Authorization", "Bearer "+jeton)
	}
	return c.faire(req, out)
}

func (c *Client) faire(req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("instance injoignable : %w", err)
	}
	defer res.Body.Close()

	// LA LECTURE EST BORNEE. Une instance hostile — ou simplement en panne —
	// pourrait repondre un flux sans fin, et le demon le lirait jusqu'a manquer
	// de memoire. 1 Mio est trois ordres de grandeur au-dessus de ce qu'une
	// reponse d'API mesure.
	corps, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return ErrPasAutorise
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		// LE MESSAGE DE L'INSTANCE EST REMONTE, borne : « erreur 422 » sans
		// explication ferait chercher la panne du mauvais cote.
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(corps, &e)
		if e.Error != "" {
			return fmt.Errorf("l'instance a refuse (%d) : %s", res.StatusCode, court(e.Error))
		}
		return fmt.Errorf("l'instance a repondu %d", res.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(corps, out)
}

func court(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
