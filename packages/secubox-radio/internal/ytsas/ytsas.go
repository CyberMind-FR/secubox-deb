// Package ytsas recupere l'audio d'une piste via la passerelle yt-dlp deja
// deployee sur la board.
//
// POURQUOI PASSER PAR ELLE plutot qu'embarquer le lecteur YouTube : l'API
// IFrame ferait dialoguer LE NAVIGATEUR DE CHAQUE AUDITEUR avec Google. Ici le
// fichier est recupere UNE FOIS, mis en cache, puis servi depuis chez nous —
// aucun contact tiers depuis les postes, et la synchronisation devient triviale
// puisque c'est notre fichier avec notre horloge.
package ytsas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Entree : ce que la passerelle dit d'une piste.
type Entree struct {
	ID      string  `json:"id"`
	URL     string  `json:"url"`
	Titre   string  `json:"title"`
	Chemin  string  `json:"path"`
	Complet int     `json:"complete"`
	Progres float64 `json:"progress"`
	Etat    string  `json:"job_status"`
}

// Pret dit si le fichier est utilisable.
func (e Entree) Pret() bool { return e.Complet == 1 && e.Etat == "complete" }

var (
	// ErrPasPrete : la recuperation est en cours. CE N'EST PAS UNE ERREUR — la
	// piste reste dans la file avec son etat, et l'on repassera.
	ErrPasPrete = errors.New("recuperation en cours")
	// ErrTropGros : au-dela de la borne. Ecarte avec une raison lisible plutot
	// que de remplir le disque en silence.
	ErrTropGros = errors.New("fichier trop volumineux")
)

type Client struct {
	Base string // http://10.100.0.180:8091
	HTTP *http.Client
	// OctetsMax borne UN fichier. Le parc entier est borne ailleurs, par la
	// purge : les deux bornes repondent a deux questions differentes, et n'en
	// avoir qu'une laisse toujours un trou.
	OctetsMax int64
}

func Nouveau(base string, octetsMax int64) *Client {
	return &Client{
		Base: base,
		// UN DELAI GENEREUX MAIS BORNE : un telechargement peut durer, une
		// passerelle en panne ne doit pas retenir le recuperateur pour
		// toujours.
		HTTP:      &http.Client{Timeout: 10 * time.Minute},
		OctetsMax: octetsMax,
	}
}

func (c *Client) url(chemin string) string { return c.Base + "/api/v1/ytsas" + chemin }

// Demande depose une adresse dans la passerelle.
func (c *Client) Demande(ctx context.Context, adresse string) error {
	corps, _ := json.Marshal(map[string]string{"url": adresse})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/add"),
		bytesReader(corps))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("passerelle injoignable : %w", err)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("la passerelle a refuse (%d)", res.StatusCode)
	}
	return nil
}

// Etat cherche une piste dans la bibliotheque de la passerelle.
func (c *Client) Etat(ctx context.Context, ytID string) (Entree, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/list"), nil)
	if err != nil {
		return Entree{}, err
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return Entree{}, fmt.Errorf("passerelle injoignable : %w", err)
	}
	defer res.Body.Close()
	// LA LECTURE EST BORNEE : une passerelle en panne pourrait repondre un flux
	// sans fin, et le demon le lirait jusqu'a manquer de memoire.
	brut, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return Entree{}, err
	}
	// La reponse est soit une liste, soit un objet qui en contient une : on
	// accepte les deux plutot que de casser au premier changement de forme.
	var liste []Entree
	if err := json.Unmarshal(brut, &liste); err != nil {
		var enveloppe map[string]json.RawMessage
		if err2 := json.Unmarshal(brut, &enveloppe); err2 != nil {
			return Entree{}, err
		}
		for _, v := range enveloppe {
			if json.Unmarshal(v, &liste) == nil && len(liste) > 0 {
				break
			}
		}
	}
	for _, e := range liste {
		if e.ID == ytID {
			return e, nil
		}
	}
	return Entree{}, ErrPasPrete
}

// Rapatrie ecrit le fichier dans le parc et rend son chemin, sa taille et son
// type.
func (c *Client) Rapatrie(ctx context.Context, ytID, versRepertoire string) (chemin, mime string, octets int64, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/files/"+ytID), nil)
	if err != nil {
		return "", "", 0, err
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", 0, fmt.Errorf("passerelle injoignable : %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", "", 0, fmt.Errorf("la passerelle rend %d", res.StatusCode)
	}
	if err := os.MkdirAll(versRepertoire, 0o750); err != nil {
		return "", "", 0, err
	}
	mime = res.Header.Get("Content-Type")
	ext := extensionDe(mime)

	// ON ECRIT DANS UN FICHIER TEMPORAIRE PUIS ON RENOMME. Sans cela, une
	// coupure en cours de route laisserait un fichier tronque que la base
	// declarerait « en cache » — la piste passerait, et s'arreterait au milieu.
	tmp, err := os.CreateTemp(versRepertoire, ".part-*")
	if err != nil {
		return "", "", 0, err
	}
	defer os.Remove(tmp.Name())

	// UN OCTET DE PLUS QUE LA BORNE : s'il arrive, c'est qu'elle est depassee.
	n, err := io.Copy(tmp, io.LimitReader(res.Body, c.OctetsMax+1))
	tmp.Close()
	if err != nil {
		return "", "", 0, err
	}
	if c.OctetsMax > 0 && n > c.OctetsMax {
		return "", "", 0, fmt.Errorf("%w (%d Mio)", ErrTropGros, n>>20)
	}
	final := filepath.Join(versRepertoire, ytID+ext)
	if err := os.Rename(tmp.Name(), final); err != nil {
		return "", "", 0, err
	}
	if err := os.Chmod(final, 0o640); err != nil {
		return "", "", 0, err
	}
	return final, mime, n, nil
}

// extensionDe : ce que le type annonce.
//
// L'EXTENSION EST DECORATIVE ICI — le type servi vient de la base, pas du nom.
// Elle n'est la que pour qu'un humain qui regarde le parc s'y retrouve.
func extensionDe(mime string) string {
	switch {
	case contient(mime, "audio/ogg"), contient(mime, "audio/opus"):
		return ".ogg"
	case contient(mime, "audio/mpeg"):
		return ".mp3"
	case contient(mime, "audio/mp4"), contient(mime, "audio/aac"):
		return ".m4a"
	case contient(mime, "video/mp4"):
		return ".mp4"
	case contient(mime, "video/webm"), contient(mime, "audio/webm"):
		return ".webm"
	}
	return ".bin"
}

func contient(s, sous string) bool {
	return len(s) >= len(sous) && (s == sous || (len(s) > len(sous) && s[:len(sous)] == sous))
}

func bytesReader(b []byte) io.Reader { return &lecteur{b: b} }

type lecteur struct {
	b []byte
	i int
}

func (l *lecteur) Read(p []byte) (int, error) {
	if l.i >= len(l.b) {
		return 0, io.EOF
	}
	n := copy(p, l.b[l.i:])
	l.i += n
	return n, nil
}

// Flux ouvre le media d'une piste chez la passerelle, en relayant la plage
// demandee.
//
// ── POURQUOI RELAYER PLUTOT QUE RAPATRIER ───────────────────────────────────
//
// La premiere version copiait le fichier dans un parc a nous. Le deploiement a
// montre ce que cela voulait dire : un clip pese 660 Mio, et le parc de ytsas
// comme le notre vivent sur LE MEME `/data`. On aurait donc ecrit 660 Mio a
// cote de 660 Mio identiques, sur le meme disque, pour chaque titre.
//
// ytsas sert deja les plages (`206`, `Accept-Ranges`) : il ne manquait qu'a
// relayer. La radio ne garde plus rien, et la retention redevient l'affaire de
// ytsas — qui a deja `conserve`, `keep` et `ephemeral` pour cela.
//
// Ce que cela coute : la passerelle doit etre debout AU MOMENT DE L'ECOUTE, et
// plus seulement au moment de la recuperation. C'est un vrai report de
// dependance, assume — dupliquer un demi-gigaoctet par titre pour s'en
// affranchir serait payer trop cher.
func (c *Client) Flux(ctx context.Context, ytID string, plage string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/stream/"+ytID), nil)
	if err != nil {
		return nil, err
	}
	// LA PLAGE EST TRANSMISE TELLE QUELLE : c'est elle qui permet a un auditeur
	// de rejoindre le direct a 3 min 41 sans telecharger ce qui precede.
	if plage != "" {
		req.Header.Set("Range", plage)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("passerelle injoignable : %w", err)
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusPartialContent {
		res.Body.Close()
		return nil, fmt.Errorf("la passerelle rend %d", res.StatusCode)
	}
	return res, nil
}

// EstMedia dit si un type annonce est bien du son ou de l'image animee.
//
// LA VERIFICATION QUI MANQUAIT, ET QUI A COUTE LE DEFAUT. `/files/{id}` rend du
// JSON decrivant les fichiers, pas les fichiers : la premiere version a pris
// ces 65 octets pour un clip, les a ecrits dans le parc, et a marque la piste
// « en cache ». La radio aurait joue du JSON.
//
// On ne fait plus confiance a ce qu'on recoit : un type qui n'est ni audio ni
// video n'est pas un media, quelle que soit la route qui l'a rendu.
func EstMedia(mime string) bool {
	return contient(mime, "audio/") || contient(mime, "video/")
}
