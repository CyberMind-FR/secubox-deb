// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

// Package diffusion publie les sujets de MetaNews comme BILLETS ÉPHÉMÈRES (#2268).
//
// Un sujet qui vient de se former (plusieurs sources, mis à jour à l'instant) passe dans le fil des billets pour quelques minutes — cinq par défaut —
// puis s'efface. MetaNews n'a aucune session d'exploitant : il parle à la socket de billets avec un jeton de flotte dont le seul pouvoir, côté billets,
// est de créer des billets à durée de vie limitée.
//
// GARDE-FOUS : plusieurs sources au moins (un événement, pas un article isolé) ; un plafond par heure ; un délai de grâce par sujet (jamais deux fois dans
// l'heure) ; une erreur de billets arrête le tour sans marquer le sujet — il repartira au tour suivant.
package diffusion

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
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/store"
)

type Config struct {
	TTL         time.Duration // durée de vie du billet
	MaxParHeure int           // plafond de sujets publiés par heure glissante
	MinSources  int           // un sujet doit être couvert par au moins ce nombre de sources
	Fenetre     time.Duration // un sujet n'est candidat que s'il a été mis à jour dans cette fenêtre
	Cooldown    time.Duration // délai de grâce avant de republier le même sujet
	SiteURL     string        // adresse publique de MetaNews (https://…), pour le lien du billet ; vide = pas de lien
}

type Charge struct {
	Titre  string // n'est pas envoyé ; sert aux journaux et aux tests
	Body   string
	RefURL string
	TTLs   int
}

type Reponse struct {
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	ExpiresAt string `json:"expires_at"`
}

type Poster func(ctx context.Context, c Charge) (Reponse, error)

type Diffuseur struct {
	st     *store.Store
	cfg    Config
	poster Poster
	jr     *log.Logger
}

func New(st *store.Store, cfg Config, poster Poster, jr *log.Logger) *Diffuseur {
	return &Diffuseur{st: st, cfg: cfg, poster: poster, jr: jr}
}

// Tour publie les sujets éligibles, dans la limite du plafond. Rend le nombre de billets créés.
func (d *Diffuseur) Tour(now int64) (int, error) {
	restant := d.cfg.MaxParHeure
	deja, err := d.st.DiffusesDepuis(now - 3600)
	if err != nil {
		return 0, err
	}
	restant -= deja
	if restant <= 0 {
		return 0, nil
	}
	sujets, err := d.st.SujetsADiffuser(now-int64(d.cfg.Fenetre.Seconds()), d.cfg.MinSources, now-int64(d.cfg.Cooldown.Seconds()), restant)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, t := range sujets {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		rep, err := d.poster(ctx, Charge{Titre: t.Title, Body: Corps(t, d.cfg.SiteURL), RefURL: refURL(t, d.cfg.SiteURL), TTLs: int(d.cfg.TTL.Seconds())})
		cancel()
		if err != nil {
			return n, fmt.Errorf("billets : %w", err) // on s'arrête : inutile d'insister sur un billets en panne
		}
		if err := d.st.MarquerDiffuse(t.ID, rep.ID, rep.Slug, now); err != nil {
			return n, err
		}
		d.jr.Printf("billet éphémère %s ← sujet %s (%d s)", rep.ID, t.ID, int(d.cfg.TTL.Seconds()))
		n++
	}
	return n, nil
}

func refURL(t store.Topic, site string) string {
	if !strings.HasPrefix(site, "https://") {
		return ""
	}
	return strings.TrimRight(site, "/") + "/#" + t.ID
}

// echapper neutralise le markdown et le HTML d'un texte venu d'un flux externe : le titre d'un article ne doit jamais mettre en forme le billet.
func echapper(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "`", "\\`", "[", `\[`, "]", `\]`, "<", "&lt;", ">", "&gt;", "#", `\#`)
	return strings.TrimSpace(r.Replace(strings.Join(strings.Fields(s), " ")))
}

// Corps compose le texte du billet : titre en gras, résumé, nombre de sources.
func Corps(t store.Topic, site string) string {
	var b strings.Builder
	b.WriteString("**" + echapper(t.Title) + "**")
	if r := echapper(t.Summary); r != "" {
		if len(r) > 600 {
			r = strings.TrimSpace(r[:600]) + "…"
		}
		b.WriteString("\n\n" + r)
	}
	b.WriteString(fmt.Sprintf("\n\n_%d sources_", t.SourcesCount))
	return b.String()
}

// ClientSocket rend un Poster qui appelle POST /service/ephemere de billets, directement sur sa socket Unix, avec un jeton de flotte de service.
func ClientSocket(socket, secret string) Poster {
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	return func(ctx context.Context, c Charge) (Reponse, error) {
		if secret == "" {
			return Reponse{}, errors.New("secret JWT de flotte absent : jamais de jeton signé avec une valeur vide")
		}
		charge := map[string]any{"body": c.Body, "ttl_s": c.TTLs}
		if c.RefURL != "" {
			charge["ref_url"] = c.RefURL
		}
		corps, _ := json.Marshal(charge)
		req, err := http.NewRequestWithContext(ctx, "POST", "http://billets/service/ephemere", bytes.NewReader(corps))
		if err != nil {
			return Reponse{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jetonService(secret, "metanews", 2*time.Minute))
		resp, err := hc.Do(req)
		if err != nil {
			return Reponse{}, err
		}
		defer resp.Body.Close()
		lu, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		if resp.StatusCode != 201 {
			return Reponse{}, fmt.Errorf("refus (%d) : %s", resp.StatusCode, strings.TrimSpace(string(lu[:min(len(lu), 200)])))
		}
		var rep Reponse
		if err := json.Unmarshal(lu, &rep); err != nil || rep.ID == "" {
			return Reponse{}, errors.New("réponse de billets illisible")
		}
		return rep, nil
	}
}

// jetonService fabrique un JWT HS256 de service (même format que le jeton qui appelle le BBS).
func jetonService(secret, sub string, ttl time.Duration) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{"sub": sub, "iss": "metanews", "iat": now.Unix(), "exp": now.Add(ttl).Unix()})
	pl := base64.RawURLEncoding.EncodeToString(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(hdr + "." + pl))
	return hdr + "." + pl + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
