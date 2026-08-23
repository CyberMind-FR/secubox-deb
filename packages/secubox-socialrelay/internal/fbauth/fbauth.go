// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package fbauth : flux OAuth « consent » de Meta pour SocialRelay.
//
// L'opérateur enregistre une app Meta (App ID + App Secret) et la dépose dans
// un fichier de secret. Le wizard génère l'URL d'autorisation (lien + QR),
// l'opérateur l'ouvre sur son appareil déjà connecté, approuve, Meta redirige
// vers /fb/callback avec un code, qu'on échange contre un jeton long-lived
// (~60 j) mis en cache. AUCUN cookie, AUCUN mot de passe, AUCUN scraping :
// c'est l'opérateur qui autorise l'app via le flux officiel de Meta.
package fbauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	graphVer    = "v20.0"
	dialogURL   = "https://www.facebook.com/" + graphVer + "/dialog/oauth"
	tokenURL    = "https://graph.facebook.com/" + graphVer + "/oauth/access_token"
	scopeDéfaut = "public_profile,pages_show_list,pages_read_engagement"
	stateTTL    = 10 * time.Minute
)

// Store : autorité du jeton Facebook (app creds + états CSRF + cache jeton).
type Store struct {
	appPath   string // secret opérateur : App ID + App Secret (2 lignes)
	tokenPath string // cache jeton (dossier d'état du démon, 0600)
	pubBase   string // base publique HTTPS pour le redirect_uri
	cli       *http.Client

	mu     sync.Mutex
	states map[string]time.Time
}

// New construit le Store. pubBase p.ex. "https://socialrelay.gk2.secubox.in".
func New(appPath, tokenPath, pubBase string) *Store {
	return &Store{
		appPath:   appPath,
		tokenPath: tokenPath,
		pubBase:   strings.TrimRight(pubBase, "/"),
		cli:       &http.Client{Timeout: 20 * time.Second},
		states:    map[string]time.Time{},
	}
}

// redirectURI est l'URL exacte à enregistrer dans l'app Meta.
func (s *Store) redirectURI() string {
	return s.pubBase + "/api/v1/socialrelay/fb/callback"
}

// appCreds lit App ID + App Secret depuis le secret opérateur.
// Format : deux lignes (id puis secret) ou "id:secret".
func (s *Store) appCreds() (id, secret string, err error) {
	b, err := os.ReadFile(s.appPath)
	if err != nil {
		return "", "", errors.New("app Meta non configurée (App ID/Secret absents)")
	}
	txt := strings.TrimSpace(string(b))
	if i := strings.IndexAny(txt, ":\n"); i >= 0 {
		id = strings.TrimSpace(txt[:i])
		secret = strings.TrimSpace(txt[i+1:])
	}
	// tolère des lignes clé=valeur
	for _, l := range strings.Split(txt, "\n") {
		l = strings.TrimSpace(l)
		if v, ok := strings.CutPrefix(l, "app_id="); ok {
			id = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "app_secret="); ok {
			secret = strings.TrimSpace(v)
		}
	}
	if id == "" || secret == "" {
		return "", "", errors.New("app Meta incomplète (App ID ou Secret manquant)")
	}
	return id, secret, nil
}

// Configured indique si l'app Meta est lisible et complète.
func (s *Store) Configured() bool {
	_, _, err := s.appCreds()
	return err == nil
}

// NouvelÉtat crée un état CSRF à usage unique.
func (s *Store) NouvelÉtat() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	st := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	// purge des états périmés
	now := time.Now()
	for k, exp := range s.states {
		if now.After(exp) {
			delete(s.states, k)
		}
	}
	s.states[st] = now.Add(stateTTL)
	return st, nil
}

// ConsommerÉtat valide et invalide un état (usage unique).
func (s *Store) ConsommerÉtat(st string) bool {
	if st == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.states[st]
	if !ok {
		return false
	}
	delete(s.states, st)
	return time.Now().Before(exp)
}

// URLAutorisation construit l'URL de dialogue OAuth de Meta pour cet état.
func (s *Store) URLAutorisation(st string) (string, error) {
	id, _, err := s.appCreds()
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("client_id", id)
	q.Set("redirect_uri", s.redirectURI())
	q.Set("state", st)
	q.Set("response_type", "code")
	q.Set("scope", scopeDéfaut)
	return dialogURL + "?" + q.Encode(), nil
}

// jetonCache : structure persistée (dossier d'état du démon).
type jetonCache struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   int64  `json:"expires_at"`
	ObtainedAt  int64  `json:"obtained_at"`
}

type réponseJeton struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Erreur      *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Échanger échange le code d'autorisation contre un jeton long-lived et le
// met en cache. now = horodatage courant (injectable pour les tests).
func (s *Store) Échanger(ctx context.Context, code string, now time.Time) error {
	id, secret, err := s.appCreds()
	if err != nil {
		return err
	}
	// 1. code -> jeton court
	court, _, err := s.appelJeton(ctx, url.Values{
		"client_id":     {id},
		"redirect_uri":  {s.redirectURI()},
		"client_secret": {secret},
		"code":          {code},
	})
	if err != nil {
		return fmt.Errorf("échange code : %w", err)
	}
	// 2. jeton court -> jeton long-lived
	long, exp, err := s.appelJeton(ctx, url.Values{
		"grant_type":        {"fb_exchange_token"},
		"client_id":         {id},
		"client_secret":     {secret},
		"fb_exchange_token": {court},
	})
	if err != nil {
		// certains flux renvoient déjà un jeton long : on garde le court.
		long, exp = court, 0
	}
	jc := jetonCache{AccessToken: long, ObtainedAt: now.Unix()}
	if exp > 0 {
		jc.ExpiresAt = now.Add(time.Duration(exp) * time.Second).Unix()
	}
	return s.écrireCache(jc)
}

func (s *Store) appelJeton(ctx context.Context, q url.Values) (string, int64, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL+"?"+q.Encode(), nil)
	resp, err := s.cli.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	var r réponseJeton
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", 0, err
	}
	if r.Erreur != nil {
		return "", 0, errors.New(r.Erreur.Message)
	}
	if r.AccessToken == "" {
		return "", 0, errors.New("réponse sans jeton")
	}
	return r.AccessToken, r.ExpiresIn, nil
}

func (s *Store) écrireCache(jc jetonCache) error {
	b, _ := json.Marshal(jc)
	tmp := s.tokenPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.tokenPath)
}

func (s *Store) lireCache() (jetonCache, bool) {
	b, err := os.ReadFile(s.tokenPath)
	if err != nil {
		return jetonCache{}, false
	}
	var jc jetonCache
	if json.Unmarshal(b, &jc) != nil || jc.AccessToken == "" {
		return jetonCache{}, false
	}
	return jc, true
}

// Jeton retourne le jeton en cache s'il est encore valide (marge 1 j).
func (s *Store) Jeton() string {
	jc, ok := s.lireCache()
	if !ok {
		return ""
	}
	if jc.ExpiresAt > 0 && time.Now().Add(24*time.Hour).After(time.Unix(jc.ExpiresAt, 0)) {
		return "" // périmé (ou sur le point de) : forcer une reconnexion
	}
	return jc.AccessToken
}

// Statut : état du wizard pour l'UI.
type Statut struct {
	Configured bool   `json:"configured"`
	Connected  bool   `json:"connected"`
	ExpiresAt  int64  `json:"expires_at"`
	Redirect   string `json:"redirect_uri"`
}

func (s *Store) Statut() Statut {
	jc, _ := s.lireCache()
	return Statut{
		Configured: s.Configured(),
		Connected:  s.Jeton() != "",
		ExpiresAt:  jc.ExpiresAt,
		Redirect:   s.redirectURI(),
	}
}
