// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package api

import (
	"encoding/binary"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/audio"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/moteur"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/ser"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/store"
)

// LA WEBSOCKET VA DANS LES DEUX SENS, et c'est tout le montage de ce module :
//
//   navigateur → board : des blocs PCM bruts (Int16 petit-boutiste, 48 kHz
//                        mono), en trames BINAIRES ;
//   board → navigateur : une image d'analyse en JSON, vingt fois par seconde.
//
// Le micro est celui de la personne ; l'analyse est sur la board. L'audio
// traverse le réseau LOCAL et s'arrête là : rien n'est écrit sur le disque,
// rien ne sort de la maison.

const (
	// Assez grand pour un bloc de 4096 échantillons (8 ko) avec de la marge,
	// assez petit pour qu'un client bavard ne puisse pas nous faire enfler.
	tailleMaxMessage = 64 << 10
	imagesParSeconde = 20
	// Un navigateur qui ne dit plus rien pendant ce temps est parti ; sans
	// cette échéance, sa session et sa goroutine resteraient indéfiniment.
	silenceMax = 30 * time.Second
)

var promoteur = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// LE MICRO EST UNE PERMISSION ACCORDÉE PAR LA PERSONNE : on n'ouvre la
	// WebSocket qu'aux pages servies par la box elle-même. Sans cette
	// vérification, n'importe quel site pourrait, depuis un onglet ouvert,
	// pousser du son vers la board.
	CheckOrigin: memeOrigine,
}

func memeOrigine(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		// Pas d'origine : ce n'est pas un navigateur (curl, un test). On
		// accepte — le service n'écoute que sur une socket unix derrière
		// nginx, qui porte l'authentification.
		return true
	}
	hote := r.Host
	for _, prefixe := range []string{"http://", "https://"} {
		if o == prefixe+hote {
			return true
		}
	}
	return false
}

type message struct {
	Type string `json:"type"`
	// Ref : la clé que le navigateur présente pour retrouver sa référence.
	// Il la fabrique et la garde lui-même ; le serveur ne l'attribue pas.
	Ref             string `json:"ref,omitempty"`
	Echantillonnage int    `json:"sampleRate,omitempty"`
	Motif           string `json:"motif,omitempty"`
	Session         string `json:"session,omitempty"`
	Reserve         string `json:"reserve,omitempty"`
	Images          int    `json:"images,omitempty"`
}

func (s *Serveur) websocket(w http.ResponseWriter, r *http.Request) {
	c, err := promoteur.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade a déjà répondu
	}
	defer c.Close()
	c.SetReadLimit(tailleMaxMessage)

	sess := s.Sessions.Ouvre(r.RemoteAddr)
	defer func() {
		// ON ENREGISTRE AVANT DE PARTIR. Sans cela, une session fermée avant
		// le prochain battement d'archivage perdrait tout ce qu'elle a appris
		// — exactement le défaut qu'on répare.
		s.enregistreReference(sess)
		s.Sessions.Ferme(sess)
	}()

	_ = c.WriteJSON(message{
		Type: "pret", Session: sess.ID, Images: imagesParSeconde,
		Echantillonnage: audio.Echantillonnage, Reserve: ser.Reserve,
	})

	// L'écriture des images se fait depuis UNE SEULE goroutine : la
	// bibliothèque interdit deux écritures concurrentes, et le bug qui en
	// résulte est intermittent, donc pénible.
	stop := make(chan struct{})
	defer close(stop)
	go s.envoieImages(c, sess, stop)

	if s.Store != nil {
		go s.archive(sess, stop)
	}

	for {
		_ = c.SetReadDeadline(time.Now().Add(silenceMax))
		genre, corps, err := c.ReadMessage()
		if err != nil {
			return
		}
		switch genre {
		case websocket.BinaryMessage:
			// DU SON. C'est le cas courant, et il doit être le moins cher :
			// pas de JSON, pas d'allocation par échantillon.
			sess.Touche()
			sess.Source.Pousse(versFlottants(corps))
		case websocket.TextMessage:
			var m message
			if json.Unmarshal(corps, &m) != nil {
				continue
			}
			if m.Type == "bonjour" {
				s.repriseReference(c, sess, m.Ref)
			}
			if m.Type == "bonjour" && m.Echantillonnage != 0 &&
				m.Echantillonnage != audio.Echantillonnage {
				// ON NE RÉÉCHANTILLONNE PAS EN SILENCE. Un flux à 44,1 kHz
				// analysé comme du 48 décalerait toutes les hauteurs de 8,8 %
				// — presque un demi-ton et demi — sans que rien ne le signale.
				_ = c.WriteJSON(message{Type: "refus", Motif: "ce module attend du 48 kHz ; " +
					"créez l'AudioContext avec { sampleRate: 48000 }"})
				return
			}
			sess.Touche()
		}
	}
}

// versFlottants convertit un bloc Int16LE reçu du navigateur.
func versFlottants(b []byte) []float64 {
	n := len(b) / 2
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		out[i] = float64(int16(binary.LittleEndian.Uint16(b[2*i:]))) / 32768
	}
	return out
}

func (s *Serveur) envoieImages(c *websocket.Conn, sess *Session, stop <-chan struct{}) {
	tic := time.NewTicker(time.Second / imagesParSeconde)
	defer tic.Stop()
	// L'analyse tourne dans sa propre goroutine, alimentée par la source.
	go func() {
		// Tourne rend une erreur quand la session se ferme : c'est la sortie
		// normale, pas un incident.
		_ = sess.Analyseur.Tourne(0, nil)
	}()
	for {
		select {
		case <-stop:
			return
		case <-tic.C:
			img := sess.Analyseur.Derniere()
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := c.WriteJSON(img); err != nil {
				return
			}
		}
	}
}

// repriseReference : le navigateur présente sa clé, on lui rend son ordinaire.
func (s *Serveur) repriseReference(c *websocket.Conn, sess *Session, cle string) {
	if cle == "" || s.Store == nil || !store.CleReference(cle) {
		return
	}
	sess.CleRef = cle
	r, ok := s.Store.ChargeReference(cle)
	if !ok {
		return
	}
	sess.Analyseur.RepriseReference(r)
	// ON LE DIT. Reprendre en silence une référence constituée ailleurs
	// laisserait croire à une lecture née de la session en cours.
	_ = c.WriteJSON(message{Type: "reprise", Session: sess.ID,
		Motif: "référence retrouvée : " + itoa(r.Observations()) + " mesures antérieures"})
}

func (s *Serveur) enregistreReference(sess *Session) {
	if sess == nil || sess.CleRef == "" || s.Store == nil {
		return
	}
	ref := sess.Analyseur.Reference()
	if err := s.Store.EnregistreReference(sess.CleRef, &ref); err != nil {
		log.Printf("référence : %v", err)
	}
}

// archive écrit UNE LIGNE PAR MINUTE — des agrégats, jamais du son.
func (s *Serveur) archive(sess *Session, stop <-chan struct{}) {
	tic := time.NewTicker(20 * time.Second)
	defer tic.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tic.C:
			t := sess.Analyseur.Traits()
			if t.TramesVoisees == 0 {
				continue // rien à dire d'une minute sans voix
			}
			// La référence est enregistrée au même rythme : une session longue
			// ne doit pas tout remettre en jeu sur sa fermeture.
			s.enregistreReference(sess)
			lec := sess.Analyseur.Lecture()
			if err := s.Store.Enregistre(store.Resume{
				Minute:  time.Now().Truncate(time.Minute).Unix(),
				Session: sess.ID, F0Median: t.F0Median, F0Etendue: t.F0Etendue,
				Energie: t.Energie, Debit: t.Debit, Jitter: t.Jitter,
				Shimmer: t.Shimmer, Activation: lec.Activation,
				Etat: lec.Etat, Confiance: lec.Confiance, PartVoisee: t.PartVoisee,
			}); err != nil {
				log.Printf("archive : %v", err)
			}
		}
	}
}

// DerniereImage : utilitaire pour les tests et le cockpit de secours.
func DerniereImage(a *moteur.Analyseur) moteur.Image { return a.Derniere() }
