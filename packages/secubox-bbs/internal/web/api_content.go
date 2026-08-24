// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// API du content spine (#1166) : un ContentObject fédère toutes les
// représentations d'un même contenu source (radio, billets, médiathèque…),
// reliées par leur provenance. Cf. internal/store/content.go pour le modèle
// et la RÈGLE D'OR (une provenance is_original ne disparaît jamais).
//
// Chaque route ici exige le JWT de flotte, comme le reste de /api/v1/bbs —
// voir api.go pour la vérification. POST .../timeline exige EN PLUS le jeton
// PROPRE du membre posteur, dans l'entête X-Sbx-Member (son sbx_token) — le
// BBS résout lui-même `sub -> membre` (membreDepuisJeton, même précédent que
// appelant() dans api_membre.go) plutôt que de faire confiance à un
// author_id fourni par l'appelant. Un module tiers (la radio, par exemple)
// ne PEUT PAS fabriquer une identité BBS : il ne fait que relayer le jeton
// du membre, le BBS reste la seule autorité d'identité. Absence, jeton
// invalide/expiré, ou sujet sans compte BBS -> 400 JSON EXPLICITE
// (store.ErrAnonymeNonPersiste est le miroir de ce gate côté store) —
// jamais une page HTML. Les panneaux qui consomment cette API parsent la
// réponse sans condition.
package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// maxCorpsContenu borne la taille d'un corps JSON accepté par cette API — un
// objet, ses provenances ou un commentaire de timeline tiennent large
// dedans ; au-delà, ce n'est plus un appel légitime.
const maxCorpsContenu = 1 << 20 // 1 MiB

// decoderContenuJSON lit un corps JSON borné et rend false (en ayant déjà
// écrit l'erreur) si la lecture ou le décodage échoue.
func decoderContenuJSON(w http.ResponseWriter, r *http.Request, dest any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, maxCorpsContenu)).Decode(dest); err != nil {
		jsonErr(w, http.StatusBadRequest, "corps JSON illisible")
		return false
	}
	return true
}

// jsonErrFr : variante de jsonErr avec la clef `erreur` plutôt que `error`.
// Réservée aux réponses dont le libellé exact est un contrat d'API — ici, le
// refus d'un commentaire anonyme (gate d'identité). Le reste de cette API
// garde `jsonErr` (clef `error`), comme tout /api/v1/bbs — introduire une
// deuxième clef partout affaiblirait la cohérence pour un gain nul.
func jsonErrFr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"ok": false, "erreur": msg})
}

// entreeProvenance : une provenance telle que reçue du client. Distincte de
// store.Provenance côté JSON pour ne pas lier le contrat d'API aux noms de
// champs Go internes.
type entreeProvenance struct {
	SourceURL  string `json:"source_url"`
	SourceType string `json:"source_type"`
	Original   bool   `json:"original"`
}

// apiContentCreer : POST /api/v1/bbs/content
// {type,title,metadata,provenance:[{source_url,source_type,original}]}
// -> {ok,id}. Idempotent sur la provenance originale (store.CreerContenu).
func (s *Server) apiContentCreer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Type       string             `json:"type"`
		Title      string             `json:"title"`
		Metadata   json.RawMessage    `json:"metadata"`
		Provenance []entreeProvenance `json:"provenance"`
	}
	if !decoderContenuJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Type) == "" || strings.TrimSpace(in.Title) == "" {
		jsonErr(w, http.StatusBadRequest, "type et title sont requis")
		return
	}

	aUneOriginale := false
	prov := make([]store.Provenance, 0, len(in.Provenance))
	for _, p := range in.Provenance {
		if p.Original {
			aUneOriginale = true
		}
		prov = append(prov, store.Provenance{
			SourceURL: p.SourceURL, SourceType: p.SourceType, Original: p.Original,
		})
	}
	if !aUneOriginale {
		jsonErr(w, http.StatusBadRequest, "au moins une provenance is_original=1 est requise")
		return
	}

	meta := "{}"
	if len(in.Metadata) > 0 {
		meta = string(in.Metadata)
	}

	id, err := s.st.CreerContenu(store.ContentObject{
		Type: in.Type, Title: in.Title, Metadata: meta,
	}, prov, time.Now().Unix())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "id": id})
}

// apiContentRepresentation : POST /api/v1/bbs/content/{id}/representation
// {kind,module,ref,is_cache,url} -> {ok}. Idempotent (UNIQUE côté store).
func (s *Server) apiContentRepresentation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.st.ContenuParID(id); err != nil {
		jsonErr(w, http.StatusNotFound, "contenu inconnu")
		return
	}
	var in struct {
		Kind    string `json:"kind"`
		Module  string `json:"module"`
		Ref     string `json:"ref"`
		IsCache bool   `json:"is_cache"`
		URL     string `json:"url"`
	}
	if !decoderContenuJSON(w, r, &in) {
		return
	}
	if err := s.st.AjouterRepresentation(id, in.Kind, in.Module, in.Ref, in.IsCache, in.URL,
		time.Now().Unix()); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

// apiContentEvent : POST /api/v1/bbs/content/{id}/event
// {kind,actor,payload} -> {ok}. Append-only côté store.
func (s *Server) apiContentEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.st.ContenuParID(id); err != nil {
		jsonErr(w, http.StatusNotFound, "contenu inconnu")
		return
	}
	var in struct {
		Kind    string          `json:"kind"`
		Actor   string          `json:"actor"`
		Payload json.RawMessage `json:"payload"`
	}
	if !decoderContenuJSON(w, r, &in) {
		return
	}
	payload := "{}"
	if len(in.Payload) > 0 {
		payload = string(in.Payload)
	}
	if err := s.st.AjouterEvent(id, in.Kind, in.Actor, payload, time.Now().Unix()); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

// apiContentTopic : POST /api/v1/bbs/content/{id}/topic — ouvre le fil BBS
// qui porte la discussion de ce ContentObject, sous l'auteur passerelle, et
// le rattache (store.LierTopic). -> {ok,bbs_topic_id}.
//
// IDEMPOTENT : un ContentObject déjà rattaché rend le fil existant plutôt
// que d'en ouvrir un second — un collecteur qui repasse ne doit jamais
// dupliquer la discussion.
func (s *Server) apiContentTopic(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	o, err := s.st.ContenuParID(id)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "contenu inconnu")
		return
	}
	if o.BBSTopicID != 0 {
		jsonOK(w, map[string]any{"ok": true, "bbs_topic_id": o.BBSTopicID})
		return
	}

	auteur, err := s.auteurPasserelle()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Salon dédié : un contenu du spine n'est ni un import billets, ni un
	// import peertube — son propre salon évite qu'il se noie dans les
	// passerelles existantes ou les pollue.
	cat, err := s.st.CreateCategory("contenus", "Contenus", "")
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	corps := o.Title
	if strings.TrimSpace(corps) == "" {
		corps = id
	}
	topicID, err := s.st.NewThread(cat, auteur, o.Title, corps, store.VisPublic)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.st.LierTopic(id, topicID); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "bbs_topic_id": topicID})
}

// vueProvenance / vueRepresentations / vueEvents / vueTimeline : mise en
// forme JSON, séparée des accesseurs store — la même convention que
// vueFil/vueFils dans api_membre.go.
func vueProvenance(prov []store.Provenance) []map[string]any {
	out := make([]map[string]any, 0, len(prov))
	for _, p := range prov {
		out = append(out, map[string]any{
			"source_url": p.SourceURL, "source_type": p.SourceType, "original": p.Original,
		})
	}
	return out
}

func vueRepresentations(repr []store.Representation) []map[string]any {
	out := make([]map[string]any, 0, len(repr))
	for _, r := range repr {
		out = append(out, map[string]any{
			"kind": r.Kind, "module": r.Module, "ref": r.Ref,
			"is_cache": r.IsCache, "url": r.URL, "created_at": r.CreatedAt,
		})
	}
	return out
}

func vueEvents(ev []store.ContentEvent) []map[string]any {
	out := make([]map[string]any, 0, len(ev))
	for _, e := range ev {
		out = append(out, map[string]any{
			"kind": e.Kind, "actor": e.Actor, "payload": json.RawMessage(e.Payload), "at": e.At,
		})
	}
	return out
}

func vueTimeline(c []store.TimelineComment) []map[string]any {
	out := make([]map[string]any, 0, len(c))
	for _, t := range c {
		out = append(out, map[string]any{
			"id": t.ID, "author": t.Author, "author_id": t.AuthorID,
			"offset_ms": t.OffsetMS, "body": t.Body,
			"broadcast_at": t.BroadcastAt, "created_at": t.CreatedAt,
		})
	}
	return out
}

// apiContentObtenir : GET /api/v1/bbs/content/{id} -> objet + provenance +
// representations + derniers events.
func (s *Server) apiContentObtenir(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	o, err := s.st.ContenuParID(id)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "contenu inconnu")
		return
	}
	prov, err := s.st.ProvenanceDe(id)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	repr, err := s.st.RepresentationsDe(id)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ev, err := s.st.EventsDe(id, 20)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]any{
		"ok": true,
		"objet": map[string]any{
			"id": o.ID, "type": o.Type, "title": o.Title,
			"metadata": json.RawMessage(o.Metadata), "bbs_topic_id": o.BBSTopicID,
			"status": o.Status, "visibility": o.Visibility,
			"created_at": o.CreatedAt, "updated_at": o.UpdatedAt,
		},
		"provenance":      vueProvenance(prov),
		"representations": vueRepresentations(repr),
		"events":          vueEvents(ev),
	})
}

// apiContentParRef : GET /api/v1/bbs/content/by-ref?module=&ref= -> {id} ou
// 404. Résout une représentation (module,ref) vers le ContentObject qui la
// fédère — le point d'entrée qu'un module consommateur utilise pour savoir
// s'il a déjà affaire à un contenu connu du spine.
func (s *Server) apiContentParRef(w http.ResponseWriter, r *http.Request) {
	module := r.URL.Query().Get("module")
	ref := r.URL.Query().Get("ref")
	id, ok := s.st.ContenuParRef(module, ref)
	if !ok {
		jsonErr(w, http.StatusNotFound, "contenu inconnu")
		return
	}
	jsonOK(w, map[string]any{"ok": true, "id": id})
}

// membreDepuisJeton résout le PORTEUR d'un jeton (l'entête X-Sbx-Member,
// verbatim un sbx_token — sans le préfixe "Bearer ") vers un compte reconnu
// du BBS, en réutilisant claimsJeton (même vérification HS256 que le reste
// de l'API — voir api.go). C'est l'AUTORITÉ D'IDENTITÉ de la timeline :
// contrairement à apiContentTimelineCreer AVANT ce correctif, l'appelant
// (un autre module, ex. la radio) ne fournit plus jamais author_id/author
// directement — il ne peut que relayer un jeton, que le BBS vérifie et
// résout lui-même.
//
// Rend (0, "", false) si le jeton est absent, mal formé, invalide, expiré,
// ou si son sujet n'a pas de compte BBS actif — dans TOUS ces cas
// l'appelant doit traiter le posteur comme anonyme et refuser 400, jamais
// persister avec un id fabriqué ou nul.
func (s *Server) membreDepuisJeton(jeton string) (id int64, nom string, ok bool) {
	jeton = strings.TrimSpace(jeton)
	if jeton == "" {
		return 0, "", false
	}
	claims, err := s.claimsJeton("Bearer " + jeton)
	if err != nil {
		return 0, "", false
	}
	sub := strings.TrimSpace(claims.Sub)
	if sub == "" {
		return 0, "", false
	}
	// UserByHandle ignore les comptes desactives : une revocation cote
	// SecuBox ferme donc la timeline immediatement, sans attendre
	// l'expiration du jeton — meme garantie que appelant() (api_membre.go).
	uid, err := s.st.UserByHandle(sub)
	if err != nil || uid <= 0 {
		return 0, "", false
	}
	info, err := s.st.UserInfo(uid)
	if err != nil {
		return 0, "", false
	}
	nom = strings.TrimSpace(info.Display)
	if nom == "" {
		nom = info.Handle
	}
	return uid, nom, true
}

// apiContentTimelineCreer : POST /api/v1/bbs/content/{id}/timeline
// {offset_ms,body} + entête X-Sbx-Member:<sbx_token> -> 200 {ok,id} ;
// jeton absent/invalide/sans compte BBS -> 400
// {ok:false,erreur:"anonyme non persisté"} (gate d'identité, verbatim).
// L'identité N'EST JAMAIS lue dans le corps — voir membreDepuisJeton.
func (s *Server) apiContentTimelineCreer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.st.ContenuParID(id); err != nil {
		jsonErr(w, http.StatusNotFound, "contenu inconnu")
		return
	}
	var in struct {
		OffsetMS int64  `json:"offset_ms"`
		Body     string `json:"body"`
	}
	if !decoderContenuJSON(w, r, &in) {
		return
	}

	authorID, author, ok := s.membreDepuisJeton(r.Header.Get("X-Sbx-Member"))
	if !ok {
		jsonErrFr(w, http.StatusBadRequest, "anonyme non persisté")
		return
	}

	cid, err := s.st.AjouterTimeline(id, store.TimelineComment{
		Author: author, AuthorID: authorID, OffsetMS: in.OffsetMS, Body: in.Body,
		CreatedAt: time.Now().Unix(),
	})
	if errors.Is(err, store.ErrAnonymeNonPersiste) {
		jsonErrFr(w, http.StatusBadRequest, "anonyme non persisté")
		return
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "id": cid})
}

// apiContentTimelineLister : GET /api/v1/bbs/content/{id}/timeline?from=&to=
// -> {comments:[…]} ordonnés par offset (store.TimelineDe).
func (s *Server) apiContentTimelineLister(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.st.ContenuParID(id); err != nil {
		jsonErr(w, http.StatusNotFound, "contenu inconnu")
		return
	}
	from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	to, _ := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
	comments, err := s.st.TimelineDe(id, from, to)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]any{"ok": true, "comments": vueTimeline(comments)})
}
