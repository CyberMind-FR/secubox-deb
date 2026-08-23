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
// voir api.go pour la vérification. POST .../timeline exige EN PLUS un
// author_id>0 (gate d'identité, store.ErrAnonymeNonPersiste) : un
// commentaire anonyme ne doit jamais atteindre la timeline, et le refus est
// un 400 JSON EXPLICITE — jamais une page HTML. Les panneaux qui consomment
// cette API parsent la réponse sans condition.
package web

import (
	"encoding/json"
	"io"
	"net/http"
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

// auteurPasserelle résout le compte 'passerelle' — celui qui signe les fils
// ouverts depuis une source automatisée, même idiome que cmd/bbsctl/main.go
// (importeSources). Get-or-create : contrairement à bbsctl, cette route ne
// peut pas supposer qu'une passerelle d'ingestion a déjà tourné et créé ce
// compte au préalable.
func (s *Server) auteurPasserelle() (int64, error) {
	if id, err := s.st.QueryRowScanInt64(
		`SELECT id FROM users WHERE handle='passerelle'`); err == nil {
		return id, nil
	}
	return s.st.CreateUser("passerelle", "Passerelle", store.RoleMember)
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
