package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/contentbbs"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/store"
)

// contenuBouchon : un ClientContenu bidon qui enregistre ce qu'on lui demande,
// sans jamais toucher au reseau — c'est le point d'injection qui rend la
// boucle de validation testable sans monter un BBS (#1166 B2).
type contenuBouchon struct {
	creerObjet                                      contentbbs.Objet
	creerProv                                       []contentbbs.Prov
	creerAppele                                     bool
	creerID                                         string
	creerErr                                        error
	representeID                                    string
	representeKind, representeModule, representeRef string
	representeCache                                 bool
	representeErr                                   error
	topicID                                         string
	topicAppele                                     bool
	topicErr                                        error
	eventID, eventKind, eventActor, eventPayload    string
	eventAppele                                     bool
	eventErr                                        error
}

func (f *contenuBouchon) Creer(o contentbbs.Objet, prov []contentbbs.Prov) (string, error) {
	f.creerAppele = true
	f.creerObjet, f.creerProv = o, prov
	if f.creerErr != nil {
		return "", f.creerErr
	}
	id := f.creerID
	if id == "" {
		id = "cnt-1"
	}
	return id, nil
}

func (f *contenuBouchon) Representation(id, kind, module, ref string, isCache bool) error {
	f.representeID, f.representeKind, f.representeModule, f.representeRef, f.representeCache =
		id, kind, module, ref, isCache
	return f.representeErr
}

func (f *contenuBouchon) Topic(id string) (int64, error) {
	f.topicAppele = true
	f.topicID = id
	if f.topicErr != nil {
		return 0, f.topicErr
	}
	return 42, nil
}

func (f *contenuBouchon) Event(id, kind, actor, payloadJSON string) error {
	f.eventAppele = true
	f.eventID, f.eventKind, f.eventActor, f.eventPayload = id, kind, actor, payloadJSON
	return f.eventErr
}

// TestValiderOuvreUnContentObject : le coeur de B2. Valider une piste doit
// ouvrir un ContentObject cote BBS (Creer -> Representation -> Topic), avec
// la source et l'identifiant de la piste, ET persister le content_id rendu
// pour que le replay (B5) puisse le retrouver.
func TestValiderOuvreUnContentObject(t *testing.T) {
	s, st := banc(t)
	fake := &contenuBouchon{}
	s.Contenu = fake

	appel(s, "POST", "/api/v1/radio/propositions", membre,
		map[string]string{"source": "https://youtu.be/ABC", "titre": "Une chanson"}, true)
	pr, _ := st.Propositions()
	if len(pr) != 1 {
		t.Fatalf("attendu une proposition, trouve %d", len(pr))
	}
	pisteID := pr[0].ID

	w := appel(s, "POST", "/api/v1/radio/propositions/1/valider", sysop, nil, true)
	if w.Code != http.StatusOK {
		t.Fatalf("validation : %d %s", w.Code, w.Body)
	}

	if !fake.creerAppele {
		t.Fatal("Creer n'a jamais ete appele")
	}
	if len(fake.creerProv) != 1 || !fake.creerProv[0].Original {
		t.Fatalf("provenance attendue = 1 entree originale, recu %+v", fake.creerProv)
	}
	// `Source` est la cle NORMALISEE (store.CleSource), pas l'URL brute
	// collee — c'est ce que la piste retient reellement, et ce que le replay
	// (B5) doit pouvoir reconcilier.
	if fake.creerProv[0].SourceURL != "yt:ABC" {
		t.Errorf("source_url = %q", fake.creerProv[0].SourceURL)
	}

	if fake.representeID != "cnt-1" {
		t.Errorf("representation.id = %q", fake.representeID)
	}
	if fake.representeKind != "radio" || fake.representeModule != "secubox-radio" {
		t.Errorf("representation kind/module = %q/%q", fake.representeKind, fake.representeModule)
	}
	if fake.representeRef == "" {
		t.Error("representation.ref est vide")
	}
	if !fake.representeCache {
		t.Error("representation.is_cache aurait du etre vrai (copie radio, pas l'original)")
	}

	if !fake.topicAppele || fake.topicID != "cnt-1" {
		t.Errorf("Topic pas appele avec le bon id : appele=%v id=%q", fake.topicAppele, fake.topicID)
	}

	p, err := st.ParID(pisteID)
	if err != nil {
		t.Fatal(err)
	}
	if p.ContentID != "cnt-1" {
		t.Errorf("content_id non persiste : %q", p.ContentID)
	}
}

// TestValiderSansClientContenuNePasPlante : le champ Contenu est optionnel —
// une radio dont le socket BBS n'est pas configure doit continuer a valider
// normalement.
func TestValiderSansClientContenuNePasPlante(t *testing.T) {
	s, st := banc(t)
	s.Contenu = nil

	appel(s, "POST", "/api/v1/radio/propositions", membre,
		map[string]string{"source": "https://youtu.be/XYZ"}, true)
	w := appel(s, "POST", "/api/v1/radio/propositions/1/valider", sysop, nil, true)
	if w.Code != http.StatusOK {
		t.Fatalf("validation : %d %s", w.Code, w.Body)
	}
	pr, _ := st.Toutes()
	if len(pr) != 1 {
		t.Fatalf("piste absente apres validation")
	}
}

// TestValiderEchecContenuNonBloquant : L'ANTENNE NE DEPEND PAS DU BBS. Un
// echec cote spine de contenu (BBS injoignable, refuse) ne doit JAMAIS faire
// echouer la validation elle-meme.
func TestValiderEchecContenuNonBloquant(t *testing.T) {
	s, st := banc(t)
	fake := &contenuBouchon{creerErr: http.ErrHandlerTimeout}
	s.Contenu = fake

	appel(s, "POST", "/api/v1/radio/propositions", membre,
		map[string]string{"source": "https://youtu.be/QRS"}, true)
	pr, _ := st.Propositions()
	pisteID := pr[0].ID

	w := appel(s, "POST", "/api/v1/radio/propositions/1/valider", sysop, nil, true)
	if w.Code != http.StatusOK {
		t.Fatalf("la validation n'aurait pas du echouer sur une panne du BBS : %d %s", w.Code, w.Body)
	}
	p, err := st.ParID(pisteID)
	if err != nil {
		t.Fatal(err)
	}
	if p.Etat != store.EtatValide {
		t.Errorf("etat = %q apres echec du client contenu", p.Etat)
	}
	if p.ContentID != "" {
		t.Errorf("content_id aurait du rester vide apres un Creer en echec : %q", p.ContentID)
	}
}

// ── diffuseBroadcast (#1166 B3) ─────────────────────────────────────────────
//
// C'est ce que `programme.Programmateur.OnBroadcast` appelle (dans sa propre
// goroutine) a chaque VRAI passage a l'antenne. On teste la methode
// directement plutot qu'a travers le hook asynchrone : deterministe, sans
// synchronisation de test a inventer pour attendre une goroutine.
func TestDiffuseBroadcastEnvoieLEvenementAvecLeContentID(t *testing.T) {
	s, st := banc(t)
	fake := &contenuBouchon{}
	s.Contenu = fake
	p, _, err := st.Ajoute("https://youtu.be/X", "Titre", 1, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FixerContenu(p.ID, "cnt-42"); err != nil {
		t.Fatal(err)
	}

	s.diffuseBroadcast(p.ID, t0.Unix())

	if !fake.eventAppele {
		t.Fatal("Event n'a pas ete appele")
	}
	if fake.eventID != "cnt-42" {
		t.Errorf("evenement pose sur %q, attendu cnt-42", fake.eventID)
	}
	if fake.eventKind != "broadcast" {
		t.Errorf("kind = %q, attendu broadcast", fake.eventKind)
	}
	if !strings.Contains(fake.eventPayload, `"piste":`) {
		t.Errorf("charge sans l'identifiant de la piste : %s", fake.eventPayload)
	}
}

// Une piste sans content_id (BBS injoignable a la validation, ou module non
// cable) n'a rien a rattacher : diffuseBroadcast ne doit pas appeler Event.
func TestDiffuseBroadcastSansContentIDNeFaitRien(t *testing.T) {
	s, st := banc(t)
	fake := &contenuBouchon{}
	s.Contenu = fake
	p, _, err := st.Ajoute("https://youtu.be/Y", "Titre", 1, t0)
	if err != nil {
		t.Fatal(err)
	}
	// Volontairement pas de FixerContenu : ContentID reste vide.

	s.diffuseBroadcast(p.ID, t0.Unix())

	if fake.eventAppele {
		t.Error("Event appele alors que la piste n'a pas de content_id")
	}
}

// Un client contenu absent (BBS non deploye) doit rester un no-op silencieux.
func TestDiffuseBroadcastSansClientNePanique(t *testing.T) {
	s, st := banc(t)
	s.Contenu = nil
	p, _, err := st.Ajoute("https://youtu.be/Z", "Titre", 1, t0)
	if err != nil {
		t.Fatal(err)
	}
	s.diffuseBroadcast(p.ID, t0.Unix())
}
