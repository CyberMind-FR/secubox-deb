package canon

import (
	"encoding/json"
	"os"
	"testing"
)

// Les vecteurs sont produits par CPython (json.dumps(sort_keys, separators)) :
// c'est la définition de canonical_bytes dans secubox-annuaire. Le Go doit
// rendre LES MÊMES OCTETS, sinon l'annuaire ne peut pas vérifier nos signatures.
func TestMemesOctetsQuePython(t *testing.T) {
	brut, err := os.ReadFile("vecteurs_test.json")
	if err != nil {
		t.Fatal(err)
	}
	var cas []struct {
		Entree any    `json:"entree"`
		Canon  string `json:"canon"`
	}
	d := json.NewDecoder(bytesReader(brut))
	d.UseNumber()
	if err := d.Decode(&cas); err != nil {
		t.Fatal(err)
	}
	for i, c := range cas {
		got, err := Encode(entiers(c.Entree))
		if err != nil {
			t.Fatalf("cas %d : %v", i, err)
		}
		if string(got) != c.Canon {
			t.Errorf("cas %d :\n go     %s\n python %s", i, got, c.Canon)
		}
	}
}

func TestLesFlottantsSontRefuses(t *testing.T) {
	if _, err := Encode(map[string]any{"x": 1.5}); err == nil {
		t.Fatal("un flottant a été accepté")
	}
}

// entiers convertit les json.Number (tous entiers ici) en int64.
func entiers(v any) any {
	switch x := v.(type) {
	case json.Number:
		n, _ := x.Int64()
		return n
	case map[string]any:
		for k, e := range x {
			x[k] = entiers(e)
		}
	case []any:
		for i, e := range x {
			x[i] = entiers(e)
		}
	}
	return v
}
