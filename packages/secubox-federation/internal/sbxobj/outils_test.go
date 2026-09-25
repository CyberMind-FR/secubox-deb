package sbxobj

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/canon"
)

func sha256Octets(b []byte) (string, error) {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// canonDe : re-sérialise via JSON pour retrouver les types du lecteur (json.Number).
func canonDe(m map[string]any) ([]byte, error) {
	b, _ := json.Marshal(m)
	var x map[string]any
	d := json.NewDecoder(bytesReader(b))
	d.UseNumber()
	d.Decode(&x)
	return canon.Encode(x)
}
