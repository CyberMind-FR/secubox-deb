// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package ws

import (
	"encoding/binary"
	"testing"
)

func TestTrameCourte(t *testing.T) {
	f := encoder([]byte("bonjour"))
	if f[0] != 0x81 {
		t.Errorf("premier octet = %#x, attendu 0x81 (FIN + texte)", f[0])
	}
	if f[1] != 7 {
		t.Errorf("longueur = %d, attendu 7", f[1])
	}
	// Le masque est INTERDIT cote serveur par la RFC 6455 : le bit de poids
	// fort du second octet doit rester a zero.
	if f[1]&0x80 != 0 {
		t.Error("le serveur ne doit jamais masquer")
	}
}

func TestTrameMoyenne(t *testing.T) {
	f := encoder(make([]byte, 300))
	if f[1] != 126 {
		t.Fatalf("indicateur = %d, attendu 126", f[1])
	}
	if n := binary.BigEndian.Uint16(f[2:4]); n != 300 {
		t.Errorf("longueur etendue = %d", n)
	}
}

func TestTrameLongue(t *testing.T) {
	f := encoder(make([]byte, 70000))
	if f[1] != 127 {
		t.Fatalf("indicateur = %d, attendu 127", f[1])
	}
	if n := binary.BigEndian.Uint64(f[2:10]); n != 70000 {
		t.Errorf("longueur etendue = %d", n)
	}
}

// Une diffusion sans client ne doit pas paniquer.
func TestDiffusionSansClient(t *testing.T) {
	NewHub().Diffuser("backend.state", map[string]string{"etat": "up"})
}
