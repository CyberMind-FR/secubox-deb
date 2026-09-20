// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package jeton

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"
)

func forger(secret, alg string, charge string) string {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	e := b64(`{"alg":"` + alg + `","typ":"JWT"}`)
	c := b64(charge)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(e + "." + c))
	return e + "." + c + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func vrfr(secret string) *Verificateur { return &Verificateur{secret: []byte(secret)} }

func TestJetonValide(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	j := forger("s3cr3t", "HS256", `{"sub":"gk2","exp":`+itoa(exp)+`}`)
	sub, err := vrfr("s3cr3t").Valide(j)
	if err != nil {
		t.Fatalf("jeton valide refuse : %v", err)
	}
	if sub != "gk2" {
		t.Errorf("sub = %q", sub)
	}
}

// LE test : sans secret, RIEN ne passe. Un demon non provisionne ne doit pas
// degrader vers « tout accepter » — c'etait le defaut de la v1.
func TestSansSecretRienNePasse(t *testing.T) {
	j := forger("s3cr3t", "HS256", `{"sub":"gk2"}`)
	if _, err := (&Verificateur{}).Valide(j); !errors.Is(err, ErrPasDeSecret) {
		t.Fatalf("sans secret, tout doit etre refuse ; obtenu %v", err)
	}
}

func TestSignatureFalsifiee(t *testing.T) {
	j := forger("le-bon-secret", "HS256", `{"sub":"gk2"}`)
	if _, err := vrfr("un-autre-secret").Valide(j); !errors.Is(err, ErrSignature) {
		t.Fatalf("signature d'un autre secret acceptee : %v", err)
	}
}

// `alg: none` est la faille classique des implementations JWT : accepter
// l'algorithme que le jeton s'attribue lui-meme.
func TestAlgorithmeNoneRefuse(t *testing.T) {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	j := b64(`{"alg":"none","typ":"JWT"}`) + "." + b64(`{"sub":"pirate"}`) + "."
	if _, err := vrfr("s3cr3t").Valide(j); err == nil {
		t.Fatal("alg=none doit etre refuse")
	}
}

func TestAlgorithmeInattenduRefuse(t *testing.T) {
	j := forger("s3cr3t", "HS512", `{"sub":"gk2"}`)
	if _, err := vrfr("s3cr3t").Valide(j); !errors.Is(err, ErrAlgo) {
		t.Fatalf("HS512 doit etre refuse : %v", err)
	}
}

func TestJetonExpire(t *testing.T) {
	exp := time.Now().Add(-2 * time.Hour).Unix()
	j := forger("s3cr3t", "HS256", `{"sub":"gk2","exp":`+itoa(exp)+`}`)
	if _, err := vrfr("s3cr3t").Valide(j); !errors.Is(err, ErrExpire) {
		t.Fatalf("jeton expire accepte : %v", err)
	}
}

func TestFormesMalFormees(t *testing.T) {
	for _, j := range []string{"", "a", "a.b", "a.b.c.d", "!!!.???.***"} {
		if _, err := vrfr("s3cr3t").Valide(j); err == nil {
			t.Errorf("forme %q acceptee", j)
		}
	}
}

func TestSecretDepuisConf(t *testing.T) {
	p := t.TempDir() + "/secubox.conf"
	if err := writeFile(p, "[autre]\njwt_secret = \"piege\"\n\n[api]\njwt_secret = \"bon\"\n"); err != nil {
		t.Fatal(err)
	}
	if got := depuisConf(p); got != "bon" {
		t.Errorf("depuisConf = %q — la section compte", got)
	}
}

func writeFile(p, contenu string) error { return os.WriteFile(p, []byte(contenu), 0o600) }

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
