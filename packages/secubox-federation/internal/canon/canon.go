// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package canon produit les octets EXACTS de annuaire.crypto.canonical_bytes :
//
//	json.dumps(obj, sort_keys=True, separators=(",", ":"))   # ensure_ascii=True
//
// POURQUOI AU BIT PRÈS. Une signature Ed25519 porte sur des octets, pas sur un
// sens. Si le Go et le Python sérialisaient différemment le même certificat,
// l'annuaire ne pourrait pas vérifier ce que la CA a signé — il y aurait deux
// autorités de confiance au lieu d'une (#1388). encoding/json ne convient pas :
// il échappe <, > et & en <…, garde l'UTF-8 brut, et ne trie que les maps.
//
// Types admis : string, bool, nil, int/int64/uint…, []any, []string,
// map[string]any, map[string]bool, map[string]string. Les flottants sont
// REFUSÉS : leur représentation diffère entre Go et Python (1e+06 / 1000000.0),
// et rien dans un certificat n'en a besoin.
package canon

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Encode rend la forme canonique de v.
func Encode(v any) ([]byte, error) {
	var b strings.Builder
	if err := enc(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func enc(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		return chaine(b, x)
	case int:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case uint:
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case uint32:
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := chaine(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := enc(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		return objet(b, len(x), func(yield func(string, any) error) error {
			for _, k := range cles(x) {
				if err := yield(k, x[k]); err != nil {
					return err
				}
			}
			return nil
		})
	case map[string]bool:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = e
		}
		return enc(b, m)
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = e
		}
		return enc(b, m)
	case float32, float64:
		return fmt.Errorf("canon : flottant refusé (%v) — représentation différente en Go et en Python", x)
	default:
		return fmt.Errorf("canon : type non pris en charge %T", v)
	}
	return nil
}

func cles[T any](m map[string]T) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	// Tri par OCTETS UTF-8 = tri par point de code, celui de sort_keys.
	sort.Strings(ks)
	return ks
}

func objet(b *strings.Builder, _ int, parcours func(func(string, any) error) error) error {
	b.WriteByte('{')
	premier := true
	err := parcours(func(k string, v any) error {
		if !premier {
			b.WriteByte(',')
		}
		premier = false
		if err := chaine(b, k); err != nil {
			return err
		}
		b.WriteByte(':')
		return enc(b, v)
	})
	b.WriteByte('}')
	return err
}

const hex = "0123456789abcdef"

// chaine reproduit ESCAPE_ASCII de CPython : tout ce qui n'est pas dans
// l'intervalle ' '..'~' est échappé ; \" \\ \n \r \t \b \f ont leur forme
// courte ; le reste devient \uXXXX (hexadécimal minuscule), paire de
// substitution au-delà du plan de base.
func chaine(b *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("canon : chaîne UTF-8 invalide")
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r >= 0x20 && r <= 0x7e {
				b.WriteRune(r)
				continue
			}
			if r > 0xffff {
				r -= 0x10000
				u(b, 0xd800+(r>>10))
				u(b, 0xdc00+(r&0x3ff))
				continue
			}
			u(b, r)
		}
	}
	b.WriteByte('"')
	return nil
}

func u(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	b.WriteByte(hex[(r>>12)&0xf])
	b.WriteByte(hex[(r>>8)&0xf])
	b.WriteByte(hex[(r>>4)&0xf])
	b.WriteByte(hex[r&0xf])
}
