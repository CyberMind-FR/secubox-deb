// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

// Empreintes TLS des clients (JA3 et JA4), calculées ICI depuis le ClientHello.
//
// POURQUOI : la libndpi livrée (4.2) n'émet ni ja3 ni ja4 dans ses événements,
// donc la page « Empreintes » de /ndpid/ restait vide. nDPId transmet en
// revanche les premiers paquets de chaque flux (événements packet-flow, champ
// pkt en base64) : on y lit le ClientHello nous-mêmes.
//
// Ce qui sort : une empreinte, jamais une adresse ni un nom d'hôte. Un
// ClientHello moderne (clés post-quantiques) dépasse un segment TCP : on
// recolle les segments d'un même flux, au plus tlsMaxSegments, avant de lire.

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	tlsMaxSegments = 4     // segments TCP recollés au plus, par flux
	tlsMaxHello    = 16384 // octets d'un ClientHello (record) retenus au plus
	tlsFlowCap     = 4096  // flux suivis en parallèle (mémoire bornée)
)

// dec lit un paquet nDPId (trame Ethernet en base64) et rend la charge utile
// TCP, ou nil si ce n'est pas du TCP/IP exploitable.
func chargeTCP(pktB64 string, l3, pktType int) []byte {
	raw, err := base64.StdEncoding.DecodeString(pktB64)
	if err != nil || l3 <= 0 || len(raw) <= l3+20 {
		return nil
	}
	var l4 int
	switch pktType {
	case 0x0800: // IPv4
		if len(raw) < l3+20 || raw[l3]>>4 != 4 || raw[l3+9] != 6 {
			return nil
		}
		l4 = l3 + int(raw[l3]&0x0f)*4
	case 0x86DD: // IPv6, sans chaîne d'en-têtes d'extension
		if len(raw) < l3+40 || raw[l3]>>4 != 6 || raw[l3+6] != 6 {
			return nil
		}
		l4 = l3 + 40
	default:
		return nil
	}
	if len(raw) < l4+20 {
		return nil
	}
	off := int(raw[l4+12]>>4) * 4
	if off < 20 || len(raw) < l4+off {
		return nil
	}
	return raw[l4+off:]
}

func estGrease(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }

// empreinteTLS : ce qu'on tire d'un ClientHello.
type empreinteTLS struct {
	JA3 string // md5 hexadécimal
	JA4 string // t13d1516h2_xxxxxxxxxxxx_xxxxxxxxxxxx
}

// lireClientHello calcule JA3 et JA4 d'une charge TCP qui COMMENCE par un
// enregistrement TLS handshake de type ClientHello. Rend (_, false) si la charge
// n'est pas un ClientHello ; incomplet := true si l'enregistrement dépasse ce
// qu'on a (il faut recoller un segment de plus).
func lireClientHello(p []byte) (e empreinteTLS, ok bool, incomplet bool) {
	// Enregistrement : 0x16, version(2), longueur(2) ; handshake : 0x01, longueur(3).
	if len(p) < 9 || p[0] != 0x16 || p[1] != 0x03 || p[5] != 0x01 {
		return e, false, false
	}
	recLen := int(binary.BigEndian.Uint16(p[3:5]))
	hsLen := int(p[6])<<16 | int(p[7])<<8 | int(p[8])
	if recLen > tlsMaxHello || hsLen+4 > recLen || hsLen > tlsMaxHello {
		return e, false, false
	}
	if len(p) < 9+hsLen {
		return e, false, true
	}
	b := p[9 : 9+hsLen]
	// version(2) + random(32)
	if len(b) < 35 {
		return e, false, false
	}
	legacy := binary.BigEndian.Uint16(b[0:2])
	b = b[34:]
	// session id
	sl := int(b[0])
	if len(b) < 1+sl+2 {
		return e, false, false
	}
	b = b[1+sl:]
	// suites
	cl := int(binary.BigEndian.Uint16(b[0:2]))
	if cl%2 != 0 || len(b) < 2+cl+1 {
		return e, false, false
	}
	var suites []uint16
	for i := 0; i < cl; i += 2 {
		if v := binary.BigEndian.Uint16(b[2+i : 4+i]); !estGrease(v) {
			suites = append(suites, v)
		}
	}
	b = b[2+cl:]
	// compression
	ml := int(b[0])
	if len(b) < 1+ml {
		return e, false, false
	}
	b = b[1+ml:]

	var (
		exts     []uint16
		curves   []uint16
		formats  []uint16
		sigalgs  []uint16
		versions []uint16
		alpn     string
		hasSNI   bool
	)
	if len(b) >= 2 {
		el := int(binary.BigEndian.Uint16(b[0:2]))
		b = b[2:]
		if el > len(b) {
			el = len(b)
		}
		x := b[:el]
		for len(x) >= 4 {
			t := binary.BigEndian.Uint16(x[0:2])
			l := int(binary.BigEndian.Uint16(x[2:4]))
			if 4+l > len(x) {
				break
			}
			d := x[4 : 4+l]
			x = x[4+l:]
			if estGrease(t) {
				continue
			}
			exts = append(exts, t)
			switch t {
			case 0x0000:
				hasSNI = true
			case 0x000a: // supported_groups
				if len(d) >= 2 {
					for i := 2; i+1 < len(d) && i < 2+int(binary.BigEndian.Uint16(d[0:2])); i += 2 {
						if v := binary.BigEndian.Uint16(d[i : i+2]); !estGrease(v) {
							curves = append(curves, v)
						}
					}
				}
			case 0x000b: // ec_point_formats
				if len(d) >= 1 {
					for i := 1; i < len(d) && i <= int(d[0]); i++ {
						formats = append(formats, uint16(d[i]))
					}
				}
			case 0x000d: // signature_algorithms
				if len(d) >= 2 {
					for i := 2; i+1 < len(d) && i < 2+int(binary.BigEndian.Uint16(d[0:2])); i += 2 {
						sigalgs = append(sigalgs, binary.BigEndian.Uint16(d[i:i+2]))
					}
				}
			case 0x0010: // ALPN
				if len(d) >= 3 && alpn == "" {
					n := int(d[2])
					if 3+n <= len(d) && n > 0 {
						alpn = string(d[3 : 3+n])
					}
				}
			case 0x002b: // supported_versions
				if len(d) >= 1 {
					for i := 1; i+1 < len(d) && i <= int(d[0]); i += 2 {
						if v := binary.BigEndian.Uint16(d[i : i+2]); !estGrease(v) {
							versions = append(versions, v)
						}
					}
				}
			}
		}
	}

	// JA3 : version,suites,extensions,groupes,formats (GREASE retiré).
	e.JA3 = ja3(legacy, suites, exts, curves, formats)

	// JA4.
	ver := legacy
	for _, v := range versions {
		if v > ver {
			ver = v
		}
	}
	sni := "i"
	if hasSNI {
		sni = "d"
	}
	e.JA4 = "t" + versionJA4(ver) + sni + deux(len(suites)) + deux(len(exts)) + alpnJA4(alpn) +
		"_" + hash12(triHex(suites)) + "_" + hash12ExtJA4(exts, sigalgs)
	return e, true, false
}

func ja3(version uint16, suites, exts, curves, formats []uint16) string {
	j := func(v []uint16) string {
		s := make([]string, len(v))
		for i, x := range v {
			s[i] = strconv.Itoa(int(x))
		}
		return strings.Join(s, "-")
	}
	chaine := strconv.Itoa(int(version)) + "," + j(suites) + "," + j(exts) + "," + j(curves) + "," + j(formats)
	sum := md5.Sum([]byte(chaine)) //nolint:gosec // JA3 est défini avec md5 : ce n'est pas un usage de sécurité
	return hex.EncodeToString(sum[:])
}

func versionJA4(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	}
	return "00"
}

func deux(n int) string {
	if n > 99 {
		n = 99
	}
	return strconv.Itoa(n/10) + strconv.Itoa(n%10)
}

// alpnJA4 : premier et dernier caractère de la première valeur ALPN ; si l'un
// d'eux n'est pas alphanumérique, premier quartet hexadécimal du premier octet
// et dernier quartet du dernier octet ; « 00 » sans ALPN.
func alpnJA4(a string) string {
	if a == "" {
		return "00"
	}
	f, l := a[0], a[len(a)-1]
	alnum := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
	if alnum(f) && alnum(l) {
		return string([]byte{f, l})
	}
	h := hex.EncodeToString([]byte{f, l})
	return string([]byte{h[0], h[3]})
}

func triHex(v []uint16) string {
	c := append([]uint16(nil), v...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return listeHex(c)
}

func listeHex(v []uint16) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = hex4(x)
	}
	return strings.Join(s, ",")
}

func hex4(x uint16) string {
	const h = "0123456789abcdef"
	return string([]byte{h[x>>12&15], h[x>>8&15], h[x>>4&15], h[x&15]})
}

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// hash12ExtJA4 : extensions triées SANS SNI (0000) ni ALPN (0010), puis les
// algorithmes de signature dans l'ordre d'origine.
func hash12ExtJA4(exts, sigalgs []uint16) string {
	var k []uint16
	for _, e := range exts {
		if e != 0x0000 && e != 0x0010 {
			k = append(k, e)
		}
	}
	if len(k) == 0 {
		return "000000000000"
	}
	s := triHex(k)
	if len(sigalgs) > 0 {
		s += "_" + listeHex(sigalgs)
	}
	return hash12(s)
}

// recolleur reconstitue le ClientHello d'un flux quand il s'étend sur plusieurs
// segments TCP, et n'émet qu'UNE empreinte par flux. Mémoire bornée.
type recolleur struct {
	mu      sync.Mutex
	partiel map[uint64][]byte // flux -> début du ClientHello déjà vu
	segs    map[uint64]int
	faits   map[uint64]struct{}
}

func newRecolleur() *recolleur {
	return &recolleur{partiel: map[uint64][]byte{}, segs: map[uint64]int{}, faits: map[uint64]struct{}{}}
}

// Observe reçoit la charge TCP d'un paquet d'un flux ; rend l'empreinte quand le
// ClientHello est complet (une seule fois par flux).
func (r *recolleur) Observe(flux uint64, charge []byte) (empreinteTLS, bool) {
	if len(charge) == 0 {
		return empreinteTLS{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.faits[flux]; ok {
		return empreinteTLS{}, false
	}
	buf, suite := r.partiel[flux]
	if suite {
		if len(buf)+len(charge) > tlsMaxHello+9 {
			r.oublier(flux)
			return empreinteTLS{}, false
		}
		buf = append(buf, charge...)
	} else {
		buf = charge
	}
	e, ok, incomplet := lireClientHello(buf)
	switch {
	case ok:
		r.oublier(flux)
		if len(r.faits) >= tlsFlowCap {
			r.faits = map[uint64]struct{}{}
		}
		r.faits[flux] = struct{}{}
		return e, true
	case incomplet:
		if !suite && len(r.partiel) >= tlsFlowCap {
			r.partiel, r.segs = map[uint64][]byte{}, map[uint64]int{}
		}
		r.segs[flux]++
		if r.segs[flux] > tlsMaxSegments {
			r.oublier(flux)
			return empreinteTLS{}, false
		}
		r.partiel[flux] = append([]byte(nil), buf...)
	default:
		r.oublier(flux)
	}
	return empreinteTLS{}, false
}

func (r *recolleur) oublier(flux uint64) {
	delete(r.partiel, flux)
	delete(r.segs, flux)
}
