// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package envelope définit l'Event Envelope v1 d'Actor Intelligence (RFC-0013 §2).
//
// C'est le format COMMUN et minimisé dans lequel les capteurs du hot path
// (sbxwaf, sbxdpi, sbx-authwatch, sbx-sentinel) réduisent leurs événements avant
// de les confier — de façon asynchrone et non bloquante — au moteur sbx-actord.
// L'enveloppe ne porte JAMAIS de secret en clair : un identifiant utile à la
// corrélation (login, jeton) est réduit par HMAC-SHA256 à secret local rotatable
// (voir Hasher) et non par un SHA256 nu, afin de résister aux dictionnaires.
//
// Validate() est volontairement STRICTE (RFC-0013 §15) : un événement forgé —
// champ absurde, chaîne géante destinée à saturer la mémoire ou à polluer le
// clustering, IP invalide, capteur inconnu — est rejeté à l'entrée, jamais ingéré.
package envelope

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

// SchemaVersion identifie le format d'enveloppe. Il est journalisé avec chaque
// preuve pour qu'une évolution du schéma ne réinterprète jamais un ancien verdict.
const SchemaVersion = "envelope/v1"

// Capteurs reconnus (RFC-0013 §2, champ `sensor`). Un événement d'un capteur hors
// liste est rejeté : la surface d'ingestion reste fermée par défaut.
const (
	SensorWAF       = "waf"       // sbxwaf (HTTP/applicatif)
	SensorDPI       = "dpi"       // sbxdpi (nDPI)
	SensorAuthWatch = "authwatch" // sbx-authwatch (SSH/SMTP/IMAP)
	SensorSentinel  = "sentinel"  // sbx-sentinel (flux/IOC)
	SensorReplay    = "replay"    // outil de rejeu (RFC-0013 §13), données anonymisées
)

// Actions observées. En Phase 0/1 le moteur est en shadow : l'action décrit ce que
// le CAPTEUR a fait, pas une décision d'Actor Intelligence.
const (
	ActionObserve   = "observe"
	ActionAllow     = "allow"
	ActionChallenge = "challenge"
	ActionTarpit    = "tarpit"
	ActionBlock     = "block"
	ActionQuarantps = "quarantine"
)

// Classes de reverse DNS (RFC-0013 §2, `reverse_dns_class`). Contexte de routage,
// jamais une identité (RFC-0007). "" = non résolu / inconnu.
const (
	RDNSCloud       = "cloud"
	RDNSHosting     = "hosting"
	RDNSISP         = "isp"
	RDNSResidential = "residential"
	RDNSTor         = "tor"
	RDNSUnknown     = "unknown"
)

// Bornes anti-forge (RFC-0013 §15). Généreuses pour le trafic légitime, fermées
// pour un événement destiné à saturer la mémoire ou polluer le clustering.
const (
	maxStr        = 512 // longueur max d'un champ chaîne courant
	maxPathShape  = 256
	maxTag        = 64
	maxTags       = 32
	maxEvidence   = 64
	maxEvidenceID = 128
	minValidUnix  = 1577836800 // 2020-01-01T00:00:00Z — antérieur = garbage
	maxValidUnix  = 4102444800 // 2100-01-01T00:00:00Z — postérieur = garbage
)

var (
	// ErrInvalid enveloppe l'échec de validation (comparable via errors.Is).
	ErrInvalid = errors.New("envelope invalide")

	validSensors = map[string]bool{
		SensorWAF: true, SensorDPI: true, SensorAuthWatch: true,
		SensorSentinel: true, SensorReplay: true,
	}
	validRDNS = map[string]bool{
		"": true, RDNSCloud: true, RDNSHosting: true, RDNSISP: true,
		RDNSResidential: true, RDNSTor: true, RDNSUnknown: true,
	}
)

// Envelope est l'Event Envelope v1 (RFC-0013 §2). Les valeurs sensibles sont
// hashées (CredentialTokenHash) ou bucketisées lorsque leur forme suffit à la
// corrélation. Les tags JSON portent les noms de la RFC (snake_case).
type Envelope struct {
	EventID   string `json:"event_id"`
	Timestamp int64  `json:"timestamp"` // secondes Unix UTC
	Sensor    string `json:"sensor"`

	SrcIP      string `json:"src_ip"`
	SrcPort    int    `json:"src_port,omitempty"`
	DstService string `json:"dst_service,omitempty"`
	Vhost      string `json:"vhost,omitempty"`

	Transport string `json:"transport,omitempty"` // tcp, udp, tls…
	Protocol  string `json:"protocol,omitempty"`  // http, https, ssh, smtp…
	Action    string `json:"action,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
	Severity  int    `json:"severity"` // 0..100

	// CredentialTokenHash : HMAC-SHA256 d'un identifiant (login/jeton) via Hasher.
	// JAMAIS un mot de passe en clair, JAMAIS un SHA256 nu.
	CredentialTokenHash string `json:"credential_token_hash,omitempty"`

	PathShape       string   `json:"path_shape,omitempty"`        // chemin normalisé (segments variables → placeholders)
	UserAgentFamily string   `json:"user_agent_family,omitempty"` // famille/outil (nuclei, sqlmap, chrome…)
	TLSFingerprint  string   `json:"tls_fingerprint,omitempty"`   // JA4
	HTTPFingerprint string   `json:"http_fingerprint,omitempty"`  // JA4H (à venir)
	BehaviorTags    []string `json:"behavior_tags,omitempty"`

	ASN             uint32 `json:"asn,omitempty"`
	GeoCountry      string `json:"geo_country,omitempty"` // ISO-3166 alpha-2
	ReverseDNSClass string `json:"reverse_dns_class,omitempty"`

	RequestRateBucket     string `json:"request_rate_bucket,omitempty"`
	SessionDurationBucket string `json:"session_duration_bucket,omitempty"`

	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

// NewEventID produit un identifiant d'événement opaque (128 bits, hex). Utilisé
// quand le capteur n'en fournit pas ; sans dépendance externe (crypto/rand).
func NewEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand ne doit pas échouer ; en dernier recours on refuse un id vide.
		return "evt-fallback-0000000000000000"
	}
	return "evt-" + hex.EncodeToString(b[:])
}

// Hasher réduit un identifiant en HMAC-SHA256 avec un secret LOCAL ROTATABLE
// (RFC-0013 §2). La rotation du secret invalide volontairement la corrélation
// des anciens hachages : c'est le prix de la minimisation des PII.
type Hasher struct {
	secret []byte
}

// NewHasher construit un Hasher. Un secret vide est refusé : sans secret, un
// HMAC dégénère en hachage nu vulnérable aux dictionnaires, ce que la RFC interdit.
func NewHasher(secret []byte) (*Hasher, error) {
	if len(secret) < 16 {
		return nil, fmt.Errorf("%w: secret HMAC trop court (%d octets, minimum 16)", ErrInvalid, len(secret))
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return &Hasher{secret: cp}, nil
}

// Hash rend le HMAC-SHA256 hex d'un identifiant. Une valeur vide rend "" (rien à
// corréler), jamais le HMAC de la chaîne vide, pour ne pas créer de faux pivot.
func (h *Hasher) Hash(credential string) string {
	if credential == "" {
		return ""
	}
	m := hmac.New(sha256.New, h.secret)
	_, _ = m.Write([]byte(credential))
	return hex.EncodeToString(m.Sum(nil))
}

// RateBucket bucketise une cadence (requêtes/minute) en classe stable, pour
// corréler la forme sans exposer la valeur brute (RFC-0013 §2).
func RateBucket(perMinute float64) string {
	switch {
	case perMinute <= 0:
		return "none"
	case perMinute < 1:
		return "lt1"
	case perMinute < 6:
		return "1-6"
	case perMinute < 30:
		return "6-30"
	case perMinute < 120:
		return "30-120"
	case perMinute < 600:
		return "120-600"
	default:
		return "gt600"
	}
}

// DurationBucket bucketise une durée de session (secondes) en classe stable.
func DurationBucket(seconds float64) string {
	switch {
	case seconds <= 0:
		return "instant"
	case seconds < 5:
		return "lt5s"
	case seconds < 60:
		return "5-60s"
	case seconds < 600:
		return "1-10m"
	case seconds < 3600:
		return "10-60m"
	default:
		return "gt1h"
	}
}

// Validate applique les invariants d'entrée (RFC-0013 §15). Retourne une erreur
// enveloppant ErrInvalid décrivant le premier champ fautif ; ne modifie rien.
func (e *Envelope) Validate() error {
	if !validSensors[e.Sensor] {
		return fmt.Errorf("%w: sensor inconnu %q", ErrInvalid, clip(e.Sensor))
	}
	if e.Timestamp < minValidUnix || e.Timestamp > maxValidUnix {
		return fmt.Errorf("%w: timestamp hors bornes (%d)", ErrInvalid, e.Timestamp)
	}
	if net.ParseIP(strings.TrimSpace(e.SrcIP)) == nil {
		return fmt.Errorf("%w: src_ip invalide %q", ErrInvalid, clip(e.SrcIP))
	}
	if e.SrcPort < 0 || e.SrcPort > 65535 {
		return fmt.Errorf("%w: src_port hors plage (%d)", ErrInvalid, e.SrcPort)
	}
	if e.Severity < 0 || e.Severity > 100 {
		return fmt.Errorf("%w: severity hors plage (%d)", ErrInvalid, e.Severity)
	}
	if !validRDNS[e.ReverseDNSClass] {
		return fmt.Errorf("%w: reverse_dns_class inconnue %q", ErrInvalid, clip(e.ReverseDNSClass))
	}
	if e.GeoCountry != "" && len(e.GeoCountry) != 2 {
		return fmt.Errorf("%w: geo_country non ISO-2 %q", ErrInvalid, clip(e.GeoCountry))
	}
	// Bornes de longueur (anti-saturation) + UTF-8 valide sur les champs libres.
	for name, v := range map[string]string{
		"event_id": e.EventID, "dst_service": e.DstService, "vhost": e.Vhost,
		"transport": e.Transport, "protocol": e.Protocol, "action": e.Action,
		"rule_id": e.RuleID, "credential_token_hash": e.CredentialTokenHash,
		"user_agent_family": e.UserAgentFamily, "tls_fingerprint": e.TLSFingerprint,
		"http_fingerprint": e.HTTPFingerprint,
	} {
		if len(v) > maxStr {
			return fmt.Errorf("%w: champ %s trop long (%d)", ErrInvalid, name, len(v))
		}
		if !utf8.ValidString(v) {
			return fmt.Errorf("%w: champ %s non-UTF8", ErrInvalid, name)
		}
	}
	if len(e.PathShape) > maxPathShape {
		return fmt.Errorf("%w: path_shape trop long (%d)", ErrInvalid, len(e.PathShape))
	}
	if len(e.BehaviorTags) > maxTags {
		return fmt.Errorf("%w: trop de behavior_tags (%d)", ErrInvalid, len(e.BehaviorTags))
	}
	for _, t := range e.BehaviorTags {
		if len(t) > maxTag || !utf8.ValidString(t) {
			return fmt.Errorf("%w: behavior_tag invalide", ErrInvalid)
		}
	}
	if len(e.EvidenceRefs) > maxEvidence {
		return fmt.Errorf("%w: trop d'evidence_refs (%d)", ErrInvalid, len(e.EvidenceRefs))
	}
	for _, r := range e.EvidenceRefs {
		if len(r) > maxEvidenceID || !utf8.ValidString(r) {
			return fmt.Errorf("%w: evidence_ref invalide", ErrInvalid)
		}
	}
	return nil
}

// clip tronque une valeur pour un message d'erreur (ne jamais réémettre une
// chaîne géante forgée dans les logs).
func clip(s string) string {
	if len(s) > 32 {
		return s[:32] + "…"
	}
	return s
}
