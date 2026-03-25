// Package identity manages DID and ZKP Hamiltonian authentication
// CyberMind — SecuBox-Deb — 2026
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Identity manages node identity and ZKP credentials
type Identity struct {
	mu         sync.RWMutex
	did        string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	zkpValid   bool
	zkpExpiry  time.Time
	stopCh     chan struct{}
}

// DIDDocument represents a did:plc document
type DIDDocument struct {
	Context            []string          `json:"@context"`
	ID                 string            `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string          `json:"authentication"`
	Service            []Service         `json:"service"`
}

// VerificationMethod for DID document
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// Service endpoint for DID document
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// New creates a new Identity manager
func New(keypairPath, did string) (*Identity, error) {
	ident := &Identity{
		did:    did,
		stopCh: make(chan struct{}),
	}

	// Load or generate keypair
	if keypairPath != "" {
		if err := ident.loadKeypair(keypairPath); err != nil {
			slog.Warn("failed to load keypair, generating new", "error", err)
			if err := ident.generateKeypair(); err != nil {
				return nil, err
			}
		}
	} else {
		if err := ident.generateKeypair(); err != nil {
			return nil, err
		}
	}

	// Generate DID if not provided
	if ident.did == "" {
		ident.did = ident.generateDID()
	}

	return ident, nil
}

// Start begins identity management (ZKP rotation, etc.)
func (i *Identity) Start(ctx context.Context) error {
	slog.Info("identity starting", "did", i.did)

	// Initial ZKP generation
	if err := i.generateZKP(); err != nil {
		return fmt.Errorf("failed to generate initial ZKP: %w", err)
	}

	// Start ZKP rotation
	go i.rotateZKP(ctx)

	return nil
}

// Stop halts identity operations
func (i *Identity) Stop() {
	close(i.stopCh)
	slog.Info("identity stopped")
}

// GetDID returns the node's DID
func (i *Identity) GetDID() string {
	return i.did
}

// GetPublicKey returns the node's public key
func (i *Identity) GetPublicKey() ed25519.PublicKey {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.publicKey
}

// Sign signs data with the node's private key
func (i *Identity) Sign(data []byte) []byte {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return ed25519.Sign(i.privateKey, data)
}

// Verify verifies a signature
func (i *Identity) Verify(pubKey ed25519.PublicKey, data, signature []byte) bool {
	return ed25519.Verify(pubKey, data, signature)
}

// IsZKPValid returns whether the current ZKP is valid
func (i *Identity) IsZKPValid() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.zkpValid && time.Now().Before(i.zkpExpiry)
}

// GetZKPExpiry returns the ZKP expiration time
func (i *Identity) GetZKPExpiry() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.zkpExpiry
}

// RotateKeys generates new keys and ZKP
func (i *Identity) RotateKeys() error {
	if err := i.generateKeypair(); err != nil {
		return err
	}
	return i.generateZKP()
}

// loadKeypair loads an existing keypair from file
func (i *Identity) loadKeypair(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if len(data) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid keypair file size")
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	i.privateKey = ed25519.PrivateKey(data)
	i.publicKey = i.privateKey.Public().(ed25519.PublicKey)

	slog.Debug("keypair loaded", "path", path)
	return nil
}

// generateKeypair creates a new Ed25519 keypair
func (i *Identity) generateKeypair() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	i.publicKey = pub
	i.privateKey = priv

	slog.Info("new keypair generated")
	return nil
}

// generateDID creates a did:plc from the public key
func (i *Identity) generateDID() string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	// Simplified did:plc generation (actual spec is more complex)
	hash := hex.EncodeToString(i.publicKey[:16])
	return fmt.Sprintf("did:plc:%s", hash)
}

// generateZKP creates a new ZKP Hamiltonian proof
func (i *Identity) generateZKP() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	// TODO: Implement actual GK-HAM-2025 ZKP generation
	// For now, mark as valid with 24h expiry
	i.zkpValid = true
	i.zkpExpiry = time.Now().Add(24 * time.Hour)

	slog.Info("ZKP generated", "expiry", i.zkpExpiry)
	return nil
}

// rotateZKP periodically rotates the ZKP credentials
func (i *Identity) rotateZKP(ctx context.Context) {
	// Rotate 1 hour before expiry
	checkInterval := time.Hour

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-i.stopCh:
			return
		case <-ticker.C:
			i.mu.RLock()
			needsRotation := time.Until(i.zkpExpiry) < 2*time.Hour
			i.mu.RUnlock()

			if needsRotation {
				if err := i.generateZKP(); err != nil {
					slog.Error("failed to rotate ZKP", "error", err)
				}
			}
		}
	}
}

// Status returns identity module status
func (i *Identity) Status() map[string]interface{} {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return map[string]interface{}{
		"did":        i.did,
		"public_key": hex.EncodeToString(i.publicKey),
		"zkp_valid":  i.zkpValid,
		"zkp_expiry": i.zkpExpiry.Format(time.RFC3339),
		"running":    true,
	}
}

// GetDIDDocument returns the DID Document for this node
func (i *Identity) GetDIDDocument() *DIDDocument {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return &DIDDocument{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      i.did,
		VerificationMethod: []VerificationMethod{
			{
				ID:                 fmt.Sprintf("%s#key-1", i.did),
				Type:               "Ed25519VerificationKey2020",
				Controller:         i.did,
				PublicKeyMultibase: "z" + hex.EncodeToString(i.publicKey),
			},
		},
		Authentication: []string{fmt.Sprintf("%s#key-1", i.did)},
		Service: []Service{
			{
				ID:              fmt.Sprintf("%s#mesh", i.did),
				Type:            "SecuBoxMesh",
				ServiceEndpoint: "wg://mesh.local",
			},
		},
	}
}
