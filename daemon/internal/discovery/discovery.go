// Package discovery implements mDNS service discovery and WireGuard beacon
// CyberMind — SecuBox-Deb — 2026
package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Peer represents a discovered mesh peer
type Peer struct {
	DID      string
	Address  net.IP
	Port     int
	Role     string
	LastSeen time.Time
}

// Discovery handles mDNS discovery and WireGuard beacon
type Discovery struct {
	mu             sync.RWMutex
	service        string
	beaconInterval time.Duration
	peers          map[string]*Peer
	stopCh         chan struct{}
}

// New creates a new Discovery instance
func New(service string, beaconInterval int) (*Discovery, error) {
	if service == "" {
		service = "_secubox._udp"
	}

	return &Discovery{
		service:        service,
		beaconInterval: time.Duration(beaconInterval) * time.Second,
		peers:          make(map[string]*Peer),
		stopCh:         make(chan struct{}),
	}, nil
}

// Start begins mDNS service advertisement and peer discovery
func (d *Discovery) Start(ctx context.Context) error {
	slog.Info("discovery starting", "service", d.service, "beacon_interval", d.beaconInterval)

	// Start mDNS service registration
	go d.registerService(ctx)

	// Start peer discovery
	go d.discoverPeers(ctx)

	// Start beacon sender
	go d.sendBeacons(ctx)

	// Start peer cleanup
	go d.cleanupPeers(ctx)

	return nil
}

// Stop halts all discovery operations
func (d *Discovery) Stop() {
	close(d.stopCh)
	slog.Info("discovery stopped")
}

// GetPeers returns a copy of all known peers
func (d *Discovery) GetPeers() []Peer {
	d.mu.RLock()
	defer d.mu.RUnlock()

	peers := make([]Peer, 0, len(d.peers))
	for _, p := range d.peers {
		peers = append(peers, *p)
	}
	return peers
}

// AddPeer registers a new peer or updates an existing one
func (d *Discovery) AddPeer(did string, addr net.IP, port int, role string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if existing, ok := d.peers[did]; ok {
		existing.LastSeen = time.Now()
		existing.Address = addr
		existing.Port = port
		slog.Debug("peer updated", "did", did, "address", addr)
	} else {
		d.peers[did] = &Peer{
			DID:      did,
			Address:  addr,
			Port:     port,
			Role:     role,
			LastSeen: time.Now(),
		}
		slog.Info("peer discovered", "did", did, "address", addr, "role", role)
	}
}

// registerService advertises this node via mDNS
func (d *Discovery) registerService(ctx context.Context) {
	// TODO: Implement zeroconf service registration
	// server, err := zeroconf.Register("secubox", d.service, "local.", 51820, nil, nil)
	slog.Debug("mDNS service registration placeholder")

	<-ctx.Done()
}

// discoverPeers listens for mDNS announcements from other nodes
func (d *Discovery) discoverPeers(ctx context.Context) {
	// TODO: Implement zeroconf service browsing
	// resolver, err := zeroconf.NewResolver(nil)
	// entries := make(chan *zeroconf.ServiceEntry)
	slog.Debug("mDNS peer discovery placeholder")

	<-ctx.Done()
}

// sendBeacons sends encrypted WireGuard beacons to known peers
func (d *Discovery) sendBeacons(ctx context.Context) {
	ticker := time.NewTicker(d.beaconInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.mu.RLock()
			peerCount := len(d.peers)
			d.mu.RUnlock()

			if peerCount > 0 {
				slog.Debug("sending beacons", "peer_count", peerCount)
				// TODO: Send encrypted beacon via WireGuard
			}
		}
	}
}

// cleanupPeers removes stale peers
func (d *Discovery) cleanupPeers(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	timeout := 2 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.mu.Lock()
			now := time.Now()
			for did, peer := range d.peers {
				if now.Sub(peer.LastSeen) > timeout {
					slog.Info("peer expired", "did", did, "last_seen", peer.LastSeen)
					delete(d.peers, did)
				}
			}
			d.mu.Unlock()
		}
	}
}

// Status returns discovery module status
func (d *Discovery) Status() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return map[string]interface{}{
		"service":         d.service,
		"beacon_interval": d.beaconInterval.String(),
		"peer_count":      len(d.peers),
		"running":         true,
	}
}

// String implements fmt.Stringer
func (d *Discovery) String() string {
	return fmt.Sprintf("Discovery{service=%s, peers=%d}", d.service, len(d.peers))
}
