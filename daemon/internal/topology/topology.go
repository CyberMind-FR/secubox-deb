// Package topology manages mesh network topology and routing
// CyberMind — SecuBox-Deb — 2026
package topology

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Role defines node roles in the mesh
type Role string

const (
	RoleEdge      Role = "edge"
	RoleRelay     Role = "relay"
	RoleAirGapped Role = "air-gapped"
)

// Node represents a node in the mesh topology
type Node struct {
	DID       string
	Address   net.IP
	Role      Role
	IsMeshGate bool
	Routes    []string
	LastSeen  time.Time
}

// Topology manages the mesh network graph
type Topology struct {
	mu        sync.RWMutex
	subnet    *net.IPNet
	localRole Role
	meshGate  string // DID of current mesh gate
	nodes     map[string]*Node
	stopCh    chan struct{}
}

// New creates a new Topology manager
func New(subnet string, role string) (*Topology, error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %w", err)
	}

	return &Topology{
		subnet:    ipnet,
		localRole: Role(role),
		nodes:     make(map[string]*Node),
		stopCh:    make(chan struct{}),
	}, nil
}

// Start begins topology management
func (t *Topology) Start(ctx context.Context) error {
	slog.Info("topology starting", "subnet", t.subnet.String(), "role", t.localRole)

	// Add mock nodes for visualization demo
	t.addMockNodes()

	// Start mesh gate election
	go t.runElection(ctx)

	// Start route convergence
	go t.convergeRoutes(ctx)

	return nil
}

// addMockNodes adds demo nodes for visualization
func (t *Topology) addMockNodes() {
	mockNodes := []struct {
		did  string
		ip   string
		role Role
	}{
		{"did:plc:secubox-gateway-001", "10.42.0.1", RoleRelay},
		{"did:plc:secubox-edge-alpha", "10.42.1.10", RoleEdge},
		{"did:plc:secubox-edge-beta", "10.42.1.20", RoleEdge},
		{"did:plc:secubox-edge-gamma", "10.42.1.30", RoleEdge},
		{"did:plc:secubox-relay-east", "10.42.2.1", RoleRelay},
		{"did:plc:secubox-edge-delta", "10.42.2.10", RoleEdge},
		{"did:plc:secubox-airgap-vault", "10.42.99.1", RoleAirGapped},
	}

	for _, m := range mockNodes {
		t.AddNode(m.did, net.ParseIP(m.ip), m.role)
	}

	slog.Info("mock nodes added for visualization", "count", len(mockNodes))
}

// Stop halts topology management
func (t *Topology) Stop() {
	close(t.stopCh)
	slog.Info("topology stopped")
}

// AddNode adds or updates a node in the topology
func (t *Topology) AddNode(did string, addr net.IP, role Role) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if existing, ok := t.nodes[did]; ok {
		existing.Address = addr
		existing.Role = role
		existing.LastSeen = time.Now()
	} else {
		t.nodes[did] = &Node{
			DID:      did,
			Address:  addr,
			Role:     role,
			LastSeen: time.Now(),
		}
		slog.Info("node added to topology", "did", did, "role", role)
	}
}

// RemoveNode removes a node from the topology
func (t *Topology) RemoveNode(did string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.nodes, did)
	slog.Info("node removed from topology", "did", did)

	// Re-elect mesh gate if removed node was the gate
	if t.meshGate == did {
		t.meshGate = ""
	}
}

// GetMeshGate returns the current mesh gate DID
func (t *Topology) GetMeshGate() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.meshGate
}

// GetNodes returns all nodes in the topology
func (t *Topology) GetNodes() []Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	nodes := make([]Node, 0, len(t.nodes))
	for _, n := range t.nodes {
		nodes = append(nodes, *n)
	}
	return nodes
}

// runElection performs mesh gate election
func (t *Topology) runElection(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.electMeshGate()
		}
	}
}

// electMeshGate selects the best node as mesh gate
// Priority: relay > edge > air-gapped, then by DID (lexicographic)
func (t *Topology) electMeshGate() {
	t.mu.Lock()
	defer t.mu.Unlock()

	var bestNode *Node
	for _, node := range t.nodes {
		if bestNode == nil {
			bestNode = node
			continue
		}

		// Prefer relay nodes
		if node.Role == RoleRelay && bestNode.Role != RoleRelay {
			bestNode = node
			continue
		}

		// Among same role, prefer lower DID
		if node.Role == bestNode.Role && node.DID < bestNode.DID {
			bestNode = node
		}
	}

	if bestNode != nil && t.meshGate != bestNode.DID {
		oldGate := t.meshGate
		t.meshGate = bestNode.DID
		bestNode.IsMeshGate = true

		// Clear old mesh gate flag
		if oldNode, ok := t.nodes[oldGate]; ok {
			oldNode.IsMeshGate = false
		}

		slog.Info("mesh gate elected", "did", bestNode.DID, "previous", oldGate)
	}
}

// convergeRoutes updates system routing tables
func (t *Topology) convergeRoutes(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.updateRoutes()
		}
	}
}

// updateRoutes applies route changes to the system
func (t *Topology) updateRoutes() {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// TODO: Implement actual routing via netlink
	// - Add routes for each peer: ip route add <peer_subnet> via <peer_wg_addr>
	// - Update policy rules: ip rule add from <local_subnet> lookup secubox
	slog.Debug("route convergence placeholder", "nodes", len(t.nodes))
}

// Status returns topology module status
func (t *Topology) Status() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return map[string]interface{}{
		"subnet":     t.subnet.String(),
		"local_role": string(t.localRole),
		"mesh_gate":  t.meshGate,
		"node_count": len(t.nodes),
		"running":    true,
	}
}
