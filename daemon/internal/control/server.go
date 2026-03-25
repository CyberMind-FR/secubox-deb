// Package control implements the Unix socket control server
// CyberMind — SecuBox-Deb — 2026
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cybermind/secubox-deb/internal/discovery"
	"github.com/cybermind/secubox-deb/internal/identity"
	"github.com/cybermind/secubox-deb/internal/telemetry"
	"github.com/cybermind/secubox-deb/internal/topology"
)

// Server handles control commands via Unix socket
type Server struct {
	mu       sync.RWMutex
	sockPath string
	listener net.Listener
	ident    *identity.Identity
	disco    *discovery.Discovery
	topo     *topology.Topology
	telem    *telemetry.Telemetry
	startTime time.Time
	stopCh   chan struct{}
}

// New creates a new control server
func New(sockPath string, ident *identity.Identity, disco *discovery.Discovery, topo *topology.Topology, telem *telemetry.Telemetry) *Server {
	return &Server{
		sockPath:  sockPath,
		ident:     ident,
		disco:     disco,
		topo:      topo,
		telem:     telem,
		startTime: time.Now(),
		stopCh:    make(chan struct{}),
	}
}

// Start begins listening on the Unix socket
func (s *Server) Start(ctx context.Context) error {
	// Remove existing socket file
	os.Remove(s.sockPath)

	listener, err := net.Listen("unix", s.sockPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %w", err)
	}
	s.listener = listener

	// Set socket permissions
	if err := os.Chmod(s.sockPath, 0660); err != nil {
		slog.Warn("failed to set socket permissions", "error", err)
	}

	slog.Info("control server starting", "socket", s.sockPath)

	go s.acceptLoop(ctx)
	return nil
}

// Stop closes the control server
func (s *Server) Stop() {
	close(s.stopCh)
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.sockPath)
	slog.Info("control server stopped")
}

// acceptLoop accepts incoming connections
func (s *Server) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				slog.Debug("accept error", "error", err)
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

// handleConnection processes a single client connection
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		slog.Debug("read error", "error", err)
		return
	}

	cmd := strings.TrimSpace(line)
	slog.Debug("received command", "cmd", cmd)

	response := s.handleCommand(cmd)
	conn.Write(response)
}

// handleCommand processes a command and returns the response
func (s *Server) handleCommand(cmd string) []byte {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return s.errorResponse("empty command")
	}

	switch parts[0] {
	case "mesh.status":
		return s.meshStatus()
	case "mesh.peers":
		return s.meshPeers()
	case "mesh.topology":
		return s.meshTopology()
	case "mesh.nodes":
		return s.meshNodes()
	case "node.info":
		return s.nodeInfo()
	case "node.rotate":
		return s.nodeRotate()
	case "telemetry.latest":
		return s.telemetryLatest()
	case "ping":
		return []byte(`{"pong":true}`)
	default:
		return s.errorResponse(fmt.Sprintf("unknown command: %s", parts[0]))
	}
}

func (s *Server) errorResponse(msg string) []byte {
	resp := map[string]interface{}{
		"error":   msg,
		"success": false,
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *Server) meshStatus() []byte {
	peers := s.disco.GetPeers()
	meshGate := s.topo.GetMeshGate()
	uptime := time.Since(s.startTime).Seconds()

	resp := map[string]interface{}{
		"state":      "running",
		"peer_count": len(peers),
		"role":       "edge", // TODO: get from config
		"mesh_gate":  meshGate,
		"uptime":     int64(uptime),
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *Server) meshPeers() []byte {
	peers := s.disco.GetPeers()
	result := make([]map[string]interface{}, 0, len(peers))

	for _, p := range peers {
		result = append(result, map[string]interface{}{
			"did":       p.DID,
			"address":   p.Address.String(),
			"role":      p.Role,
			"last_seen": p.LastSeen.Format(time.RFC3339),
		})
	}

	data, _ := json.Marshal(result)
	return data
}

func (s *Server) meshTopology() []byte {
	nodes := s.topo.GetNodes()
	meshGate := s.topo.GetMeshGate()

	nodeList := make([]map[string]interface{}, 0, len(nodes))
	edges := make([]map[string]interface{}, 0)

	// Layout nodes in a force-directed style
	// Center relay nodes, edge nodes around them
	relayCount := 0
	edgeCount := 0
	airGapCount := 0

	for _, n := range nodes {
		var x, y int
		switch n.Role {
		case "relay":
			// Relays in center area
			x = 200 + (relayCount%2)*200
			y = 150 + (relayCount/2)*100
			relayCount++
		case "edge":
			// Edges around the perimeter
			angle := float64(edgeCount) * 0.8
			x = 300 + int(180*math.Cos(angle))
			y = 200 + int(120*math.Sin(angle))
			edgeCount++
		case "air-gapped":
			// Air-gapped nodes isolated
			x = 520
			y = 80 + airGapCount*60
			airGapCount++
		default:
			x = 100 + (len(nodeList)%4)*120
			y = 100 + (len(nodeList)/4)*80
		}

		nodeList = append(nodeList, map[string]interface{}{
			"id":   n.DID,
			"role": string(n.Role),
			"ip":   n.Address.String(),
			"x":    x,
			"y":    y,
		})
	}

	// Generate edges: connect edges to nearest relay, relays to each other
	var relays []string
	var edgeNodes []string
	for _, n := range nodes {
		if n.Role == "relay" {
			relays = append(relays, n.DID)
		} else if n.Role == "edge" {
			edgeNodes = append(edgeNodes, n.DID)
		}
	}

	// Connect relays to each other (full mesh between relays)
	for i := 0; i < len(relays); i++ {
		for j := i + 1; j < len(relays); j++ {
			edges = append(edges, map[string]interface{}{
				"source": relays[i],
				"target": relays[j],
				"type":   "relay-link",
			})
		}
	}

	// Connect edge nodes to first relay (simplified)
	if len(relays) > 0 {
		for i, e := range edgeNodes {
			targetRelay := relays[i%len(relays)]
			edges = append(edges, map[string]interface{}{
				"source": e,
				"target": targetRelay,
				"type":   "edge-link",
			})
		}
	}

	resp := map[string]interface{}{
		"nodes":     nodeList,
		"edges":     edges,
		"mesh_gate": meshGate,
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *Server) meshNodes() []byte {
	nodes := s.topo.GetNodes()
	result := make([]map[string]interface{}, 0, len(nodes))

	for _, n := range nodes {
		result = append(result, map[string]interface{}{
			"did":       n.DID,
			"role":      string(n.Role),
			"address":   n.Address.String(),
			"last_seen": n.LastSeen.Format(time.RFC3339),
			"zkp_valid": true, // TODO: implement
		})
	}

	data, _ := json.Marshal(result)
	return data
}

func (s *Server) nodeInfo() []byte {
	resp := map[string]interface{}{
		"did":        s.ident.GetDID(),
		"role":       "edge", // TODO: get from config
		"public_key": fmt.Sprintf("%x", s.ident.GetPublicKey()),
		"address":    "", // TODO: get local mesh address
		"zkp_valid":  s.ident.IsZKPValid(),
		"zkp_expiry": s.ident.GetZKPExpiry().Format(time.RFC3339),
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *Server) nodeRotate() []byte {
	err := s.ident.RotateKeys()
	if err != nil {
		return s.errorResponse(fmt.Sprintf("failed to rotate keys: %v", err))
	}

	resp := map[string]interface{}{
		"success":    true,
		"new_expiry": s.ident.GetZKPExpiry().Format(time.RFC3339),
	}
	data, _ := json.Marshal(resp)
	return data
}

func (s *Server) telemetryLatest() []byte {
	latest := s.telem.GetLatest()
	if latest == nil {
		return s.errorResponse("no telemetry data available")
	}

	resp := map[string]interface{}{
		"timestamp":      latest.Timestamp.Format(time.RFC3339),
		"uptime":         latest.Uptime,
		"peer_count":     latest.PeerCount,
		"nftables_rules": latest.NFTablesRules,
		"crowdsec_bans":  latest.CrowdSecBans,
		"cpu_percent":    latest.CPUPercent,
		"memory_percent": latest.MemoryPercent,
		"disk_percent":   latest.DiskPercent,
	}
	data, _ := json.Marshal(resp)
	return data
}
