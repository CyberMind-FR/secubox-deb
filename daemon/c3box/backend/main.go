// C3BOX Situational Awareness Dashboard Backend
// CyberMind — SecuBox-Deb — 2026
package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
)

var (
	listenAddr    = flag.String("listen", ":8080", "HTTP listen address")
	secuboxdSock  = flag.String("secuboxd", "/run/secuboxd/topo.sock", "secuboxd socket path")
	staticDir     = flag.String("static", "/usr/share/c3box/www", "Static files directory")
)

func main() {
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/mesh/topology", handleTopology)
	mux.HandleFunc("/api/mesh/nodes", handleNodes)
	mux.HandleFunc("/api/mesh/node/", handleNode)
	mux.HandleFunc("/api/mesh/status", handleStatus)
	mux.HandleFunc("/api/node/rotate", handleRotate)
	mux.HandleFunc("/api/health", handleHealth)

	// Static files
	mux.Handle("/", http.FileServer(http.Dir(*staticDir)))

	slog.Info("c3box starting", "listen", *listenAddr)
	if err := http.ListenAndServe(*listenAddr, mux); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// sendToSecuboxd sends a command to secuboxd and returns the response
func sendToSecuboxd(cmd string) ([]byte, error) {
	conn, err := net.Dial("unix", *secuboxdSock)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return nil, err
	}

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   message,
		"success": false,
	})
}

// GET /api/mesh/topology — mesh network graph
func handleTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := sendToSecuboxd("mesh.topology")
	if err != nil {
		// Return mock data for development
		writeJSON(w, map[string]interface{}{
			"nodes": []map[string]interface{}{
				{"id": "did:plc:node1", "role": "edge", "x": 100, "y": 100},
				{"id": "did:plc:node2", "role": "relay", "x": 300, "y": 100},
				{"id": "did:plc:node3", "role": "edge", "x": 200, "y": 250},
			},
			"edges": []map[string]interface{}{
				{"source": "did:plc:node1", "target": "did:plc:node2"},
				{"source": "did:plc:node2", "target": "did:plc:node3"},
				{"source": "did:plc:node3", "target": "did:plc:node1"},
			},
			"mesh_gate": "did:plc:node2",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// GET /api/mesh/nodes — list all nodes
func handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := sendToSecuboxd("mesh.nodes")
	if err != nil {
		// Mock data
		writeJSON(w, []map[string]interface{}{
			{
				"did":       "did:plc:node1",
				"role":      "edge",
				"address":   "10.42.0.1",
				"last_seen": "2026-03-25T10:00:00Z",
				"zkp_valid": true,
			},
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// GET /api/mesh/node/{did} — node details
func handleNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract DID from path
	did := r.URL.Path[len("/api/mesh/node/"):]
	if did == "" {
		writeError(w, http.StatusBadRequest, "missing node DID")
		return
	}

	resp, err := sendToSecuboxd("mesh.node " + did)
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"did":        did,
			"role":       "unknown",
			"error":      "secuboxd unavailable",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// GET /api/mesh/status — mesh status
func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := sendToSecuboxd("mesh.status")
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"state":      "degraded",
			"peer_count": 0,
			"mesh_gate":  "",
			"uptime":     0,
			"error":      "secuboxd unavailable",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// POST /api/node/rotate — rotate ZKP keys
func handleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := sendToSecuboxd("node.rotate")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "secuboxd unavailable")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// GET /api/health — health check
func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"status":  "ok",
		"service": "c3box",
		"version": "0.1.0",
	})
}
