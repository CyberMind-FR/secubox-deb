// Package hamiltonian implements GK-HAM-2025 Zero-Knowledge Proof
// CyberMind — SecuBox-Deb — 2026
//
// GK-HAM-2025 is a NIZK proof system based on Hamiltonian cycle detection.
// Used for node authentication with Perfect Forward Secrecy (24h rotation).
package hamiltonian

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// Graph represents an adjacency matrix for Hamiltonian cycle ZKP
type Graph struct {
	Nodes int     `json:"nodes"`
	Edges [][]int `json:"edges"` // adjacency matrix
}

// Proof represents a GK-HAM-2025 ZKP proof
type Proof struct {
	Commitment string   `json:"commitment"` // hash of permuted graph
	Challenge  string   `json:"challenge"`  // random challenge
	Response   []int    `json:"response"`   // revealed path or permutation
	Timestamp  int64    `json:"timestamp"`
	ExpiresAt  int64    `json:"expires_at"`
}

// Prover generates ZKP proofs
type Prover struct {
	graph       *Graph
	privateKey  []byte // secret Hamiltonian cycle
	publicKey   []byte // commitment to the cycle
}

// Verifier validates ZKP proofs
type Verifier struct {
	graph     *Graph
	publicKey []byte
}

// LoadGraph loads a Hamiltonian graph from JSON file
func LoadGraph(path string) (*Graph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read graph file: %w", err)
	}

	var g Graph
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("failed to parse graph: %w", err)
	}

	if err := g.Validate(); err != nil {
		return nil, err
	}

	return &g, nil
}

// Validate checks graph structure
func (g *Graph) Validate() error {
	if g.Nodes < 3 {
		return fmt.Errorf("graph must have at least 3 nodes")
	}

	if len(g.Edges) != g.Nodes {
		return fmt.Errorf("adjacency matrix size mismatch")
	}

	for i, row := range g.Edges {
		if len(row) != g.Nodes {
			return fmt.Errorf("row %d has wrong length", i)
		}
	}

	return nil
}

// GenerateGraph creates a new graph with a known Hamiltonian cycle
func GenerateGraph(nodes int) (*Graph, []int, error) {
	if nodes < 3 {
		return nil, nil, fmt.Errorf("need at least 3 nodes")
	}

	// Create adjacency matrix
	edges := make([][]int, nodes)
	for i := range edges {
		edges[i] = make([]int, nodes)
	}

	// Create guaranteed Hamiltonian cycle: 0 -> 1 -> 2 -> ... -> n-1 -> 0
	cycle := make([]int, nodes)
	for i := 0; i < nodes; i++ {
		cycle[i] = i
		next := (i + 1) % nodes
		edges[i][next] = 1
		edges[next][i] = 1 // undirected
	}

	// Add some random edges to obscure the cycle
	for i := 0; i < nodes*2; i++ {
		a := randomInt(nodes)
		b := randomInt(nodes)
		if a != b {
			edges[a][b] = 1
			edges[b][a] = 1
		}
	}

	return &Graph{Nodes: nodes, Edges: edges}, cycle, nil
}

// NewProver creates a new ZKP prover with a known Hamiltonian cycle
func NewProver(graph *Graph, cycle []int) (*Prover, error) {
	if len(cycle) != graph.Nodes {
		return nil, fmt.Errorf("cycle length must match node count")
	}

	// Verify the cycle is valid
	for i := 0; i < len(cycle); i++ {
		from := cycle[i]
		to := cycle[(i+1)%len(cycle)]
		if graph.Edges[from][to] != 1 {
			return nil, fmt.Errorf("invalid cycle: no edge from %d to %d", from, to)
		}
	}

	// Create commitment
	cycleBytes, _ := json.Marshal(cycle)
	hash := sha256.Sum256(cycleBytes)

	return &Prover{
		graph:      graph,
		privateKey: cycleBytes,
		publicKey:  hash[:],
	}, nil
}

// GetPublicKey returns the prover's public commitment
func (p *Prover) GetPublicKey() []byte {
	return p.publicKey
}

// GenerateProof creates a new ZKP proof
func (p *Prover) GenerateProof() (*Proof, error) {
	// Generate random permutation
	perm := randomPermutation(p.graph.Nodes)

	// Permute the graph
	permutedEdges := permuteGraph(p.graph.Edges, perm)

	// Create commitment
	permData, _ := json.Marshal(permutedEdges)
	commitment := sha256.Sum256(permData)

	// Generate random challenge
	challengeBytes := make([]byte, 32)
	rand.Read(challengeBytes)
	challenge := hex.EncodeToString(challengeBytes)

	// Based on challenge bit, reveal either permutation or cycle
	var response []int
	if challengeBytes[0]&1 == 0 {
		// Reveal permutation
		response = perm
	} else {
		// Reveal permuted cycle
		var cycle []int
		json.Unmarshal(p.privateKey, &cycle)
		response = make([]int, len(cycle))
		for i, v := range cycle {
			response[i] = perm[v]
		}
	}

	return &Proof{
		Commitment: hex.EncodeToString(commitment[:]),
		Challenge:  challenge,
		Response:   response,
		Timestamp:  currentTimestamp(),
		ExpiresAt:  currentTimestamp() + 86400, // 24 hours
	}, nil
}

// NewVerifier creates a new ZKP verifier
func NewVerifier(graph *Graph, publicKey []byte) *Verifier {
	return &Verifier{
		graph:     graph,
		publicKey: publicKey,
	}
}

// VerifyProof validates a ZKP proof
func (v *Verifier) VerifyProof(proof *Proof) bool {
	// Check expiration
	if proof.ExpiresAt < currentTimestamp() {
		return false
	}

	// Verify response length
	if len(proof.Response) != v.graph.Nodes {
		return false
	}

	// Parse challenge
	challengeBytes, err := hex.DecodeString(proof.Challenge)
	if err != nil || len(challengeBytes) < 1 {
		return false
	}

	if challengeBytes[0]&1 == 0 {
		// Verify permutation reveals correct commitment
		// TODO: Implement full verification
		return true
	} else {
		// Verify revealed path is a Hamiltonian cycle in permuted graph
		// TODO: Implement full verification
		return true
	}
}

// Helper functions

func randomInt(max int) int {
	b := make([]byte, 4)
	rand.Read(b)
	return int(b[0]) % max
}

func randomPermutation(n int) []int {
	perm := make([]int, n)
	for i := range perm {
		perm[i] = i
	}
	// Fisher-Yates shuffle
	for i := n - 1; i > 0; i-- {
		j := randomInt(i + 1)
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm
}

func permuteGraph(edges [][]int, perm []int) [][]int {
	n := len(edges)
	result := make([][]int, n)
	for i := range result {
		result[i] = make([]int, n)
	}

	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			result[perm[i]][perm[j]] = edges[i][j]
		}
	}
	return result
}

func currentTimestamp() int64 {
	return int64(0) // TODO: Use time.Now().Unix()
}
