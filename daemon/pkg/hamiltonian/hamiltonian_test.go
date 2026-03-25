package hamiltonian

import (
	"testing"
)

func TestGenerateGraph(t *testing.T) {
	graph, cycle, err := GenerateGraph(8)
	if err != nil {
		t.Fatalf("failed to generate graph: %v", err)
	}

	if graph.Nodes != 8 {
		t.Errorf("expected 8 nodes, got %d", graph.Nodes)
	}

	if len(cycle) != 8 {
		t.Errorf("expected cycle length 8, got %d", len(cycle))
	}

	// Verify cycle is valid
	for i := 0; i < len(cycle); i++ {
		from := cycle[i]
		to := cycle[(i+1)%len(cycle)]
		if graph.Edges[from][to] != 1 {
			t.Errorf("invalid cycle: no edge from %d to %d", from, to)
		}
	}
}

func TestGraphValidation(t *testing.T) {
	tests := []struct {
		name    string
		graph   Graph
		wantErr bool
	}{
		{
			name: "valid graph",
			graph: Graph{
				Nodes: 3,
				Edges: [][]int{{0, 1, 1}, {1, 0, 1}, {1, 1, 0}},
			},
			wantErr: false,
		},
		{
			name: "too few nodes",
			graph: Graph{
				Nodes: 2,
				Edges: [][]int{{0, 1}, {1, 0}},
			},
			wantErr: true,
		},
		{
			name: "mismatched matrix",
			graph: Graph{
				Nodes: 3,
				Edges: [][]int{{0, 1}, {1, 0}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.graph.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProverVerifier(t *testing.T) {
	// Generate a graph with known cycle
	graph, cycle, err := GenerateGraph(8)
	if err != nil {
		t.Fatal(err)
	}

	// Create prover
	prover, err := NewProver(graph, cycle)
	if err != nil {
		t.Fatalf("failed to create prover: %v", err)
	}

	pubKey := prover.GetPublicKey()
	if len(pubKey) != 32 {
		t.Errorf("expected 32-byte public key, got %d", len(pubKey))
	}

	// Generate proof
	proof, err := prover.GenerateProof()
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	if proof.Commitment == "" {
		t.Error("empty commitment")
	}

	if proof.Challenge == "" {
		t.Error("empty challenge")
	}

	if len(proof.Response) != graph.Nodes {
		t.Errorf("expected response length %d, got %d", graph.Nodes, len(proof.Response))
	}

	// Create verifier
	verifier := NewVerifier(graph, pubKey)

	// Verify proof
	if !verifier.VerifyProof(proof) {
		t.Error("proof verification failed")
	}
}

func BenchmarkProofGeneration(b *testing.B) {
	graph, cycle, _ := GenerateGraph(16)
	prover, _ := NewProver(graph, cycle)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prover.GenerateProof()
	}
}
