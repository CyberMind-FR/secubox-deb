// SecuBox CLI Management Tool
// CyberMind — SecuBox-Deb — 2026
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"
)

var socketPath = "/run/secuboxd/topo.sock"

func main() {
	rootCmd := &cobra.Command{
		Use:   "secuboxctl",
		Short: "SecuBox mesh management CLI",
		Long:  "Command-line interface for managing SecuBox mesh network",
	}

	// mesh subcommand
	meshCmd := &cobra.Command{
		Use:   "mesh",
		Short: "Mesh network operations",
	}

	meshStatusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show mesh network status",
		RunE:  meshStatus,
	}

	meshPeersCmd := &cobra.Command{
		Use:   "peers",
		Short: "List mesh peers",
		RunE:  meshPeers,
	}

	meshCmd.AddCommand(meshStatusCmd, meshPeersCmd)

	// node subcommand
	nodeCmd := &cobra.Command{
		Use:   "node",
		Short: "Node operations",
	}

	nodeInfoCmd := &cobra.Command{
		Use:   "info",
		Short: "Show node information",
		RunE:  nodeInfo,
	}

	nodeRotateCmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate ZKP keys",
		RunE:  nodeRotate,
	}

	nodeCmd.AddCommand(nodeInfoCmd, nodeRotateCmd)

	// version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("secuboxctl v0.1.0")
			fmt.Println("CyberMind — SecuBox-Deb — 2026")
		},
	}

	rootCmd.AddCommand(meshCmd, nodeCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func sendCommand(cmd string) ([]byte, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to secuboxd: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return nil, fmt.Errorf("failed to send command: %w", err)
	}

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return buf[:n], nil
}

func meshStatus(cmd *cobra.Command, args []string) error {
	resp, err := sendCommand("mesh.status")
	if err != nil {
		return err
	}

	var status map[string]interface{}
	if err := json.Unmarshal(resp, &status); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Println("Mesh Status:")
	fmt.Printf("  State:      %v\n", status["state"])
	fmt.Printf("  Peers:      %v\n", status["peer_count"])
	fmt.Printf("  Role:       %v\n", status["role"])
	fmt.Printf("  Mesh Gate:  %v\n", status["mesh_gate"])
	fmt.Printf("  Uptime:     %v\n", status["uptime"])

	return nil
}

func meshPeers(cmd *cobra.Command, args []string) error {
	resp, err := sendCommand("mesh.peers")
	if err != nil {
		return err
	}

	var peers []map[string]interface{}
	if err := json.Unmarshal(resp, &peers); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Println("Mesh Peers:")
	fmt.Printf("%-45s %-15s %-10s %s\n", "DID", "ADDRESS", "ROLE", "LAST SEEN")
	fmt.Println("─────────────────────────────────────────────────────────────────────────────")

	for _, peer := range peers {
		fmt.Printf("%-45v %-15v %-10v %v\n",
			peer["did"], peer["address"], peer["role"], peer["last_seen"])
	}

	return nil
}

func nodeInfo(cmd *cobra.Command, args []string) error {
	resp, err := sendCommand("node.info")
	if err != nil {
		return err
	}

	var info map[string]interface{}
	if err := json.Unmarshal(resp, &info); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Println("Node Information:")
	fmt.Printf("  DID:        %v\n", info["did"])
	fmt.Printf("  Role:       %v\n", info["role"])
	fmt.Printf("  Public Key: %v\n", info["public_key"])
	fmt.Printf("  Address:    %v\n", info["address"])
	fmt.Printf("  ZKP Valid:  %v\n", info["zkp_valid"])
	fmt.Printf("  ZKP Expiry: %v\n", info["zkp_expiry"])

	return nil
}

func nodeRotate(cmd *cobra.Command, args []string) error {
	resp, err := sendCommand("node.rotate")
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result["success"] == true {
		fmt.Println("ZKP keys rotated successfully")
		fmt.Printf("  New expiry: %v\n", result["new_expiry"])
	} else {
		fmt.Printf("Failed to rotate keys: %v\n", result["error"])
	}

	return nil
}
