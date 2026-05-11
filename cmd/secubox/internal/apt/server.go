/*
SecuBox-Deb :: APT Server
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
*/

package apt

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	DefaultRepoPath = "/srv/apt"
)

// Server handles APT repository server operations
type Server struct {
	RepoPath   string
	ScriptsDir string
	Codename   string
	Component  string
	DryRun     bool
	Verbose    bool
}

// NewServer creates a server with default settings
func NewServer(repoRoot string) *Server {
	return &Server{
		RepoPath:   DefaultRepoPath,
		ScriptsDir: filepath.Join(repoRoot, "scripts"),
		Codename:   DefaultCodename,
		Component:  DefaultComponent,
	}
}

// Init initializes the local APT repository
func (s *Server) Init() error {
	// Check reprepro
	if _, err := exec.LookPath("reprepro"); err != nil {
		return fmt.Errorf("reprepro not installed (apt install reprepro)")
	}

	// Create directories
	dirs := []string{"conf", "db", "dists", "pool", "incoming", "tmp"}
	for _, d := range dirs {
		path := filepath.Join(s.RepoPath, d)
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
	}

	// Run reprepro export
	cmd := exec.Command("reprepro", "-b", s.RepoPath, "export")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reprepro export: %w", err)
	}

	return nil
}

// Publish publishes .deb packages using the publish script
func (s *Server) Publish(files []string, skipLintian bool) error {
	script := filepath.Join(s.ScriptsDir, "apt-publish.sh")
	if _, err := os.Stat(script); os.IsNotExist(err) {
		return fmt.Errorf("publish script not found: %s", script)
	}

	args := []string{}
	args = append(args, "-c", s.Codename)
	args = append(args, "-C", s.Component)
	if skipLintian {
		args = append(args, "--skip-lintian")
	}
	if s.DryRun {
		args = append(args, "--dry-run")
	}
	args = append(args, files...)

	cmd := exec.Command(script, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Sync syncs repository to remote using the sync script
func (s *Server) Sync() error {
	script := filepath.Join(s.ScriptsDir, "apt-sync.sh")
	if _, err := os.Stat(script); os.IsNotExist(err) {
		return fmt.Errorf("sync script not found: %s", script)
	}

	args := []string{}
	if s.DryRun {
		args = append(args, "--dry-run")
	}
	if s.Verbose {
		args = append(args, "--verbose")
	}

	cmd := exec.Command(script, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// List lists packages in the repository
func (s *Server) List() error {
	cmd := exec.Command("reprepro", "-b", s.RepoPath, "list", s.Codename)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Remove removes a package from the repository
func (s *Server) Remove(pkgName string) error {
	if s.DryRun {
		fmt.Printf("[DRY-RUN] Would remove: %s from %s\n", pkgName, s.Codename)
		return nil
	}

	cmd := exec.Command("reprepro", "-b", s.RepoPath, "remove", s.Codename, pkgName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Check verifies repository integrity
func (s *Server) Check() error {
	cmd := exec.Command("reprepro", "-b", s.RepoPath, "check")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
