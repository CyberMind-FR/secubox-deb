// cmd/secubox/internal/wizard/wizard.go
package wizard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/profile"
	"github.com/manifoldco/promptui"
)

// doneIdx is the index of the "Done" option in selection menus
const doneIdx = 0

// contains checks if a string slice contains an item
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Options holds wizard results
type Options struct {
	Board   string
	Tier    string
	Enable  []string
	Formats []string
}

// BoardInfo represents a selectable board with metadata
type BoardInfo struct {
	Name        string
	Description string
	Tier        string
	Arch        string
}

// Run executes the interactive wizard
func Run(repoRoot string) (*Options, error) {
	opts := &Options{}

	// Discover available boards
	boards, err := discoverBoards(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("discover boards: %w", err)
	}

	if len(boards) == 0 {
		return nil, fmt.Errorf("no boards found in %s/board/", repoRoot)
	}

	// Select board
	boardItems := make([]string, len(boards))
	for i, b := range boards {
		boardItems[i] = fmt.Sprintf("%s - %s", b.Name, b.Description)
	}

	boardPrompt := promptui.Select{
		Label: "Select target board",
		Items: boardItems,
		Size:  10,
	}
	boardIdx, _, err := boardPrompt.Run()
	if err != nil {
		return nil, fmt.Errorf("board selection: %w", err)
	}
	opts.Board = boards[boardIdx].Name
	defaultTier := boards[boardIdx].Tier

	// Select tier
	tierItems := []string{}
	if defaultTier != "" {
		tierItems = append(tierItems, fmt.Sprintf("%s (recommended for %s)", defaultTier, opts.Board))
	}
	tierItems = append(tierItems, "tier-lite", "tier-standard", "tier-pro")

	tierPrompt := promptui.Select{
		Label: "Select tier",
		Items: tierItems,
	}
	tierIdx, tierResult, err := tierPrompt.Run()
	if err != nil {
		return nil, fmt.Errorf("tier selection: %w", err)
	}

	// Parse tier from selection (handle "(recommended for ...)" suffix)
	if tierIdx == 0 && defaultTier != "" {
		opts.Tier = defaultTier
	} else {
		// Strip any suffix like "(recommended for ...)"
		opts.Tier = strings.Fields(tierResult)[0]
	}

	// Optional packages selection
	optionalPackages := []string{
		"ollama - Local LLM inference",
		"jellyfin - Media server",
		"homeassistant - Home automation",
		"matrix - Secure messaging server",
		"nextcloud - File sync and share",
		"gitea - Git hosting",
	}

	fmt.Println("\nSelect additional packages to enable (Enter to skip, Ctrl+C to abort):")
	for {
		enablePrompt := promptui.Select{
			Label: "Add package (or select 'Done')",
			Items: append([]string{"[Done - continue]"}, optionalPackages...),
			Size:  8,
		}

		idx, _, err := enablePrompt.Run()
		if err != nil {
			return nil, fmt.Errorf("package selection: %w", err)
		}
		if idx == doneIdx {
			break
		}
		// Extract package name (before " - ")
		pkg := strings.Split(optionalPackages[idx-1], " - ")[0]
		// Check for duplicates
		if !contains(opts.Enable, pkg) {
			opts.Enable = append(opts.Enable, pkg)
			fmt.Printf("  + %s\n", pkg)
		}
	}

	// Output formats selection
	formats := []string{
		"img.gz - Compressed raw image (default)",
		"img.xz - XZ compressed raw image",
		"vdi - VirtualBox disk image",
		"qcow2 - QEMU/KVM disk image",
	}

	opts.Formats = []string{"img.gz"} // Default
	fmt.Println("\nSelect output formats (img.gz is always included):")
	for {
		formatPrompt := promptui.Select{
			Label: "Add format (or select 'Done')",
			Items: append([]string{"[Done - continue]"}, formats...),
			Size:  6,
		}

		idx, _, err := formatPrompt.Run()
		if err != nil {
			return nil, fmt.Errorf("format selection: %w", err)
		}
		if idx == doneIdx {
			break
		}
		// Extract format name (before " - ")
		format := strings.Split(formats[idx-1], " - ")[0]
		// Check for duplicates (img.gz is already in defaults)
		if !contains(opts.Formats, format) {
			opts.Formats = append(opts.Formats, format)
			fmt.Printf("  + %s\n", format)
		}
	}

	// Summary
	fmt.Println("\n--- Summary ---")
	fmt.Printf("Board:    %s\n", opts.Board)
	fmt.Printf("Tier:     %s\n", opts.Tier)
	if len(opts.Enable) > 0 {
		fmt.Printf("Packages: %s\n", strings.Join(opts.Enable, ", "))
	}
	fmt.Printf("Formats:  %s\n", strings.Join(opts.Formats, ", "))
	fmt.Println()

	return opts, nil
}

// discoverBoards scans the board/ directory for available boards
func discoverBoards(repoRoot string) ([]BoardInfo, error) {
	boardsDir := filepath.Join(repoRoot, "board")
	entries, err := os.ReadDir(boardsDir)
	if err != nil {
		return nil, fmt.Errorf("read board directory: %w", err)
	}

	boards := make([]BoardInfo, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		boardDir := filepath.Join(boardsDir, name)

		// Try to load board.yaml if it exists
		board, err := profile.LoadBoard(boardDir)
		if err == nil {
			// Use info from board.yaml
			desc := fmt.Sprintf("%s, %s", board.SOC, board.Hardware.RAM)
			if board.Hardware.EMMC != "" {
				desc += ", " + board.Hardware.EMMC + " eMMC"
			}
			boards = append(boards, BoardInfo{
				Name:        board.Name,
				Description: desc,
				Tier:        board.Tier,
				Arch:        board.Arch,
			})
		} else {
			// Fall back to defaults based on board name
			info := boardInfoFromName(name)
			boards = append(boards, info)
		}
	}

	return boards, nil
}

// boardInfoFromName provides default board info when board.yaml is missing
func boardInfoFromName(name string) BoardInfo {
	info := BoardInfo{
		Name:        name,
		Description: name,
		Tier:        "tier-standard",
		Arch:        "arm64",
	}

	switch name {
	case "mochabin":
		info.Description = "Armada 7040, 4-8GB RAM, 6 ports"
		info.Tier = "tier-pro"
	case "espressobin-v7":
		info.Description = "Armada 3720, 1-2GB RAM, 3 ports"
		info.Tier = "tier-lite"
	case "espressobin-ultra":
		info.Description = "Armada 3720 Ultra, 4GB RAM"
		info.Tier = "tier-standard"
	case "rpi400":
		info.Description = "Raspberry Pi 400, Broadcom BCM2711"
		info.Tier = "tier-standard"
	case "vm-x64":
		info.Description = "VirtualBox/QEMU x64 VM"
		info.Tier = "tier-standard"
		info.Arch = "amd64"
	case "vm-arm64":
		info.Description = "QEMU ARM64 VM"
		info.Tier = "tier-standard"
	case "x64-live":
		info.Description = "x64 Live USB image"
		info.Tier = "tier-standard"
		info.Arch = "amd64"
	case "x64-vm":
		info.Description = "x64 VM image"
		info.Tier = "tier-standard"
		info.Arch = "amd64"
	}

	return info
}
