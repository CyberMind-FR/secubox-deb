// cmd/secubox/cmd/fetch.go
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	fetchBoard   string
	fetchVersion string
	fetchOutput  string
	fetchList    bool
	fetchForce   bool
)

const (
	githubOwner     = "CyberMind-FR"
	githubRepo      = "secubox-deb"
	githubAPIBase   = "https://api.github.com"
	githubDLBase    = "https://github.com"
	defaultTimeout  = 30 * time.Minute
	progressBarSize = 50
)

// supportedBoards lists boards that have pre-built images
var supportedBoards = []string{
	"mochabin",
	"espressobin-v7",
	"espressobin-ultra",
	"rpi400",
	"vm-x64",
	"vm-arm64",
}

// GitHubRelease represents a GitHub release
type GitHubRelease struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	PublishedAt string         `json:"published_at"`
	Assets      []GitHubAsset  `json:"assets"`
	Prerelease  bool           `json:"prerelease"`
	Draft       bool           `json:"draft"`
}

// GitHubAsset represents a release asset
type GitHubAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
	ContentType        string `json:"content_type"`
}

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Download pre-built SecuBox images",
	Long: `Download pre-built SecuBox images from GitHub releases.

This command fetches official pre-built images that are ready to flash
onto supported hardware boards.

Examples:
  # List available images
  secubox fetch --list

  # Download latest image for a board
  secubox fetch --board mochabin

  # Download specific version
  secubox fetch --board mochabin --version 2.8.0

  # Download to custom location
  secubox fetch --board mochabin --output /tmp/secubox.img.gz

Supported boards:
  - mochabin         (Armada 7040, Pro tier)
  - espressobin-v7   (Armada 3720, Lite tier)
  - espressobin-ultra (Armada 3720 Ultra)
  - rpi400           (Raspberry Pi 400)
  - vm-x64           (x86-64 VM)
  - vm-arm64         (ARM64 VM)`,
	RunE: runFetch,
}

func init() {
	rootCmd.AddCommand(fetchCmd)
	fetchCmd.Flags().StringVarP(&fetchBoard, "board", "b", "", "target board (mochabin, espressobin-v7, etc.)")
	fetchCmd.Flags().StringVarP(&fetchVersion, "version", "V", "", "specific version to download (default: latest)")
	fetchCmd.Flags().StringVarP(&fetchOutput, "output", "o", "", "output file path (default: ./secubox-<board>-<version>.img.gz)")
	fetchCmd.Flags().BoolVarP(&fetchList, "list", "l", false, "list available releases and images")
	fetchCmd.Flags().BoolVarP(&fetchForce, "force", "f", false, "overwrite existing file")
}

func runFetch(cmd *cobra.Command, args []string) error {
	// List mode
	if fetchList {
		return listReleases()
	}

	// Require board for download
	if fetchBoard == "" {
		return fmt.Errorf("--board is required for download\nUse --list to see available images")
	}

	// Validate board
	if !isValidBoard(fetchBoard) {
		return fmt.Errorf("unsupported board: %s\nSupported boards: %s", fetchBoard, strings.Join(supportedBoards, ", "))
	}

	// Get release info
	release, err := getRelease(fetchVersion)
	if err != nil {
		return fmt.Errorf("get release: %w", err)
	}

	// Find image asset
	imageAsset, checksumAsset := findAssets(release, fetchBoard)
	if imageAsset == nil {
		return fmt.Errorf("no image found for board %s in release %s", fetchBoard, release.TagName)
	}

	// Determine output path
	outputPath := fetchOutput
	if outputPath == "" {
		outputPath = filepath.Join(".", imageAsset.Name)
	}

	// Check if file exists
	if !fetchForce {
		if _, err := os.Stat(outputPath); err == nil {
			return fmt.Errorf("file already exists: %s\nUse --force to overwrite", outputPath)
		}
	}

	// Print download info
	fmt.Printf("SecuBox Fetch\n")
	fmt.Printf("  Board:   %s\n", fetchBoard)
	fmt.Printf("  Version: %s\n", release.TagName)
	fmt.Printf("  Size:    %s\n", formatSize(imageAsset.Size))
	fmt.Printf("  Output:  %s\n\n", outputPath)

	// Download image
	fmt.Printf("Downloading %s...\n", imageAsset.Name)
	if err := downloadWithProgress(imageAsset.BrowserDownloadURL, outputPath, imageAsset.Size); err != nil {
		// Clean up partial file
		os.Remove(outputPath)
		return fmt.Errorf("download failed: %w", err)
	}

	// Verify checksum if available
	if checksumAsset != nil {
		fmt.Printf("\nVerifying checksum...\n")
		if err := verifyChecksum(outputPath, checksumAsset, imageAsset.Name); err != nil {
			return fmt.Errorf("checksum verification failed: %w", err)
		}
		fmt.Printf("Checksum verified OK\n")
	} else {
		fmt.Printf("\nWarning: No checksum file available for verification\n")
	}

	fmt.Printf("\nDownload complete: %s\n", outputPath)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  1. Decompress: gunzip %s\n", outputPath)
	fmt.Printf("  2. Flash: dd if=%s of=/dev/sdX bs=4M status=progress\n", strings.TrimSuffix(outputPath, ".gz"))

	return nil
}

func listReleases() error {
	releases, err := getReleases()
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}

	if len(releases) == 0 {
		fmt.Println("No releases found")
		return nil
	}

	fmt.Printf("Available SecuBox Releases\n")
	fmt.Printf("Repository: %s/%s\n\n", githubOwner, githubRepo)

	for i, rel := range releases {
		if rel.Draft {
			continue
		}

		status := ""
		if rel.Prerelease {
			status = " (prerelease)"
		}
		if i == 0 {
			status = " (latest)"
		}

		fmt.Printf("Version: %s%s\n", rel.TagName, status)
		fmt.Printf("  Published: %s\n", formatDate(rel.PublishedAt))

		// Group assets by board
		boards := make(map[string][]GitHubAsset)
		for _, asset := range rel.Assets {
			for _, board := range supportedBoards {
				if strings.Contains(asset.Name, board) && strings.HasSuffix(asset.Name, ".img.gz") {
					boards[board] = append(boards[board], asset)
				}
			}
		}

		if len(boards) > 0 {
			fmt.Printf("  Images:\n")
			for board, assets := range boards {
				for _, asset := range assets {
					fmt.Printf("    - %-20s %s\n", board, formatSize(asset.Size))
				}
			}
		}
		fmt.Println()
	}

	fmt.Printf("Download with: secubox fetch --board <board> [--version <version>]\n")
	return nil
}

func getReleases() ([]GitHubRelease, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases", githubAPIBase, githubOwner, githubRepo)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "secubox-cli/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %s - %s", resp.Status, string(body))
	}

	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return releases, nil
}

func getRelease(version string) (*GitHubRelease, error) {
	var url string
	if version == "" {
		url = fmt.Sprintf("%s/repos/%s/%s/releases/latest", githubAPIBase, githubOwner, githubRepo)
	} else {
		// Normalize version tag
		tag := version
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		url = fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", githubAPIBase, githubOwner, githubRepo, tag)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "secubox-cli/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		if version == "" {
			return nil, fmt.Errorf("no releases found")
		}
		return nil, fmt.Errorf("release %s not found", version)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %s - %s", resp.Status, string(body))
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &release, nil
}

func findAssets(release *GitHubRelease, board string) (*GitHubAsset, *GitHubAsset) {
	var imageAsset *GitHubAsset
	var checksumAsset *GitHubAsset

	// Expected naming: secubox-<board>-<version>.img.gz
	// Checksum: secubox-<board>-<version>.img.gz.sha256 or SHA256SUMS
	for i := range release.Assets {
		asset := &release.Assets[i]

		// Look for image file
		if strings.Contains(asset.Name, board) && strings.HasSuffix(asset.Name, ".img.gz") {
			imageAsset = asset
		}

		// Look for checksum file
		if strings.Contains(asset.Name, board) && strings.HasSuffix(asset.Name, ".sha256") {
			checksumAsset = asset
		}

		// Also check for SHA256SUMS file
		if asset.Name == "SHA256SUMS" || asset.Name == "checksums.txt" {
			if checksumAsset == nil {
				checksumAsset = asset
			}
		}
	}

	return imageAsset, checksumAsset
}

func downloadWithProgress(url, destPath string, totalSize int64) error {
	// Create output file
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer out.Close()

	// Start download
	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download error: %s", resp.Status)
	}

	// If server provides content-length and we don't have it
	if totalSize == 0 && resp.ContentLength > 0 {
		totalSize = resp.ContentLength
	}

	// Create progress reader
	progress := &progressReader{
		reader:    resp.Body,
		totalSize: totalSize,
		startTime: time.Now(),
	}

	// Copy with progress
	_, err = io.Copy(out, progress)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	// Final newline after progress bar
	fmt.Println()

	return nil
}

// progressReader wraps an io.Reader and prints progress
type progressReader struct {
	reader      io.Reader
	totalSize   int64
	downloaded  int64
	startTime   time.Time
	lastPrint   time.Time
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.downloaded += int64(n)

	// Rate limit progress updates
	if time.Since(pr.lastPrint) > 100*time.Millisecond || err == io.EOF {
		pr.printProgress()
		pr.lastPrint = time.Now()
	}

	return n, err
}

func (pr *progressReader) printProgress() {
	percent := float64(0)
	if pr.totalSize > 0 {
		percent = float64(pr.downloaded) / float64(pr.totalSize) * 100
	}

	elapsed := time.Since(pr.startTime).Seconds()
	speed := float64(0)
	if elapsed > 0 {
		speed = float64(pr.downloaded) / elapsed
	}

	// Calculate ETA
	eta := ""
	if speed > 0 && pr.totalSize > 0 {
		remaining := float64(pr.totalSize-pr.downloaded) / speed
		if remaining > 0 {
			eta = fmt.Sprintf(" ETA: %s", formatDuration(time.Duration(remaining)*time.Second))
		}
	}

	// Progress bar
	barWidth := progressBarSize
	completed := 0
	if pr.totalSize > 0 {
		completed = int(float64(barWidth) * float64(pr.downloaded) / float64(pr.totalSize))
	}
	bar := strings.Repeat("=", completed) + strings.Repeat("-", barWidth-completed)

	// Print progress line
	fmt.Printf("\r[%s] %5.1f%% %s @ %s/s%s   ",
		bar,
		percent,
		formatSize(pr.downloaded),
		formatSize(int64(speed)),
		eta,
	)
}

func verifyChecksum(filePath string, checksumAsset *GitHubAsset, imageName string) error {
	// Download checksum file
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(checksumAsset.BrowserDownloadURL)
	if err != nil {
		return fmt.Errorf("download checksum: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checksum download error: %s", resp.Status)
	}

	checksumData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read checksum: %w", err)
	}

	// Parse checksum (format: "sha256sum  filename" or just "sha256sum")
	expectedChecksum := ""
	lines := strings.Split(string(checksumData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Handle "sha256  filename" format
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			// If this is a SHA256SUMS file, match by filename
			if len(parts) >= 2 {
				if parts[1] == imageName || strings.HasSuffix(parts[1], imageName) {
					expectedChecksum = parts[0]
					break
				}
			} else {
				// Single checksum file for this specific image
				expectedChecksum = parts[0]
				break
			}
		}
	}

	if expectedChecksum == "" {
		return fmt.Errorf("could not parse checksum for %s", imageName)
	}

	// Calculate file checksum
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return fmt.Errorf("calculate checksum: %w", err)
	}

	actualChecksum := hex.EncodeToString(hasher.Sum(nil))

	if !strings.EqualFold(actualChecksum, expectedChecksum) {
		return fmt.Errorf("checksum mismatch:\n  expected: %s\n  actual:   %s", expectedChecksum, actualChecksum)
	}

	return nil
}

func isValidBoard(board string) bool {
	for _, b := range supportedBoards {
		if b == board {
			return true
		}
	}
	return false
}

func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func formatDate(dateStr string) string {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return dateStr
	}
	return t.Format("2006-01-02 15:04")
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}
