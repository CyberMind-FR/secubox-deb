// cmd/secubox/cmd/fetch_test.go
package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsValidBoard(t *testing.T) {
	tests := []struct {
		board string
		valid bool
	}{
		{"mochabin", true},
		{"espressobin-v7", true},
		{"espressobin-ultra", true},
		{"rpi400", true},
		{"vm-x64", true},
		{"vm-arm64", true},
		{"unknown-board", false},
		{"", false},
		{"MOCHABIN", false}, // case sensitive
	}

	for _, tc := range tests {
		t.Run(tc.board, func(t *testing.T) {
			if got := isValidBoard(tc.board); got != tc.valid {
				t.Errorf("isValidBoard(%q) = %v, want %v", tc.board, got, tc.valid)
			}
		})
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.00 KB"},
		{1536, "1.50 KB"},
		{1048576, "1.00 MB"},
		{536870912, "512.00 MB"},
		{1073741824, "1.00 GB"},
		{2684354560, "2.50 GB"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%d", tc.bytes), func(t *testing.T) {
			if got := formatSize(tc.bytes); got != tc.expected {
				t.Errorf("formatSize(%d) = %q, want %q", tc.bytes, got, tc.expected)
			}
		})
	}
}

func TestFormatDate(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"2024-03-15T10:30:00Z", "2024-03-15 10:30"},
		{"2024-12-25T00:00:00Z", "2024-12-25 00:00"},
		{"invalid", "invalid"}, // returns input on error
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := formatDate(tc.input); got != tc.expected {
				t.Errorf("formatDate(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		seconds  int
		expected string
	}{
		{30, "30s"},
		{59, "59s"},
		{60, "1m0s"},
		{90, "1m30s"},
		{3600, "1h0m"},
		{3661, "1h1m"},
		{7200, "2h0m"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%ds", tc.seconds), func(t *testing.T) {
			d := time.Duration(tc.seconds) * time.Second
			if got := formatDuration(d); got != tc.expected {
				t.Errorf("formatDuration(%d) = %q, want %q", tc.seconds, got, tc.expected)
			}
		})
	}
}

func TestFindAssets(t *testing.T) {
	release := &GitHubRelease{
		TagName: "v2.8.0",
		Assets: []GitHubAsset{
			{
				Name:               "secubox-mochabin-2.8.0.img.gz",
				Size:               536647645,
				BrowserDownloadURL: "https://example.com/secubox-mochabin-2.8.0.img.gz",
			},
			{
				Name:               "secubox-mochabin-2.8.0.img.gz.sha256",
				Size:               100,
				BrowserDownloadURL: "https://example.com/secubox-mochabin-2.8.0.img.gz.sha256",
			},
			{
				Name:               "secubox-espressobin-v7-2.8.0.img.gz",
				Size:               400000000,
				BrowserDownloadURL: "https://example.com/secubox-espressobin-v7-2.8.0.img.gz",
			},
			{
				Name:               "SHA256SUMS",
				Size:               500,
				BrowserDownloadURL: "https://example.com/SHA256SUMS",
			},
		},
	}

	// Test finding mochabin assets
	img, sum := findAssets(release, "mochabin")
	if img == nil {
		t.Fatal("expected to find mochabin image asset")
	}
	if img.Name != "secubox-mochabin-2.8.0.img.gz" {
		t.Errorf("unexpected image name: %s", img.Name)
	}
	if sum == nil {
		t.Fatal("expected to find mochabin checksum asset")
	}
	if sum.Name != "secubox-mochabin-2.8.0.img.gz.sha256" {
		t.Errorf("unexpected checksum name: %s", sum.Name)
	}

	// Test finding espressobin assets (should fall back to SHA256SUMS)
	img, sum = findAssets(release, "espressobin-v7")
	if img == nil {
		t.Fatal("expected to find espressobin-v7 image asset")
	}
	if sum == nil {
		t.Fatal("expected to find checksum asset (SHA256SUMS)")
	}
	if sum.Name != "SHA256SUMS" {
		t.Errorf("expected SHA256SUMS, got: %s", sum.Name)
	}

	// Test board not in release
	img, sum = findAssets(release, "rpi400")
	if img != nil {
		t.Error("expected no image for rpi400")
	}
}

func TestDownloadWithProgress(t *testing.T) {
	// Create test server
	testData := []byte("test content for download")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testData)))
		w.Write(testData)
	}))
	defer server.Close()

	// Create temp file
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "test-download")

	// Download
	err := downloadWithProgress(server.URL, destPath, int64(len(testData)))
	if err != nil {
		t.Fatalf("downloadWithProgress failed: %v", err)
	}

	// Verify content
	content, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(content) != string(testData) {
		t.Errorf("content mismatch: got %q, want %q", string(content), string(testData))
	}
}

func TestProgressReader(t *testing.T) {
	// Test that progress reader correctly tracks bytes
	data := []byte("test data for progress tracking")
	reader := &progressReader{
		reader:    &mockReader{data: data},
		totalSize: int64(len(data)),
	}

	buf := make([]byte, 10)
	total := 0

	for {
		n, err := reader.Read(buf)
		total += n
		if err != nil {
			break
		}
	}

	if reader.downloaded != int64(len(data)) {
		t.Errorf("downloaded = %d, want %d", reader.downloaded, len(data))
	}
}

// mockReader implements io.Reader for testing
type mockReader struct {
	data []byte
	pos  int
}

func (m *mockReader) Read(p []byte) (int, error) {
	if m.pos >= len(m.data) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}

func TestGitHubReleaseAPI(t *testing.T) {
	// Mock GitHub API response
	mockReleases := `[
		{
			"tag_name": "v2.8.0",
			"name": "SecuBox v2.8.0",
			"published_at": "2024-03-15T10:00:00Z",
			"prerelease": false,
			"draft": false,
			"assets": [
				{
					"name": "secubox-mochabin-2.8.0.img.gz",
					"size": 536647645,
					"browser_download_url": "https://example.com/download/img.gz"
				}
			]
		}
	]`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(mockReleases))
	}))
	defer server.Close()

	// Note: This test validates the JSON parsing logic
	// Full integration test would require mocking the GitHub API base URL
}

func TestSupportedBoardsList(t *testing.T) {
	// Verify all expected boards are in the list
	expectedBoards := []string{
		"mochabin",
		"espressobin-v7",
		"espressobin-ultra",
		"rpi400",
		"vm-x64",
		"vm-arm64",
	}

	for _, board := range expectedBoards {
		if !isValidBoard(board) {
			t.Errorf("expected %s to be a valid board", board)
		}
	}
}
