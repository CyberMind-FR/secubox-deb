// Package telemetry handles heartbeat and metrics collection
// CyberMind — SecuBox-Deb — 2026
package telemetry

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

// Metrics represents collected system metrics
type Metrics struct {
	Timestamp     time.Time
	Uptime        int64
	PeerCount     int
	NFTablesRules int
	CrowdSecBans  int
	CPUPercent    float64
	MemoryPercent float64
	DiskPercent   float64
}

// Telemetry handles metrics collection and reporting
type Telemetry struct {
	mu       sync.RWMutex
	db       *sql.DB
	dbPath   string
	interval time.Duration
	latest   *Metrics
	stopCh   chan struct{}
}

// New creates a new Telemetry instance
func New(dbPath string, intervalSec int) (*Telemetry, error) {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open telemetry db: %w", err)
	}

	t := &Telemetry{
		db:       db,
		dbPath:   dbPath,
		interval: time.Duration(intervalSec) * time.Second,
		stopCh:   make(chan struct{}),
	}

	if err := t.initDB(); err != nil {
		db.Close()
		return nil, err
	}

	return t, nil
}

// initDB creates the telemetry tables
func (t *Telemetry) initDB() error {
	schema := `
	CREATE TABLE IF NOT EXISTS metrics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		uptime INTEGER,
		peer_count INTEGER,
		nftables_rules INTEGER,
		crowdsec_bans INTEGER,
		cpu_percent REAL,
		memory_percent REAL,
		disk_percent REAL
	);

	CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp);

	-- Keep only last 24 hours of data
	CREATE TRIGGER IF NOT EXISTS cleanup_old_metrics
	AFTER INSERT ON metrics
	BEGIN
		DELETE FROM metrics WHERE timestamp < datetime('now', '-1 day');
	END;
	`

	_, err := t.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to init telemetry schema: %w", err)
	}

	return nil
}

// Start begins telemetry collection
func (t *Telemetry) Start(ctx context.Context) error {
	slog.Info("telemetry starting", "interval", t.interval, "db", t.dbPath)

	// Collect initial metrics
	t.collect()

	// Start collection loop
	go t.collectLoop(ctx)

	return nil
}

// Stop halts telemetry collection
func (t *Telemetry) Stop() {
	close(t.stopCh)
	if t.db != nil {
		t.db.Close()
	}
	slog.Info("telemetry stopped")
}

// GetLatest returns the most recent metrics
func (t *Telemetry) GetLatest() *Metrics {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.latest
}

// GetHistory returns metrics from the last N minutes
func (t *Telemetry) GetHistory(minutes int) ([]Metrics, error) {
	query := `
	SELECT timestamp, uptime, peer_count, nftables_rules, crowdsec_bans,
	       cpu_percent, memory_percent, disk_percent
	FROM metrics
	WHERE timestamp > datetime('now', ?)
	ORDER BY timestamp DESC
	`

	rows, err := t.db.Query(query, fmt.Sprintf("-%d minutes", minutes))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []Metrics
	for rows.Next() {
		var m Metrics
		err := rows.Scan(
			&m.Timestamp, &m.Uptime, &m.PeerCount, &m.NFTablesRules,
			&m.CrowdSecBans, &m.CPUPercent, &m.MemoryPercent, &m.DiskPercent,
		)
		if err != nil {
			continue
		}
		metrics = append(metrics, m)
	}

	return metrics, nil
}

// collectLoop runs periodic metric collection
func (t *Telemetry) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.collect()
		}
	}
}

// collect gathers current system metrics
func (t *Telemetry) collect() {
	metrics := &Metrics{
		Timestamp: time.Now(),
	}

	// Collect uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		var uptime float64
		fmt.Sscanf(string(data), "%f", &uptime)
		metrics.Uptime = int64(uptime)
	}

	// Collect CPU usage (simplified)
	metrics.CPUPercent = t.getCPUPercent()

	// Collect memory usage
	metrics.MemoryPercent = t.getMemoryPercent()

	// Collect disk usage
	metrics.DiskPercent = t.getDiskPercent()

	// Collect nftables rule count
	metrics.NFTablesRules = t.getNFTablesRuleCount()

	// Collect CrowdSec ban count
	metrics.CrowdSecBans = t.getCrowdSecBans()

	// Store metrics
	t.mu.Lock()
	t.latest = metrics
	t.mu.Unlock()

	// Persist to database
	t.persist(metrics)

	slog.Debug("metrics collected",
		"uptime", metrics.Uptime,
		"cpu", metrics.CPUPercent,
		"memory", metrics.MemoryPercent,
	)
}

// persist saves metrics to the database
func (t *Telemetry) persist(m *Metrics) {
	query := `
	INSERT INTO metrics (uptime, peer_count, nftables_rules, crowdsec_bans,
	                     cpu_percent, memory_percent, disk_percent)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := t.db.Exec(query,
		m.Uptime, m.PeerCount, m.NFTablesRules, m.CrowdSecBans,
		m.CPUPercent, m.MemoryPercent, m.DiskPercent,
	)
	if err != nil {
		slog.Error("failed to persist metrics", "error", err)
	}
}

// getCPUPercent returns current CPU usage percentage
func (t *Telemetry) getCPUPercent() float64 {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0.0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				user, _ := strconv.ParseFloat(fields[1], 64)
				nice, _ := strconv.ParseFloat(fields[2], 64)
				system, _ := strconv.ParseFloat(fields[3], 64)
				idle, _ := strconv.ParseFloat(fields[4], 64)

				total := user + nice + system + idle
				if total > 0 {
					return 100.0 * (user + nice + system) / total
				}
			}
		}
	}
	return 0.0
}

// getMemoryPercent returns current memory usage percentage
func (t *Telemetry) getMemoryPercent() float64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0.0
	}

	var total, available int64
	fmt.Sscanf(string(data), "MemTotal: %d kB\nMemFree: %d", &total, &available)

	if total == 0 {
		return 0.0
	}

	return 100.0 * float64(total-available) / float64(total)
}

// getDiskPercent returns root filesystem usage percentage
func (t *Telemetry) getDiskPercent() float64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0.0
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	if total == 0 {
		return 0.0
	}

	used := total - free
	return 100.0 * float64(used) / float64(total)
}

// getNFTablesRuleCount returns the number of nftables rules
func (t *Telemetry) getNFTablesRuleCount() int {
	cmd := exec.Command("nft", "-a", "list", "ruleset")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	// Count lines containing "handle" (each rule has a handle)
	count := 0
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "handle") && !strings.Contains(line, "table") && !strings.Contains(line, "chain") {
			count++
		}
	}
	return count
}

// getCrowdSecBans returns the number of active CrowdSec bans
func (t *Telemetry) getCrowdSecBans() int {
	cmd := exec.Command("cscli", "decisions", "list", "-o", "raw")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	// Count non-empty lines (excluding header)
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) <= 1 {
		return 0
	}
	return len(lines) - 1 // Subtract header line
}

// Status returns telemetry module status
func (t *Telemetry) Status() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var latestTime string
	if t.latest != nil {
		latestTime = t.latest.Timestamp.Format(time.RFC3339)
	}

	return map[string]interface{}{
		"interval": t.interval.String(),
		"db_path":  t.dbPath,
		"latest":   latestTime,
		"running":  true,
	}
}
