// cmd/secubox/internal/ota/partition.go
package ota

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Partition layout constants
const (
	// ESP is the EFI System Partition
	ESPPartition = 1
	// RootA is the primary root partition (slot A)
	RootAPartition = 2
	// RootB is the secondary root partition (slot B)
	RootBPartition = 3
	// Data is the persistent data partition
	DataPartition = 4
)

// Boot control paths
const (
	ESPMountPoint     = "/boot/efi"
	BootControlDir    = "/boot/efi/secubox"
	ActiveSlotFile    = "/boot/efi/secubox/active"
	FallbackSlotFile  = "/boot/efi/secubox/fallback"
	BootCountFile     = "/boot/efi/secubox/boot-count"
	MaxBootCount      = 3
)

// Slot represents a boot slot (A or B)
type Slot string

const (
	SlotA Slot = "a"
	SlotB Slot = "b"
)

// PartitionInfo holds information about a partition
type PartitionInfo struct {
	Slot       Slot
	Device     string
	MountPoint string
	Label      string
	Size       int64
	Used       int64
	Free       int64
}

// BootState holds the current boot state
type BootState struct {
	ActiveSlot   Slot
	FallbackSlot Slot
	BootCount    int
	IsRecovery   bool
}

// atomicWriteFile writes data to a file atomically using temp file + rename.
// This prevents partial writes and race conditions.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)

	// Create temp file in same directory (required for atomic rename)
	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Clean up temp file on any error
	defer func() {
		if tmpPath != "" {
			os.Remove(tmpPath)
		}
	}()

	// Set permissions before writing content
	if err := tmpFile.Chmod(perm); err != nil {
		tmpFile.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}

	// Write data
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp file: %w", err)
	}

	// Sync to disk
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	// Clear tmpPath so defer doesn't try to remove
	tmpPath = ""
	return nil
}

// GetActiveSlot reads the active boot slot from the boot control file
func GetActiveSlot() (Slot, error) {
	data, err := os.ReadFile(ActiveSlotFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Default to slot A if file doesn't exist
			return SlotA, nil
		}
		return "", fmt.Errorf("read active slot: %w", err)
	}

	slot := Slot(strings.TrimSpace(string(data)))
	if slot != SlotA && slot != SlotB {
		return "", fmt.Errorf("invalid active slot value: %s", slot)
	}

	return slot, nil
}

// GetFallbackSlot reads the fallback boot slot
func GetFallbackSlot() (Slot, error) {
	data, err := os.ReadFile(FallbackSlotFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Default to opposite of active
			active, err := GetActiveSlot()
			if err != nil {
				return "", err
			}
			return active.Opposite(), nil
		}
		return "", fmt.Errorf("read fallback slot: %w", err)
	}

	slot := Slot(strings.TrimSpace(string(data)))
	if slot != SlotA && slot != SlotB {
		return "", fmt.Errorf("invalid fallback slot value: %s", slot)
	}

	return slot, nil
}

// GetBootCount reads the current boot count (for watchdog rollback)
func GetBootCount() (int, error) {
	data, err := os.ReadFile(BootCountFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read boot count: %w", err)
	}

	count, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse boot count: %w", err)
	}

	return count, nil
}

// GetBootState returns the complete boot state
func GetBootState() (*BootState, error) {
	active, err := GetActiveSlot()
	if err != nil {
		return nil, fmt.Errorf("get active slot: %w", err)
	}

	fallback, err := GetFallbackSlot()
	if err != nil {
		return nil, fmt.Errorf("get fallback slot: %w", err)
	}

	bootCount, err := GetBootCount()
	if err != nil {
		return nil, fmt.Errorf("get boot count: %w", err)
	}

	return &BootState{
		ActiveSlot:   active,
		FallbackSlot: fallback,
		BootCount:    bootCount,
		IsRecovery:   bootCount >= MaxBootCount,
	}, nil
}

// SetActiveSlot writes the active slot to the boot control file atomically
func SetActiveSlot(slot Slot) error {
	if slot != SlotA && slot != SlotB {
		return fmt.Errorf("invalid slot: %s", slot)
	}

	// Ensure boot control directory exists
	if err := os.MkdirAll(BootControlDir, 0755); err != nil {
		return fmt.Errorf("create boot control dir: %w", err)
	}

	// Use atomic write: write to temp file then rename
	if err := atomicWriteFile(ActiveSlotFile, []byte(string(slot)+"\n"), 0600); err != nil {
		return fmt.Errorf("write active slot: %w", err)
	}

	return nil
}

// SetFallbackSlot writes the fallback slot to the boot control file atomically
func SetFallbackSlot(slot Slot) error {
	if slot != SlotA && slot != SlotB {
		return fmt.Errorf("invalid slot: %s", slot)
	}

	// Ensure boot control directory exists
	if err := os.MkdirAll(BootControlDir, 0755); err != nil {
		return fmt.Errorf("create boot control dir: %w", err)
	}

	// Use atomic write with restrictive permissions
	if err := atomicWriteFile(FallbackSlotFile, []byte(string(slot)+"\n"), 0600); err != nil {
		return fmt.Errorf("write fallback slot: %w", err)
	}

	return nil
}

// SetBootCount sets the boot count value atomically
func SetBootCount(count int) error {
	if count < 0 {
		count = 0
	}

	// Ensure boot control directory exists
	if err := os.MkdirAll(BootControlDir, 0755); err != nil {
		return fmt.Errorf("create boot control dir: %w", err)
	}

	// Use atomic write with restrictive permissions
	if err := atomicWriteFile(BootCountFile, []byte(strconv.Itoa(count)+"\n"), 0600); err != nil {
		return fmt.Errorf("write boot count: %w", err)
	}

	return nil
}

// ResetBootCount resets the boot count to 0 (called after successful boot)
func ResetBootCount() error {
	return SetBootCount(0)
}

// IncrementBootCount increments the boot count
func IncrementBootCount() error {
	count, err := GetBootCount()
	if err != nil {
		return err
	}
	return SetBootCount(count + 1)
}

// SwapSlots swaps active and fallback slots atomically
func SwapSlots() error {
	state, err := GetBootState()
	if err != nil {
		return fmt.Errorf("get boot state: %w", err)
	}

	// Swap active and fallback
	newActive := state.FallbackSlot
	newFallback := state.ActiveSlot

	// Write fallback first (safer order)
	if err := SetFallbackSlot(newFallback); err != nil {
		return fmt.Errorf("set fallback slot: %w", err)
	}

	if err := SetActiveSlot(newActive); err != nil {
		// Try to restore fallback
		SetFallbackSlot(state.FallbackSlot)
		return fmt.Errorf("set active slot: %w", err)
	}

	// Reset boot count for new slot
	if err := ResetBootCount(); err != nil {
		return fmt.Errorf("reset boot count: %w", err)
	}

	return nil
}

// Opposite returns the opposite slot
func (s Slot) Opposite() Slot {
	if s == SlotA {
		return SlotB
	}
	return SlotA
}

// PartitionNumber returns the partition number for the slot
func (s Slot) PartitionNumber() int {
	if s == SlotA {
		return RootAPartition
	}
	return RootBPartition
}

// Label returns the partition label for the slot
func (s Slot) Label() string {
	if s == SlotA {
		return "root-a"
	}
	return "root-b"
}

// String returns the slot as a string
func (s Slot) String() string {
	return string(s)
}

// GetPartitionDevice returns the device path for a partition slot
func GetPartitionDevice(slot Slot) (string, error) {
	// Find the root device by looking at current mounts
	// The active slot is mounted at /
	rootDev, err := findRootDevice()
	if err != nil {
		return "", fmt.Errorf("find root device: %w", err)
	}

	// Extract base device (e.g., /dev/mmcblk0 from /dev/mmcblk0p2)
	baseDev := extractBaseDevice(rootDev)
	if baseDev == "" {
		return "", fmt.Errorf("could not extract base device from %s", rootDev)
	}

	// Construct partition device path
	partNum := slot.PartitionNumber()
	if strings.Contains(baseDev, "mmcblk") || strings.Contains(baseDev, "nvme") {
		return fmt.Sprintf("%sp%d", baseDev, partNum), nil
	}
	return fmt.Sprintf("%s%d", baseDev, partNum), nil
}

// findRootDevice reads /proc/mounts to find the device mounted at /
func findRootDevice() (string, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", fmt.Errorf("read /proc/mounts: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "/" {
			return fields[0], nil
		}
	}

	return "", fmt.Errorf("root mount point not found")
}

// extractBaseDevice extracts the base device from a partition device
// e.g., /dev/mmcblk0p2 -> /dev/mmcblk0
// e.g., /dev/nvme0n1p2 -> /dev/nvme0n1
// e.g., /dev/sda2 -> /dev/sda
// e.g., /dev/loop0p1 -> /dev/loop0
func extractBaseDevice(partDev string) string {
	// Handle devices with 'p' separator before partition number
	// This includes: mmcblk0p2, nvme0n1p2, loop0p1
	if strings.Contains(partDev, "mmcblk") || strings.Contains(partDev, "nvme") || strings.Contains(partDev, "loop") {
		// Find the last 'p' followed by digits only
		for i := len(partDev) - 1; i >= 0; i-- {
			if partDev[i] == 'p' {
				// Check if everything after 'p' is digits
				suffix := partDev[i+1:]
				allDigits := len(suffix) > 0
				for _, c := range suffix {
					if c < '0' || c > '9' {
						allDigits = false
						break
					}
				}
				if allDigits {
					return partDev[:i]
				}
			}
		}
	}

	// Handle sda style (e.g., /dev/sda2 -> /dev/sda)
	// Remove trailing digits
	dev := strings.TrimRight(partDev, "0123456789")
	if dev != partDev {
		return dev
	}

	return ""
}

// IsSlotMounted checks if a slot is currently mounted
func IsSlotMounted(slot Slot) (bool, string, error) {
	dev, err := GetPartitionDevice(slot)
	if err != nil {
		return false, "", err
	}

	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false, "", fmt.Errorf("read /proc/mounts: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == dev {
			return true, fields[1], nil
		}
	}

	return false, "", nil
}

// GetInactiveSlotMountPoint returns a temporary mount point for the inactive slot
func GetInactiveSlotMountPoint() string {
	return filepath.Join("/mnt", "secubox-inactive")
}

// BootControlExists checks if the boot control directory and files exist
func BootControlExists() bool {
	if _, err := os.Stat(BootControlDir); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(ActiveSlotFile); os.IsNotExist(err) {
		return false
	}
	return true
}

// InitBootControl initializes the boot control files with default values
func InitBootControl() error {
	if err := os.MkdirAll(BootControlDir, 0755); err != nil {
		return fmt.Errorf("create boot control dir: %w", err)
	}

	// Initialize active slot to A if not exists
	if _, err := os.Stat(ActiveSlotFile); os.IsNotExist(err) {
		if err := SetActiveSlot(SlotA); err != nil {
			return err
		}
	}

	// Initialize fallback slot to B if not exists
	if _, err := os.Stat(FallbackSlotFile); os.IsNotExist(err) {
		if err := SetFallbackSlot(SlotB); err != nil {
			return err
		}
	}

	// Initialize boot count to 0 if not exists
	if _, err := os.Stat(BootCountFile); os.IsNotExist(err) {
		if err := SetBootCount(0); err != nil {
			return err
		}
	}

	return nil
}
