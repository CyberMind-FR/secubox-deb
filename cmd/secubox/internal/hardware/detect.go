// cmd/secubox/internal/hardware/detect.go
package hardware

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Package-level compiled regex for performance
var memTotalRe = regexp.MustCompile(`MemTotal:\s+(\d+)\s+kB`)

// Info holds detected hardware information
type Info struct {
	Board      string
	Arch       string
	CPUModel   string
	CPUCores   int
	RAMTotal   uint64 // bytes
	RAMTotalMB uint64
	DiskTotal  uint64 // bytes
}

// Detect gathers hardware information
func Detect() (*Info, error) {
	info := &Info{}

	// Detect architecture
	info.Arch = detectArch()

	// Detect CPU
	info.CPUModel, info.CPUCores = detectCPU()

	// Detect RAM
	info.RAMTotal = detectRAM()
	info.RAMTotalMB = info.RAMTotal / 1024 / 1024

	// Detect board (from device tree)
	info.Board = detectBoard()

	return info, nil
}

func detectArch() string {
	// Use Go's runtime for architecture detection
	arch := runtime.GOARCH
	switch arch {
	case "arm64":
		return "arm64"
	case "amd64":
		return "amd64"
	case "arm":
		return "arm"
	default:
		// Fallback: read from /proc/cpuinfo
		data, err := os.ReadFile("/proc/cpuinfo")
		if err != nil {
			return arch
		}

		content := string(data)
		if strings.Contains(content, "aarch64") || strings.Contains(content, "ARMv8") {
			return "arm64"
		}
		if strings.Contains(content, "x86_64") {
			return "amd64"
		}
		return arch
	}
}

func detectCPU() (string, int) {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "unknown", runtime.NumCPU()
	}
	defer file.Close()

	var model string
	cores := 0
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		// ARM uses "Model" or "model name"
		if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Model") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				model = strings.TrimSpace(parts[1])
			}
		}
		// Also check Hardware line for ARM
		if strings.HasPrefix(line, "Hardware") && model == "" {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				model = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "processor") {
			cores++
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		// Log error but continue with what we have
		if cores == 0 {
			cores = runtime.NumCPU()
		}
		if model == "" {
			model = "unknown"
		}
		return model, cores
	}

	// Fallback to runtime if no cores found
	if cores == 0 {
		cores = runtime.NumCPU()
	}

	if model == "" {
		model = "unknown"
	}

	return model, cores
}

func detectRAM() uint64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		matches := memTotalRe.FindStringSubmatch(scanner.Text())
		if len(matches) == 2 {
			kb, err := strconv.ParseUint(matches[1], 10, 64)
			if err != nil {
				return 0
			}
			return kb * 1024 // Convert to bytes
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		return 0
	}

	return 0
}

func detectBoard() string {
	// Try device tree model (ARM boards)
	data, err := os.ReadFile("/proc/device-tree/model")
	if err == nil {
		model := strings.TrimSpace(strings.TrimRight(string(data), "\x00"))
		boardName := identifyBoardFromModel(model)
		if boardName != "" {
			return boardName
		}
	}

	// Try device tree compatible (ARM boards)
	data, err = os.ReadFile("/proc/device-tree/compatible")
	if err == nil {
		compatible := strings.TrimSpace(strings.TrimRight(string(data), "\x00"))
		boardName := identifyBoardFromCompatible(compatible)
		if boardName != "" {
			return boardName
		}
	}

	// Try DMI (x86 systems)
	data, err = os.ReadFile("/sys/class/dmi/id/product_name")
	if err == nil {
		product := strings.TrimSpace(string(data))
		boardName := identifyBoardFromDMI(product)
		if boardName != "" {
			return boardName
		}
	}

	// Try virtualization detection
	if isVirtualMachine() {
		return "vm-x64"
	}

	return "unknown"
}

func identifyBoardFromModel(model string) string {
	modelLower := strings.ToLower(model)

	// MOCHAbin (Armada 7040)
	if strings.Contains(modelLower, "mochabin") {
		return "mochabin"
	}

	// ESPRESSObin variants (Armada 3720)
	if strings.Contains(modelLower, "espressobin") {
		if strings.Contains(modelLower, "ultra") {
			return "espressobin-ultra"
		}
		return "espressobin-v7"
	}

	// Raspberry Pi
	if strings.Contains(modelLower, "raspberry") {
		if strings.Contains(modelLower, "400") {
			return "rpi400"
		}
		if strings.Contains(modelLower, "4") {
			return "rpi4"
		}
		if strings.Contains(modelLower, "5") {
			return "rpi5"
		}
	}

	// Marvell Armada generic
	if strings.Contains(modelLower, "armada") {
		if strings.Contains(modelLower, "7040") || strings.Contains(modelLower, "8040") {
			return "mochabin"
		}
		if strings.Contains(modelLower, "3720") {
			return "espressobin-v7"
		}
	}

	return ""
}

func identifyBoardFromCompatible(compatible string) string {
	compatLower := strings.ToLower(compatible)

	if strings.Contains(compatLower, "mochabin") || strings.Contains(compatLower, "globalscale,mochabin") {
		return "mochabin"
	}
	if strings.Contains(compatLower, "espressobin") || strings.Contains(compatLower, "globalscale,espressobin") {
		return "espressobin-v7"
	}
	if strings.Contains(compatLower, "raspberrypi,400") {
		return "rpi400"
	}
	if strings.Contains(compatLower, "raspberrypi,4") {
		return "rpi4"
	}

	return ""
}

func identifyBoardFromDMI(product string) string {
	productLower := strings.ToLower(product)

	if strings.Contains(productLower, "virtualbox") {
		return "vm-x64"
	}
	if strings.Contains(productLower, "vmware") {
		return "vm-x64"
	}
	if strings.Contains(productLower, "kvm") || strings.Contains(productLower, "qemu") {
		return "vm-x64"
	}

	return ""
}

func isVirtualMachine() bool {
	// Check for hypervisor in /proc/cpuinfo
	data, err := os.ReadFile("/proc/cpuinfo")
	if err == nil && strings.Contains(string(data), "hypervisor") {
		return true
	}

	// Check systemd-detect-virt style detection
	virtFiles := []string{
		"/sys/hypervisor/type",
		"/proc/xen",
	}
	for _, f := range virtFiles {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}

	return false
}

// SuggestTier suggests a tier based on RAM
func (i *Info) SuggestTier() string {
	ramGB := i.RAMTotalMB / 1024
	if ramGB >= 8 {
		return "tier-pro"
	}
	if ramGB >= 4 {
		return "tier-standard"
	}
	return "tier-lite"
}

// String returns a formatted string of hardware info
func (i *Info) String() string {
	return fmt.Sprintf(`Hardware Information:
  Board:     %s
  Arch:      %s
  CPU:       %s (%d cores)
  RAM:       %d MB
  Suggested: %s`,
		i.Board, i.Arch, i.CPUModel, i.CPUCores,
		i.RAMTotalMB, i.SuggestTier())
}
