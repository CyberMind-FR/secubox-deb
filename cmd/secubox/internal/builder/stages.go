// cmd/secubox/internal/builder/stages.go
package builder

import (
	"fmt"
	"path/filepath"
	"strings"
)

// stageRootfs creates the root filesystem using debootstrap
func (b *Builder) stageRootfs() ([]string, error) {
	var cmds []string

	rootfs := b.rootfsPath()
	arch := b.manifest.Arch
	if arch == "" {
		arch = "arm64"
	}

	// Ensure output directory exists
	cmds = append(cmds, fmt.Sprintf("mkdir -p %s", rootfs))

	// Determine if we need cross-compilation
	crossCompile := b.needsCrossCompile()

	// Base debootstrap command
	var debootstrapCmd string
	if crossCompile {
		// Two-stage debootstrap for cross-compilation
		debootstrapCmd = fmt.Sprintf(
			"debootstrap --arch=%s --foreign --variant=minbase bookworm %s http://deb.debian.org/debian",
			arch, rootfs,
		)
		cmds = append(cmds, debootstrapCmd)

		// Copy qemu-user-static for second stage
		cmds = append(cmds, fmt.Sprintf(
			"cp /usr/bin/qemu-%s-static %s/usr/bin/ 2>/dev/null || true",
			archToQemu(arch), rootfs,
		))

		// Run second stage in chroot
		cmds = append(cmds, fmt.Sprintf(
			"chroot %s /debootstrap/debootstrap --second-stage",
			rootfs,
		))
	} else {
		// Native debootstrap (same architecture)
		debootstrapCmd = fmt.Sprintf(
			"debootstrap --arch=%s --variant=minbase bookworm %s http://deb.debian.org/debian",
			arch, rootfs,
		)
		cmds = append(cmds, debootstrapCmd)
	}

	// Configure apt sources
	sourcesContent := `deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
`
	cmds = append(cmds, fmt.Sprintf(
		"cat > %s/etc/apt/sources.list << 'EOF'\n%sEOF",
		rootfs, sourcesContent,
	))

	// Update package lists in chroot
	cmds = append(cmds, fmt.Sprintf(
		"chroot %s apt-get update",
		rootfs,
	))

	// Install packages from manifest
	if len(b.manifest.Packages) > 0 {
		packages := strings.Join(b.manifest.Packages, " ")
		cmds = append(cmds, fmt.Sprintf(
			"chroot %s apt-get install -y --no-install-recommends %s",
			rootfs, packages,
		))
	}

	// Install kernel if specified
	if b.manifest.Kernel.Version != "" {
		kernelPkg := fmt.Sprintf("linux-image-%s-%s", b.manifest.Kernel.Version, arch)
		cmds = append(cmds, fmt.Sprintf(
			"chroot %s apt-get install -y %s || echo 'Kernel package not found, will use custom kernel'",
			rootfs, kernelPkg,
		))
	}

	// Enable kernel modules
	if len(b.manifest.Kernel.Modules.Enable) > 0 {
		modulesFile := filepath.Join(rootfs, "etc/modules-load.d/secubox.conf")
		modules := strings.Join(b.manifest.Kernel.Modules.Enable, "\n")
		cmds = append(cmds, fmt.Sprintf(
			"mkdir -p %s/etc/modules-load.d && echo '%s' > %s",
			rootfs, modules, modulesFile,
		))
	}

	// Blacklist kernel modules
	if len(b.manifest.Kernel.Modules.Blacklist) > 0 {
		blacklistFile := filepath.Join(rootfs, "etc/modprobe.d/secubox-blacklist.conf")
		var blacklistLines []string
		for _, mod := range b.manifest.Kernel.Modules.Blacklist {
			blacklistLines = append(blacklistLines, fmt.Sprintf("blacklist %s", mod))
		}
		cmds = append(cmds, fmt.Sprintf(
			"mkdir -p %s/etc/modprobe.d && echo '%s' > %s",
			rootfs, strings.Join(blacklistLines, "\n"), blacklistFile,
		))
	}

	// Clean up apt cache to save space
	cmds = append(cmds, fmt.Sprintf(
		"chroot %s apt-get clean && rm -rf %s/var/lib/apt/lists/*",
		rootfs, rootfs,
	))

	return cmds, nil
}

// stagePartition creates the disk image and partitions
func (b *Builder) stagePartition() ([]string, error) {
	var cmds []string

	imagePath := b.imagePath()

	// Parse partition sizes
	espSize, err := ParsePartitionSize(b.manifest.Partitions.ESP)
	if err != nil && b.manifest.Partitions.ESP != "" {
		return nil, fmt.Errorf("parse ESP size: %w", err)
	}
	if espSize == 0 {
		espSize = 256 * 1024 * 1024 // Default 256M
	}

	rootSize, err := ParsePartitionSize(b.manifest.Partitions.Root)
	if err != nil && b.manifest.Partitions.Root != "" {
		return nil, fmt.Errorf("parse root size: %w", err)
	}
	if rootSize == 0 {
		rootSize = 6 * 1024 * 1024 * 1024 // Default 6G
	}

	dataSize, err := ParsePartitionSize(b.manifest.Partitions.Data)
	if err != nil && b.manifest.Partitions.Data != "" {
		return nil, fmt.Errorf("parse data size: %w", err)
	}
	if dataSize == 0 {
		dataSize = 2 * 1024 * 1024 * 1024 // Default 2G
	}

	// Total image size (add 64M for GPT overhead)
	totalSize := espSize + rootSize + dataSize + (64 * 1024 * 1024)
	totalSizeMB := totalSize / (1024 * 1024)

	// Create sparse image file
	cmds = append(cmds, fmt.Sprintf(
		"dd if=/dev/zero of=%s bs=1M count=0 seek=%d",
		imagePath, totalSizeMB,
	))

	// Create GPT partition table
	cmds = append(cmds, fmt.Sprintf(
		"parted -s %s mklabel gpt",
		imagePath,
	))

	// Calculate partition boundaries (in MB for simplicity)
	espSizeMB := espSize / (1024 * 1024)
	rootSizeMB := rootSize / (1024 * 1024)
	dataSizeMB := dataSize / (1024 * 1024)

	espStart := 1       // Start at 1MB (alignment)
	espEnd := espStart + int(espSizeMB)
	rootStart := espEnd
	rootEnd := rootStart + int(rootSizeMB)
	dataStart := rootEnd
	dataEnd := dataStart + int(dataSizeMB)

	// Create ESP partition (EFI System Partition)
	cmds = append(cmds, fmt.Sprintf(
		"parted -s %s mkpart ESP fat32 %dMiB %dMiB",
		imagePath, espStart, espEnd,
	))
	cmds = append(cmds, fmt.Sprintf(
		"parted -s %s set 1 esp on",
		imagePath,
	))

	// Create root partition
	cmds = append(cmds, fmt.Sprintf(
		"parted -s %s mkpart root ext4 %dMiB %dMiB",
		imagePath, rootStart, rootEnd,
	))

	// Create data partition
	cmds = append(cmds, fmt.Sprintf(
		"parted -s %s mkpart data ext4 %dMiB %dMiB",
		imagePath, dataStart, dataEnd,
	))

	// Mount operations as single script with cleanup trap
	rootfs := b.rootfsPath()
	mntDir := filepath.Join(b.outputDir, "mnt")

	// Generate fstab content
	fstab := `# /etc/fstab - SecuBox generated
LABEL=rootfs    /           ext4    errors=remount-ro   0   1
LABEL=ESP       /boot/efi   vfat    umask=0077          0   2
LABEL=data      /srv        ext4    defaults            0   2
`

	// Single script with trap for cleanup on failure
	mountScript := fmt.Sprintf(`set -e

# Set up loop device
LOOPDEV=$(losetup --find --show --partscan %s)

# Cleanup function
cleanup() {
    umount %s/srv 2>/dev/null || true
    umount %s/boot/efi 2>/dev/null || true
    umount %s 2>/dev/null || true
    losetup -d $LOOPDEV 2>/dev/null || true
}
trap cleanup EXIT

# Format partitions
mkfs.vfat -F 32 -n ESP ${LOOPDEV}p1
mkfs.ext4 -L rootfs ${LOOPDEV}p2
mkfs.ext4 -L data ${LOOPDEV}p3

# Mount partitions
mkdir -p %s
mount ${LOOPDEV}p2 %s
mkdir -p %s/boot/efi
mount ${LOOPDEV}p1 %s/boot/efi
mkdir -p %s/srv
mount ${LOOPDEV}p3 %s/srv

# Copy rootfs to image
cp -a %s/* %s/

# Generate fstab
cat > %s/etc/fstab << 'FSTAB_EOF'
%sFSTAB_EOF

# Cleanup runs via trap on exit
`,
		imagePath,
		mntDir, mntDir, mntDir,
		mntDir, mntDir, mntDir, mntDir, mntDir, mntDir,
		rootfs, mntDir,
		mntDir, fstab,
	)

	cmds = append(cmds, mountScript)

	return cmds, nil
}

// stageBoot installs the bootloader
func (b *Builder) stageBoot() ([]string, error) {
	var cmds []string

	imagePath := b.imagePath()
	bootMethod := b.manifest.Boot.Method
	if bootMethod == "" {
		bootMethod = "uboot" // Default for ARM
	}

	mntDir := filepath.Join(b.outputDir, "mnt")

	// Get boot-specific commands
	var bootCmds []string
	switch bootMethod {
	case "uboot":
		bootCmds = b.installUBoot(mntDir)
	case "grub":
		bootCmds = b.installGrub(mntDir)
	case "extlinux":
		bootCmds = b.installExtlinux(mntDir)
	default:
		bootCmds = []string{fmt.Sprintf("echo 'Unknown boot method: %s'", bootMethod)}
	}

	// Single script with trap for cleanup on failure
	bootScript := fmt.Sprintf(`set -e

# Set up loop device
LOOPDEV=$(losetup --find --show --partscan %s)

# Cleanup function
cleanup() {
    umount %s/boot/efi 2>/dev/null || true
    umount %s 2>/dev/null || true
    losetup -d $LOOPDEV 2>/dev/null || true
}
trap cleanup EXIT

# Mount partitions
mount ${LOOPDEV}p2 %s
mount ${LOOPDEV}p1 %s/boot/efi

# Boot installation commands
%s

# Cleanup runs via trap on exit
`,
		imagePath,
		mntDir, mntDir,
		mntDir, mntDir,
		strings.Join(bootCmds, "\n"),
	)

	cmds = append(cmds, bootScript)

	return cmds, nil
}

// installUBoot generates U-Boot installation commands
func (b *Builder) installUBoot(mntDir string) []string {
	var cmds []string

	kernelImage := b.manifest.Boot.KernelImage
	if kernelImage == "" {
		kernelImage = "Image" // Default for ARM64
	}

	dts := b.manifest.Kernel.DTS
	board := b.manifest.Board

	// Create boot script directory
	cmds = append(cmds, fmt.Sprintf("mkdir -p %s/boot", mntDir))

	// Copy kernel image (assuming it's in the rootfs)
	cmds = append(cmds, fmt.Sprintf(
		"cp %s/boot/vmlinuz-* %s/boot/%s 2>/dev/null || echo 'Kernel not found in rootfs'",
		mntDir, mntDir, kernelImage,
	))

	// Copy DTB if specified
	if dts != "" {
		cmds = append(cmds, fmt.Sprintf(
			"cp %s/usr/lib/linux-image-*/marvell/%s.dtb %s/boot/ 2>/dev/null || cp %s/boot/dtbs/*/%s.dtb %s/boot/ 2>/dev/null || echo 'DTB not found'",
			mntDir, dts, mntDir, mntDir, dts, mntDir,
		))
	}

	// Create boot.scr
	bootScript := fmt.Sprintf(`# SecuBox U-Boot boot script for %s
setenv bootargs root=LABEL=rootfs rootfstype=ext4 rootwait console=ttyMV0,115200
load ${devtype} ${devnum}:${bootpart} ${kernel_addr_r} /boot/%s
`, board, kernelImage)

	if dts != "" {
		bootScript += fmt.Sprintf(`load ${devtype} ${devnum}:${bootpart} ${fdt_addr_r} /boot/%s.dtb
booti ${kernel_addr_r} - ${fdt_addr_r}
`, dts)
	} else {
		bootScript += `booti ${kernel_addr_r} - ${fdt_addr_r}
`
	}

	cmds = append(cmds, fmt.Sprintf(
		"cat > %s/boot/boot.cmd << 'EOF'\n%sEOF",
		mntDir, bootScript,
	))

	// Compile boot.scr
	cmds = append(cmds, fmt.Sprintf(
		"mkimage -C none -A arm64 -T script -d %s/boot/boot.cmd %s/boot/boot.scr",
		mntDir, mntDir,
	))

	return cmds
}

// installGrub generates GRUB installation commands (for x86/VM)
func (b *Builder) installGrub(mntDir string) []string {
	var cmds []string

	// Install GRUB for UEFI
	cmds = append(cmds, fmt.Sprintf(
		"chroot %s grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=secubox --no-nvram",
		mntDir,
	))

	// Copy GRUB EFI to removable media location for broader compatibility
	cmds = append(cmds, fmt.Sprintf(
		"mkdir -p %s/boot/efi/EFI/BOOT && cp %s/boot/efi/EFI/secubox/grubx64.efi %s/boot/efi/EFI/BOOT/BOOTX64.EFI",
		mntDir, mntDir, mntDir,
	))

	// Generate GRUB config
	grubConfig := `# SecuBox GRUB Configuration
set timeout=5
set default=0

menuentry "SecuBox" {
    linux /vmlinuz root=LABEL=rootfs rootfstype=ext4 quiet
    initrd /initrd.img
}

menuentry "SecuBox (Recovery)" {
    linux /vmlinuz root=LABEL=rootfs rootfstype=ext4 single
    initrd /initrd.img
}
`
	cmds = append(cmds, fmt.Sprintf(
		"cat > %s/boot/grub/grub.cfg << 'EOF'\n%sEOF",
		mntDir, grubConfig,
	))

	return cmds
}

// installExtlinux generates extlinux configuration (simpler alternative)
func (b *Builder) installExtlinux(mntDir string) []string {
	var cmds []string

	kernelImage := b.manifest.Boot.KernelImage
	if kernelImage == "" {
		kernelImage = "Image"
	}

	dts := b.manifest.Kernel.DTS

	cmds = append(cmds, fmt.Sprintf("mkdir -p %s/boot/extlinux", mntDir))

	extlinuxConf := fmt.Sprintf(`DEFAULT secubox
TIMEOUT 30
PROMPT 0

LABEL secubox
    KERNEL /boot/%s
`, kernelImage)

	if dts != "" {
		extlinuxConf += fmt.Sprintf("    FDT /boot/%s.dtb\n", dts)
	}

	extlinuxConf += `    APPEND root=LABEL=rootfs rootfstype=ext4 rootwait console=ttyMV0,115200
`

	cmds = append(cmds, fmt.Sprintf(
		"cat > %s/boot/extlinux/extlinux.conf << 'EOF'\n%sEOF",
		mntDir, extlinuxConf,
	))

	return cmds
}

// stageCompress compresses the image
func (b *Builder) stageCompress() ([]string, error) {
	var cmds []string

	imagePath := b.imagePath()
	formats := b.manifest.Output.Formats
	if len(formats) == 0 {
		formats = []string{"img.gz"} // Default
	}

	for _, format := range formats {
		switch format {
		case "img.gz":
			cmds = append(cmds, fmt.Sprintf(
				"gzip -k -f %s",
				imagePath,
			))
		case "img.xz":
			// Use parallel xz if available
			cmds = append(cmds, fmt.Sprintf(
				"xz -k -f -T%d %s || xz -k -f %s",
				b.parallelJobs, imagePath, imagePath,
			))
		case "img.zst":
			cmds = append(cmds, fmt.Sprintf(
				"zstd -k -f -T%d %s",
				b.parallelJobs, imagePath,
			))
		case "qcow2":
			cmds = append(cmds, fmt.Sprintf(
				"qemu-img convert -f raw -O qcow2 %s %s.qcow2",
				imagePath, strings.TrimSuffix(imagePath, ".img"),
			))
		case "vmdk":
			cmds = append(cmds, fmt.Sprintf(
				"qemu-img convert -f raw -O vmdk %s %s.vmdk",
				imagePath, strings.TrimSuffix(imagePath, ".img"),
			))
		default:
			cmds = append(cmds, fmt.Sprintf("# Unknown format: %s", format))
		}
	}

	return cmds, nil
}

// stageChecksums generates checksums for the image files
func (b *Builder) stageChecksums() ([]string, error) {
	var cmds []string

	imagePath := b.imagePath()
	checksums := b.manifest.Output.Checksums
	if len(checksums) == 0 {
		checksums = []string{"sha256"} // Default
	}

	formats := b.manifest.Output.Formats
	if len(formats) == 0 {
		formats = []string{"img.gz"}
	}

	// Build list of files to checksum
	files := []string{imagePath} // Raw image
	for _, format := range formats {
		switch format {
		case "img.gz":
			files = append(files, imagePath+".gz")
		case "img.xz":
			files = append(files, imagePath+".xz")
		case "img.zst":
			files = append(files, imagePath+".zst")
		case "qcow2":
			files = append(files, strings.TrimSuffix(imagePath, ".img")+".qcow2")
		case "vmdk":
			files = append(files, strings.TrimSuffix(imagePath, ".img")+".vmdk")
		}
	}

	// Generate checksums
	for _, algo := range checksums {
		var sumCmd string
		switch algo {
		case "sha256":
			sumCmd = "sha256sum"
		case "sha512":
			sumCmd = "sha512sum"
		case "md5":
			sumCmd = "md5sum"
		case "sha1":
			sumCmd = "sha1sum"
		default:
			continue
		}

		// Generate checksum for each file
		for _, file := range files {
			cmds = append(cmds, fmt.Sprintf(
				"%s %s > %s.%s 2>/dev/null || true",
				sumCmd, file, file, algo,
			))
		}
	}

	return cmds, nil
}

// archToQemu maps architecture names to qemu-user binary names
func archToQemu(arch string) string {
	switch arch {
	case "arm64", "aarch64":
		return "aarch64"
	case "armhf", "arm":
		return "arm"
	case "amd64", "x86_64":
		return "x86_64"
	case "i386", "i686":
		return "i386"
	default:
		return arch
	}
}
