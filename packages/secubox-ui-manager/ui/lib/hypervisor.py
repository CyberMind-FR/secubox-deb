"""
SecuBox UI Manager - Hypervisor Detection & Optimization
=========================================================

Detects virtualization environment and configures graphics
for optimal performance.

Supported hypervisors:
    - VirtualBox (oracle)
    - QEMU/KVM (kvm, qemu)
    - VMware (vmware)
    - Xen (xen)
    - Bare metal (none)
"""

import subprocess
import re
from dataclasses import dataclass
from typing import Optional, List
from pathlib import Path

from .debug import get_logger

log = get_logger("hypervisor")


@dataclass
class GraphicsConfig:
    """X11 graphics configuration."""
    driver: str = "modesetting"
    disable_3d: bool = False
    use_llvmpipe: bool = False
    resolution: str = "auto"
    depth: int = 24
    vt: int = 7
    extra_options: Optional[dict] = None

    def __post_init__(self):
        if self.extra_options is None:
            self.extra_options = {}


@dataclass
class HypervisorInfo:
    """Information about detected hypervisor."""
    type: str  # oracle, kvm, vmware, xen, none
    graphics: str  # vmware, vboxvideo, virtio, cirrus, etc.
    has_3d: bool
    recommended_driver: str
    framebuffer_fallback: bool
    config: GraphicsConfig


class HypervisorDetector:
    """
    Detect hypervisor type and configure graphics accordingly.

    Usage:
        detector = HypervisorDetector()
        info = detector.detect()
        print(f"Running on: {info.type}")
        print(f"Using driver: {info.recommended_driver}")
    """

    # Graphics device patterns
    GRAPHICS_PATTERNS = {
        "vmware": r"VMware SVGA|VMSVGA",
        "vboxvideo": r"VirtualBox Graphics|VBox",
        "virtio": r"Virtio|Red Hat.*VGA|QXL",
        "cirrus": r"Cirrus",
        "intel": r"Intel.*Graphics|Intel.*HD",
        "amd": r"AMD|ATI|Radeon",
        "nvidia": r"NVIDIA|GeForce|Quadro",
    }

    def detect(self) -> HypervisorInfo:
        """
        Detect hypervisor and return configuration.

        Returns:
            HypervisorInfo with detected settings
        """
        virt_type = self._detect_virt()
        graphics = self._detect_graphics()
        has_3d = self._detect_3d_accel(virt_type, graphics)

        log.info("Hypervisor: %s, Graphics: %s, 3D: %s", virt_type, graphics, has_3d)

        config = self._build_config(virt_type, graphics, has_3d)

        return HypervisorInfo(
            type=virt_type,
            graphics=graphics,
            has_3d=has_3d,
            recommended_driver=config.driver,
            framebuffer_fallback=self._has_framebuffer(),
            config=config,
        )

    def _detect_virt(self) -> str:
        """Detect virtualization type using systemd-detect-virt."""
        try:
            result = subprocess.run(
                ["systemd-detect-virt", "--vm"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            virt = result.stdout.strip()
            if virt and virt != "none":
                log.debug("systemd-detect-virt: %s", virt)
                return virt
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log.debug("systemd-detect-virt failed: %s", e)

        # Fallback: check DMI
        dmi_vendor = self._read_dmi("sys_vendor")
        if dmi_vendor:
            if "VirtualBox" in dmi_vendor:
                return "oracle"
            elif "QEMU" in dmi_vendor or "KVM" in dmi_vendor:
                return "kvm"
            elif "VMware" in dmi_vendor:
                return "vmware"
            elif "Xen" in dmi_vendor:
                return "xen"

        return "none"

    def _read_dmi(self, field: str) -> str:
        """Read DMI field from sysfs."""
        path = Path(f"/sys/class/dmi/id/{field}")
        try:
            if path.exists():
                return path.read_text().strip()
        except IOError:
            pass
        return ""

    def _detect_graphics(self) -> str:
        """Detect graphics device type."""
        try:
            result = subprocess.run(
                ["lspci", "-nn"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            for line in result.stdout.splitlines():
                # Look for VGA or 3D controller
                if "VGA" in line or "3D controller" in line or "Display" in line:
                    log.debug("Graphics PCI: %s", line)

                    for name, pattern in self.GRAPHICS_PATTERNS.items():
                        if re.search(pattern, line, re.IGNORECASE):
                            return name

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log.debug("lspci failed: %s", e)

        # Fallback: check for framebuffer
        if self._has_framebuffer():
            return "fbdev"

        return "unknown"

    def _detect_3d_accel(self, virt_type: str, graphics: str) -> bool:
        """Detect if 3D acceleration is available."""
        # VirtualBox 3D is buggy and slow
        if virt_type == "oracle":
            return False

        # Virtio-GPU with virgil can do 3D
        if graphics == "virtio":
            # Check for virgl
            try:
                result = subprocess.run(
                    ["glxinfo"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    env={"DISPLAY": ":0"},
                )
                if "virgl" in result.stdout.lower():
                    return True
            except Exception:
                pass
            return False

        # VMware usually has 3D
        if virt_type == "vmware":
            return True

        # Bare metal with discrete GPU
        if virt_type == "none" and graphics in ("nvidia", "amd", "intel"):
            return True

        return False

    def _has_framebuffer(self) -> bool:
        """Check if framebuffer device exists."""
        return Path("/dev/fb0").exists()

    def _build_config(
        self, virt_type: str, graphics: str, has_3d: bool
    ) -> GraphicsConfig:
        """Build optimal graphics configuration."""

        if virt_type == "oracle":
            # VirtualBox: Use modesetting, disable 3D, lower resolution
            return GraphicsConfig(
                driver="modesetting",
                disable_3d=True,
                use_llvmpipe=True,
                resolution="1280x720",
                extra_options={
                    "AccelMethod": "none",
                },
            )

        elif virt_type == "kvm":
            # QEMU/KVM: virtio-gpu if available, else modesetting
            if graphics == "virtio":
                return GraphicsConfig(
                    driver="modesetting",
                    disable_3d=not has_3d,
                    resolution="auto",
                )
            else:
                return GraphicsConfig(
                    driver="modesetting",
                    disable_3d=True,
                    resolution="1024x768",
                )

        elif virt_type == "vmware":
            # VMware: Use vmware driver with 3D
            return GraphicsConfig(
                driver="vmware",
                disable_3d=False,
                resolution="auto",
            )

        elif virt_type == "none":
            # Bare metal: Auto-detect
            driver = "modesetting"

            if graphics == "nvidia":
                # Prefer nouveau for compatibility
                driver = "modesetting"
            elif graphics == "amd":
                driver = "amdgpu"
            elif graphics == "intel":
                driver = "modesetting"  # Modern Intel uses modesetting

            return GraphicsConfig(
                driver=driver,
                disable_3d=not has_3d,
                resolution="auto",
            )

        # Default fallback
        return GraphicsConfig(
            driver="modesetting" if not self._has_framebuffer() else "fbdev",
            disable_3d=True,
            resolution="1024x768",
        )

    def generate_xorg_conf(self, config: GraphicsConfig) -> str:
        """Generate xorg.conf.d snippet for the configuration."""
        sections = []

        # Device section
        device = f'''Section "Device"
    Identifier "SecuBox Graphics"
    Driver "{config.driver}"'''

        if config.extra_options:
            for key, value in config.extra_options.items():
                device += f'\n    Option "{key}" "{value}"'

        device += "\nEndSection"
        sections.append(device)

        # Screen section (if resolution specified)
        if config.resolution != "auto":
            screen = f'''Section "Screen"
    Identifier "SecuBox Screen"
    Device "SecuBox Graphics"
    DefaultDepth {config.depth}
    SubSection "Display"
        Depth {config.depth}
        Modes "{config.resolution}"
    EndSubSection
EndSection'''
            sections.append(screen)

        # Server flags
        server_flags = '''Section "ServerFlags"
    Option "DontZap" "false"
    Option "BlankTime" "0"
    Option "StandbyTime" "0"
    Option "SuspendTime" "0"
    Option "OffTime" "0"'''

        if config.disable_3d:
            server_flags += '\n    Option "DRI" "0"'

        server_flags += "\nEndSection"
        sections.append(server_flags)

        return "\n\n".join(sections)

    def write_xorg_conf(
        self, config: GraphicsConfig, path: str = "/etc/X11/xorg.conf.d/10-secubox.conf"
    ):
        """Write xorg.conf.d file."""
        content = self.generate_xorg_conf(config)
        log.info("Writing X11 config to %s", path)
        log.debug("Config:\n%s", content)

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content)
