"""
SecuBox-Deb :: Console TUI — Theme System
Board-specific theming for Textual TUI.

Works standalone (without secubox-core) with auto-detection fallback.
"""
from __future__ import annotations
from typing import Dict
import platform
import os
from pathlib import Path

# Try to import secubox_core, fallback to local detection if not available
try:
    from secubox_core.kiosk import detect_board_type, get_board_model
    HAS_SECUBOX_CORE = True
except ImportError:
    HAS_SECUBOX_CORE = False

    def detect_board_type() -> str:
        """Fallback board detection for standalone mode."""
        # Check DMI/device-tree for board info
        try:
            # Check device-tree (ARM boards)
            dt_model = Path("/proc/device-tree/model")
            if dt_model.exists():
                model = dt_model.read_text().strip().lower()
                if "raspberry" in model:
                    return "rpi"
                if "mochi" in model or "7040" in model:
                    return "mochabin"
                if "espresso" in model or "3720" in model:
                    return "espressobin-v7"

            # Check DMI (x86)
            dmi_vendor = Path("/sys/class/dmi/id/sys_vendor")
            if dmi_vendor.exists():
                vendor = dmi_vendor.read_text().strip().lower()
                if "virtualbox" in vendor or "vmware" in vendor or "qemu" in vendor:
                    return "x64-vm"
                return "x64-baremetal"

            # Fallback based on architecture
            arch = platform.machine()
            if arch in ("x86_64", "amd64"):
                return "x64-baremetal"
            elif arch in ("aarch64", "arm64"):
                return "unknown-arm64"

        except Exception:
            pass

        return "unknown"

    def get_board_model() -> str:
        """Fallback model detection for standalone mode."""
        try:
            dt_model = Path("/proc/device-tree/model")
            if dt_model.exists():
                return dt_model.read_text().strip()

            dmi_name = Path("/sys/class/dmi/id/product_name")
            if dmi_name.exists():
                return dmi_name.read_text().strip()
        except Exception:
            pass

        return platform.machine()


# Board-specific color schemes
# Format: (primary, secondary, accent, success, warning, error)
BOARD_COLORS: Dict[str, Dict[str, str]] = {
    "mochabin": {
        "primary": "#0ea5e9",      # Sky blue
        "secondary": "#0284c7",
        "accent": "#38bdf8",
        "success": "#22c55e",
        "warning": "#f59e0b",
        "error": "#ef4444",
        "name": "SecuBox Pro",
        "badge": "PRO",
    },
    "espressobin-v7": {
        "primary": "#22c55e",       # Green
        "secondary": "#16a34a",
        "accent": "#4ade80",
        "success": "#22c55e",
        "warning": "#eab308",
        "error": "#dc2626",
        "name": "SecuBox Lite",
        "badge": "LITE",
    },
    "espressobin-ultra": {
        "primary": "#14b8a6",       # Teal
        "secondary": "#0d9488",
        "accent": "#2dd4bf",
        "success": "#22c55e",
        "warning": "#f59e0b",
        "error": "#ef4444",
        "name": "SecuBox Ultra",
        "badge": "ULTRA",
    },
    "x64-vm": {
        "primary": "#8b5cf6",       # Purple
        "secondary": "#7c3aed",
        "accent": "#a78bfa",
        "success": "#22c55e",
        "warning": "#f59e0b",
        "error": "#ef4444",
        "name": "SecuBox VM",
        "badge": "VM",
    },
    "x64-baremetal": {
        "primary": "#f97316",       # Orange
        "secondary": "#ea580c",
        "accent": "#fb923c",
        "success": "#22c55e",
        "warning": "#fbbf24",
        "error": "#dc2626",
        "name": "SecuBox Server",
        "badge": "SERVER",
    },
    "rpi": {
        "primary": "#ec4899",       # Pink/Raspberry
        "secondary": "#db2777",
        "accent": "#f472b6",
        "success": "#22c55e",
        "warning": "#f59e0b",
        "error": "#ef4444",
        "name": "SecuBox Pi",
        "badge": "PI",
    },
    "unknown": {
        "primary": "#58a6ff",       # Default blue
        "secondary": "#1f6feb",
        "accent": "#79c0ff",
        "success": "#3fb950",
        "warning": "#d29922",
        "error": "#f85149",
        "name": "SecuBox",
        "badge": None,
    },
}


def get_board_theme() -> Dict[str, str]:
    """Get theme colors for the detected board."""
    board_type = detect_board_type()
    return BOARD_COLORS.get(board_type, BOARD_COLORS["unknown"])


def get_board_name() -> str:
    """Get display name for the detected board."""
    theme = get_board_theme()
    return theme["name"]


def get_board_badge() -> str:
    """Get badge text for the detected board (or empty string)."""
    theme = get_board_theme()
    return theme.get("badge") or ""


def generate_tcss() -> str:
    """Generate Textual CSS with board-specific colors."""
    theme = get_board_theme()
    board_type = detect_board_type()
    model = get_board_model()

    return f"""
/* SecuBox Console Theme — {theme['name']} */
/* Board: {board_type} — {model} */

$primary: {theme['primary']};
$primary-darken-1: {theme['secondary']};
$primary-lighten-1: {theme['accent']};
$success: {theme['success']};
$warning: {theme['warning']};
$error: {theme['error']};

/* Base colors */
$background: #0a0a0f;
$surface: #16161d;
$panel: #1e1e28;
$foreground: #e8e6d9;
$foreground-muted: #6b6b7a;
$border: #2a2a3a;

/* Apply to components */
Screen {{
    background: $background;
}}

Header {{
    background: $primary;
    color: $background;
    text-style: bold;
}}

Footer {{
    background: $surface;
    color: $foreground-muted;
}}

DataTable {{
    background: $surface;
    color: $foreground;
}}

DataTable > .datatable--header {{
    background: $panel;
    color: $primary;
    text-style: bold;
}}

DataTable > .datatable--cursor {{
    background: $primary;
    color: $background;
}}

ProgressBar > .bar--bar {{
    color: $primary;
}}

ProgressBar > .bar--complete {{
    color: $success;
}}

Static {{
    background: transparent;
    color: $foreground;
}}

Label {{
    color: $foreground;
}}

Button {{
    background: $panel;
    color: $foreground;
    border: tall $border;
}}

Button:hover {{
    background: $primary;
    color: $background;
}}

Button.-primary {{
    background: $primary;
    color: $background;
}}

Button.-success {{
    background: $success;
    color: $background;
}}

Button.-warning {{
    background: $warning;
    color: $background;
}}

Button.-error {{
    background: $error;
    color: $background;
}}

Input {{
    background: $surface;
    color: $foreground;
    border: tall $border;
}}

Input:focus {{
    border: tall $primary;
}}

Select {{
    background: $surface;
    color: $foreground;
    border: tall $border;
}}

Select:focus {{
    border: tall $primary;
}}

SelectCurrent {{
    background: $surface;
}}

SelectOverlay {{
    background: $panel;
    border: tall $border;
}}

/* Custom classes */
.status-healthy {{
    color: $success;
}}

.status-degraded {{
    color: $warning;
}}

.status-critical {{
    color: $error;
}}

.status-unknown {{
    color: $foreground-muted;
}}

.metric-label {{
    color: $foreground-muted;
    text-style: italic;
}}

.metric-value {{
    color: $foreground;
    text-style: bold;
}}

.service-running {{
    color: $success;
}}

.service-stopped {{
    color: $error;
}}

.service-disabled {{
    color: $foreground-muted;
}}

.card {{
    background: $surface;
    border: tall $border;
    padding: 1;
    margin: 1;
}}

.card-title {{
    color: $primary;
    text-style: bold;
    margin-bottom: 1;
}}

.board-badge {{
    background: $primary;
    color: $background;
    text-style: bold;
    padding: 0 1;
}}

/* Log levels */
.log-info {{
    color: $foreground;
}}

.log-warning {{
    color: $warning;
}}

.log-error {{
    color: $error;
}}

.log-debug {{
    color: $foreground-muted;
}}
"""
