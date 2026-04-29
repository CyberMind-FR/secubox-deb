#!/usr/bin/env python3
"""
SecuBox Profile Generator — GUI Application
============================================

Multiplatform GUI for generating SecuBox appliance profiles.
Can be launched via USB autorun on Windows/Mac/Linux.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""

import sys
import os
import json
import platform
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from enum import Enum

# Try PyQt6 first, fall back to tkinter
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QComboBox, QCheckBox, QGroupBox, QTabWidget,
        QListWidget, QListWidgetItem, QProgressBar, QTextEdit, QFileDialog,
        QMessageBox, QFrame, QSplitter, QScrollArea, QGridLayout, QSpacerItem,
        QSizePolicy, QStackedWidget
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QFont, QColor, QPalette, QIcon, QPixmap
    USE_QT = True
except ImportError:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    USE_QT = False


# ══════════════════════════════════════════════════════════════════════════════
# Data Models (from profile-generator.md v0.2)
# ══════════════════════════════════════════════════════════════════════════════

class Tier(Enum):
    LITE = "lite"           # ≤1GB RAM, ≤2 cores
    STANDARD = "standard"   # 2-4GB RAM, 2-4 cores
    PRO = "pro"             # 4GB+ RAM, 4+ cores


class ModuleLevel(Enum):
    DISABLED = "disabled"
    MINIMAL = "minimal"
    STANDARD = "standard"
    FULL = "full"


@dataclass
class Board:
    id: str
    name: str
    arch: str
    min_tier: Tier
    ram_mb: int
    cores: int
    description: str
    icon: str = "🖥️"


@dataclass
class Module:
    id: str
    name: str
    color: str      # Light 3 palette
    zkp_layer: str  # L1, L2, L3, or "-"
    description: str


@dataclass
class Profile:
    tier: Tier
    board: Board
    stage: str = "dev"  # dev / staging / cspn-frozen
    modules: Dict[str, ModuleLevel] = field(default_factory=dict)
    tweaks: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════════
# Static Data
# ══════════════════════════════════════════════════════════════════════════════

BOARDS = [
    Board("rpi-zero-w", "Raspberry Pi Zero W", "arm", Tier.LITE, 512, 1,
          "Minimal USB gadget device", "🍓"),
    Board("espressobin-v7", "ESPRESSObin v7", "arm64", Tier.LITE, 1024, 2,
          "Compact network appliance", "☕"),
    Board("rpi4", "Raspberry Pi 4", "arm64", Tier.STANDARD, 4096, 4,
          "Versatile SBC", "🍓"),
    Board("vm-x64", "Virtual Machine x64", "amd64", Tier.STANDARD, 2048, 2,
          "VirtualBox/QEMU/VMware", "💻"),
    Board("mochabin", "MOCHAbin", "arm64", Tier.PRO, 8192, 4,
          "High-performance network appliance", "☕"),
    Board("bare-metal", "Bare Metal x64", "amd64", Tier.PRO, 16384, 8,
          "Server / Desktop hardware", "🖥️"),
]

MODULES = [
    Module("auth", "AUTH", "#C04E24", "L1", "NIZK Hamiltonian, G rotation 24h, PFS"),
    Module("wall", "WALL", "#9A6010", "-", "nftables, CrowdSec, rate limiting"),
    Module("boot", "BOOT", "#803018", "-", "secure boot, LUKS, dm-verity"),
    Module("mind", "MIND", "#3D35A0", "L2", "nDPId, mitmproxy bridge, DPI"),
    Module("root", "ROOT", "#0A5840", "-", "base Debian, kernel, systemd"),
    Module("mesh", "MESH", "#104A88", "L3", "WireGuard, Tailscale, MirrorNet"),
]

STAGES = [
    ("dev", "Development", "Unrestricted, all debug enabled"),
    ("staging", "Staging", "Production-like, logs enabled"),
    ("cspn-frozen", "CSPN Frozen", "Certified config, no modifications"),
]

COMPONENTS = {
    "security": [
        ("secubox-crowdsec", "CrowdSec IDS/IPS", True),
        ("secubox-suricata", "Suricata IDS", False),
        ("secubox-nftables", "nftables Firewall", True),
        ("secubox-fail2ban", "Fail2ban", False),
    ],
    "network": [
        ("secubox-wireguard", "WireGuard VPN", True),
        ("secubox-tailscale", "Tailscale Mesh", False),
        ("secubox-unbound", "Unbound DNS", True),
        ("secubox-haproxy", "HAProxy LB", True),
    ],
    "monitoring": [
        ("secubox-netdata", "Netdata", True),
        ("secubox-prometheus", "Prometheus", False),
        ("secubox-grafana", "Grafana", False),
    ],
    "services": [
        ("secubox-mitmproxy", "mitmproxy WAF", True),
        ("secubox-nginx", "Nginx", True),
        ("secubox-squid", "Squid Cache", False),
    ],
}


# ══════════════════════════════════════════════════════════════════════════════
# SecuBox Color Palette (SPIRITUALCEPT Light 3)
# ══════════════════════════════════════════════════════════════════════════════

COLORS = {
    "bg_main": "#f5f0e8",       # Warm parchment
    "bg_panel": "#ebe5d9",      # Panel background
    "bg_card": "#ffffff",       # Card background
    "text_primary": "#2d2a24",  # Dark brown text
    "text_secondary": "#5c564a", # Muted text
    "accent_gold": "#c9a84c",   # Hermetic gold
    "accent_red": "#c04e24",    # AUTH red
    "border": "#d4cfc3",        # Subtle border
    "success": "#0a5840",       # ROOT green
    "warning": "#9a6010",       # WALL amber
    "error": "#803018",         # BOOT rust
}


# ══════════════════════════════════════════════════════════════════════════════
# PyQt6 GUI Implementation
# ══════════════════════════════════════════════════════════════════════════════

if USE_QT:
    class ModuleCard(QFrame):
        """Card widget for a single module with level selector."""

        def __init__(self, module: Module, parent=None):
            super().__init__(parent)
            self.module = module
            self.setup_ui()

        def setup_ui(self):
            self.setFrameStyle(QFrame.Shape.StyledPanel)
            self.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['bg_card']};
                    border: 2px solid {self.module.color};
                    border-radius: 8px;
                    padding: 8px;
                }}
            """)

            layout = QVBoxLayout(self)
            layout.setSpacing(8)

            # Header with module name and ZKP layer
            header = QHBoxLayout()

            name_label = QLabel(f"<b>{self.module.name}</b>")
            name_label.setStyleSheet(f"color: {self.module.color}; font-size: 14px;")
            header.addWidget(name_label)

            if self.module.zkp_layer != "-":
                layer_label = QLabel(f"[{self.module.zkp_layer}]")
                layer_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
                header.addWidget(layer_label)

            header.addStretch()
            layout.addLayout(header)

            # Description
            desc_label = QLabel(self.module.description)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
            layout.addWidget(desc_label)

            # Level selector
            self.level_combo = QComboBox()
            for level in ModuleLevel:
                self.level_combo.addItem(level.value.capitalize(), level)
            self.level_combo.setCurrentText("Standard")
            layout.addWidget(self.level_combo)

        def get_level(self) -> ModuleLevel:
            return self.level_combo.currentData()


    class BoardSelector(QWidget):
        """Board selection widget with filtering by tier."""

        board_changed = pyqtSignal(Board)

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setup_ui()

        def setup_ui(self):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)

            # Tier filter
            filter_layout = QHBoxLayout()
            filter_layout.addWidget(QLabel("Tier:"))

            self.tier_combo = QComboBox()
            self.tier_combo.addItem("All", None)
            for tier in Tier:
                self.tier_combo.addItem(tier.value.capitalize(), tier)
            self.tier_combo.currentIndexChanged.connect(self.filter_boards)
            filter_layout.addWidget(self.tier_combo)
            filter_layout.addStretch()
            layout.addLayout(filter_layout)

            # Board list
            self.board_list = QListWidget()
            self.board_list.setStyleSheet(f"""
                QListWidget {{
                    background-color: {COLORS['bg_card']};
                    border: 1px solid {COLORS['border']};
                    border-radius: 4px;
                }}
                QListWidget::item {{
                    padding: 8px;
                    border-bottom: 1px solid {COLORS['border']};
                }}
                QListWidget::item:selected {{
                    background-color: {COLORS['accent_gold']};
                    color: white;
                }}
            """)
            self.board_list.itemClicked.connect(self.on_board_selected)
            layout.addWidget(self.board_list)

            self.populate_boards()

        def populate_boards(self, tier_filter: Optional[Tier] = None):
            self.board_list.clear()
            for board in BOARDS:
                if tier_filter and board.min_tier != tier_filter:
                    continue
                item = QListWidgetItem(f"{board.icon} {board.name}")
                item.setData(Qt.ItemDataRole.UserRole, board)
                item.setToolTip(f"{board.description}\nArch: {board.arch}\nRAM: {board.ram_mb}MB\nCores: {board.cores}")
                self.board_list.addItem(item)

        def filter_boards(self):
            tier = self.tier_combo.currentData()
            self.populate_boards(tier)

        def on_board_selected(self, item):
            board = item.data(Qt.ItemDataRole.UserRole)
            self.board_changed.emit(board)

        def get_selected_board(self) -> Optional[Board]:
            item = self.board_list.currentItem()
            if item:
                return item.data(Qt.ItemDataRole.UserRole)
            return None


    class ComponentsPanel(QWidget):
        """Component selection panel organized by category."""

        def __init__(self, parent=None):
            super().__init__(parent)
            self.checkboxes = {}
            self.setup_ui()

        def setup_ui(self):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setStyleSheet("QScrollArea { border: none; }")

            content = QWidget()
            content_layout = QVBoxLayout(content)

            for category, components in COMPONENTS.items():
                group = QGroupBox(category.capitalize())
                group.setStyleSheet(f"""
                    QGroupBox {{
                        font-weight: bold;
                        border: 1px solid {COLORS['border']};
                        border-radius: 4px;
                        margin-top: 12px;
                        padding-top: 8px;
                    }}
                    QGroupBox::title {{
                        color: {COLORS['accent_gold']};
                    }}
                """)
                group_layout = QVBoxLayout(group)

                for comp_id, comp_name, default in components:
                    cb = QCheckBox(comp_name)
                    cb.setChecked(default)
                    cb.setStyleSheet(f"color: {COLORS['text_primary']};")
                    group_layout.addWidget(cb)
                    self.checkboxes[comp_id] = cb

                content_layout.addWidget(group)

            content_layout.addStretch()
            scroll.setWidget(content)
            layout.addWidget(scroll)

        def get_selected_components(self) -> List[str]:
            return [comp_id for comp_id, cb in self.checkboxes.items() if cb.isChecked()]


    class OutputPanel(QWidget):
        """Panel showing generated manifest and actions."""

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setup_ui()

        def setup_ui(self):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)

            # Output format selector
            format_layout = QHBoxLayout()
            format_layout.addWidget(QLabel("Output Format:"))

            self.format_combo = QComboBox()
            self.format_combo.addItems(["ISO Live", "VDI (VirtualBox)", "QCOW2", "Raw IMG", "Chroot Tarball"])
            format_layout.addWidget(self.format_combo)
            format_layout.addStretch()
            layout.addLayout(format_layout)

            # Manifest preview
            preview_label = QLabel("Generated Manifest:")
            preview_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold;")
            layout.addWidget(preview_label)

            self.manifest_preview = QTextEdit()
            self.manifest_preview.setReadOnly(True)
            self.manifest_preview.setStyleSheet(f"""
                QTextEdit {{
                    background-color: {COLORS['bg_card']};
                    border: 1px solid {COLORS['border']};
                    border-radius: 4px;
                    font-family: 'JetBrains Mono', 'Consolas', monospace;
                    font-size: 11px;
                }}
            """)
            layout.addWidget(self.manifest_preview)

            # Progress bar
            self.progress = QProgressBar()
            self.progress.setVisible(False)
            layout.addWidget(self.progress)

            # Action buttons
            btn_layout = QHBoxLayout()

            self.save_btn = QPushButton("💾 Save Manifest")
            self.save_btn.setStyleSheet(self.button_style(COLORS['accent_gold']))
            btn_layout.addWidget(self.save_btn)

            self.build_btn = QPushButton("🔨 Build Image")
            self.build_btn.setStyleSheet(self.button_style(COLORS['success']))
            btn_layout.addWidget(self.build_btn)

            self.fetch_btn = QPushButton("⬇️ Fetch Pre-built")
            self.fetch_btn.setStyleSheet(self.button_style(COLORS['accent_red']))
            btn_layout.addWidget(self.fetch_btn)

            layout.addLayout(btn_layout)

        def button_style(self, color: str) -> str:
            return f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 10px 20px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    opacity: 0.9;
                }}
            """

        def update_manifest(self, manifest: dict):
            import yaml
            try:
                text = yaml.dump(manifest, default_flow_style=False, allow_unicode=True)
            except:
                text = json.dumps(manifest, indent=2)
            self.manifest_preview.setText(text)


    class SecuBoxGenGUI(QMainWindow):
        """Main application window."""

        def __init__(self):
            super().__init__()
            self.current_profile = Profile(tier=Tier.STANDARD, board=BOARDS[3])  # Default: vm-x64
            self.setup_ui()
            self.update_manifest()

        def setup_ui(self):
            self.setWindowTitle("SecuBox Profile Generator")
            self.setMinimumSize(1200, 800)
            self.setStyleSheet(f"background-color: {COLORS['bg_main']};")

            # Central widget
            central = QWidget()
            self.setCentralWidget(central)

            main_layout = QHBoxLayout(central)
            main_layout.setSpacing(16)
            main_layout.setContentsMargins(16, 16, 16, 16)

            # Left panel: Board & Stage selection
            left_panel = QWidget()
            left_panel.setMaximumWidth(300)
            left_layout = QVBoxLayout(left_panel)

            # Logo/Header
            header = QLabel("⬡ SecuBox Generator")
            header.setStyleSheet(f"""
                font-size: 20px;
                font-weight: bold;
                color: {COLORS['accent_gold']};
                padding: 8px;
            """)
            left_layout.addWidget(header)

            # Board selector
            board_group = QGroupBox("Target Board")
            board_group.setStyleSheet(self.group_style())
            board_layout = QVBoxLayout(board_group)
            self.board_selector = BoardSelector()
            self.board_selector.board_changed.connect(self.on_board_changed)
            board_layout.addWidget(self.board_selector)
            left_layout.addWidget(board_group)

            # Stage selector
            stage_group = QGroupBox("Stage")
            stage_group.setStyleSheet(self.group_style())
            stage_layout = QVBoxLayout(stage_group)
            self.stage_combo = QComboBox()
            for stage_id, stage_name, stage_desc in STAGES:
                self.stage_combo.addItem(f"{stage_name}", stage_id)
            self.stage_combo.currentIndexChanged.connect(self.update_manifest)
            stage_layout.addWidget(self.stage_combo)
            left_layout.addWidget(stage_group)

            left_layout.addStretch()
            main_layout.addWidget(left_panel)

            # Center panel: Modules
            center_panel = QWidget()
            center_layout = QVBoxLayout(center_panel)

            modules_label = QLabel("Modules Configuration")
            modules_label.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['text_primary']};")
            center_layout.addWidget(modules_label)

            modules_grid = QGridLayout()
            modules_grid.setSpacing(12)

            self.module_cards = {}
            for i, module in enumerate(MODULES):
                card = ModuleCard(module)
                card.level_combo.currentIndexChanged.connect(self.update_manifest)
                self.module_cards[module.id] = card
                modules_grid.addWidget(card, i // 3, i % 3)

            center_layout.addLayout(modules_grid)

            # Components panel
            components_label = QLabel("Components")
            components_label.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['text_primary']};")
            center_layout.addWidget(components_label)

            self.components_panel = ComponentsPanel()
            center_layout.addWidget(self.components_panel)

            main_layout.addWidget(center_panel, stretch=2)

            # Right panel: Output
            right_panel = QWidget()
            right_panel.setMaximumWidth(400)
            right_layout = QVBoxLayout(right_panel)

            output_label = QLabel("Output")
            output_label.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['text_primary']};")
            right_layout.addWidget(output_label)

            self.output_panel = OutputPanel()
            self.output_panel.save_btn.clicked.connect(self.save_manifest)
            self.output_panel.build_btn.clicked.connect(self.build_image)
            self.output_panel.fetch_btn.clicked.connect(self.fetch_prebuilt)
            right_layout.addWidget(self.output_panel)

            main_layout.addWidget(right_panel)

        def group_style(self) -> str:
            return f"""
                QGroupBox {{
                    font-weight: bold;
                    border: 1px solid {COLORS['border']};
                    border-radius: 8px;
                    margin-top: 12px;
                    padding: 12px;
                    background-color: {COLORS['bg_panel']};
                }}
                QGroupBox::title {{
                    color: {COLORS['accent_gold']};
                    subcontrol-position: top left;
                    padding: 0 8px;
                }}
            """

        def on_board_changed(self, board: Board):
            self.current_profile.board = board
            self.current_profile.tier = board.min_tier
            self.update_manifest()

        def update_manifest(self):
            board = self.board_selector.get_selected_board()
            if not board:
                board = BOARDS[3]  # Default vm-x64

            stage = self.stage_combo.currentData() or "dev"

            modules = {}
            for mod_id, card in self.module_cards.items():
                modules[mod_id] = card.get_level().value

            components = self.components_panel.get_selected_components()

            manifest = {
                "schema_version": 1,
                "profile": {
                    "tier": board.min_tier.value,
                    "board": board.id,
                    "stage": stage,
                },
                "modules": modules,
                "components": components,
                "tweaks": [],
            }

            self.output_panel.update_manifest(manifest)

        def save_manifest(self):
            filepath, _ = QFileDialog.getSaveFileName(
                self, "Save Manifest", "manifest.yaml", "YAML Files (*.yaml *.yml)"
            )
            if filepath:
                text = self.output_panel.manifest_preview.toPlainText()
                Path(filepath).write_text(text)
                QMessageBox.information(self, "Saved", f"Manifest saved to:\n{filepath}")

        def build_image(self):
            QMessageBox.information(
                self, "Build Image",
                "This will call:\n\nsecubox-build --manifest manifest.yaml --format iso-live\n\n"
                "(Not implemented in mockup)"
            )

        def fetch_prebuilt(self):
            board = self.board_selector.get_selected_board()
            if not board:
                QMessageBox.warning(self, "No Board", "Please select a target board first.")
                return

            QMessageBox.information(
                self, "Fetch Pre-built",
                f"This will call:\n\nsecubox-fetch download --board {board.id}\n\n"
                "(Not implemented in mockup)"
            )


    def run_qt_app():
        app = QApplication(sys.argv)

        # Set application-wide font
        font = QFont("Segoe UI", 10)
        app.setFont(font)

        window = SecuBoxGenGUI()
        window.show()

        sys.exit(app.exec())


# ══════════════════════════════════════════════════════════════════════════════
# Tkinter Fallback Implementation (minimal)
# ══════════════════════════════════════════════════════════════════════════════

else:
    def run_tk_app():
        root = tk.Tk()
        root.title("SecuBox Profile Generator")
        root.geometry("800x600")
        root.configure(bg=COLORS['bg_main'])

        # Header
        header = tk.Label(
            root, text="⬡ SecuBox Profile Generator",
            font=("Arial", 18, "bold"),
            fg=COLORS['accent_gold'],
            bg=COLORS['bg_main']
        )
        header.pack(pady=20)

        # Info label
        info = tk.Label(
            root,
            text="Install PyQt6 for the full GUI experience:\n\npip install PyQt6",
            font=("Arial", 12),
            fg=COLORS['text_secondary'],
            bg=COLORS['bg_main']
        )
        info.pack(pady=20)

        # Board selector
        frame = tk.Frame(root, bg=COLORS['bg_panel'])
        frame.pack(pady=10, padx=20, fill='x')

        tk.Label(frame, text="Target Board:", bg=COLORS['bg_panel']).pack(side='left')
        board_var = tk.StringVar(value="vm-x64")
        board_combo = ttk.Combobox(frame, textvariable=board_var, values=[b.id for b in BOARDS])
        board_combo.pack(side='left', padx=10)

        # Generate button
        def generate():
            board = board_var.get()
            messagebox.showinfo("Generate", f"Would generate manifest for: {board}")

        btn = tk.Button(
            root, text="Generate Manifest",
            command=generate,
            bg=COLORS['accent_gold'],
            fg='white'
        )
        btn.pack(pady=20)

        root.mainloop()


# ══════════════════════════════════════════════════════════════════════════════
# USB Autorun Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def detect_usb_mode() -> bool:
    """Detect if running from USB drive (portable mode)."""
    exe_path = Path(sys.executable if getattr(sys, 'frozen', False) else __file__).resolve()

    if platform.system() == "Windows":
        # Check if on removable drive
        import ctypes
        drive = str(exe_path)[:2]
        return ctypes.windll.kernel32.GetDriveTypeW(drive) == 2  # DRIVE_REMOVABLE
    else:
        # Check if path contains /media/ or /mnt/ (typical USB mount points)
        return any(p in str(exe_path) for p in ['/media/', '/mnt/', '/Volumes/'])


def main():
    """Main entry point."""
    # Check for portable/USB mode
    portable = detect_usb_mode()
    if portable:
        print("Running in portable USB mode")
        # Could load config from USB drive here

    if USE_QT:
        run_qt_app()
    else:
        run_tk_app()


if __name__ == "__main__":
    main()
