"""
SecuBox Eye Remote - Menu Definitions
Static menu structures for radial menu navigation.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class MenuID(Enum):
    """Identifiants des menus."""
    ROOT = auto()
    DEVICES = auto()
    SECUBOX = auto()
    SECUBOX_STATUS = auto()
    SECUBOX_MODULES = auto()
    LOCAL = auto()
    LOCAL_DISPLAY = auto()
    LOCAL_NETWORK = auto()
    LOCAL_SYSTEM = auto()
    LOCAL_OTG = auto()       # Menu OTG
    NETWORK = auto()
    SECURITY = auto()
    EXIT = auto()


@dataclass
class MenuItem:
    """
    Un element de menu radial.

    Attributes:
        label: Texte affiche (peut contenir {placeholders} pour donnees dynamiques)
        icon: Nom de l'icone sans extension (ex: "scan" -> scan-48.png)
        action: Action a executer (format "module.method:param")
        submenu: MenuID du sous-menu a ouvrir
        confirm: Demander confirmation avant execution
    """
    label: str
    icon: str
    action: Optional[str] = None
    submenu: Optional[MenuID] = None
    confirm: bool = False


# =============================================================================
# Static Menu Definitions
# =============================================================================

MENUS: dict[MenuID, list[MenuItem]] = {
    # Root Menu - 6 slices
    MenuID.ROOT: [
        MenuItem("DEVICES", "devices", submenu=MenuID.DEVICES),
        MenuItem("SECUBOX", "secubox", submenu=MenuID.SECUBOX),
        MenuItem("LOCAL", "local", submenu=MenuID.LOCAL),
        MenuItem("NETWORK", "network", submenu=MenuID.NETWORK),
        MenuItem("SECURITY", "security", submenu=MenuID.SECURITY),
        MenuItem("EXIT", "exit", submenu=MenuID.EXIT),
    ],

    # DEVICES Menu
    MenuID.DEVICES: [
        MenuItem("SCAN", "scan", action="devices.scan"),
        MenuItem("PAIR NEW", "plus", action="devices.pair"),
        MenuItem("FORGET", "trash", action="devices.forget"),
        MenuItem("REFRESH", "refresh", action="devices.refresh"),
        MenuItem("INFO", "info", action="devices.info"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # SECUBOX Menu
    MenuID.SECUBOX: [
        MenuItem("STATUS", "status", submenu=MenuID.SECUBOX_STATUS),
        MenuItem("MODULES", "modules", submenu=MenuID.SECUBOX_MODULES),
        MenuItem("LOGS", "logs", action="secubox.logs"),
        MenuItem("RESTART", "restart", action="secubox.restart", confirm=True),
        MenuItem("UPDATE", "update", action="secubox.update"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # SECUBOX.STATUS Menu
    MenuID.SECUBOX_STATUS: [
        MenuItem("CPU: {cpu}%", "cpu", action="secubox.detail:cpu"),
        MenuItem("MEM: {mem}%", "memory", action="secubox.detail:mem"),
        MenuItem("DISK: {disk}%", "disk", action="secubox.detail:disk"),
        MenuItem("TEMP: {temp}C", "temp", action="secubox.detail:temp"),
        MenuItem("UPTIME", "clock", action="secubox.detail:uptime"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # SECUBOX.MODULES Menu
    MenuID.SECUBOX_MODULES: [
        MenuItem("CROWDSEC", "auth", action="secubox.module:crowdsec"),
        MenuItem("WIREGUARD", "mesh", action="secubox.module:wireguard"),
        MenuItem("FIREWALL", "wall", action="secubox.module:firewall"),
        MenuItem("DPI", "mind", action="secubox.module:dpi"),
        MenuItem("DNS", "root", action="secubox.module:dns"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # LOCAL Menu
    MenuID.LOCAL: [
        MenuItem("DISPLAY", "display", submenu=MenuID.LOCAL_DISPLAY),
        MenuItem("NETWORK", "network", submenu=MenuID.LOCAL_NETWORK),
        MenuItem("USB/OTG", "usb", submenu=MenuID.LOCAL_OTG),
        MenuItem("SYSTEM", "system", submenu=MenuID.LOCAL_SYSTEM),
        MenuItem("ABOUT", "info", action="local.about"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # LOCAL.DISPLAY Menu
    MenuID.LOCAL_DISPLAY: [
        MenuItem("BRIGHTNESS", "brightness", action="local.brightness"),
        MenuItem("THEME", "theme", action="local.theme"),
        MenuItem("TIMEOUT", "timeout", action="local.timeout"),
        MenuItem("ROTATION", "rotate", action="local.rotation"),
        MenuItem("TEST", "test", action="local.display_test"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # LOCAL.NETWORK Menu
    MenuID.LOCAL_NETWORK: [
        MenuItem("USB IP", "usb", action="local.usb_ip"),
        MenuItem("WIFI", "wifi", action="local.wifi"),
        MenuItem("HOSTNAME", "hostname", action="local.hostname"),
        MenuItem("DNS", "dns", action="local.dns"),
        MenuItem("STATUS", "status", action="local.net_status"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # LOCAL.SYSTEM Menu
    MenuID.LOCAL_SYSTEM: [
        MenuItem("STORAGE", "disk", action="local.storage"),
        MenuItem("MEMORY", "memory", action="local.memory"),
        MenuItem("CPU", "cpu", action="local.cpu_info"),
        MenuItem("LOGS", "logs", action="local.system_logs"),
        MenuItem("UPDATES", "update", action="local.updates"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # LOCAL.OTG Menu - Modes USB OTG
    # Label dynamique : {otg_state} sera remplacé par l'état actuel
    MenuID.LOCAL_OTG: [
        MenuItem("{otg_state}", "usb", action="otg.status"),       # État actuel
        MenuItem("NORMAL", "network", action="otg.mode:normal"),   # ECM + ACM
        MenuItem("FLASH", "boot", action="otg.mode:flash"),        # Mass Storage bootable
        MenuItem("DEBUG", "root", action="otg.mode:debug"),        # ECM + Storage + ACM
        MenuItem("TTY", "mind", action="otg.mode:tty"),            # HID Keyboard + ACM
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # NETWORK Menu
    MenuID.NETWORK: [
        MenuItem("INTERFACES", "interfaces", action="network.interfaces"),
        MenuItem("ROUTES", "routes", action="network.routes"),
        MenuItem("DNS", "dns", action="network.dns"),
        MenuItem("FIREWALL", "wall", action="network.firewall"),
        MenuItem("TRAFFIC", "traffic", action="network.traffic"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # SECURITY Menu
    MenuID.SECURITY: [
        MenuItem("ALERTS", "alert", action="security.alerts"),
        MenuItem("BANS", "ban", action="security.bans"),
        MenuItem("RULES", "rules", action="security.rules"),
        MenuItem("AUDIT", "audit", action="security.audit"),
        MenuItem("LOCKDOWN", "lock", action="security.lockdown", confirm=True),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # EXIT Menu
    MenuID.EXIT: [
        MenuItem("DASHBOARD", "dashboard", action="nav.dashboard"),
        MenuItem("SLEEP", "sleep", action="system.sleep"),
        MenuItem("REBOOT PI", "reboot", action="system.reboot", confirm=True),
        MenuItem("SHUTDOWN", "shutdown", action="system.shutdown", confirm=True),
        MenuItem("REBOOT BOX", "restart", action="secubox.reboot", confirm=True),
        MenuItem("< BACK", "back", action="nav.back"),
    ],
}
