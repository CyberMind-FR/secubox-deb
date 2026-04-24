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
