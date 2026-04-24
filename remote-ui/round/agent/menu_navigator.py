"""
SecuBox Eye Remote - Menu Navigator
State machine for radial menu navigation.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Callable, Any

from menu_definitions import MenuID, MenuItem, MENUS


class MenuMode(Enum):
    """Mode d'affichage actuel."""
    DASHBOARD = auto()  # Affichage dashboard normal
    MENU = auto()       # Navigation menu radial
    CONFIRM = auto()    # Dialogue de confirmation
    LOADING = auto()    # Attente d'une action async
    RESULT = auto()     # Affichage resultat d'action


@dataclass
class MenuState:
    """
    Etat complet du systeme de menu.

    Attributes:
        mode: Mode d'affichage actuel
        current_menu: Menu actuellement affiche
        selected_index: Index de la tranche selectionnee (0-5)
        breadcrumb: Pile de navigation pour retour arriere
        animation_frame: Frame d'animation en cours (0-30)
        pending_action: Action en attente de confirmation
        result_message: Message de resultat a afficher
        result_success: Indicateur de succes pour resultat
    """
    mode: MenuMode = MenuMode.DASHBOARD
    current_menu: MenuID = MenuID.ROOT
    selected_index: int = 0
    breadcrumb: list[MenuID] = field(default_factory=list)
    animation_frame: int = 0
    pending_action: Optional[str] = None
    result_message: Optional[str] = None
    result_success: bool = True
