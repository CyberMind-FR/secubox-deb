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
    DASHBOARD = auto()  # Affichage dashboard metrics
    MENU = auto()       # Navigation menu radial
    CONFIRM = auto()    # Dialogue de confirmation
    LOADING = auto()    # Attente d'une action async
    RESULT = auto()     # Affichage resultat d'action
    UBOOT = auto()      # U-Boot serial console helper


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


class MenuNavigator:
    """
    Gestionnaire de navigation dans les menus radiaux.

    Gere les transitions d'etat, la pile de navigation,
    et les actions de selection.
    """

    def __init__(self):
        self.state = MenuState()
        self._on_state_change: Optional[Callable[[MenuState], None]] = None

    def on_state_change(self, callback: Callable[[MenuState], None]):
        """Enregistrer un callback pour les changements d'etat."""
        self._on_state_change = callback

    def _notify_change(self):
        """Notifier les observateurs d'un changement d'etat."""
        if self._on_state_change:
            self._on_state_change(self.state)

    def enter_menu(self):
        """Entrer en mode menu (depuis dashboard)."""
        self.state.mode = MenuMode.MENU
        self.state.current_menu = MenuID.ROOT
        self.state.selected_index = 0
        self.state.breadcrumb = []
        self._notify_change()

    def exit_to_dashboard(self):
        """Retourner au dashboard."""
        self.state.mode = MenuMode.DASHBOARD
        self.state.current_menu = MenuID.ROOT
        self.state.selected_index = 0
        self.state.breadcrumb = []
        self._notify_change()

    def enter_uboot_mode(self):
        """Entrer en mode U-Boot helper (serial console detected)."""
        self.state.mode = MenuMode.UBOOT
        self._notify_change()

    def exit_uboot_mode(self):
        """Quitter le mode U-Boot, retour au dashboard."""
        self.state.mode = MenuMode.DASHBOARD
        self._notify_change()

    def go_back(self):
        """Retourner au menu precedent."""
        if self.state.breadcrumb:
            self.state.current_menu = self.state.breadcrumb.pop()
            self.state.selected_index = 0
            self._notify_change()
        else:
            self.exit_to_dashboard()

    def select_current(self) -> Optional[str]:
        """
        Selectionner l'element actuellement en surbrillance.

        Returns:
            Action string si c'est un item action, None sinon
        """
        items = self.get_current_items()
        if not items or self.state.selected_index >= len(items):
            return None

        item = items[self.state.selected_index]

        # Navigation actions
        if item.action == "nav.back":
            self.go_back()
            return None

        if item.action == "nav.dashboard":
            self.exit_to_dashboard()
            return None

        # Submenu navigation
        if item.submenu is not None:
            self.state.breadcrumb.append(self.state.current_menu)
            self.state.current_menu = item.submenu
            self.state.selected_index = 0
            self._notify_change()
            return None

        # Confirm required?
        if item.confirm:
            self.state.mode = MenuMode.CONFIRM
            self.state.pending_action = item.action
            self._notify_change()
            return None

        # Direct action
        return item.action

    def confirm_action(self) -> Optional[str]:
        """Confirmer l'action en attente."""
        if self.state.mode != MenuMode.CONFIRM:
            return None
        action = self.state.pending_action
        self.state.pending_action = None
        self.state.mode = MenuMode.MENU
        self._notify_change()
        return action

    def cancel_action(self):
        """Annuler l'action en attente."""
        self.state.pending_action = None
        self.state.mode = MenuMode.MENU
        self._notify_change()

    def rotate_selection(self, direction: int):
        """
        Tourner la selection.

        Args:
            direction: +1 pour horaire, -1 pour anti-horaire
        """
        items = self.get_current_items()
        if not items:
            return
        self.state.selected_index = (
            self.state.selected_index + direction
        ) % len(items)
        self._notify_change()

    def select_by_index(self, index: int):
        """Selectionner directement par index."""
        items = self.get_current_items()
        if items and 0 <= index < len(items):
            self.state.selected_index = index
            self._notify_change()

    def get_current_items(self) -> list[MenuItem]:
        """Obtenir les items du menu actuel."""
        return MENUS.get(self.state.current_menu, [])

    def show_result(self, message: str, success: bool = True):
        """Afficher un message de resultat."""
        self.state.mode = MenuMode.RESULT
        self.state.result_message = message
        self.state.result_success = success
        self._notify_change()

    def clear_result(self):
        """Effacer le message de resultat."""
        self.state.result_message = None
        self.state.mode = MenuMode.MENU
        self._notify_change()

    def show_loading(self):
        """Afficher l'indicateur de chargement."""
        self.state.mode = MenuMode.LOADING
        self._notify_change()

    def hide_loading(self):
        """Masquer l'indicateur de chargement."""
        self.state.mode = MenuMode.MENU
        self._notify_change()
