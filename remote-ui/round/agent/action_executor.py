"""
Action executor for menu system.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
import logging
from dataclasses import dataclass
from typing import Any, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ActionResult:
    """Result of action execution."""

    success: bool
    message: str
    data: Optional[dict] = None


class ActionExecutor:
    """Executes menu actions and routes to appropriate handlers."""

    def __init__(self, local_api=None):
        """Initialize action executor.

        Args:
            local_api: Optional LocalAPI instance for local actions.
        """
        self._local_api = local_api
        self._handlers = {
            "local": self._execute_local,
            "secubox": self._execute_secubox,
            "network": self._execute_network,
            "security": self._execute_security,
            "system": self._execute_system,
            "devices": self._execute_devices,
            "nav": self._execute_navigation,
            "otg": self._execute_otg,
        }
        # OTG manager instance (lazy loaded)
        self._otg_manager = None

    def parse_action(self, action: str) -> Tuple[str, str, Optional[str]]:
        """
        Parse action string into components.

        Args:
            action: Action string in format "module.method" or "module.method:param"

        Returns:
            Tuple of (module, method, param)
        """
        # Split module.method:param
        if ":" in action:
            action_part, param = action.split(":", 1)
        else:
            action_part = action
            param = None

        # Split module.method
        parts = action_part.split(".", 1)
        if len(parts) == 2:
            module, method = parts
        else:
            module = "unknown"
            method = action_part

        return module, method, param

    async def execute(self, action: str) -> ActionResult:
        """
        Execute menu action.

        Args:
            action: Action string to execute

        Returns:
            ActionResult with execution status
        """
        try:
            module, method, param = self.parse_action(action)

            # Route to appropriate handler
            handler = self._handlers.get(module)
            if not handler:
                return ActionResult(
                    success=False,
                    message=f"Unknown module: {module}",
                )

            return await handler(method, param)

        except Exception as e:
            logger.exception(f"Action execution failed: {action}")
            return ActionResult(
                success=False,
                message=f"Execution error: {str(e)}",
            )

    async def _execute_local(self, method: str, param: Optional[str]) -> ActionResult:
        """Execute local actions (about, settings, etc)."""
        # Delegate to LocalAPI if available
        if self._local_api:
            return await self._local_api.execute(method, param)

        # Fallback handlers when LocalAPI not configured
        if method == "about":
            return ActionResult(
                success=True,
                message="About SecuBox Eye Remote",
                data={
                    "version": "1.0.0",
                    "platform": "Debian Bookworm ARM64",
                },
            )
        elif method == "settings":
            return ActionResult(
                success=True,
                message="Settings screen",
            )
        else:
            return ActionResult(
                success=False,
                message=f"Unknown local action: {method}",
            )

    async def _execute_secubox(
        self, method: str, param: Optional[str]
    ) -> ActionResult:
        """Execute SecuBox module actions."""
        if method == "module":
            return ActionResult(
                success=True,
                message=f"Opening module: {param}",
                data={"module": param},
            )
        elif method == "status":
            return ActionResult(
                success=True,
                message="SecuBox status",
                data={"status": "running"},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Unknown SecuBox action: {method}",
            )

    async def _execute_network(
        self, method: str, param: Optional[str]
    ) -> ActionResult:
        """Execute network actions."""
        if method == "scan":
            return ActionResult(
                success=True,
                message="Network scan started",
            )
        elif method == "status":
            return ActionResult(
                success=True,
                message="Network status",
                data={"interfaces": []},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Unknown network action: {method}",
            )

    async def _execute_security(
        self, method: str, param: Optional[str]
    ) -> ActionResult:
        """Execute security actions."""
        if method == "threats":
            return ActionResult(
                success=True,
                message="Threat list",
                data={"threats": []},
            )
        elif method == "rules":
            return ActionResult(
                success=True,
                message="Security rules",
            )
        else:
            return ActionResult(
                success=False,
                message=f"Unknown security action: {method}",
            )

    async def _execute_system(self, method: str, param: Optional[str]) -> ActionResult:
        """Execute system actions."""
        if method == "reboot":
            return ActionResult(
                success=True,
                message="Reboot scheduled",
            )
        elif method == "shutdown":
            return ActionResult(
                success=True,
                message="Shutdown scheduled",
            )
        elif method == "logs":
            return ActionResult(
                success=True,
                message="System logs",
                data={"logs": []},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Unknown system action: {method}",
            )

    async def _execute_devices(
        self, method: str, param: Optional[str]
    ) -> ActionResult:
        """Execute device actions."""
        if method == "scan":
            return ActionResult(
                success=True,
                message="Device scan started",
            )
        elif method == "list":
            return ActionResult(
                success=True,
                message="Device list",
                data={"devices": []},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Unknown device action: {method}",
            )

    async def _execute_otg(self, method: str, param: Optional[str]) -> ActionResult:
        """Execute OTG/USB gadget actions."""
        # Lazy load OTG manager
        if self._otg_manager is None:
            try:
                from usb_host_detector import OtgModeManager
                self._otg_manager = OtgModeManager()
            except ImportError:
                return ActionResult(
                    success=False,
                    message="OTG manager not available",
                )

        if method == "status":
            status = self._otg_manager.get_status()
            return ActionResult(
                success=True,
                message=f"OTG: {status['mode']} ({status['state']})",
                data=status,
            )
        elif method == "mode":
            if not param:
                return ActionResult(
                    success=False,
                    message="Mode parameter required",
                )
            if param not in self._otg_manager.MODES:
                return ActionResult(
                    success=False,
                    message=f"Unknown mode: {param}",
                    data={"available_modes": list(self._otg_manager.MODES.keys())},
                )
            success = self._otg_manager.switch_mode(param)
            return ActionResult(
                success=success,
                message=f"Mode changed to {param}" if success else f"Failed to switch to {param}",
                data={"mode": self._otg_manager.current_mode},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Unknown OTG action: {method}",
            )

    async def _execute_navigation(
        self, method: str, param: Optional[str]
    ) -> ActionResult:
        """Execute navigation actions."""
        if method == "back":
            return ActionResult(
                success=True,
                message="Navigate back",
            )
        elif method == "home":
            return ActionResult(
                success=True,
                message="Navigate home",
            )
        else:
            return ActionResult(
                success=False,
                message=f"Unknown navigation action: {method}",
            )
