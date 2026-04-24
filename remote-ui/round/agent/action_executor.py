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

    def __init__(self):
        """Initialize action executor."""
        self._handlers = {
            "local": self._execute_local,
            "secubox": self._execute_secubox,
            "network": self._execute_network,
            "security": self._execute_security,
            "system": self._execute_system,
            "devices": self._execute_devices,
            "nav": self._execute_navigation,
        }

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
        if method == "about":
            return ActionResult(
                success=True,
                message="About SecuBox Eye",
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
