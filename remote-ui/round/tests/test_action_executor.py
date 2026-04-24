"""
Tests for action executor.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))

from action_executor import ActionExecutor, ActionResult


class TestActionExecutor:
    """Tests for ActionExecutor class."""

    def test_parse_action_simple(self):
        """Parse simple action without params."""
        executor = ActionExecutor()
        module, method, param = executor.parse_action("devices.scan")
        assert module == "devices"
        assert method == "scan"
        assert param is None

    def test_parse_action_with_param(self):
        """Parse action with parameter."""
        executor = ActionExecutor()
        module, method, param = executor.parse_action("secubox.module:wireguard")
        assert module == "secubox"
        assert method == "module"
        assert param == "wireguard"

    def test_parse_navigation_action(self):
        """Navigation actions have 'nav' module."""
        executor = ActionExecutor()
        module, method, param = executor.parse_action("nav.back")
        assert module == "nav"
        assert method == "back"

    @pytest.mark.asyncio
    async def test_execute_returns_result(self):
        """Execute returns ActionResult."""
        executor = ActionExecutor()
        result = await executor.execute("local.about")
        assert isinstance(result, ActionResult)

    @pytest.mark.asyncio
    async def test_unknown_module_returns_error(self):
        """Unknown module returns error result."""
        executor = ActionExecutor()
        result = await executor.execute("unknown.action")
        assert result.success is False
        assert "Unknown" in result.message
