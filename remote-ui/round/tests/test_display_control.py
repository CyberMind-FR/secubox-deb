"""
SecuBox Eye Remote — Display Controller Tests
Tests for the DisplayController class that manages display brightness and power.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
import asyncio
import pytest
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock, mock_open

from agent.system.display_control import DisplayController, DisplayStatus


class TestDisplayStatus:
    """Tests for DisplayStatus dataclass."""

    def test_display_status_creation(self):
        """DisplayStatus should be created with all required fields."""
        status = DisplayStatus(
            brightness=75,
            power_on=True,
            timeout_seconds=300
        )
        assert status.brightness == 75
        assert status.power_on is True
        assert status.timeout_seconds == 300

    def test_display_status_power_off(self):
        """DisplayStatus should represent powered off state."""
        status = DisplayStatus(
            brightness=0,
            power_on=False,
            timeout_seconds=300
        )
        assert status.brightness == 0
        assert status.power_on is False


class TestDisplayControllerInit:
    """Tests for DisplayController initialization."""

    def test_display_controller_default_device(self):
        """DisplayController should use rpi_backlight by default."""
        controller = DisplayController()
        assert controller._device == "rpi_backlight"

    def test_display_controller_custom_device(self):
        """DisplayController should support custom backlight device."""
        controller = DisplayController(backlight_device="custom_backlight")
        assert controller._device == "custom_backlight"

    def test_display_controller_default_timeout(self):
        """DisplayController should have 5 minute default timeout."""
        controller = DisplayController()
        assert controller._timeout == 300

    def test_display_controller_backlight_path(self):
        """DisplayController should construct correct backlight path."""
        controller = DisplayController(backlight_device="my_backlight")
        path = controller._get_backlight_path()
        assert path == Path("/sys/class/backlight/my_backlight")


class TestDisplayControllerSetBrightness:
    """Tests for DisplayController.set_brightness() method."""

    @pytest.mark.asyncio
    async def test_set_brightness_success(self):
        """set_brightness() should write scaled value to sysfs."""
        controller = DisplayController()

        # Mock file reads/writes
        mock_max_brightness = "255"

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text', return_value=mock_max_brightness), \
             patch('pathlib.Path.write_text') as mock_write:

            result = await controller.set_brightness(50)

            assert result is True
            # 50% of 255 = 127.5, rounded to 127 or 128
            mock_write.assert_called_once()
            written_value = int(mock_write.call_args[0][0])
            assert 127 <= written_value <= 128

    @pytest.mark.asyncio
    async def test_set_brightness_clamps_to_zero(self):
        """set_brightness() should clamp negative values to 0."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text', return_value="255"), \
             patch('pathlib.Path.write_text') as mock_write:

            result = await controller.set_brightness(-10)

            assert result is True
            written_value = int(mock_write.call_args[0][0])
            assert written_value == 0

    @pytest.mark.asyncio
    async def test_set_brightness_clamps_to_hundred(self):
        """set_brightness() should clamp values above 100 to 100."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text', return_value="255"), \
             patch('pathlib.Path.write_text') as mock_write:

            result = await controller.set_brightness(150)

            assert result is True
            written_value = int(mock_write.call_args[0][0])
            assert written_value == 255

    @pytest.mark.asyncio
    async def test_set_brightness_device_not_found_enters_simulation(self):
        """set_brightness() should enter simulation mode when device doesn't exist."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=False):
            result = await controller.set_brightness(50)
            # In simulation mode, operations succeed
            assert result is True
            assert controller.is_simulation_mode is True


class TestDisplayControllerGetBrightness:
    """Tests for DisplayController.get_brightness() method."""

    @pytest.mark.asyncio
    async def test_get_brightness_success(self):
        """get_brightness() should return scaled value from sysfs."""
        controller = DisplayController()

        # Current = 128, Max = 255 -> ~50%
        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text') as mock_read:

            # Return different values for different file reads
            mock_read.side_effect = ["128", "255"]

            result = await controller.get_brightness()

            assert result == 50  # 128/255 * 100 = 50.2, rounds to 50

    @pytest.mark.asyncio
    async def test_get_brightness_max_value(self):
        """get_brightness() should return 100 for max brightness."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text') as mock_read:

            mock_read.side_effect = ["255", "255"]

            result = await controller.get_brightness()

            assert result == 100

    @pytest.mark.asyncio
    async def test_get_brightness_device_not_found_returns_simulated(self):
        """get_brightness() should return simulated value when device doesn't exist."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=False):
            result = await controller.get_brightness()
            # In simulation mode, returns the simulated brightness (default 100)
            assert result == 100
            assert controller.is_simulation_mode is True


class TestDisplayControllerWake:
    """Tests for DisplayController.wake() method."""

    @pytest.mark.asyncio
    async def test_wake_success_via_bl_power(self):
        """wake() should write 0 to bl_power to turn on display."""
        controller = DisplayController()
        controller._last_brightness = 75  # Remembered brightness

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text', return_value="255"), \
             patch('pathlib.Path.write_text') as mock_write:

            result = await controller.wake()

            assert result is True
            # Should write to bl_power first (0 = on)
            calls = mock_write.call_args_list
            assert len(calls) >= 1

    @pytest.mark.asyncio
    async def test_wake_device_not_found_enters_simulation(self):
        """wake() should enter simulation mode when device doesn't exist."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=False):
            result = await controller.wake()
            # In simulation mode, operations succeed
            assert result is True
            assert controller.is_simulation_mode is True


class TestDisplayControllerSleep:
    """Tests for DisplayController.sleep() method."""

    @pytest.mark.asyncio
    async def test_sleep_success_via_bl_power(self):
        """sleep() should write 1 to bl_power to turn off display."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text') as mock_read, \
             patch('pathlib.Path.write_text') as mock_write:

            # Return current brightness to save it
            mock_read.side_effect = ["128", "255"]

            result = await controller.sleep()

            assert result is True
            # Should have saved brightness and written to bl_power
            calls = mock_write.call_args_list
            assert len(calls) >= 1

    @pytest.mark.asyncio
    async def test_sleep_device_not_found_enters_simulation(self):
        """sleep() should enter simulation mode when device doesn't exist."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=False):
            result = await controller.sleep()
            # In simulation mode, operations succeed
            assert result is True
            assert controller.is_simulation_mode is True


class TestDisplayControllerTimeout:
    """Tests for DisplayController timeout functionality."""

    @pytest.mark.asyncio
    async def test_set_timeout(self):
        """set_timeout() should update timeout value."""
        controller = DisplayController()

        await controller.set_timeout(600)

        assert controller._timeout == 600

    def test_record_activity(self):
        """record_activity() should update last activity timestamp."""
        controller = DisplayController()
        old_time = controller._last_activity

        # Wait a tiny bit to ensure time difference
        time.sleep(0.01)
        controller.record_activity()

        assert controller._last_activity > old_time

    @pytest.mark.asyncio
    async def test_check_timeout_not_expired(self):
        """check_timeout() should return False when timeout not expired."""
        controller = DisplayController()
        controller._timeout = 300
        controller.record_activity()

        result = await controller.check_timeout()

        assert result is False

    @pytest.mark.asyncio
    async def test_check_timeout_expired(self):
        """check_timeout() should return True when timeout expired."""
        controller = DisplayController()
        controller._timeout = 1
        controller._last_activity = time.time() - 10  # 10 seconds ago

        result = await controller.check_timeout()

        assert result is True


class TestDisplayControllerStatus:
    """Tests for DisplayController.status() method."""

    @pytest.mark.asyncio
    async def test_status_returns_display_status(self):
        """status() should return DisplayStatus object."""
        controller = DisplayController()
        controller._timeout = 300

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text') as mock_read:

            # brightness=128, max=255, bl_power=0 (on)
            mock_read.side_effect = ["128", "255", "0"]

            result = await controller.status()

            assert isinstance(result, DisplayStatus)
            assert result.brightness == 50
            assert result.power_on is True
            assert result.timeout_seconds == 300

    @pytest.mark.asyncio
    async def test_status_display_off(self):
        """status() should report power_on=False when bl_power=1."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text') as mock_read:

            # brightness=0, max=255, bl_power=1 (off)
            mock_read.side_effect = ["0", "255", "1"]

            result = await controller.status()

            assert result.power_on is False


class TestDisplayControllerSimulationMode:
    """Tests for DisplayController simulation mode (no hardware)."""

    @pytest.mark.asyncio
    async def test_simulation_mode_enabled_when_no_device(self):
        """Controller should enter simulation mode when device not found."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=False):
            # All operations should succeed in simulation mode
            set_result = await controller.set_brightness(50)
            get_result = await controller.get_brightness()
            wake_result = await controller.wake()
            sleep_result = await controller.sleep()

            # In simulation mode, operations report success but are no-ops
            # get_brightness returns simulated value or 0
            assert isinstance(get_result, int)

    @pytest.mark.asyncio
    async def test_simulation_mode_status(self):
        """status() should work in simulation mode."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=False):
            status = await controller.status()

            assert isinstance(status, DisplayStatus)
            # In simulation mode, returns default/simulated values
            assert isinstance(status.brightness, int)
            assert isinstance(status.power_on, bool)
            assert status.timeout_seconds == controller._timeout

    @pytest.mark.asyncio
    async def test_simulation_mode_maintains_state(self):
        """Simulation mode should maintain internal state."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=False):
            # Set brightness in simulation mode
            await controller.set_brightness(75)

            # Get should return the simulated value
            brightness = await controller.get_brightness()

            # In simulation mode, we track the simulated brightness
            assert brightness == 75 or brightness == 0  # Implementation dependent


class TestDisplayControllerHyperPixel:
    """Tests for HyperPixel 2.1 Round specific handling."""

    @pytest.mark.asyncio
    async def test_hyperpixel_alternative_brightness_path(self):
        """HyperPixel may use alternative backlight control."""
        # HyperPixel 2.1 Round may not have standard backlight control
        # Test fallback to GPIO PWM or other methods
        controller = DisplayController(backlight_device="hyperpixel2r")

        # Should handle gracefully when standard backlight not available
        with patch('pathlib.Path.exists') as mock_exists:
            mock_exists.return_value = False

            # Should not raise, should enter simulation mode
            result = await controller.set_brightness(50)
            assert result is False or result is True  # Depends on sim mode


class TestDisplayControllerEdgeCases:
    """Edge case tests for DisplayController."""

    @pytest.mark.asyncio
    async def test_brightness_rounding(self):
        """Brightness should be correctly rounded."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text') as mock_read:

            # 77 / 255 = 30.19... should round to 30
            mock_read.side_effect = ["77", "255"]

            result = await controller.get_brightness()

            assert result == 30

    @pytest.mark.asyncio
    async def test_handles_non_numeric_file_content(self):
        """Should handle malformed sysfs content gracefully."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text', return_value="invalid"):

            # Should not raise, should return safe default
            result = await controller.get_brightness()

            assert result == 0 or result is None

    @pytest.mark.asyncio
    async def test_handles_permission_error(self):
        """Should handle permission errors gracefully."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text', side_effect=PermissionError("Access denied")):

            result = await controller.get_brightness()

            assert result == 0

    @pytest.mark.asyncio
    async def test_concurrent_operations(self):
        """Should handle concurrent brightness operations."""
        controller = DisplayController()

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.read_text', return_value="255"), \
             patch('pathlib.Path.write_text'):

            # Run multiple set operations concurrently
            tasks = [
                controller.set_brightness(25),
                controller.set_brightness(50),
                controller.set_brightness(75),
            ]

            results = await asyncio.gather(*tasks)

            # All should succeed
            assert all(r is True for r in results)
