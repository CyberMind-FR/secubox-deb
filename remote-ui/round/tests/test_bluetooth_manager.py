"""
SecuBox Eye Remote — Bluetooth Manager Tests
Tests for the BluetoothManager class that wraps bluetoothctl commands.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from agent.system.bluetooth import BluetoothManager, BluetoothDevice, BluetoothStatus


class TestBluetoothDevice:
    """Tests for BluetoothDevice dataclass."""

    def test_bluetooth_device_creation(self):
        """BluetoothDevice should be created with required fields."""
        device = BluetoothDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="TestDevice",
            paired=True,
            connected=False,
            trusted=True
        )
        assert device.address == "AA:BB:CC:DD:EE:FF"
        assert device.name == "TestDevice"
        assert device.paired is True
        assert device.connected is False
        assert device.trusted is True

    def test_bluetooth_device_defaults(self):
        """BluetoothDevice should have correct defaults."""
        device = BluetoothDevice(
            address="11:22:33:44:55:66",
            name="AnotherDevice",
            paired=False,
            connected=False,
            trusted=False
        )
        assert device.paired is False
        assert device.connected is False
        assert device.trusted is False


class TestBluetoothStatus:
    """Tests for BluetoothStatus dataclass."""

    def test_bluetooth_status_enabled(self):
        """BluetoothStatus should represent enabled adapter."""
        status = BluetoothStatus(
            powered=True,
            discovering=False,
            pairable=True,
            adapter_name="hci0"
        )
        assert status.powered is True
        assert status.discovering is False
        assert status.pairable is True
        assert status.adapter_name == "hci0"

    def test_bluetooth_status_disabled(self):
        """BluetoothStatus should represent disabled adapter."""
        status = BluetoothStatus(
            powered=False,
            discovering=False,
            pairable=False,
            adapter_name="hci0"
        )
        assert status.powered is False
        assert status.discovering is False
        assert status.pairable is False


class TestBluetoothManagerScan:
    """Tests for BluetoothManager.scan() method."""

    @pytest.mark.asyncio
    async def test_bluetooth_manager_scan_returns_devices(self):
        """scan() should return list of BluetoothDevice from bluetoothctl output."""
        # Mock the scan on and devices output
        devices_output = b"Device AA:BB:CC:DD:EE:FF HeadphonesXL\nDevice 11:22:33:44:55:66 Speaker\n"

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            # First call: scan on
            mock_scan_on = AsyncMock()
            mock_scan_on.communicate = AsyncMock(return_value=(b"Discovery started\n", b""))
            mock_scan_on.returncode = 0

            # Second call: scan off
            mock_scan_off = AsyncMock()
            mock_scan_off.communicate = AsyncMock(return_value=(b"Discovery stopped\n", b""))
            mock_scan_off.returncode = 0

            # Third call: devices
            mock_devices = AsyncMock()
            mock_devices.communicate = AsyncMock(return_value=(devices_output, b""))
            mock_devices.returncode = 0

            mock_exec.side_effect = [mock_scan_on, mock_scan_off, mock_devices]

            manager = BluetoothManager()
            devices = await manager.scan(duration=1)

            assert len(devices) == 2
            assert devices[0].address == "AA:BB:CC:DD:EE:FF"
            assert devices[0].name == "HeadphonesXL"
            assert devices[1].address == "11:22:33:44:55:66"
            assert devices[1].name == "Speaker"

    @pytest.mark.asyncio
    async def test_bluetooth_manager_scan_handles_empty_result(self):
        """scan() should return empty list when no devices found."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_scan_on = AsyncMock()
            mock_scan_on.communicate = AsyncMock(return_value=(b"Discovery started\n", b""))
            mock_scan_on.returncode = 0

            mock_scan_off = AsyncMock()
            mock_scan_off.communicate = AsyncMock(return_value=(b"Discovery stopped\n", b""))
            mock_scan_off.returncode = 0

            mock_devices = AsyncMock()
            mock_devices.communicate = AsyncMock(return_value=(b"", b""))
            mock_devices.returncode = 0

            mock_exec.side_effect = [mock_scan_on, mock_scan_off, mock_devices]

            manager = BluetoothManager()
            devices = await manager.scan(duration=1)

            assert devices == []

    @pytest.mark.asyncio
    async def test_bluetooth_manager_scan_handles_bluetoothctl_error(self):
        """scan() should return empty list when bluetoothctl fails."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"", b"Error: bluetooth not found"))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            devices = await manager.scan(duration=1)

            assert devices == []

    @pytest.mark.asyncio
    async def test_bluetooth_manager_scan_timeout(self):
        """scan() should handle subprocess timeout."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = asyncio.TimeoutError()

            manager = BluetoothManager()
            devices = await manager.scan(duration=1)

            assert devices == []

    @pytest.mark.asyncio
    async def test_bluetooth_manager_scan_bluetoothctl_not_found(self):
        """scan() should handle bluetoothctl not installed."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = FileNotFoundError()

            manager = BluetoothManager()
            devices = await manager.scan(duration=1)

            assert devices == []


class TestBluetoothManagerPair:
    """Tests for BluetoothManager.pair() method."""

    @pytest.mark.asyncio
    async def test_bluetooth_manager_pair_success(self):
        """pair() should return True on successful pairing."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"Pairing successful\n",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.pair("AA:BB:CC:DD:EE:FF")

            assert result is True
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0]
            assert "bluetoothctl" in call_args
            assert "pair" in call_args
            assert "AA:BB:CC:DD:EE:FF" in call_args

    @pytest.mark.asyncio
    async def test_bluetooth_manager_pair_failure(self):
        """pair() should return False on pairing failure."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Failed to pair: org.bluez.Error.AuthenticationFailed"
            ))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.pair("AA:BB:CC:DD:EE:FF")

            assert result is False

    @pytest.mark.asyncio
    async def test_bluetooth_manager_pair_already_paired(self):
        """pair() should return True if device is already paired."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"AlreadyExists\n",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.pair("AA:BB:CC:DD:EE:FF")

            assert result is True

    @pytest.mark.asyncio
    async def test_bluetooth_manager_pair_timeout(self):
        """pair() should return False on timeout."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = asyncio.TimeoutError()

            manager = BluetoothManager()
            result = await manager.pair("AA:BB:CC:DD:EE:FF")

            assert result is False


class TestBluetoothManagerConnect:
    """Tests for BluetoothManager.connect() method."""

    @pytest.mark.asyncio
    async def test_bluetooth_manager_connect_success(self):
        """connect() should return True on successful connection."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"Connection successful\n",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.connect("AA:BB:CC:DD:EE:FF")

            assert result is True
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0]
            assert "bluetoothctl" in call_args
            assert "connect" in call_args
            assert "AA:BB:CC:DD:EE:FF" in call_args

    @pytest.mark.asyncio
    async def test_bluetooth_manager_connect_failure(self):
        """connect() should return False on connection failure."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Failed to connect: org.bluez.Error.Failed"
            ))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.connect("AA:BB:CC:DD:EE:FF")

            assert result is False

    @pytest.mark.asyncio
    async def test_bluetooth_manager_connect_already_connected(self):
        """connect() should return True if device is already connected."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"Already connected\n",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.connect("AA:BB:CC:DD:EE:FF")

            assert result is True

    @pytest.mark.asyncio
    async def test_bluetooth_manager_connect_timeout(self):
        """connect() should return False on timeout."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = asyncio.TimeoutError()

            manager = BluetoothManager()
            result = await manager.connect("AA:BB:CC:DD:EE:FF")

            assert result is False


class TestBluetoothManagerDisconnect:
    """Tests for BluetoothManager.disconnect() method."""

    @pytest.mark.asyncio
    async def test_bluetooth_manager_disconnect_success(self):
        """disconnect() should return True on successful disconnection."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"Successful disconnected\n",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.disconnect("AA:BB:CC:DD:EE:FF")

            assert result is True

    @pytest.mark.asyncio
    async def test_bluetooth_manager_disconnect_no_address(self):
        """disconnect() should disconnect all when no address provided."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"Successful disconnected\n",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.disconnect()

            assert result is True
            call_args = mock_exec.call_args[0]
            assert "disconnect" in call_args

    @pytest.mark.asyncio
    async def test_bluetooth_manager_disconnect_not_connected(self):
        """disconnect() should return True even when not connected."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Not connected"
            ))
            # bluetoothctl may still return 0 for this
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.disconnect("AA:BB:CC:DD:EE:FF")

            assert result is True

    @pytest.mark.asyncio
    async def test_bluetooth_manager_disconnect_failure(self):
        """disconnect() should return False on failure."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"org.bluez.Error.Failed"
            ))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.disconnect("AA:BB:CC:DD:EE:FF")

            assert result is False


class TestBluetoothManagerListDevices:
    """Tests for BluetoothManager.list_devices() method."""

    @pytest.mark.asyncio
    async def test_bluetooth_manager_list_devices_returns_paired(self):
        """list_devices() should return list of paired devices."""
        # bluetoothctl devices Paired output
        devices_output = b"Device AA:BB:CC:DD:EE:FF MyHeadphones\nDevice 11:22:33:44:55:66 Speaker\n"

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(devices_output, b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            devices = await manager.list_devices()

            assert len(devices) == 2
            assert devices[0].address == "AA:BB:CC:DD:EE:FF"
            assert devices[0].name == "MyHeadphones"
            assert devices[0].paired is True
            assert devices[1].address == "11:22:33:44:55:66"
            assert devices[1].name == "Speaker"
            assert devices[1].paired is True

    @pytest.mark.asyncio
    async def test_bluetooth_manager_list_devices_empty(self):
        """list_devices() should return empty list when no devices paired."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            devices = await manager.list_devices()

            assert devices == []

    @pytest.mark.asyncio
    async def test_bluetooth_manager_list_devices_error(self):
        """list_devices() should return empty list on error."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"", b"Error"))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            devices = await manager.list_devices()

            assert devices == []


class TestBluetoothManagerStatus:
    """Tests for BluetoothManager.status() method."""

    @pytest.mark.asyncio
    async def test_bluetooth_manager_status_enabled(self):
        """status() should return adapter status when powered on."""
        # bluetoothctl show output
        show_output = b"""Controller AA:BB:CC:DD:EE:FF (public)
	Name: raspberrypi
	Alias: raspberrypi
	Class: 0x00000000
	Powered: yes
	Discoverable: no
	Pairable: yes
	UUID: Generic Attribute Profile (00001801-0000-1000-8000-00805f9b34fb)
	Modalias: usb:v1D6Bp0246d0542
	Discovering: no
"""

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(show_output, b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            status = await manager.status()

            assert status.powered is True
            assert status.discovering is False
            assert status.pairable is True
            assert status.adapter_name == "raspberrypi"

    @pytest.mark.asyncio
    async def test_bluetooth_manager_status_disabled(self):
        """status() should return adapter status when powered off."""
        show_output = b"""Controller AA:BB:CC:DD:EE:FF (public)
	Name: raspberrypi
	Alias: raspberrypi
	Powered: no
	Pairable: no
	Discovering: no
"""

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(show_output, b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            status = await manager.status()

            assert status.powered is False
            assert status.discovering is False
            assert status.pairable is False

    @pytest.mark.asyncio
    async def test_bluetooth_manager_status_error(self):
        """status() should return disabled status on error."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"", b"Error: No adapter"))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            status = await manager.status()

            assert status.powered is False
            assert status.discovering is False
            assert status.pairable is False


class TestBluetoothManagerEnableDisable:
    """Tests for BluetoothManager.enable() and disable() methods."""

    @pytest.mark.asyncio
    async def test_bluetooth_manager_enable_success(self):
        """enable() should return True on successful power on."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"Changing power on succeeded\n",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.enable()

            assert result is True
            call_args = mock_exec.call_args[0]
            assert "bluetoothctl" in call_args
            assert "power" in call_args
            assert "on" in call_args

    @pytest.mark.asyncio
    async def test_bluetooth_manager_enable_failure(self):
        """enable() should return False on failure."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Failed to set power on"
            ))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.enable()

            assert result is False

    @pytest.mark.asyncio
    async def test_bluetooth_manager_disable_success(self):
        """disable() should return True on successful power off."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"Changing power off succeeded\n",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.disable()

            assert result is True
            call_args = mock_exec.call_args[0]
            assert "bluetoothctl" in call_args
            assert "power" in call_args
            assert "off" in call_args

    @pytest.mark.asyncio
    async def test_bluetooth_manager_disable_failure(self):
        """disable() should return False on failure."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Failed to set power off"
            ))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.disable()

            assert result is False


class TestBluetoothManagerForget:
    """Tests for BluetoothManager.forget() method."""

    @pytest.mark.asyncio
    async def test_bluetooth_manager_forget_success(self):
        """forget() should return True on successful device removal."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"Device has been removed\n",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.forget("AA:BB:CC:DD:EE:FF")

            assert result is True
            call_args = mock_exec.call_args[0]
            assert "bluetoothctl" in call_args
            assert "remove" in call_args
            assert "AA:BB:CC:DD:EE:FF" in call_args

    @pytest.mark.asyncio
    async def test_bluetooth_manager_forget_not_found(self):
        """forget() should return False when device not found."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Device AA:BB:CC:DD:EE:FF not available"
            ))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.forget("AA:BB:CC:DD:EE:FF")

            assert result is False

    @pytest.mark.asyncio
    async def test_bluetooth_manager_forget_failure(self):
        """forget() should return False on failure."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"org.bluez.Error.Failed"
            ))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            result = await manager.forget("AA:BB:CC:DD:EE:FF")

            assert result is False


class TestBluetoothManagerConfig:
    """Tests for BluetoothManager configuration."""

    def test_bluetooth_manager_default_timeout(self):
        """BluetoothManager should have 10 second default timeout."""
        manager = BluetoothManager()
        assert manager.timeout == 10

    def test_bluetooth_manager_custom_timeout(self):
        """BluetoothManager should support custom timeout."""
        manager = BluetoothManager(timeout=30)
        assert manager.timeout == 30


class TestBluetoothManagerEdgeCases:
    """Edge case tests for BluetoothManager."""

    @pytest.mark.asyncio
    async def test_scan_handles_malformed_device_line(self):
        """scan() should skip malformed device lines."""
        # Mix of valid and invalid lines
        devices_output = b"Device AA:BB:CC:DD:EE:FF ValidDevice\nInvalid line without device\nDevice 11:22:33:44:55:66 Another Device\n"

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_scan_on = AsyncMock()
            mock_scan_on.communicate = AsyncMock(return_value=(b"Discovery started\n", b""))
            mock_scan_on.returncode = 0

            mock_scan_off = AsyncMock()
            mock_scan_off.communicate = AsyncMock(return_value=(b"Discovery stopped\n", b""))
            mock_scan_off.returncode = 0

            mock_devices = AsyncMock()
            mock_devices.communicate = AsyncMock(return_value=(devices_output, b""))
            mock_devices.returncode = 0

            mock_exec.side_effect = [mock_scan_on, mock_scan_off, mock_devices]

            manager = BluetoothManager()
            devices = await manager.scan(duration=1)

            # Should only return the 2 valid devices
            assert len(devices) == 2
            assert devices[0].address == "AA:BB:CC:DD:EE:FF"
            assert devices[0].name == "ValidDevice"
            assert devices[1].address == "11:22:33:44:55:66"
            assert devices[1].name == "Another Device"

    @pytest.mark.asyncio
    async def test_scan_handles_device_with_spaces_in_name(self):
        """scan() should handle device names with spaces."""
        devices_output = b"Device AA:BB:CC:DD:EE:FF My Bluetooth Headphones Pro\n"

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_scan_on = AsyncMock()
            mock_scan_on.communicate = AsyncMock(return_value=(b"Discovery started\n", b""))
            mock_scan_on.returncode = 0

            mock_scan_off = AsyncMock()
            mock_scan_off.communicate = AsyncMock(return_value=(b"Discovery stopped\n", b""))
            mock_scan_off.returncode = 0

            mock_devices = AsyncMock()
            mock_devices.communicate = AsyncMock(return_value=(devices_output, b""))
            mock_devices.returncode = 0

            mock_exec.side_effect = [mock_scan_on, mock_scan_off, mock_devices]

            manager = BluetoothManager()
            devices = await manager.scan(duration=1)

            assert len(devices) == 1
            assert devices[0].address == "AA:BB:CC:DD:EE:FF"
            assert devices[0].name == "My Bluetooth Headphones Pro"

    @pytest.mark.asyncio
    async def test_list_devices_handles_empty_name(self):
        """list_devices() should handle devices with no name."""
        # Some devices may just show the MAC address
        devices_output = b"Device AA:BB:CC:DD:EE:FF \n"

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(devices_output, b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = BluetoothManager()
            devices = await manager.list_devices()

            assert len(devices) == 1
            assert devices[0].address == "AA:BB:CC:DD:EE:FF"
            # Name should be empty or the address
            assert devices[0].name == "" or devices[0].name == "AA:BB:CC:DD:EE:FF"
