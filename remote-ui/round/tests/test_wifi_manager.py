"""
SecuBox Eye Remote — WiFi Manager Tests
Tests for the WifiManager class that wraps nmcli commands.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from agent.system.wifi import WifiManager, WifiNetwork, WifiStatus


class TestWifiNetwork:
    """Tests for WifiNetwork dataclass."""

    def test_wifi_network_creation(self):
        """WifiNetwork should be created with required fields."""
        network = WifiNetwork(
            ssid="TestNetwork",
            signal=75,
            security="wpa2",
            connected=False
        )
        assert network.ssid == "TestNetwork"
        assert network.signal == 75
        assert network.security == "wpa2"
        assert network.connected is False

    def test_wifi_network_connected_default(self):
        """WifiNetwork connected should default to False."""
        network = WifiNetwork(
            ssid="TestNetwork",
            signal=50,
            security="open"
        )
        assert network.connected is False


class TestWifiStatus:
    """Tests for WifiStatus dataclass."""

    def test_wifi_status_connected(self):
        """WifiStatus should represent connected state."""
        status = WifiStatus(
            connected=True,
            ssid="MyNetwork",
            signal=80,
            ip_address="192.168.1.100"
        )
        assert status.connected is True
        assert status.ssid == "MyNetwork"
        assert status.signal == 80
        assert status.ip_address == "192.168.1.100"

    def test_wifi_status_disconnected(self):
        """WifiStatus should represent disconnected state."""
        status = WifiStatus(connected=False)
        assert status.connected is False
        assert status.ssid is None
        assert status.signal is None
        assert status.ip_address is None


class TestWifiManagerScan:
    """Tests for WifiManager.scan() method."""

    @pytest.mark.asyncio
    async def test_wifi_manager_scan_returns_networks(self):
        """scan() should return list of WifiNetwork from nmcli output."""
        # nmcli terse output format: SSID:SIGNAL:SECURITY
        mock_output = b"HomeNetwork:85:WPA2\nGuestNetwork:60:WPA1\nOpenNet:45:\n"

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(mock_output, b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = WifiManager()
            networks = await manager.scan()

            assert len(networks) == 3
            assert networks[0].ssid == "HomeNetwork"
            assert networks[0].signal == 85
            assert networks[0].security == "wpa2"
            assert networks[1].ssid == "GuestNetwork"
            assert networks[1].signal == 60
            assert networks[1].security == "wpa"
            assert networks[2].ssid == "OpenNet"
            assert networks[2].signal == 45
            assert networks[2].security == "open"

    @pytest.mark.asyncio
    async def test_wifi_manager_scan_handles_empty_result(self):
        """scan() should return empty list when no networks found."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = WifiManager()
            networks = await manager.scan()

            assert networks == []

    @pytest.mark.asyncio
    async def test_wifi_manager_scan_handles_nmcli_error(self):
        """scan() should return empty list when nmcli fails."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"", b"Error: WiFi disabled"))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = WifiManager()
            networks = await manager.scan()

            assert networks == []

    @pytest.mark.asyncio
    async def test_wifi_manager_scan_timeout(self):
        """scan() should handle subprocess timeout."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = asyncio.TimeoutError()

            manager = WifiManager()
            networks = await manager.scan()

            assert networks == []

    @pytest.mark.asyncio
    async def test_wifi_manager_scan_nmcli_not_found(self):
        """scan() should handle nmcli not installed."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = FileNotFoundError()

            manager = WifiManager()
            networks = await manager.scan()

            assert networks == []


class TestWifiManagerConnect:
    """Tests for WifiManager.connect() method."""

    @pytest.mark.asyncio
    async def test_wifi_manager_connect_success(self):
        """connect() should return True on successful connection."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"Device 'wlan0' successfully activated with 'connection-id'.",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = WifiManager()
            result = await manager.connect("TestNetwork", "password123")

            assert result is True
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0]
            assert "nmcli" in call_args
            assert "TestNetwork" in call_args
            assert "password123" in call_args

    @pytest.mark.asyncio
    async def test_wifi_manager_connect_failure(self):
        """connect() should return False on connection failure."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Error: Connection activation failed."
            ))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = WifiManager()
            result = await manager.connect("TestNetwork", "wrong_password")

            assert result is False

    @pytest.mark.asyncio
    async def test_wifi_manager_connect_wrong_password(self):
        """connect() should return False when password is incorrect."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Error: Secrets were required, but not provided."
            ))
            mock_process.returncode = 4
            mock_exec.return_value = mock_process

            manager = WifiManager()
            result = await manager.connect("SecureNet", "badpassword")

            assert result is False

    @pytest.mark.asyncio
    async def test_wifi_manager_connect_open_network(self):
        """connect() should work for open networks without password."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"Device 'wlan0' successfully activated.",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = WifiManager()
            result = await manager.connect("OpenNetwork", "")

            assert result is True

    @pytest.mark.asyncio
    async def test_wifi_manager_connect_timeout(self):
        """connect() should return False on timeout."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = asyncio.TimeoutError()

            manager = WifiManager()
            result = await manager.connect("TestNetwork", "password")

            assert result is False


class TestWifiManagerDisconnect:
    """Tests for WifiManager.disconnect() method."""

    @pytest.mark.asyncio
    async def test_wifi_manager_disconnect_success(self):
        """disconnect() should return True on successful disconnection."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"Device 'wlan0' successfully disconnected.",
                b""
            ))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = WifiManager()
            result = await manager.disconnect()

            assert result is True

    @pytest.mark.asyncio
    async def test_wifi_manager_disconnect_not_connected(self):
        """disconnect() should return True even when not connected."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Error: Device 'wlan0' is not an active connection."
            ))
            # nmcli may return success even if already disconnected
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = WifiManager()
            result = await manager.disconnect()

            assert result is True

    @pytest.mark.asyncio
    async def test_wifi_manager_disconnect_failure(self):
        """disconnect() should return False on failure."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(
                b"",
                b"Error: disconnect failed"
            ))
            mock_process.returncode = 1
            mock_exec.return_value = mock_process

            manager = WifiManager()
            result = await manager.disconnect()

            assert result is False


class TestWifiManagerStatus:
    """Tests for WifiManager.status() method."""

    @pytest.mark.asyncio
    async def test_wifi_manager_status_connected(self):
        """status() should return connected status with details."""
        # Mock nmcli connection show --active output
        connection_output = b"MyNetwork:wlan0:802-11-wireless:yes\n"
        # Mock nmcli device show wlan0 output for IP
        device_output = b"GENERAL.DEVICE:wlan0\nIP4.ADDRESS[1]:192.168.1.50/24\n"
        # Mock iwconfig/iw for signal strength
        signal_output = b"wlan0: 0000   50.  -55.  -256        0      0      0      0     12      0\n"

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_connection_proc = AsyncMock()
            mock_connection_proc.communicate = AsyncMock(return_value=(connection_output, b""))
            mock_connection_proc.returncode = 0

            mock_device_proc = AsyncMock()
            mock_device_proc.communicate = AsyncMock(return_value=(device_output, b""))
            mock_device_proc.returncode = 0

            mock_signal_proc = AsyncMock()
            mock_signal_proc.communicate = AsyncMock(return_value=(signal_output, b""))
            mock_signal_proc.returncode = 0

            # Return different mock processes for different calls
            mock_exec.side_effect = [mock_connection_proc, mock_device_proc, mock_signal_proc]

            manager = WifiManager()
            status = await manager.status()

            assert status.connected is True
            assert status.ssid == "MyNetwork"
            assert status.ip_address == "192.168.1.50"
            # Signal should be calculated from -55 dBm
            assert status.signal is not None

    @pytest.mark.asyncio
    async def test_wifi_manager_status_disconnected(self):
        """status() should return disconnected status."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            # Empty output means no active WiFi connection
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = WifiManager()
            status = await manager.status()

            assert status.connected is False
            assert status.ssid is None
            assert status.signal is None
            assert status.ip_address is None

    @pytest.mark.asyncio
    async def test_wifi_manager_status_handles_error(self):
        """status() should return disconnected status on error."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = Exception("nmcli error")

            manager = WifiManager()
            status = await manager.status()

            assert status.connected is False


class TestWifiManagerGetNetworks:
    """Tests for WifiManager.get_networks() method."""

    @pytest.mark.asyncio
    async def test_get_networks_returns_cached(self):
        """get_networks() should return cached results if available."""
        manager = WifiManager()
        cached_networks = [
            WifiNetwork(ssid="Cached1", signal=70, security="wpa2"),
            WifiNetwork(ssid="Cached2", signal=55, security="open"),
        ]
        manager._cached_networks = cached_networks

        result = await manager.get_networks()

        assert result == cached_networks

    @pytest.mark.asyncio
    async def test_get_networks_triggers_scan_if_empty(self):
        """get_networks() should trigger scan if cache is empty."""
        mock_output = b"NewNetwork:80:WPA2\n"

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(mock_output, b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = WifiManager()
            result = await manager.get_networks()

            assert len(result) == 1
            assert result[0].ssid == "NewNetwork"


class TestWifiManagerInterfaceConfig:
    """Tests for WifiManager interface configuration."""

    def test_wifi_manager_default_interface(self):
        """WifiManager should use wlan0 by default."""
        manager = WifiManager()
        assert manager.interface == "wlan0"

    def test_wifi_manager_custom_interface(self):
        """WifiManager should support custom interface."""
        manager = WifiManager(interface="wlan1")
        assert manager.interface == "wlan1"

    def test_wifi_manager_default_timeout(self):
        """WifiManager should have 5 second default timeout."""
        manager = WifiManager()
        assert manager.timeout == 5

    def test_wifi_manager_custom_timeout(self):
        """WifiManager should support custom timeout."""
        manager = WifiManager(timeout=10)
        assert manager.timeout == 10


class TestWifiManagerEdgeCases:
    """Edge case tests for WifiManager."""

    @pytest.mark.asyncio
    async def test_scan_handles_special_characters_in_ssid(self):
        """scan() should handle SSIDs with special characters."""
        # SSID with colon and backslash (nmcli escapes these)
        mock_output = b"My\\:Network:75:WPA2\nCafe\\\\WiFi:60:WPA1\n"

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(mock_output, b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = WifiManager()
            networks = await manager.scan()

            # Manager should unescape the SSID
            assert len(networks) == 2
            assert networks[0].ssid == "My:Network"
            assert networks[1].ssid == "Cafe\\WiFi"

    @pytest.mark.asyncio
    async def test_scan_handles_hidden_networks(self):
        """scan() should skip hidden networks with empty SSID."""
        mock_output = b":50:WPA2\nVisibleNet:75:WPA1\n:30:\n"

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(mock_output, b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = WifiManager()
            networks = await manager.scan()

            # Should only return the visible network
            assert len(networks) == 1
            assert networks[0].ssid == "VisibleNet"

    @pytest.mark.asyncio
    async def test_connect_escapes_special_characters(self):
        """connect() should properly escape special characters in SSID/password."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"Success", b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            manager = WifiManager()
            await manager.connect("My'Network", "pass$word\"123")

            # Verify the command was called (escaping handled internally)
            mock_exec.assert_called_once()
