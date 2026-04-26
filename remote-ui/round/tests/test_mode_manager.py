"""Tests for mode manager state machine."""
import asyncio
import pytest
from unittest.mock import patch
from agent.mode_manager import Mode, ModeManager, FLAG_FILE_FLASH, FLAG_FILE_GATEWAY


def test_mode_enum_values():
    """Mode enum should have 4 modes."""
    assert Mode.DASHBOARD.value == "dashboard"
    assert Mode.LOCAL.value == "local"
    assert Mode.FLASH.value == "flash"
    assert Mode.GATEWAY.value == "gateway"


def test_mode_manager_init():
    """ModeManager should start in LOCAL mode by default."""
    mm = ModeManager()
    assert mm.current_mode == Mode.LOCAL
    assert mm.previous_mode is None


def test_mode_manager_init_with_mode():
    """ModeManager can be initialized with specific mode."""
    mm = ModeManager(initial_mode=Mode.DASHBOARD)
    assert mm.current_mode == Mode.DASHBOARD


@pytest.mark.asyncio
async def test_mode_manager_set_mode():
    """ModeManager should transition between modes."""
    mm = ModeManager()
    assert mm.current_mode == Mode.LOCAL

    # Transition to DASHBOARD
    changed = await mm.set_mode(Mode.DASHBOARD)
    assert changed is True
    assert mm.current_mode == Mode.DASHBOARD
    assert mm.previous_mode == Mode.LOCAL

    # Transition to FLASH
    changed = await mm.set_mode(Mode.FLASH)
    assert changed is True
    assert mm.current_mode == Mode.FLASH
    assert mm.previous_mode == Mode.DASHBOARD


@pytest.mark.asyncio
async def test_mode_manager_set_mode_no_change():
    """ModeManager should return False when setting same mode."""
    mm = ModeManager(initial_mode=Mode.LOCAL)
    changed = await mm.set_mode(Mode.LOCAL)
    assert changed is False
    assert mm.current_mode == Mode.LOCAL


@pytest.mark.asyncio
async def test_mode_manager_listener():
    """ModeManager should notify listeners on mode change."""
    mm = ModeManager()
    transitions = []

    def listener(old_mode, new_mode):
        transitions.append((old_mode, new_mode))

    mm.add_listener(listener)
    await mm.set_mode(Mode.DASHBOARD)
    await mm.set_mode(Mode.FLASH)

    assert len(transitions) == 2
    assert transitions[0] == (Mode.LOCAL, Mode.DASHBOARD)
    assert transitions[1] == (Mode.DASHBOARD, Mode.FLASH)


@pytest.mark.asyncio
async def test_mode_manager_remove_listener():
    """ModeManager should remove listeners."""
    mm = ModeManager()
    transitions = []

    def listener(old_mode, new_mode):
        transitions.append((old_mode, new_mode))

    mm.add_listener(listener)
    mm.remove_listener(listener)
    await mm.set_mode(Mode.DASHBOARD)

    assert len(transitions) == 0


@pytest.mark.asyncio
async def test_mode_manager_listener_error_handling():
    """ModeManager should handle listener errors gracefully."""
    mm = ModeManager()

    def bad_listener(_old_mode, _new_mode):
        raise ValueError("Listener error")

    def good_listener(_old_mode, _new_mode):
        good_listener.called = True

    good_listener.called = False

    mm.add_listener(bad_listener)
    mm.add_listener(good_listener)

    # Should not raise even though bad_listener fails
    await mm.set_mode(Mode.DASHBOARD)

    assert mm.current_mode == Mode.DASHBOARD
    assert good_listener.called is True


def test_check_flag_files_no_flags():
    """ModeManager should return None when no flag files exist."""
    mm = ModeManager()
    result = mm.check_flag_files()
    assert result is None


def test_check_flag_files_force_flash():
    """ModeManager should return FLASH mode when FORCE_FLASH file exists."""
    mm = ModeManager()
    with patch('agent.mode_manager.FLAG_FILE_FLASH') as mock_flash:
        mock_flash.exists.return_value = True
        result = mm.check_flag_files()
        assert result == Mode.FLASH


def test_check_flag_files_force_gateway():
    """ModeManager should return GATEWAY mode when FORCE_GATEWAY file exists."""
    mm = ModeManager()
    with patch('agent.mode_manager.FLAG_FILE_FLASH') as mock_flash:
        mock_flash.exists.return_value = False
        with patch('agent.mode_manager.FLAG_FILE_GATEWAY') as mock_gateway:
            mock_gateway.exists.return_value = True
            result = mm.check_flag_files()
            assert result == Mode.GATEWAY


def test_check_flag_files_flash_priority_over_gateway():
    """ModeManager should prioritize FORCE_FLASH over FORCE_GATEWAY."""
    mm = ModeManager()
    with patch('agent.mode_manager.FLAG_FILE_FLASH') as mock_flash:
        with patch('agent.mode_manager.FLAG_FILE_GATEWAY') as mock_gateway:
            # Both files "exist", but FLASH is checked first
            mock_flash.exists.return_value = True
            mock_gateway.exists.return_value = True
            result = mm.check_flag_files()
            assert result == Mode.FLASH


@pytest.mark.asyncio
async def test_determine_initial_mode_api_available():
    """ModeManager should transition to DASHBOARD when API is available."""
    mm = ModeManager()
    mode = await mm.determine_initial_mode(api_available=True)

    assert mode == Mode.DASHBOARD
    assert mm.current_mode == Mode.DASHBOARD


@pytest.mark.asyncio
async def test_determine_initial_mode_api_unavailable():
    """ModeManager should transition to LOCAL when API is unavailable."""
    mm = ModeManager()
    mode = await mm.determine_initial_mode(api_available=False)

    assert mode == Mode.LOCAL
    assert mm.current_mode == Mode.LOCAL


@pytest.mark.asyncio
async def test_determine_initial_mode_with_flash_flag():
    """Flag file should override API availability."""
    mm = ModeManager()
    with patch('agent.mode_manager.FLAG_FILE_FLASH') as mock_flash:
        mock_flash.exists.return_value = True
        mode = await mm.determine_initial_mode(api_available=True)

        assert mode == Mode.FLASH
        assert mm.current_mode == Mode.FLASH


@pytest.mark.asyncio
async def test_determine_initial_mode_with_gateway_flag():
    """Flag file should override API unavailability."""
    mm = ModeManager()
    with patch('agent.mode_manager.FLAG_FILE_FLASH') as mock_flash:
        mock_flash.exists.return_value = False
        with patch('agent.mode_manager.FLAG_FILE_GATEWAY') as mock_gateway:
            mock_gateway.exists.return_value = True
            mode = await mm.determine_initial_mode(api_available=False)

            assert mode == Mode.GATEWAY
            assert mm.current_mode == Mode.GATEWAY


@pytest.mark.asyncio
async def test_mode_manager_concurrent_transitions():
    """ModeManager should handle concurrent mode transitions safely."""
    mm = ModeManager()

    # Try to change to multiple modes concurrently
    # Lock should ensure atomic transitions
    results = await asyncio.gather(
        mm.set_mode(Mode.DASHBOARD),
        mm.set_mode(Mode.FLASH),
        mm.set_mode(Mode.GATEWAY),
    )

    # At least one should succeed, others should fail or queue
    # Final mode should be one of the three
    assert mm.current_mode in [Mode.DASHBOARD, Mode.FLASH, Mode.GATEWAY]


@pytest.mark.asyncio
async def test_set_mode_changes_mode():
    """set_mode should change current mode."""
    mm = ModeManager(initial_mode=Mode.LOCAL)
    result = await mm.set_mode(Mode.DASHBOARD)
    assert result is True
    assert mm.current_mode == Mode.DASHBOARD
    assert mm.previous_mode == Mode.LOCAL


@pytest.mark.asyncio
async def test_set_mode_same_mode_returns_false():
    """set_mode with same mode should return False."""
    mm = ModeManager(initial_mode=Mode.LOCAL)
    result = await mm.set_mode(Mode.LOCAL)
    assert result is False
    assert mm.current_mode == Mode.LOCAL


@pytest.mark.asyncio
async def test_mode_listener_called():
    """Mode change should notify listeners."""
    mm = ModeManager(initial_mode=Mode.LOCAL)
    calls = []

    def listener(old_mode, new_mode):
        calls.append((old_mode, new_mode))

    mm.add_listener(listener)
    await mm.set_mode(Mode.DASHBOARD)

    assert len(calls) == 1
    assert calls[0] == (Mode.LOCAL, Mode.DASHBOARD)


@pytest.mark.asyncio
async def test_determine_initial_mode_with_api():
    """Should select DASHBOARD when API available."""
    mm = ModeManager()
    mode = await mm.determine_initial_mode(api_available=True)
    assert mode == Mode.DASHBOARD


@pytest.mark.asyncio
async def test_determine_initial_mode_without_api():
    """Should select LOCAL when API unavailable."""
    mm = ModeManager()
    mode = await mm.determine_initial_mode(api_available=False)
    assert mode == Mode.LOCAL
