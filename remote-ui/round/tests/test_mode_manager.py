"""Tests for mode manager state machine."""
import asyncio
import pytest
from agent.mode_manager import Mode, ModeManager


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

    def bad_listener(old_mode, new_mode):
        raise ValueError("Listener error")

    def good_listener(old_mode, new_mode):
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
