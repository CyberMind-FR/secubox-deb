"""Tests for failover monitoring."""
import pytest
import time
from agent.failover import FailoverState, FailoverMonitor


def test_failover_state_enum():
    """FailoverState should have correct states."""
    assert FailoverState.CONNECTED.value == "connected"
    assert FailoverState.STALE.value == "stale"
    assert FailoverState.DEGRADED.value == "degraded"
    assert FailoverState.DISCONNECTED.value == "disconnected"


def test_failover_monitor_init():
    """FailoverMonitor should start DISCONNECTED."""
    fm = FailoverMonitor()
    assert fm.state == FailoverState.DISCONNECTED
    assert fm.seconds_since_success == float('inf')


def test_record_success_changes_state():
    """record_success should transition to CONNECTED."""
    fm = FailoverMonitor()
    fm.record_success()
    assert fm.state == FailoverState.CONNECTED
    assert fm.seconds_since_success < 1.0


def test_update_state_progression():
    """State should progress through stages based on time."""
    fm = FailoverMonitor(
        stale_threshold=0,
        degraded_threshold=0.1,
        disconnect_threshold=0.2,
    )
    fm.record_success()
    assert fm.state == FailoverState.CONNECTED

    time.sleep(0.05)
    fm.update_state()
    assert fm.state == FailoverState.STALE

    time.sleep(0.1)
    fm.update_state()
    assert fm.state == FailoverState.DEGRADED

    time.sleep(0.15)
    fm.update_state()
    assert fm.state == FailoverState.DISCONNECTED


def test_failover_listener_called():
    """State change should notify listeners."""
    fm = FailoverMonitor()
    calls = []

    def listener(old_state, new_state):
        calls.append((old_state, new_state))

    fm.add_listener(listener)
    fm.record_success()
    assert len(calls) == 1
    assert calls[0] == (FailoverState.DISCONNECTED, FailoverState.CONNECTED)
