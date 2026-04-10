"""
SecuBox UI Manager - State Machine
===================================

Manages UI mode transitions with automatic fallback.

States:
    INIT       - Initial state, loading config
    DETECTING  - Detecting hypervisor and display
    SELECTING  - Choosing mode based on capabilities
    KUI_*      - Kiosk UI states
    TUI_*      - Terminal UI states
    CONSOLE_OK - Console mode (terminal state)
    FALLBACK   - Falling back to next mode
    ERROR      - Unrecoverable error

Transitions are logged and persisted to /run/secubox/ui/state.json
"""

import json
import time
from enum import Enum, auto
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable, Dict, List, Any

from .debug import get_logger

log = get_logger("state")


class UIState(Enum):
    """UI state machine states."""
    INIT = auto()
    DETECTING = auto()
    SELECTING = auto()
    KUI_STARTING = auto()
    KUI_OK = auto()
    KUI_FAILED = auto()
    TUI_STARTING = auto()
    TUI_OK = auto()
    TUI_FAILED = auto()
    CONSOLE_STARTING = auto()
    CONSOLE_OK = auto()
    FALLBACK = auto()
    ERROR = auto()


@dataclass
class StateData:
    """Data associated with current state."""
    state: UIState = UIState.INIT
    mode: str = ""
    timestamp: float = field(default_factory=time.time)
    attempts: int = 0
    last_error: str = ""
    hypervisor: str = ""
    graphics: str = ""
    fallback_chain: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "state": self.state.name,
            "mode": self.mode,
            "timestamp": self.timestamp,
            "attempts": self.attempts,
            "last_error": self.last_error,
            "hypervisor": self.hypervisor,
            "graphics": self.graphics,
            "fallback_chain": self.fallback_chain,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "StateData":
        """Create from dictionary."""
        return cls(
            state=UIState[data.get("state", "INIT")],
            mode=data.get("mode", ""),
            timestamp=data.get("timestamp", time.time()),
            attempts=data.get("attempts", 0),
            last_error=data.get("last_error", ""),
            hypervisor=data.get("hypervisor", ""),
            graphics=data.get("graphics", ""),
            fallback_chain=data.get("fallback_chain", []),
        )


# Valid state transitions
TRANSITIONS: Dict[UIState, List[UIState]] = {
    UIState.INIT: [UIState.DETECTING, UIState.ERROR],
    UIState.DETECTING: [UIState.SELECTING, UIState.ERROR],
    UIState.SELECTING: [
        UIState.KUI_STARTING,
        UIState.TUI_STARTING,
        UIState.CONSOLE_STARTING,
        UIState.ERROR,
    ],
    UIState.KUI_STARTING: [UIState.KUI_OK, UIState.KUI_FAILED],
    UIState.KUI_OK: [UIState.KUI_FAILED, UIState.FALLBACK],
    UIState.KUI_FAILED: [UIState.FALLBACK],
    UIState.TUI_STARTING: [UIState.TUI_OK, UIState.TUI_FAILED],
    UIState.TUI_OK: [UIState.TUI_FAILED, UIState.FALLBACK],
    UIState.TUI_FAILED: [UIState.FALLBACK],
    UIState.CONSOLE_STARTING: [UIState.CONSOLE_OK, UIState.ERROR],
    UIState.CONSOLE_OK: [],  # Terminal state
    UIState.FALLBACK: [
        UIState.KUI_STARTING,
        UIState.TUI_STARTING,
        UIState.CONSOLE_STARTING,
        UIState.ERROR,
    ],
    UIState.ERROR: [],  # Terminal state
}


class UIStateMachine:
    """
    State machine for UI mode management.

    Usage:
        sm = UIStateMachine()
        sm.transition(UIState.DETECTING)
        sm.transition(UIState.SELECTING, mode="kui")
        sm.transition(UIState.KUI_STARTING)
        if success:
            sm.transition(UIState.KUI_OK)
        else:
            sm.transition(UIState.KUI_FAILED, error="X11 failed")
            sm.transition(UIState.FALLBACK)
    """

    def __init__(self, state_file: Optional[Path] = None):
        self.state_file = state_file or Path("/run/secubox/ui/state.json")
        self.data = StateData()
        self._callbacks: Dict[UIState, List[Callable]] = {}

        # Try to load existing state
        self._load_state()

    def _load_state(self):
        """Load state from file if exists."""
        try:
            if self.state_file.exists():
                with open(self.state_file) as f:
                    data = json.load(f)
                    self.data = StateData.from_dict(data)
                    log.debug("Loaded state: %s", self.data.state.name)
        except (json.JSONDecodeError, IOError) as e:
            log.warn("Failed to load state: %s", e)

    def _save_state(self):
        """Save current state to file."""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, "w") as f:
                json.dump(self.data.to_dict(), f, indent=2)
        except IOError as e:
            log.warn("Failed to save state: %s", e)

    @property
    def state(self) -> UIState:
        """Get current state."""
        return self.data.state

    @property
    def mode(self) -> str:
        """Get current/selected mode."""
        return self.data.mode

    def can_transition(self, new_state: UIState) -> bool:
        """Check if transition is valid."""
        return new_state in TRANSITIONS.get(self.data.state, [])

    def transition(self, new_state: UIState, **kwargs) -> bool:
        """
        Transition to a new state.

        Args:
            new_state: Target state
            **kwargs: Additional data to store (mode, error, etc.)

        Returns:
            True if transition succeeded
        """
        if not self.can_transition(new_state):
            log.error(
                "Invalid transition: %s -> %s",
                self.data.state.name,
                new_state.name,
            )
            return False

        old_state = self.data.state
        self.data.state = new_state
        self.data.timestamp = time.time()

        # Update data from kwargs
        if "mode" in kwargs:
            self.data.mode = kwargs["mode"]
        if "error" in kwargs:
            self.data.last_error = kwargs["error"]
        if "hypervisor" in kwargs:
            self.data.hypervisor = kwargs["hypervisor"]
        if "graphics" in kwargs:
            self.data.graphics = kwargs["graphics"]
        if "fallback_chain" in kwargs:
            self.data.fallback_chain = kwargs["fallback_chain"]

        # Increment attempts on failures or fallback
        if new_state in (UIState.KUI_FAILED, UIState.TUI_FAILED, UIState.FALLBACK):
            self.data.attempts += 1

        log.info(
            "State: %s -> %s (mode=%s, attempts=%d)",
            old_state.name,
            new_state.name,
            self.data.mode,
            self.data.attempts,
        )

        # Save state
        self._save_state()

        # Call callbacks
        self._fire_callbacks(new_state)

        return True

    def on_state(self, state: UIState, callback: Callable[["UIStateMachine"], None]):
        """Register a callback for when a state is entered."""
        if state not in self._callbacks:
            self._callbacks[state] = []
        self._callbacks[state].append(callback)

    def _fire_callbacks(self, state: UIState):
        """Fire registered callbacks for a state."""
        for callback in self._callbacks.get(state, []):
            try:
                callback(self)
            except Exception as e:
                log.error("Callback error for %s: %s", state.name, e)

    def reset(self):
        """Reset state machine to initial state."""
        self.data = StateData()
        self._save_state()
        log.info("State machine reset")

    def is_terminal(self) -> bool:
        """Check if in a terminal state."""
        return self.data.state in (UIState.CONSOLE_OK, UIState.ERROR)

    def is_ok(self) -> bool:
        """Check if in a successful state."""
        return self.data.state in (
            UIState.KUI_OK,
            UIState.TUI_OK,
            UIState.CONSOLE_OK,
        )

    def get_active_mode(self) -> Optional[str]:
        """Get the currently active mode, if any."""
        if self.data.state == UIState.KUI_OK:
            return "kui"
        elif self.data.state == UIState.TUI_OK:
            return "tui"
        elif self.data.state == UIState.CONSOLE_OK:
            return "console"
        return None

    def status(self) -> dict:
        """Get status summary."""
        return {
            "state": self.data.state.name,
            "mode": self.data.mode,
            "active_mode": self.get_active_mode(),
            "is_ok": self.is_ok(),
            "attempts": self.data.attempts,
            "last_error": self.data.last_error,
            "uptime": time.time() - self.data.timestamp,
        }
