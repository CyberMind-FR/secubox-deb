"""Tests for agent config module."""
import pytest
from pathlib import Path
import tempfile


def test_load_config_from_file():
    """Config should load from TOML file."""
    from agent.config import load_config

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-test-001"
name = "Test Eye"

[[secubox]]
name = "Lab"
host = "10.55.0.1"
token = "test-token"
active = true
''')
        f.flush()

        config = load_config(Path(f.name))

        assert config.device.id == "eye-test-001"
        assert config.device.name == "Test Eye"
        assert len(config.secuboxes) == 1
        assert config.secuboxes[0].name == "Lab"
        assert config.secuboxes[0].host == "10.55.0.1"
        assert config.secuboxes[0].active is True


def test_get_active_secubox():
    """Should return the active SecuBox config."""
    from agent.config import load_config, get_active_secubox

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[[secubox]]
name = "Primary"
host = "10.55.0.1"
token = "token1"
active = true

[[secubox]]
name = "Secondary"
host = "192.168.1.100"
token = "token2"
active = false
''')
        f.flush()

        config = load_config(Path(f.name))
        active = get_active_secubox(config)

        assert active.name == "Primary"
        assert active.host == "10.55.0.1"


def test_config_default_values():
    """Config should have sensible defaults."""
    from agent.config import load_config

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[[secubox]]
name = "Lab"
host = "10.55.0.1"
token = "token"
active = true
''')
        f.flush()

        config = load_config(Path(f.name))

        # Should have default fallback
        assert config.secuboxes[0].fallback is None
        assert config.secuboxes[0].poll_interval == 2.0


def test_set_active_secubox():
    """Should switch active SecuBox by name."""
    from agent.config import load_config, get_active_secubox, set_active_secubox

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[[secubox]]
name = "Primary"
host = "10.55.0.1"
token = "token1"
active = true

[[secubox]]
name = "Secondary"
host = "192.168.1.100"
token = "token2"
active = false
''')
        f.flush()

        config = load_config(Path(f.name))

        # Initial state
        assert get_active_secubox(config).name == "Primary"

        # Switch to Secondary
        result = set_active_secubox(config, "Secondary")
        assert result is True
        assert get_active_secubox(config).name == "Secondary"

        # Primary should now be inactive
        assert config.secuboxes[0].active is False
        assert config.secuboxes[1].active is True


def test_set_active_secubox_not_found():
    """Should return False when SecuBox name not found."""
    from agent.config import load_config, set_active_secubox

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[[secubox]]
name = "Primary"
host = "10.55.0.1"
token = "token1"
active = true
''')
        f.flush()

        config = load_config(Path(f.name))
        result = set_active_secubox(config, "NonExistent")
        assert result is False


def test_get_active_secubox_fallback_to_first():
    """Should return first SecuBox if none marked active."""
    from agent.config import load_config, get_active_secubox

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[[secubox]]
name = "First"
host = "10.55.0.1"
token = "token1"
active = false

[[secubox]]
name = "Second"
host = "192.168.1.100"
token = "token2"
active = false
''')
        f.flush()

        config = load_config(Path(f.name))
        active = get_active_secubox(config)

        # Should fallback to first
        assert active.name == "First"


def test_device_default_name():
    """Device should have default name if not specified."""
    from agent.config import load_config

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[[secubox]]
name = "Lab"
host = "10.55.0.1"
token = "token"
active = true
''')
        f.flush()

        config = load_config(Path(f.name))
        assert config.device.name == "Eye Remote"
