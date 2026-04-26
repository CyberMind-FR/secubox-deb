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
        assert len(config.secuboxes.devices) == 1
        assert config.secuboxes.devices[0].name == "Lab"
        assert config.secuboxes.devices[0].host == "10.55.0.1"
        assert config.secuboxes.devices[0].active is True


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
        assert config.secuboxes.devices[0].fallback is None
        assert config.secuboxes.devices[0].poll_interval == 2.0


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
        assert config.secuboxes.devices[0].active is False
        assert config.secuboxes.devices[1].active is True


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


def test_display_config_defaults():
    """DisplayConfig should have default values."""
    from agent.config import DisplayConfig

    dc = DisplayConfig()
    assert dc.brightness == 80
    assert dc.timeout_seconds == 300
    assert dc.theme == "neon"


def test_mode_config_defaults():
    """ModeConfig should have default values."""
    from agent.config import ModeConfig

    mc = ModeConfig()
    assert mc.default == "auto"
    assert mc.auto_fallback_seconds == 60
    assert mc.reconnect_interval_seconds == 10


def test_web_config_defaults():
    """WebConfig should have default values."""
    from agent.config import WebConfig

    wc = WebConfig()
    assert wc.enabled is True
    assert wc.port == 8080
    assert wc.bind == "0.0.0.0"


def test_config_defaults():
    """Config should have all sections with defaults."""
    from agent.config import Config

    c = Config()
    assert c.device.id == "eye-remote-001"
    assert c.display.brightness == 80
    assert c.mode.default == "auto"
    assert c.web.enabled is True


def test_load_config_missing_file():
    """load_config should return defaults when file missing."""
    from agent.config import load_config

    c = load_config(Path("/nonexistent/path/config.toml"))
    assert c.device.id == "eye-remote-001"
    assert c.display.brightness == 80


def test_load_config_with_display_settings():
    """Config should load display settings from TOML."""
    from agent.config import load_config

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"
name = "Test Eye"

[display]
brightness = 60
timeout_seconds = 600
theme = "classic"

[[secubox]]
name = "Lab"
host = "10.55.0.1"
token = "token"
active = true
''')
        f.flush()

        config = load_config(Path(f.name))
        assert config.display.brightness == 60
        assert config.display.timeout_seconds == 600
        assert config.display.theme == "classic"


def test_load_config_with_mode_settings():
    """Config should load mode settings from TOML."""
    from agent.config import load_config

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[mode]
default = "local"
auto_fallback_seconds = 30
reconnect_interval_seconds = 5

[[secubox]]
name = "Lab"
host = "10.55.0.1"
token = "token"
active = true
''')
        f.flush()

        config = load_config(Path(f.name))
        assert config.mode.default == "local"
        assert config.mode.auto_fallback_seconds == 30
        assert config.mode.reconnect_interval_seconds == 5


def test_load_config_with_web_settings():
    """Config should load web settings from TOML."""
    from agent.config import load_config

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[web]
enabled = true
port = 9000
bind = "127.0.0.1"

[[secubox]]
name = "Lab"
host = "10.55.0.1"
token = "token"
active = true
''')
        f.flush()

        config = load_config(Path(f.name))
        assert config.web.enabled is True
        assert config.web.port == 9000
        assert config.web.bind == "127.0.0.1"


def test_load_config_with_secuboxes_devices():
    """Config should load secuboxes.devices array from TOML."""
    from agent.config import load_config

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[secuboxes]
primary = "secubox-main"

[[secuboxes.devices]]
id = "secubox-main"
name = "SecuBox Main"
host = "10.55.0.1"
port = 8000
transport = "otg"
active = true

[[secuboxes.devices]]
id = "secubox-backup"
name = "SecuBox Backup"
host = "192.168.1.100"
port = 8000
transport = "wifi"
active = false
''')
        f.flush()

        config = load_config(Path(f.name))
        assert len(config.secuboxes.devices) == 2
        assert config.secuboxes.primary == "secubox-main"
        assert config.secuboxes.devices[0].id == "secubox-main"
        assert config.secuboxes.devices[0].transport == "otg"
        assert config.secuboxes.devices[1].transport == "wifi"


def test_get_active_secubox_with_fleet():
    """Should return the active SecuBox from fleet config."""
    from agent.config import load_config, get_active_secubox

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[secuboxes]
primary = "secubox-main"

[[secuboxes.devices]]
id = "secubox-main"
name = "Main"
host = "10.55.0.1"
port = 8000
active = true

[[secuboxes.devices]]
id = "secubox-backup"
name = "Backup"
host = "192.168.1.100"
port = 8000
active = false
''')
        f.flush()

        config = load_config(Path(f.name))
        active = get_active_secubox(config)
        assert active.id == "secubox-main"
        assert active.name == "Main"


def test_backward_compat_secubox_array():
    """Config should support old [[secubox]] array format."""
    from agent.config import load_config

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[[secubox]]
name = "Lab"
host = "10.55.0.1"
token = "token1"
active = true

[[secubox]]
name = "Prod"
host = "10.55.0.2"
token = "token2"
active = false
''')
        f.flush()

        config = load_config(Path(f.name))
        assert len(config.secuboxes.devices) == 2
        assert config.secuboxes.devices[0].name == "Lab"
        assert config.secuboxes.devices[1].name == "Prod"
