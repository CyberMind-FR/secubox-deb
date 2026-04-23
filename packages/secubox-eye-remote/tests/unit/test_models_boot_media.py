"""
Tests for boot media Pydantic models.
"""
import pytest
from datetime import datetime, timezone

from models.boot_media import BootSlot, BootImage, BootMediaState


class TestBootSlot:
    def test_enum_values(self):
        assert BootSlot.ACTIVE == "active"
        assert BootSlot.SHADOW == "shadow"


class TestBootImage:
    def test_create_valid(self):
        img = BootImage(
            path="images/abc123.img",
            sha256="abc123def456",
            size_bytes=16777216,
            created_at=datetime.now(timezone.utc),
            label="test-image",
        )
        assert img.path == "images/abc123.img"
        assert img.size_bytes == 16777216

    def test_label_optional(self):
        img = BootImage(
            path="images/abc.img",
            sha256="abc",
            size_bytes=1000,
            created_at=datetime.now(timezone.utc),
        )
        assert img.label is None


class TestBootMediaState:
    def test_empty_state(self):
        state = BootMediaState(
            active=None,
            shadow=None,
            lun_attached=False,
            last_swap_at=None,
            tftp_armed=False,
        )
        assert state.active is None
        assert not state.lun_attached

    def test_with_active_image(self):
        img = BootImage(
            path="images/x.img",
            sha256="x",
            size_bytes=1000,
            created_at=datetime.now(timezone.utc),
        )
        state = BootMediaState(
            active=img,
            shadow=None,
            lun_attached=True,
            last_swap_at=None,
            tftp_armed=False,
        )
        assert state.active is not None
        assert state.active.sha256 == "x"
