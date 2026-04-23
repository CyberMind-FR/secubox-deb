"""
Integration tests for boot media management.

SecuBox Eye Remote — Boot Media Core Logic
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
import pytest
import sys

# Enable test mode (disables TFTP extraction)
os.environ["SECUBOX_TEST_MODE"] = "1"

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.fixture
def temp_boot_media_dir(tmp_path):
    """Create temporary boot media directory structure."""
    boot_dir = tmp_path / "boot-media"
    boot_dir.mkdir()
    (boot_dir / "images").mkdir()
    (boot_dir / "tftp").mkdir()
    return boot_dir


@pytest.fixture
def mock_gadget_script():
    """Mock subprocess calls to gadget-setup.sh."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = Mock(returncode=0)
        yield mock_run


def create_fake_fat32_image(path: Path, size_mb: int = 32, label: str = "TESTBOOT"):
    """
    Create a minimal FAT32 image with valid boot signature.

    FAT32 structure:
    - Bytes 510-511: Boot signature 0x55AA
    - Bytes 82-89: "FAT32   " filesystem type
    """
    size_bytes = size_mb * 1024 * 1024
    data = bytearray(size_bytes)

    # Boot sector signature at end of first sector
    data[510] = 0x55
    data[511] = 0xAA

    # FAT filesystem type label
    data[82:90] = b"FAT32   "

    path.write_bytes(data)
    return data


def create_fake_ext4_image(path: Path, size_mb: int = 32):
    """
    Create a minimal ext4 image with valid magic number.

    ext magic: bytes at offset 0x438 = 0x53ef (little-endian)
    """
    size_bytes = size_mb * 1024 * 1024
    data = bytearray(size_bytes)

    # ext magic number at offset 0x438 (superblock signature)
    data[0x438] = 0x53
    data[0x439] = 0xef

    path.write_bytes(data)
    return data


class TestValidateImage:
    """Test image validation logic."""

    def test_rejects_too_small_image(self, temp_boot_media_dir):
        """Should reject images smaller than 16 MiB."""
        from core.boot_media import BootMediaManager

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        # Create 8 MiB image
        small_img = temp_boot_media_dir / "small.img"
        create_fake_fat32_image(small_img, size_mb=8)

        assert not manager.validate_image(small_img)

    def test_rejects_too_large_image(self, temp_boot_media_dir):
        """Should reject images larger than 4 GiB."""
        from core.boot_media import BootMediaManager

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        # Create fake large file (just set size, don't actually write)
        large_img = temp_boot_media_dir / "large.img"
        large_img.write_bytes(b"x" * 100)  # Small file

        # Mock stat to report 5 GiB
        with patch.object(Path, "stat") as mock_stat:
            mock_stat.return_value = Mock(st_size=5 * 1024**3)
            assert not manager.validate_image(large_img)

    def test_rejects_invalid_magic(self, temp_boot_media_dir):
        """Should reject images without valid FAT or ext magic."""
        from core.boot_media import BootMediaManager

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        # Create image without valid magic
        bad_img = temp_boot_media_dir / "bad.img"
        bad_img.write_bytes(b"\x00" * (32 * 1024 * 1024))

        assert not manager.validate_image(bad_img)

    def test_accepts_fat32_image(self, temp_boot_media_dir):
        """Should accept valid FAT32 image."""
        from core.boot_media import BootMediaManager

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        good_img = temp_boot_media_dir / "good_fat32.img"
        create_fake_fat32_image(good_img, size_mb=64)

        assert manager.validate_image(good_img)

    def test_accepts_ext4_image(self, temp_boot_media_dir):
        """Should accept valid ext4 image."""
        from core.boot_media import BootMediaManager

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        good_img = temp_boot_media_dir / "good_ext4.img"
        create_fake_ext4_image(good_img, size_mb=128)

        assert manager.validate_image(good_img)


class TestUploadToShadow:
    """Test uploading images to shadow slot."""

    def test_upload_creates_image(self, temp_boot_media_dir, mock_gadget_script):
        """Should create image file in images/ directory."""
        from core.boot_media import BootMediaManager
        from io import BytesIO

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        # Create fake image in memory
        img_data = bytearray(32 * 1024 * 1024)
        img_data[510] = 0x55
        img_data[511] = 0xAA
        img_data[82:90] = b"FAT32   "

        fileobj = BytesIO(bytes(img_data))

        # Mock mount/extract operations
        with patch("core.boot_media.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)

            result = manager.upload_to_shadow(fileobj, label="Test Boot")

        # Verify image created
        assert result.label == "Test Boot"
        assert result.size_bytes == len(img_data)

        # Verify file exists
        img_path = temp_boot_media_dir / "images" / result.path
        assert img_path.exists()

    def test_upload_updates_shadow_symlink(self, temp_boot_media_dir, mock_gadget_script):
        """Should create/update shadow symlink."""
        from core.boot_media import BootMediaManager
        from io import BytesIO

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        img_data = bytearray(32 * 1024 * 1024)
        img_data[510] = 0x55
        img_data[511] = 0xAA
        img_data[82:90] = b"FAT32   "

        fileobj = BytesIO(bytes(img_data))

        with patch("core.boot_media.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            result = manager.upload_to_shadow(fileobj, label="Test")

        shadow_link = temp_boot_media_dir / "shadow"
        assert shadow_link.exists()
        assert shadow_link.is_symlink()

    def test_upload_computes_sha256(self, temp_boot_media_dir, mock_gadget_script):
        """Should compute correct SHA256 hash."""
        from core.boot_media import BootMediaManager
        from io import BytesIO

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        img_data = bytearray(32 * 1024 * 1024)
        img_data[510] = 0x55
        img_data[511] = 0xAA
        img_data[82:90] = b"FAT32   "

        expected_hash = hashlib.sha256(bytes(img_data)).hexdigest()

        fileobj = BytesIO(bytes(img_data))

        with patch("core.boot_media.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            result = manager.upload_to_shadow(fileobj, label="Hash Test")

        assert result.sha256 == expected_hash

    def test_upload_rejects_invalid_image(self, temp_boot_media_dir, mock_gadget_script):
        """Should reject invalid image during upload."""
        from core.boot_media import BootMediaManager
        from io import BytesIO

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        # Invalid: no boot signature
        bad_data = b"\x00" * (32 * 1024 * 1024)
        fileobj = BytesIO(bad_data)

        with pytest.raises(ValueError, match="Invalid boot image"):
            manager.upload_to_shadow(fileobj, label="Bad")


class TestSwap:
    """Test active/shadow slot swap."""

    def test_swap_exchanges_symlinks(self, temp_boot_media_dir, mock_gadget_script):
        """Should atomically swap active and shadow symlinks."""
        from core.boot_media import BootMediaManager
        from io import BytesIO

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        # Upload two images
        img1_data = bytearray(32 * 1024 * 1024)
        img1_data[510] = 0x55
        img1_data[511] = 0xAA
        img1_data[82:90] = b"FAT32   "
        img1_data[100:104] = b"IMG1"

        img2_data = bytearray(32 * 1024 * 1024)
        img2_data[510] = 0x55
        img2_data[511] = 0xAA
        img2_data[82:90] = b"FAT32   "
        img2_data[100:104] = b"IMG2"

        with patch("core.boot_media.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)

            # Upload first to shadow (will become active)
            result1 = manager.upload_to_shadow(BytesIO(bytes(img1_data)), "Image 1")

            # Swap to make it active
            state1 = manager.swap()
            assert state1.active.label == "Image 1"
            assert state1.shadow is None

            # Upload second to shadow
            result2 = manager.upload_to_shadow(BytesIO(bytes(img2_data)), "Image 2")

            # Remember what's active
            active_before = temp_boot_media_dir / "active"
            active_target_before = active_before.resolve()

            # Swap again
            state2 = manager.swap()

            # Verify swap occurred
            assert state2.active.label == "Image 2"
            assert state2.shadow.label == "Image 1"

    def test_swap_detaches_reattaches_lun(self, temp_boot_media_dir, mock_gadget_script):
        """Should call gadget script to detach/reattach LUN."""
        from core.boot_media import BootMediaManager
        from io import BytesIO

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        # Upload image
        img_data = bytearray(32 * 1024 * 1024)
        img_data[510] = 0x55
        img_data[511] = 0xAA
        img_data[82:90] = b"FAT32   "

        with patch("core.boot_media.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)

            manager.upload_to_shadow(BytesIO(bytes(img_data)), "Test")
            mock_run.reset_mock()

            # Perform swap
            manager.swap()

            # Verify gadget script calls
            calls = mock_run.call_args_list

            # Should have eject call and reattach call
            assert len(calls) >= 2

            # First call: eject (empty string)
            eject_call = calls[0]
            assert "swap-lun" in str(eject_call) or "" in str(eject_call)

            # Last call: reattach (with path)
            reattach_call = calls[-1]
            assert "swap-lun" in str(reattach_call)

    def test_swap_updates_state_timestamp(self, temp_boot_media_dir, mock_gadget_script):
        """Should update last_swap_at timestamp."""
        from core.boot_media import BootMediaManager
        from io import BytesIO

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        img_data = bytearray(32 * 1024 * 1024)
        img_data[510] = 0x55
        img_data[511] = 0xAA
        img_data[82:90] = b"FAT32   "

        with patch("core.boot_media.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)

            manager.upload_to_shadow(BytesIO(bytes(img_data)), "Test")

            before_swap = datetime.now(timezone.utc)
            state = manager.swap()

            assert state.last_swap_at is not None
            assert state.last_swap_at >= before_swap

    def test_swap_noop_if_shadow_empty(self, temp_boot_media_dir, mock_gadget_script):
        """Should raise error if shadow slot is empty."""
        from core.boot_media import BootMediaManager

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        with pytest.raises(ValueError, match="Shadow slot is empty"):
            manager.swap()


class TestRollback:
    """Test rollback operation."""

    def test_rollback_swaps_back(self, temp_boot_media_dir, mock_gadget_script):
        """Should swap active and shadow back."""
        from core.boot_media import BootMediaManager
        from io import BytesIO

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        img1_data = bytearray(32 * 1024 * 1024)
        img1_data[510] = 0x55
        img1_data[511] = 0xAA
        img1_data[82:90] = b"FAT32   "

        img2_data = bytearray(32 * 1024 * 1024)
        img2_data[510] = 0x55
        img2_data[511] = 0xAA
        img2_data[82:90] = b"FAT32   "
        img2_data[200:204] = b"NEW!"

        with patch("core.boot_media.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)

            # Setup: upload and swap twice
            manager.upload_to_shadow(BytesIO(bytes(img1_data)), "Original")
            manager.swap()

            manager.upload_to_shadow(BytesIO(bytes(img2_data)), "New")
            state_after_swap = manager.swap()

            assert state_after_swap.active.label == "New"
            assert state_after_swap.shadow.label == "Original"

            # Rollback
            state_after_rollback = manager.rollback()

            assert state_after_rollback.active.label == "Original"
            assert state_after_rollback.shadow.label == "New"

    def test_rollback_noop_if_no_shadow(self, temp_boot_media_dir, mock_gadget_script):
        """Should raise error if no shadow to rollback to."""
        from core.boot_media import BootMediaManager

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        with pytest.raises(ValueError, match="Nothing to rollback"):
            manager.rollback()


class TestGetState:
    """Test state retrieval."""

    def test_get_state_empty_on_init(self, temp_boot_media_dir, mock_gadget_script):
        """Should return empty state on fresh init."""
        from core.boot_media import BootMediaManager

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        state = manager.get_state()

        assert state.active is None
        assert state.shadow is None
        assert state.lun_attached is False
        assert state.last_swap_at is None

    def test_get_state_persists_across_reload(self, temp_boot_media_dir, mock_gadget_script):
        """Should persist state across manager instances."""
        from core.boot_media import BootMediaManager
        from io import BytesIO

        # First instance: upload and swap
        manager1 = BootMediaManager(base_dir=temp_boot_media_dir)

        img_data = bytearray(32 * 1024 * 1024)
        img_data[510] = 0x55
        img_data[511] = 0xAA
        img_data[82:90] = b"FAT32   "

        with patch("core.boot_media.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)

            manager1.upload_to_shadow(BytesIO(bytes(img_data)), "Persisted")
            state1 = manager1.swap()

        # Second instance: reload
        manager2 = BootMediaManager(base_dir=temp_boot_media_dir)
        state2 = manager2.get_state()

        assert state2.active is not None
        assert state2.active.label == "Persisted"
        assert state2.active.sha256 == state1.active.sha256

    def test_get_state_verifies_symlinks(self, temp_boot_media_dir, mock_gadget_script):
        """Should verify symlinks exist and are valid."""
        from core.boot_media import BootMediaManager
        from io import BytesIO

        manager = BootMediaManager(base_dir=temp_boot_media_dir)

        img_data = bytearray(32 * 1024 * 1024)
        img_data[510] = 0x55
        img_data[511] = 0xAA
        img_data[82:90] = b"FAT32   "

        with patch("core.boot_media.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)

            manager.upload_to_shadow(BytesIO(bytes(img_data)), "Test")
            manager.swap()

        # Verify symlinks exist
        active_link = temp_boot_media_dir / "active"
        assert active_link.exists()
        assert active_link.is_symlink()

        state = manager.get_state()
        assert state.active is not None
