"""Pytest configuration for secubox-eye-remote tests."""
import sys
from pathlib import Path

# Add package root to Python path
pkg_root = Path(__file__).parent.parent
sys.path.insert(0, str(pkg_root))
