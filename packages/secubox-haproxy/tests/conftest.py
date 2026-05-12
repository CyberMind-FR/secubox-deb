"""Add the package's api/ directory and common/ to sys.path for tests."""
import sys
from pathlib import Path

# Add the secubox-haproxy package root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Add the common/ directory which contains secubox_core
repo_root = Path(__file__).resolve().parents[3]  # Go up from tests/ -> .. -> .. -> ..
sys.path.insert(0, str(repo_root / "common"))
