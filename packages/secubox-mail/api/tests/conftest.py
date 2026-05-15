"""pytest conftest — make secubox_core importable when running locally
out of the source tree (no system-wide install)."""
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
COMMON = REPO_ROOT / "common"
if COMMON.is_dir() and str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
