# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(ICI.parents[1] / "common"))
