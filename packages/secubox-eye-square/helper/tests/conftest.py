# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import os
import sys
from pathlib import Path

_PKG = Path(__file__).resolve().parent.parent
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))
