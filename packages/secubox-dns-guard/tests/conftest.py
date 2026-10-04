# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys
from pathlib import Path
from unittest import mock

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(ICI.parents[1] / "common"))

# `guard = DnsGuard(DATA_DIR)` est instancié à l'import et crée /var/lib/secubox/dns-guard : on neutralise mkdir le temps de l'import.
with mock.patch("pathlib.Path.mkdir"):
    import api.main  # noqa: E402,F401
