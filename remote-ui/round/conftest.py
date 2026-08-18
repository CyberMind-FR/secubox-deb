# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Pytest configuration for Eye Remote tests."""
import sys
from pathlib import Path

# Add the round directory to the path so 'agent' module can be imported
sys.path.insert(0, str(Path(__file__).parent))
