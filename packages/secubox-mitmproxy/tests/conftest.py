# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import os
import sys

ADDONS_DIR = os.path.join(os.path.dirname(__file__), "..", "addons")
sys.path.insert(0, os.path.abspath(ADDONS_DIR))
