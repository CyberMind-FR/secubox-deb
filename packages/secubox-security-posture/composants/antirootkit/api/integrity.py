# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit integrity-scanner wrappers

Thin wrappers around the proven tools `debsums` and `rkhunter`, plus an
authorized_keys drift check. All runners are injected for testing; every
wrapper degrades gracefully to an empty list/set when the underlying tool
is absent or produces no relevant output.
"""

import subprocess


def run_debsums(runner=subprocess.run) -> list[str]:
    """Run `debsums -c` and return the list of altered file paths.

    `debsums -c` exits non-zero when it finds altered files, so the
    returncode is ignored — stdout is parsed regardless. Degrades to []
    if the tool is absent (runner raises) or produces no output.
    """
    try:
        r = runner(["debsums", "-c"], capture_output=True, text=True, timeout=300)
    except Exception:
        return []
    if not r.stdout:
        return []
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]


def run_rkhunter(runner=subprocess.run) -> list[str]:
    """Run `rkhunter --check --sk --nocolors` and return warning lines.

    Degrades to [] if the tool is absent (runner raises) or reports no
    warnings.
    """
    try:
        r = runner(
            ["rkhunter", "--check", "--sk", "--nocolors"],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except Exception:
        return []
    if not r.stdout:
        return []
    return [line.strip() for line in r.stdout.splitlines() if "Warning:" in line]


def authkeys_drift(current: set, baseline: set) -> set:
    """Return keys present in `current` but absent from `baseline`.

    Newly-added SSH authorized_keys entries not in the signed baseline
    represent a persistence vector.
    """
    return current - baseline
