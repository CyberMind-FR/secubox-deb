# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit quarantine preparation (manual, alert-only)

Computes the PLAN for neutralizing a confirmed-malicious binary as data —
a dict of shell command strings the operator may choose to run separately.
`prepare()` NEVER executes anything: no os.system, no subprocess, no
os.chmod, no file writes, no kill. The only allowed side effect is calling
the injected `sha_fn`, which in production would hash the file and in
tests is a fake.
"""

import shlex


def prepare(
    path: str,
    c2_ip: str | None = None,
    unit: str | None = None,
    sha_fn=None,
) -> dict:
    """Return the planned quarantine steps for `path` as data (not executed).

    Keys:
      chmod        -- str, `chmod 000 <path>` (revoke all permissions)
      copy         -- str, `cp -a <path> /root/quarantine/` (evidence copy)
      sha256       -- str | None, hex digest via sha_fn(path) if provided, else None
      nft_block    -- str | None, nft rule dropping egress to c2_ip if given, else None
      disable_unit -- str | None, systemctl disable --now <unit> if given, else None
    """
    quoted_path = shlex.quote(path)

    return {
        "chmod": f"chmod 000 {quoted_path}",
        "copy": f"cp -a {quoted_path} /root/quarantine/",
        "sha256": sha_fn(path) if sha_fn is not None else None,
        "nft_block": (
            f"nft add rule inet filter output ip daddr {c2_ip} drop"
            if c2_ip is not None
            else None
        ),
        "disable_unit": (
            f"systemctl disable --now {unit}" if unit is not None else None
        ),
    }
