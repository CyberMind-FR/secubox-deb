# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — presence alert mailer (Project B, #820, Task 6).

`send_alert(subject, body, *, to, ...)` builds a minimal RFC822 message
(`email.message.EmailMessage`) and feeds it to
`/usr/sbin/sendmail -t -oi` (`-t` = read recipients from the To/Cc/Bcc
headers, `-oi` = don't treat a lone "." as end-of-input) — the exact send
path `packages/secubox-smtp-relay/api/main.py`'s `test_email()` already
uses in production on this board.

Fail-safe: this module NEVER raises. A missing `sendmail` binary, a
non-zero return code, and a timeout all resolve to `False`. The subprocess
call is factored behind an injectable `runner` parameter (defaults to
`subprocess.run`) so tests can substitute a mock instead of shelling out
for real.

Pure stdlib (`email`, `subprocess`). No I/O at import time — only
`send_alert()` touches the filesystem/spawns a process.
"""
from __future__ import annotations

import subprocess
from email.message import EmailMessage

DEFAULT_SENDMAIL_BIN = "/usr/sbin/sendmail"
DEFAULT_FROM_ADDR = "secubox-guardian@localhost"
DEFAULT_TIMEOUT = 10


def send_alert(
    subject: str,
    body: str,
    *,
    to: str,
    sendmail_bin: str = DEFAULT_SENDMAIL_BIN,
    from_addr: str = DEFAULT_FROM_ADDR,
    timeout: int = DEFAULT_TIMEOUT,
    runner=subprocess.run,
) -> bool:
    """Send a plain-text alert email via `sendmail -t -oi`. Never raises.

    Returns `True` only when the subprocess exits with return code 0.
    Any exception (missing binary -> `FileNotFoundError`, a timeout ->
    `subprocess.TimeoutExpired`, a permission error, ...) is caught here
    and turned into a `False` return — an alert engine calling this must
    be able to treat a failed send as "just didn't email this time",
    never as a crash.

    `runner` is injectable so tests can pass a mock instead of actually
    invoking `subprocess.run` — it must accept the same positional/keyword
    shape as `subprocess.run` (a command list, `input=`, `timeout=`, ...)
    and return an object with a `.returncode` attribute.
    """
    if not to:
        return False

    try:
        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body or "")

        proc = runner(
            [sendmail_bin, "-t", "-oi"],
            input=msg.as_bytes(),
            capture_output=True,
            timeout=timeout,
        )
        return getattr(proc, "returncode", 1) == 0
    except Exception:
        # Fail-safe: missing binary, timeout, permission error, malformed
        # input, a raising mock runner in tests — all degrade to False.
        return False
