# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

"""
OPAD invariant tests — verify the structural proof that this sensor never
captures third-party subscriber identifiers.

These tests are the auditable proof — they read the *shape* of the
dataclasses + the *contents* of the AT allowlist, not runtime behaviour.

Per spec §6.1 / §6.2 / §6.3.
"""

from dataclasses import fields
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from rbs_sensor.observer import (
    CAPTURES_SUBSCRIBER_IDENTIFIERS,
    CellObservation,
    NeighbourObservation,
)
from rbs_sensor.ep06 import AT_ALLOWLIST, AT_FORBIDDEN

# Anything in this set is grounds for failing the test. Names cover the
# common spellings of subscriber-bound identifiers used in cellular ASN.1
# and AT command vocab.
SUBSCRIBER_ID_TOKENS = (
    "imsi", "tmsi", "imei", "msisdn", "iccid", "esn", "meid",
    "subscriber", "phone_number", "msrn", "guti",
)


def test_capture_flag_is_false():
    """Module-level constant exposed via /api/v1/rbs-sensor/status."""
    assert CAPTURES_SUBSCRIBER_IDENTIFIERS is False


def _check_dataclass(cls) -> None:
    for f in fields(cls):
        lower = f.name.lower()
        for tok in SUBSCRIBER_ID_TOKENS:
            assert tok not in lower, (
                f"{cls.__name__}.{f.name} looks like a subscriber identifier "
                f"(matched token '{tok}') — violates OPAD invariant"
            )


def test_cell_observation_has_no_subscriber_fields():
    _check_dataclass(CellObservation)


def test_neighbour_observation_has_no_subscriber_fields():
    _check_dataclass(NeighbourObservation)


def test_at_allowlist_does_not_intersect_forbidden():
    """No allowed command can be a forbidden one (defence in depth)."""
    assert AT_ALLOWLIST.isdisjoint(AT_FORBIDDEN)


def test_at_forbidden_covers_subscriber_id_commands():
    """The forbidden set must include the AT commands that would leak
    subscriber identifiers if invoked."""
    must_be_forbidden = {"AT+CIMI", "AT+CMGL", "AT+CPBR"}
    assert must_be_forbidden.issubset(AT_FORBIDDEN), (
        f"missing forbidden AT commands: "
        f"{must_be_forbidden - AT_FORBIDDEN}"
    )


def test_at_allowlist_has_no_sms_or_phonebook():
    """No AT command in the allowlist should read SMS or phonebook."""
    for cmd in AT_ALLOWLIST:
        lo = cmd.lower()
        for forbidden_token in ("cmg", "cpb", "cscb", "cnmi"):
            assert forbidden_token not in lo, (
                f"AT_ALLOWLIST contains '{cmd}' which looks SMS/phonebook-related"
            )
