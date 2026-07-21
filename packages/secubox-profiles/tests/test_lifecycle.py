# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api.lifecycle import (boot_should_start, effective_lifecycle, idle_threshold,
                           is_sleepable, wake_budget, watchdog_should_manage)
from api.manifest import Manifest


def _m(lifecycle="eager", wake_class="normal", protected=False):
    return Manifest(id="x", category="infra", runtime="native", exposure="lan",
                    units=("x.service",), protected=protected,
                    lifecycle=lifecycle, wake_class=wake_class)


def test_protected_is_effectively_always_on():
    assert effective_lifecycle(_m(lifecycle="on-demand", protected=True)) == "always-on"


def test_effective_passthrough_when_not_protected():
    assert effective_lifecycle(_m(lifecycle="on-demand")) == "on-demand"


def test_is_sleepable_only_eager_and_on_demand():
    assert is_sleepable(_m(lifecycle="eager")) is True
    assert is_sleepable(_m(lifecycle="on-demand")) is True
    assert is_sleepable(_m(lifecycle="always-on")) is False
    assert is_sleepable(_m(lifecycle="manual")) is False
    assert is_sleepable(_m(lifecycle="on-demand", protected=True)) is False  # protected wins


def test_idle_threshold_urgent_is_longer():
    assert idle_threshold(_m(wake_class="normal"), base=900.0, urgent_mult=4.0) == 900.0
    assert idle_threshold(_m(wake_class="urgent"), base=900.0, urgent_mult=4.0) == 3600.0


def test_wake_budget_history_beats_default():
    assert wake_budget(_m(wake_class="normal"), history_median=None, normal=45.0) == 45.0
    assert wake_budget(_m(wake_class="urgent"), history_median=None, urgent=15.0) == 15.0
    assert wake_budget(_m(wake_class="normal"), history_median=30.0) == 30.0


def test_boot_should_start_always_on_and_eager():
    assert boot_should_start(_m(lifecycle="always-on")) is True
    assert boot_should_start(_m(lifecycle="eager")) is True


def test_boot_should_start_false_for_on_demand_and_manual():
    assert boot_should_start(_m(lifecycle="on-demand")) is False
    assert boot_should_start(_m(lifecycle="manual")) is False


def test_boot_should_start_protected_always_true_even_if_on_demand():
    # protected forces effective_lifecycle to always-on regardless of the
    # declared lifecycle — a negligent manifest must never keep the core off
    # at boot (same invariant as effective_lifecycle/is_sleepable).
    assert boot_should_start(_m(lifecycle="on-demand", protected=True)) is True


def test_watchdog_should_manage_true_for_always_on_and_manual():
    assert watchdog_should_manage(_m(lifecycle="always-on")) is True
    assert watchdog_should_manage(_m(lifecycle="manual")) is True


def test_watchdog_should_manage_false_for_sleepable():
    # eager/on-demand modules cycle up/down by design (scale-to-zero, #896) —
    # the watchdog must never force one back up just because it is stopped.
    assert watchdog_should_manage(_m(lifecycle="eager")) is False
    assert watchdog_should_manage(_m(lifecycle="on-demand")) is False


def test_watchdog_should_manage_protected_wins_over_on_demand():
    assert watchdog_should_manage(_m(lifecycle="on-demand", protected=True)) is True
