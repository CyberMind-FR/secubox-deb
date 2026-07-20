# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api.lifecycle import effective_lifecycle, is_sleepable, idle_threshold, wake_budget
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
