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


# ─────────────────────────────────────────────────────────────────────────
# La politique LIVRÉE (#1322) — un module dont le panneau appelle l'API et
# dont nginx route vers son propre backend ne doit jamais être endormi.
# ─────────────────────────────────────────────────────────────────────────

def _politique_livree() -> dict:
    import tomllib
    from pathlib import Path
    p = Path(__file__).resolve().parent.parent / "policy" / "lifecycle-defaults.toml"
    with open(p, "rb") as fh:
        return tomllib.load(fh)


def test_la_politique_livree_est_lisible_et_bornee():
    """Une valeur hors vocabulaire ferait silencieusement retomber un module
    sur `always-on` (charger_politique ne valide pas) : le défaut serait sûr,
    mais l'intention écrite ici serait perdue sans que rien ne le dise."""
    d = _politique_livree()
    assert set(d["lifecycle"].values()) <= {"always-on", "eager", "on-demand", "manual"}
    assert set(d["wake_class"].values()) <= {"normal", "urgent"}


def test_les_modules_a_api_du_panneau_ne_dorment_pas():
    """CE QUI A ÉTÉ SUBI (#1322). `metablogizer` était `on-demand` : le sleeper
    l'arrêtait ET le désactivait, le waker ne réveille que sur les vhosts de
    sites — le panneau rendait 502 sur /api/v1/metablogizer/ sans que rien ne
    puisse le relever, et le `POST /webhook` des déploiements tombait avec.

    Critère : route nginx vers son propre backend (pas `aggregator.sock`) +
    API appelée par une page de /usr/share/secubox/www."""
    lc = _politique_livree()["lifecycle"]
    for mod in ("metablogizer", "podcaster"):
        assert lc.get(mod) == "always-on", f"{mod} doit rester always-on"
