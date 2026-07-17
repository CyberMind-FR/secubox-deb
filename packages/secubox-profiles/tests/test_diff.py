# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest

from api.diff import Change, ProtectedViolation, plan_changes
from api.manifest import Manifest
from api.observe import Actual
from api.state import Profile


def mk(mid, priority=50, protected=False):
    return Manifest(id=mid, category="media", runtime="native", exposure="lan",
                    units=(f"secubox-{mid}.service",), priority=priority,
                    protected=protected)


def on():
    return Actual(enabled=True, active=True)


def off():
    return Actual(enabled=False, active=False)


def test_no_changes_when_already_converged():
    ms = {"lyrion": mk("lyrion")}
    prof = Profile(name="media", label="m", on=frozenset({"lyrion"}))
    assert plan_changes(ms, prof, {}, {"lyrion": on()}) == []


def test_start_what_profile_wants_and_stop_what_it_does_not():
    ms = {"lyrion": mk("lyrion"), "gitea": mk("gitea")}
    prof = Profile(name="media", label="m", on=frozenset({"lyrion"}))
    actual = {"lyrion": off(), "gitea": on()}
    changes = plan_changes(ms, prof, {}, actual)
    assert {(c.id, c.action) for c in changes} == {("lyrion", "start"), ("gitea", "stop")}


def test_all_stops_come_before_all_starts():
    # La box a ~2 Go libres : allumer avant d'éteindre ferait un pic fatal.
    ms = {"a": mk("a", priority=10), "b": mk("b", priority=90)}
    prof = Profile(name="p", label="p", on=frozenset({"a"}))
    changes = plan_changes(ms, prof, {}, {"a": off(), "b": on()})
    assert [c.action for c in changes] == ["stop", "start"]


def test_stops_ordered_by_ascending_priority():
    # Le moins prioritaire s'éteint en premier ; le plus prioritaire tient
    # le plus longtemps.
    ms = {"hi": mk("hi", priority=90), "lo": mk("lo", priority=10), "mid": mk("mid", priority=50)}
    prof = Profile(name="p", label="p", on=frozenset())
    actual = {k: on() for k in ms}
    changes = plan_changes(ms, prof, {}, actual)
    assert [c.id for c in changes] == ["lo", "mid", "hi"]


def test_starts_ordered_by_descending_priority():
    ms = {"hi": mk("hi", priority=90), "lo": mk("lo", priority=10), "mid": mk("mid", priority=50)}
    prof = Profile(name="p", label="p", on=frozenset({"hi", "lo", "mid"}))
    actual = {k: off() for k in ms}
    changes = plan_changes(ms, prof, {}, actual)
    assert [c.id for c in changes] == ["hi", "mid", "lo"]


def test_protected_module_never_stopped():
    # Refus, pas avertissement : sans ça un profil éteint l'auth et
    # l'utilisateur perd tout moyen de revenir.
    ms = {"auth": mk("auth", protected=True)}
    prof = Profile(name="p", label="p", on=frozenset())
    plan = plan_changes(ms, prof, {}, {"auth": on()})
    assert plan == []   # protected → désiré ON → déjà ON → aucun changement


def test_protected_module_off_is_started_not_refused():
    ms = {"auth": mk("auth", protected=True)}
    prof = Profile(name="p", label="p", on=frozenset())
    plan = plan_changes(ms, prof, {}, {"auth": off()})
    assert [(c.id, c.action) for c in plan] == [("auth", "start")]


def test_pin_off_on_protected_module_is_refused():
    ms = {"auth": mk("auth", protected=True)}
    prof = Profile(name="p", label="p", on=frozenset())
    with pytest.raises(ProtectedViolation):
        plan_changes(ms, prof, {"auth": "off"}, {"auth": on()})


def test_change_carries_reason():
    ms = {"gitea": mk("gitea")}
    prof = Profile(name="media", label="m", on=frozenset())
    c = plan_changes(ms, prof, {}, {"gitea": on()})[0]
    assert c.reason and isinstance(c.reason, str)


def test_module_without_observation_is_skipped():
    # Un manifeste sans observation (module absent de la board) ne doit pas
    # produire de changement fantôme.
    ms = {"ghost": mk("ghost")}
    prof = Profile(name="p", label="p", on=frozenset({"ghost"}))
    assert plan_changes(ms, prof, {}, {}) == []
