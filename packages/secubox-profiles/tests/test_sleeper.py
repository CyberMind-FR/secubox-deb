from api.sleeper import should_sleep
from api.front_signals import Signal
from api.manifest import Manifest


def _m(lifecycle="on-demand", wake_class="normal", protected=False):
    return Manifest(id="x", category="infra", runtime="native", exposure="lan",
                    units=("x.service",), protected=protected,
                    lifecycle=lifecycle, wake_class=wake_class)


def test_sleeps_when_idle_and_no_conns():
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=0),
                        hint_idle=None, now_up=True) is True


def test_not_sleep_if_conns_open():
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=2),
                        hint_idle=None, now_up=True) is False


def test_not_sleep_if_recent_request():
    assert should_sleep(_m(), Signal(last_request_age=10.0, active_conns=0),
                        hint_idle=None, now_up=True) is False


def test_module_hint_vetoes_sleep():
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=0),
                        hint_idle=False, now_up=True) is False


def test_unknown_signal_never_sleeps():
    assert should_sleep(_m(), None, hint_idle=None, now_up=True) is False
    assert should_sleep(_m(), Signal(last_request_age=None, active_conns=0),
                        hint_idle=None, now_up=True) is False
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=None),
                        hint_idle=None, now_up=True) is False


def test_never_sleeps_non_sleepable_or_down():
    assert should_sleep(_m(lifecycle="always-on"),
                        Signal(1000.0, 0), hint_idle=None, now_up=True) is False
    assert should_sleep(_m(protected=True),
                        Signal(1000.0, 0), hint_idle=None, now_up=True) is False
    assert should_sleep(_m(), Signal(1000.0, 0), hint_idle=None, now_up=False) is False


def test_urgent_uses_longer_threshold():
    # 1000s idle: normal (threshold 900) sleeps, urgent (threshold 3600) does not
    assert should_sleep(_m(wake_class="normal"), Signal(1000.0, 0),
                        hint_idle=None, now_up=True) is True
    assert should_sleep(_m(wake_class="urgent"), Signal(1000.0, 0),
                        hint_idle=None, now_up=True) is False
