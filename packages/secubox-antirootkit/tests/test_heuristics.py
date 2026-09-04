from api.heuristics import score
from api.execwatch import ExecEvent


def test_strong_notwork_profile():
    e = ExecEvent(pid=1, ppid=1, uid=0, exe="/usr/local/bin/notwork-monitoring", argv=[], success=False)
    s, reasons = score(e, pkg=None, unit_flags={"restart_always": True, "logs_silenced": True}, failed_count=5)
    assert s >= 3 and "non-dpkg-exec-path" in reasons and "silenced-restart-always" in reasons and "crash-loop" in reasons


def test_legit_dpkg_zero():
    e = ExecEvent(pid=1, ppid=1, uid=0, exe="/usr/bin/yacy", argv=[], success=True)
    s, reasons = score(e, pkg="secubox-yacy", unit_flags={"restart_always": False, "logs_silenced": False}, failed_count=0)
    assert s == 0
