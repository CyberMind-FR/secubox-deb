from api import execwatch as ew

AU = '''type=SYSCALL msg=audit(1785200000.123:42): arch=c00000b7 syscall=221 success=yes exit=0 ppid=1 pid=999 uid=0 exe="/usr/local/bin/notwork-monitoring" key="sbx_exec"
type=EXECVE msg=audit(1785200000.123:42): argc=2 a0="notwork-monitoring" a1="-server"'''


def test_parse():
    evs = ew.parse_ausearch(AU)
    assert len(evs) == 1
    e = evs[0]
    assert e.pid == 999 and e.exe == "/usr/local/bin/notwork-monitoring" and e.success is True
    assert e.argv == ["notwork-monitoring", "-server"]


def test_decide_jails_unknown():
    e = ew.ExecEvent(pid=999, ppid=1, uid=0, exe="/usr/local/bin/notwork-monitoring", argv=[], success=True)
    assert ew.decide(e, allow=set(), is_backed_fn=lambda p: False) == "jail"


def test_decide_allows_dpkg():
    e = ew.ExecEvent(pid=1, ppid=1, uid=0, exe="/usr/bin/yacy", argv=[], success=True)
    assert ew.decide(e, allow=set(), is_backed_fn=lambda p: True) == "allow"


def test_decide_allows_allowlisted():
    e = ew.ExecEvent(pid=2, ppid=1, uid=0, exe="/usr/local/bin/certbot", argv=[], success=True)
    assert ew.decide(e, allow={"/usr/local/bin/certbot"}, is_backed_fn=lambda p: False) == "allow"


def test_run_once_jails_and_logs():
    from api import execwatch as ew

    e = ew.ExecEvent(pid=7, ppid=1, uid=0, exe="/tmp/x", argv=[], success=True)
    jailed = []
    logged = []
    n = ew.run_once([e], set(), lambda p: False, jailed.append, lambda ev, d: logged.append(d))
    assert n == 1 and jailed == [7] and logged == ["jail"]
