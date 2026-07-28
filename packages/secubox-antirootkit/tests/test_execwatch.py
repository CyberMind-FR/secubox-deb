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
    e = ew.ExecEvent(pid=7, ppid=1, uid=0, exe="/tmp/x", argv=[], success=True)
    jailed = []
    logged = []
    n = ew.run_once([e], set(), lambda p: False, jailed.append, lambda ev, d: logged.append(d))
    assert n == 1 and jailed == [7] and logged == ["jail"]


def test_parse_hex_encoded_exe():
    hex_exe = "/tmp/.x evil".encode("utf-8").hex().upper()
    au = (
        f'type=SYSCALL msg=audit(1785200000.123:43): arch=c00000b7 syscall=221 '
        f'success=yes exit=0 ppid=1 pid=1000 uid=0 exe={hex_exe} key="sbx_exec"\n'
        f'type=EXECVE msg=audit(1785200000.123:43): argc=1 a0="evil"'
    )
    evs = ew.parse_ausearch(au)
    assert len(evs) == 1
    e = evs[0]
    assert e.exe == "/tmp/.x evil"
    assert ew.decide(e, set(), lambda p: False) == "jail"


def test_parse_hex_encoded_argv():
    hex_arg = "-c".encode("utf-8").hex().upper()
    au = (
        'type=SYSCALL msg=audit(1785200000.123:44): arch=c00000b7 syscall=221 '
        'success=yes exit=0 ppid=1 pid=1001 uid=0 exe="/bin/sh" key="sbx_exec"\n'
        f'type=EXECVE msg=audit(1785200000.123:44): argc=2 a0="sh" a1={hex_arg}'
    )
    evs = ew.parse_ausearch(au)
    assert len(evs) == 1
    assert evs[0].argv == ["sh", "-c"]


def test_run_once_fail_closed_on_raise():
    e1 = ew.ExecEvent(pid=101, ppid=1, uid=0, exe="/tmp/a", argv=[], success=True)
    e2 = ew.ExecEvent(pid=102, ppid=1, uid=0, exe="/tmp/b", argv=[], success=True)

    calls = {"n": 0}

    def flaky_is_backed(path):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return False

    jailed = []
    logged = []
    n = ew.run_once(
        [e1, e2], set(), flaky_is_backed, jailed.append, lambda ev, d: logged.append(d)
    )
    assert n == 2
    assert jailed == [101, 102]
    assert logged == ["jail", "jail"]
