# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""`update` ne doit JAMAIS décaler l'argv transmis au conteneur : un `_`
surnuméraire dans le script `cmd_update` fait que `$1` du script distant vaut
"_" au lieu du SHA, et `git fetch --depth 1 origin "$1"` échoue toujours.

On fabrique de faux `lxc-attach` / `lxc-info` / `id` en tête de PATH pour
capturer l'argv RÉELLEMENT transmis, sans toucher à un vrai LXC ni exiger
root. Ce test doit ÉCHOUER si on réintroduit le `_` surnuméraire à l'appel de
`lxc_attach` dans `cmd_update`.
"""
import os
import stat
import subprocess
from pathlib import Path

CTL = str(Path(__file__).resolve().parents[1] / "sbin" / "picobrewctl")
SHA = "0123456789abcdef0123456789abcdef01234567"


def _make_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def test_update_passes_the_sha_as_dollar_1_of_the_remote_script(tmp_path):
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    capture_dir = tmp_path / "calls"
    capture_dir.mkdir()
    session_file = tmp_path / "no-such-session"  # inexistant => pas de brassage en cours

    # `id -u` doit répondre 0 : cmd_update exige root avant d'attacher le LXC.
    _make_executable(fakebin / "id", """#!/bin/bash
if [ "$1" = "-u" ]; then echo 0; else echo root; fi
""")

    # `lxc-info` doit rapporter un conteneur RUNNING pour passer la garde
    # `lxc_running` de cmd_update.
    _make_executable(fakebin / "lxc-info", """#!/bin/bash
echo "State: RUNNING"
""")

    # `lxc-attach` capture son argv complet (séparateur NUL, un fichier par
    # appel) au lieu d'attacher un vrai conteneur.
    _make_executable(fakebin / "lxc-attach", """#!/bin/bash
i=0
while [ -e "$CAPTURE_DIR/call-$i" ]; do i=$((i+1)); done
printf '%s\\0' "$@" > "$CAPTURE_DIR/call-$i"
exit 0
""")

    env = dict(
        os.environ,
        PATH=f"{fakebin}:{os.environ['PATH']}",
        PICOBREW_SESSION_FILE=str(session_file),
        CAPTURE_DIR=str(capture_dir),
    )
    p = subprocess.run(["bash", CTL, "update", SHA], capture_output=True, text=True, env=env)
    assert p.returncode == 0, f"stdout={p.stdout!r} stderr={p.stderr!r}"

    first_call = capture_dir / "call-0"
    assert first_call.exists(), "lxc-attach n'a jamais été invoqué"
    argv = first_call.read_bytes().decode().split("\0")
    if argv and argv[-1] == "":
        argv = argv[:-1]

    # argv ressemble à: -n picobrew -P /data/lxc -- sh -c "<script>" _ <sha>
    dashdash = argv.index("--")
    assert argv[dashdash + 1] == "sh"
    assert argv[dashdash + 2] == "-c"
    dollar_0 = argv[dashdash + 4]
    dollar_1 = argv[dashdash + 5] if len(argv) > dashdash + 5 else None

    assert dollar_0 == "_", f"argv inattendu autour de $0: {argv[dashdash:]!r}"
    assert dollar_1 == SHA, (
        f"$1 du script distant vaut {dollar_1!r} au lieu du SHA {SHA!r} — "
        f"argv complet={argv!r}"
    )
