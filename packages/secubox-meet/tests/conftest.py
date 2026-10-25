# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Aides de test de meetctl : lxc-*, curl, nft et secubox-domaine simulés par des exécutables sur PATH."""
import json
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "meetctl"


def _ecrire_exec(chemin: Path, contenu: str) -> None:
    chemin.write_text(contenu)
    chemin.chmod(0o755)


def _env_ctl(tmp_path: Path, lxc_state="RUNNING", is_active=None, rootfs=True) -> dict:
    """Prépare le faux PATH et l'arbre de fichiers ; renvoie l'environnement du ctl."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    sortie_etat = f'echo "State: {lxc_state}"' if lxc_state else "true"
    _ecrire_exec(bin_dir / "lxc-info", f"#!/bin/bash\n{sortie_etat}\nexit 0\n")
    # lxc-attach : ne répond qu'à « systemctl is-active <unité> », selon FAKE_IS_ACTIVE (unité=état,…).
    _ecrire_exec(bin_dir / "lxc-attach", """#!/bin/bash
while [ $# -gt 0 ]; do
  case "$1" in
    -n|-P) shift 2 ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
if [ "$1" = systemctl ] && [ "$2" = is-active ]; then
  IFS=, read -ra paires <<< "${FAKE_IS_ACTIVE:-}"
  for p in "${paires[@]}"; do
    [ "${p%%=*}" = "$3" ] && { echo "${p#*=}"; exit 0; }
  done
  echo active
fi
exit 0
""")
    _ecrire_exec(bin_dir / "lxc-start", "#!/bin/bash\nexit 0\n")
    _ecrire_exec(bin_dir / "lxc-stop", "#!/bin/bash\nexit 0\n")
    _ecrire_exec(bin_dir / "curl", "#!/bin/bash\nexit 7\n")
    _ecrire_exec(bin_dir / "nft", "#!/bin/bash\nexit 1\n")
    _ecrire_exec(bin_dir / "secubox-domaine", '#!/bin/bash\necho "$1.exemple.test"\n')
    lxc_path = tmp_path / "lxc"
    if rootfs:
        (lxc_path / "meet" / "rootfs").mkdir(parents=True, exist_ok=True)
    conf = tmp_path / "meet.toml"
    if not conf.exists():
        conf.write_text('lxc_name = "meet"\nlxc_ip = "10.100.0.195"\n')
    etat = tmp_path / "etat"
    etat.mkdir(exist_ok=True)
    secrets = tmp_path / "secrets"
    secrets.mkdir(exist_ok=True)
    return {
        "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_MEET_CONFIG": str(conf),
        "SECUBOX_LXC_PATH": str(lxc_path),
        "SECUBOX_MEET_STATE_DIR": str(etat),
        "SECUBOX_MEET_SECRETS_DIR": str(secrets),
        "SECUBOX_MEET_NFT_SRC": str(tmp_path / "meet.nft"),
        "SECUBOX_MEET_NFT_DST": str(tmp_path / "nftables.d" / "secubox-meet-dnat.nft"),
        "FAKE_IS_ACTIVE": ",".join(f"{u}={e}" for u, e in (is_active or {}).items()),
    }


def run_ctl_rc(tmp_path, *args, **kw):
    """Lance meetctl ; renvoie (code, stdout)."""
    env = _env_ctl(tmp_path, **kw)
    r = subprocess.run(["bash", str(CTL), *args], capture_output=True, text=True, env=env, timeout=60)
    return r.returncode, r.stdout


def run_ctl(tmp_path, *args, **kw):
    """Lance meetctl, exige le code 0 ; renvoie stdout."""
    rc, out = run_ctl_rc(tmp_path, *args, **kw)
    assert rc == 0, out
    return out


@pytest.fixture
def lire_json():
    return json.loads
