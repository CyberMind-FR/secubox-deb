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


def _env_ctl(tmp_path: Path, lxc_state="RUNNING", is_active=None, rootfs=True, domaine=None,
             attach_curl=None, oidcctl_secret=None, env_extra=None) -> dict:
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
if [ "$1" = curl ]; then
  echo "$*" >> "${FAKE_URLS_FILE:-/dev/null}"
  # Faux curl du conteneur : <clé> est cherchée dans l'URL, la réponse vient de FAKE_ATTACH_CURL_DIR/<clé>.
  for cle in openid-configuration jwks; do
    case "$*" in
      *"$cle"*) [ -f "${FAKE_ATTACH_CURL_DIR:-/nonexistent}/$cle" ] && { cat "$FAKE_ATTACH_CURL_DIR/$cle"; exit 0; } ;;
    esac
  done
  exit 22
fi
if [ "$1" = systemctl ] && [ "$2" = is-active ]; then
  IFS=, read -ra paires <<< "${FAKE_IS_ACTIVE:-}"
  for p in "${paires[@]}"; do
    if [ "${p%%=*}" = "$3" ]; then
      etat="${p#*=}"; echo "$etat"
      # Comme le vrai systemctl : code 3 pour tout état différent de « active ».
      [ "$etat" = active ] && exit 0 || exit 3
    fi
  done
  echo active
fi
exit 0
""")
    _ecrire_exec(bin_dir / "lxc-start", "#!/bin/bash\nexit 0\n")
    _ecrire_exec(bin_dir / "lxc-stop", "#!/bin/bash\nexit 0\n")
    _ecrire_exec(bin_dir / "curl", "#!/bin/bash\nexit 7\n")
    _ecrire_exec(bin_dir / "nft", "#!/bin/bash\nexit 1\n")
    if domaine is None:
        _ecrire_exec(bin_dir / "secubox-domaine", '#!/bin/bash\necho "$1.exemple.test"\n')
    else:  # sortie brute imposée (caractères de contrôle compris)
        (tmp_path / "domaine.txt").write_text(domaine)
        _ecrire_exec(bin_dir / "secubox-domaine", f'#!/bin/bash\ncat "{tmp_path}/domaine.txt"\n')
    # Réponses du faux curl du conteneur : un fichier par clé (openid-configuration, jwks).
    reponses = tmp_path / "attach_curl"
    reponses.mkdir(exist_ok=True)
    for ancien in reponses.iterdir():  # un appel = ses seules réponses
        ancien.unlink()
    for cle, corps in (attach_curl or {}).items():
        (reponses / cle).write_text(corps)
    # Faux secubox-oidcctl : secret sur stdout, argv ajouté à <tmp>/appels ; échec si aucun secret.
    # client-add : journalise l'argv dans <tmp>/appels ; client-ls : relit ce journal (clients de l'exécution).
    _ecrire_exec(bin_dir / "secubox-oidcctl", f"""#!/bin/bash
if [ "$1" = client-ls ]; then
  [ -f "{tmp_path}/appels" ] || exit 0
  while read -r cmd id _n nom _r uri; do
    [ "$cmd" = client-add ] && printf '%s\\t%s\\tapp=-\\t%s\\n' "$id" "$nom" "$uri"
  done < "{tmp_path}/appels"
  exit 0
fi
echo "$*" >> "{tmp_path}/appels"
[ -n "${{FAKE_OIDCCTL_SECRET:-}}" ] || exit 1
echo "$FAKE_OIDCCTL_SECRET"
""")
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
        **(env_extra or {}),
        "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_MEET_CONFIG": str(conf),
        "SECUBOX_LXC_PATH": str(lxc_path),
        "SECUBOX_MEET_STATE_DIR": str(etat),
        "SECUBOX_MEET_SECRETS_DIR": str(secrets),
        "SECUBOX_MEET_NFT_SRC": str(tmp_path / "meet.nft"),
        "SECUBOX_MEET_NFT_DST": str(tmp_path / "nftables.d" / "secubox-meet-dnat.nft"),
        "FAKE_URLS_FILE": str(tmp_path / "urls"),
        "FAKE_ATTACH_CURL_DIR": str(reponses),
        "FAKE_OIDCCTL_SECRET": oidcctl_secret or "",
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
