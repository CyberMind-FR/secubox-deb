"""medialib — detection des peripheriques bloc et montage hote (#993).

Le panneau annoncait « aucun candidat detecte » alors qu'un disque etiquete
etait bien present : la detection n'examinait que des repertoires DEJA montes.
Une cle USB fraichement branchee, qu'aucun automontage ne prend en charge,
restait invisible — et `mount`, qui n'ajoutait qu'un lxc.mount.entry, aurait de
toute facon echoue sur elle.

Ces tests epinglent : un peripherique non monte est vu, il est rapporte
SEPAREMENT d'un chemin deja pret, le montage hote est en lecture seule, et une
etiquette venue du support ne peut pas s'echapper du repertoire du module.
"""
import json
import os
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "lyrionctl"


def _write_exec(p: Path, content: str) -> None:
    p.write_text(content)
    p.chmod(0o755)


def _env(tmp_path, extra_path):
    return {
        "PATH": f"{extra_path}:/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_LYRION_MOUNT_ROOT": str(tmp_path / "media"),
        "SECUBOX_LYRION_VERSION_CACHE": str(tmp_path / "version.json"),
        "HOME": str(tmp_path),
    }


def _run(args, env):
    return subprocess.run(["bash", str(CTL)] + args,
                          capture_output=True, text=True, env=env, timeout=60)


def _mock_lsblk(tmp_path: Path, rows: str) -> None:
    _write_exec(tmp_path / "lsblk", f"""#!/bin/bash
# -no LABEL <dev> : interrogation ciblee utilisee par le montage
if [ "$1" = "-no" ]; then echo "MYDISK"; exit 0; fi
cat <<'ROWS'
{rows}
ROWS
""")


def test_unmounted_partition_is_detected(tmp_path):
    """Le cas exact du terrain : une partition avec systeme de fichiers, sans
    point de montage."""
    _mock_lsblk(tmp_path, 'NAME="sdc1" LABEL="MUSIQUE" SIZE="931.5G" FSTYPE="ext4" MOUNTPOINT="" RM="1" TYPE="part"')
    r = _run(["medialib", "detect"], _env(tmp_path, tmp_path))
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert "devices" in data, "les peripheriques doivent etre rapportes"
    devs = data["devices"]
    assert len(devs) == 1, devs
    assert devs[0]["device"] == "/dev/sdc1"
    assert devs[0]["label"] == "MUSIQUE"
    assert devs[0]["removable"] is True
    assert devs[0]["mounted"] is False


def test_mounted_partition_is_not_listed_as_a_device(tmp_path):
    """Un chemin deja monte est un `candidate`, pas un `device` : les confondre
    ferait promettre au panneau une action de montage qui n'a pas lieu d'etre."""
    _mock_lsblk(tmp_path, 'NAME="sda1" LABEL="data" SIZE="931G" FSTYPE="ext4" MOUNTPOINT="/data" RM="0" TYPE="part"')
    r = _run(["medialib", "detect"], _env(tmp_path, tmp_path))
    assert json.loads(r.stdout)["devices"] == []


def test_partition_without_filesystem_is_ignored(tmp_path):
    """Une partition sans systeme de fichiers ne peut pas etre montee ; la
    proposer serait une promesse vide."""
    _mock_lsblk(tmp_path, 'NAME="sdc1" LABEL="" SIZE="1G" FSTYPE="" MOUNTPOINT="" RM="1" TYPE="part"')
    r = _run(["medialib", "detect"], _env(tmp_path, tmp_path))
    assert json.loads(r.stdout)["devices"] == []


def test_whole_disk_is_ignored(tmp_path):
    """Seules les partitions sont proposees : monter un disque entier n'a pas
    de sens et masquerait ses partitions."""
    _mock_lsblk(tmp_path, 'NAME="sdc" LABEL="" SIZE="1T" FSTYPE="" MOUNTPOINT="" RM="1" TYPE="disk"')
    r = _run(["medialib", "detect"], _env(tmp_path, tmp_path))
    assert json.loads(r.stdout)["devices"] == []


def test_lsblk_output_never_clobbers_the_shell_path(tmp_path):
    """`lsblk -P` sait emettre PATH="/dev/sdc1". L'evaluer ecraserait le PATH du
    shell et rendrait introuvable toute commande externe appelee ensuite dans
    la boucle. Le champ est volontairement exclu et le chemin reconstruit."""
    src = CTL.read_text()
    i = src.index("_medialib_block_candidates")
    window = src[i:i + 1200]
    assert "lsblk -P -o NAME,LABEL" in window
    assert ",PATH," not in window, "PATH ne doit pas figurer dans la liste lsblk -P"


def test_device_label_cannot_escape_the_module_mount_root(tmp_path):
    """L'etiquette vient du SUPPORT, donc d'une source non maitrisee, et finit
    dans un chemin. Elle doit etre assainie."""
    src = CTL.read_text()
    i = src.index("_medialib_mount_device")
    window = src[i:i + 1200]
    assert "tr -c 'A-Za-z0-9._-' '_'" in window, (
        "l'etiquette doit etre assainie avant de composer un chemin"
    )


def test_host_mount_is_read_only(tmp_path):
    """Le ro est tenu de bout en bout : une mediatheque n'a pas a etre ecrite
    par le serveur, et HFS+ en ecriture sous Linux est un risque connu."""
    src = CTL.read_text()
    i = src.index("_medialib_mount_device")
    window = src[i:i + 1200]
    assert "mount -o ro,noexec,nosuid,nodev" in window
