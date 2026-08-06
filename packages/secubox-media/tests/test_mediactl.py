"""mediactl — confinement, lecture seule, et le refus de supprimer (#995).

Ce ctl recoit des CHEMINS venus d'une requete HTTP et les applique au systeme
de fichiers. Trois choses doivent tenir quoi qu'il arrive, et chacune
correspond a un mode de panne reel :

  - un chemin hors des racines autorisees est REFUSE, y compris via un lien
    symbolique pose sur le support ;
  - un support externe est monte en LECTURE SEULE ;
  - une synchronisation n'efface JAMAIS — un --delete sur une destination mal
    choisie viderait une mediatheque entiere.
"""
import json
import os
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "mediactl"


def _env(tmp_path, extra_roots=None):
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        "SECUBOX_MEDIA_MOUNT_ROOT": str(tmp_path / "media"),
        "SECUBOX_MEDIA_STATE_DIR": str(tmp_path / "state"),
        "SECUBOX_MEDIA_EXTRA_ROOTS": extra_roots or str(tmp_path / "dest"),
        "HOME": str(tmp_path),
    }


def _run(args, env):
    return subprocess.run(["bash", str(CTL)] + args,
                          capture_output=True, text=True, env=env, timeout=60)


def test_browse_refuses_a_path_outside_the_roots(tmp_path):
    (tmp_path / "media").mkdir()
    r = _run(["browse", "/etc"], _env(tmp_path))
    d = json.loads(r.stdout)
    assert d["ok"] is False
    assert "racines" in d["error"]


def test_browse_refuses_traversal(tmp_path):
    (tmp_path / "media").mkdir()
    r = _run(["browse", str(tmp_path / "media" / ".." / ".." / "etc")], _env(tmp_path))
    assert json.loads(r.stdout)["ok"] is False


def test_browse_refuses_a_symlink_escaping_the_root(tmp_path):
    """Le confinement porte sur le chemin RESOLU. Un lien pose sur le support
    suffirait sinon a sortir de la racine — et un support externe est, par
    definition, du contenu qu'on ne maitrise pas."""
    media = tmp_path / "media"; media.mkdir()
    (media / "evasion").symlink_to("/etc")
    r = _run(["browse", str(media / "evasion")], _env(tmp_path))
    assert json.loads(r.stdout)["ok"] is False


def test_browse_lists_directories_first(tmp_path):
    media = tmp_path / "media"; media.mkdir()
    (media / "zzz_dossier").mkdir()
    (media / "aaa_fichier.txt").write_text("x")
    r = _run(["browse", str(media)], _env(tmp_path))
    d = json.loads(r.stdout)
    assert d["ok"] is True
    assert d["entries"][0]["name"] == "zzz_dossier", "les repertoires viennent d'abord"


def test_unmount_refuses_a_mount_this_module_did_not_create(tmp_path):
    """On ne demonte jamais un support monte par l'operateur ou un autre
    module : ce serait couper l'acces de quelqu'un d'autre."""
    (tmp_path / "media").mkdir()
    r = _run(["unmount", "/data"], _env(tmp_path))
    d = json.loads(r.stdout)
    assert d["ok"] is False
    assert "gérés" in d["error"] or "geres" in d["error"]


def test_copy_refuses_a_destination_outside_the_roots(tmp_path):
    media = tmp_path / "media"; media.mkdir()
    (media / "src").mkdir()
    r = _run(["copy", str(media / "src"), "/tmp"], _env(tmp_path))
    d = json.loads(r.stdout)
    assert d["ok"] is False
    assert "destination" in d["error"]


def test_copy_enqueues_and_does_not_transfer_inline(tmp_path):
    """Une copie de plusieurs centaines de Mo ne tient pas dans une requete
    HTTP : le verbe met en file et rend la main."""
    media = tmp_path / "media"; media.mkdir()
    src = media / "album"; src.mkdir(); (src / "a.flac").write_text("x" * 100)
    dest = tmp_path / "dest"; dest.mkdir()
    r = _run(["copy", str(src), str(dest)], _env(tmp_path))
    d = json.loads(r.stdout)
    assert d["ok"] is True and d["job"]
    assert not (dest / "album").exists(), "la mise en file ne doit rien transferer"
    assert list((tmp_path / "state" / "queue").glob("*.json"))


def test_drain_actually_copies(tmp_path):
    media = tmp_path / "media"; media.mkdir()
    src = media / "album"; src.mkdir(); (src / "a.flac").write_text("x" * 100)
    dest = tmp_path / "dest"; dest.mkdir()
    env = _env(tmp_path)
    _run(["copy", str(src), str(dest)], env)
    _run(["drain"], env)
    assert (dest / "album" / "a.flac").exists()


def test_sync_never_deletes_at_the_destination(tmp_path):
    """La garde la plus importante du fichier. Aligner une destination ne doit
    pas pouvoir effacer ce qui s'y trouvait deja."""
    media = tmp_path / "media"; media.mkdir()
    src = media / "album"; src.mkdir(); (src / "a.flac").write_text("x")
    dest = tmp_path / "dest"; dest.mkdir()
    temoin = dest / "ne_pas_effacer.txt"; temoin.write_text("precieux")
    env = _env(tmp_path)
    _run(["sync", str(src), str(dest)], env)
    _run(["drain"], env)
    assert temoin.exists(), "sync ne doit jamais supprimer a la destination"
    assert temoin.read_text() == "precieux"


def test_drain_never_passes_delete_to_rsync(tmp_path):
    """Examine les lignes EXECUTABLES, pas les commentaires.

    Premiere version de ce test : un grep brut sur la source, qui echouait sur
    le commentaire « JAMAIS --delete » du drainage. Chercher une chaine dans un
    fichier qui melange prose et code donne des faux positifs — et un test qui
    crie a tort finit par etre ignore."""
    src = CTL.read_text()
    i = src.index("cmd_drain")
    code = [l for l in src[i:i + 2500].splitlines()
            if l.strip() and not l.strip().startswith("#")]
    for line in code:
        assert "--delete" not in line, f"--delete ne doit jamais etre passe a rsync : {line.strip()}"


def test_mount_is_read_only(tmp_path):
    src = CTL.read_text()
    i = src.index("cmd_mount")
    assert "mount -o ro,noexec,nosuid,nodev" in src[i:i + 1500]


def test_device_label_is_sanitised_before_composing_a_path(tmp_path):
    """L'etiquette vient du support, donc d'une source non maitrisee."""
    src = CTL.read_text()
    i = src.index("cmd_mount")
    assert "tr -c 'A-Za-z0-9._-' '_'" in src[i:i + 1500]
