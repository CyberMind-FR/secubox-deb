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
    """TOUTE invocation de montage est en lecture seule, sans exception.

    Vérifié sur l'ensemble de la fonction plutôt que sur une fenêtre de
    caractères : une fenêtre laisse passer un montage ajouté plus bas, ce qui
    est exactement ce qui arrive quand on câble un relais FUSE."""
    fn = _func("cmd_mount")
    invocations = [l.strip() for l in fn.splitlines()
                   if (" -o " in l and ("mount" in l or "ntfs-3g" in l or "hfsfuse" in l))]
    assert invocations, "aucune invocation de montage trouvée"
    for line in invocations:
        assert "ro," in line, f"montage sans lecture seule : {line}"


def test_device_label_is_sanitised_before_composing_a_path(tmp_path):
    """L'etiquette vient du support, donc d'une source non maitrisee."""
    src = CTL.read_text()
    i = src.index("cmd_mount")
    assert "tr -c 'A-Za-z0-9._-' '_'" in src[i:i + 1500]



# ── Systèmes de fichiers non lisibles par ce noyau ───────────────────────────
#
# Le noyau 6.12.85 de cette board n'a ni `hfsplus` ni `exfat`. Le premier vrai
# support branché — un disque Apple en HFS+ — a donc répondu « montage refusé »
# sans motif, ce qui envoie chercher le défaut dans le module alors qu'il est
# dans le noyau. Ces tests fixent le comportement : dire pourquoi, et ne pas
# proposer un bouton qui ne peut pas aboutir.

def _func(name):
    """Extrait le corps d'une fonction bash du ctl."""
    src = CTL.read_text()
    start = src.index(f"{name}() {{")
    end = src.index("\n}\n", start)
    return src[start:end]


def _fs_support(fs, path=None):
    """Appelle la vraie fonction _fs_support du ctl.

    La fonction est extraite puis évaluée seule : `source` du script complet
    déclencherait aussi son dispatch principal, qui imprime l'aide et pollue
    la sortie."""
    body = _func("_fs_support") + "\n}"
    r = subprocess.run(
        ["/bin/bash", "-c", body + f'\n_fs_support "{fs}"'],
        capture_output=True, text=True, timeout=30,
        env={"PATH": path if path is not None else os.environ.get("PATH", "/usr/bin:/bin")},
    )
    return r.stdout.strip()


def test_fs_support_recognises_what_the_kernel_can_read():
    """ext4 est dans /proc/filesystems partout où ces tests tournent."""
    assert _fs_support("ext4") == "kernel"


def test_fs_support_reports_none_without_driver_or_relay():
    """Sans pilote noyau ni relais FUSE, le verdict est `none`, pas un espoir.

    PATH vidé : aucun relais n'est trouvable, ce qui reproduit la board face à
    un disque HFS+."""
    assert _fs_support("hfsplus", path="") == "none"


def test_fs_support_accepts_a_fuse_relay_when_present(tmp_path):
    """ntfs-3g est installé sur la board : le verdict doit en tenir compte."""
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "ntfs-3g").write_text("#!/bin/sh\nexit 0\n")
    (fake / "ntfs-3g").chmod(0o755)
    assert _fs_support("ntfs", path=str(fake)) == "fuse"


def test_mount_refuses_unsupported_filesystem_with_a_reason():
    """Un refus doit nommer le système de fichiers en cause, avant le mkdir.

    Sans motif, l'utilisateur re-clique sur une action que la machine ne peut
    pas honorer ; et un verdict rendu après coup laisse un point de montage
    vide derrière chaque refus."""
    fn = _func("cmd_mount")
    assert "_fs_support" in fn
    assert "non pris en charge" in fn
    assert fn.index("_fs_support") < fn.index("mkdir -p"), \
        "le verdict doit précéder la création du point de montage"


def test_fuse_relay_is_still_read_only():
    """La règle « lecture seule » ne change pas parce que le pilote change."""
    fn = _func("cmd_mount")
    for relay in ("ntfs-3g", "mount.exfat-fuse", "hfsfuse"):
        line = next((l for l in fn.splitlines() if relay in l and " -o " in l), None)
        assert line, f"{relay} doit être câblé"
        assert "ro," in line, f"{relay} monté sans ro : {line.strip()}"


def test_detect_computes_the_verdict_for_every_device():
    """Sans cette ligne, `support` est indéfini et detect lève un NameError."""
    src = CTL.read_text()
    assert "support, why = fs_support(" in src
    assert '"mountable"' in src and '"unsupported_reason"' in src


def test_panel_replaces_the_button_by_the_reason():
    """Un bouton mort est une invitation à l'échec."""
    html = (CTL.parents[1] / "www" / "media" / "index.html").read_text()
    assert "devAction" in html
    assert "d.mountable === false" in html
