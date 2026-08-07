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


def test_mount_defaults_to_read_only(tmp_path):
    """Le DEFAUT est la lecture seule ; l'ecriture est un choix explicite.

    L'invariant a change en 1.2.0 : exporter vers une cle USB exige de pouvoir
    ecrire. Ce qui reste garanti, c'est qu'un support fraichement branche n'est
    jamais monte en ecriture sans qu'on l'ait demande."""
    fn = _func("cmd_mount")
    default = next(l for l in fn.splitlines() if "mopts=" in l and "--rw" not in l)
    assert "ro," in default, f"le defaut doit etre ro : {default.strip()}"
    rw = next(l for l in fn.splitlines() if "--rw" in l and "mopts=" in l)
    assert "rw," in rw, "l'ecriture doit etre conditionnee a --rw"


def test_no_mount_invocation_hardcodes_write_access(tmp_path):
    """Aucun montage ne doit contourner $mopts.

    Verifie sur TOUTE la fonction : une fenetre de caracteres laisserait passer
    un montage ajoute plus bas, ce qui est exactement ce qui est arrive en
    cablant les relais FUSE."""
    fn = _func("cmd_mount")
    invocations = [l.strip() for l in fn.splitlines()
                   if " -o " in l and any(c in l for c in ("mount", "ntfs-3g", "hfsfuse"))]
    assert invocations, "aucune invocation de montage trouvee"
    for line in invocations:
        assert '"$mopts"' in line, f"montage hors politique : {line}"


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


def test_fuse_relays_follow_the_same_policy():
    """La politique de montage ne change pas parce que le pilote change."""
    fn = _func("cmd_mount")
    for relay in ("ntfs-3g", "mount.exfat-fuse", "hfsfuse"):
        line = next((l for l in fn.splitlines() if relay in l and " -o " in l), None)
        assert line, f"{relay} doit etre cable"
        assert '"$mopts"' in line, f"{relay} hors politique : {line.strip()}"


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


def test_panel_sends_the_token_and_redirects_on_401():
    """Un 401 doit emmener à la connexion, pas laisser un panneau inerte.

    Les trois POST portent l'en-tête ; sans redirection, l'utilisateur lit
    « connexion requise » sans savoir où aller — c'est ce qui est arrivé au
    premier clic sur « Monter »."""
    html = (CTL.parents[1] / "www" / "media" / "index.html").read_text()
    assert "localStorage.getItem('sbx_token')" in html, "clé de jeton du projet"
    assert html.count("headers: hdrs()") >= 3, "chaque POST doit porter le jeton"
    assert "login.html?redirect=" in html, "un 401 doit rediriger vers la connexion"


def test_service_can_write_the_mount_root_and_propagates_mounts():
    """Deux gardes nees du meme echec : « Montage : mkdir failed ».

    ProtectSystem=strict rend /media en lecture seule DANS l'espace de noms du
    service — la meme commande reussit depuis un shell root, ce qui egare le
    diagnostic. Et comme PrivateTmp/ProtectSystem donnent a l'unite un espace
    de noms de montage prive, un support monte sans propagation partagee
    resterait invisible du minuteur de drainage (unite distincte) : les
    transferts echoueraient sans rien dire."""
    unit = (CTL.parents[1] / "debian" / "secubox-media.service").read_text()
    rw = next(l for l in unit.splitlines() if l.startswith("ReadWritePaths="))
    assert "/media" in rw, "la racine des montages doit etre inscriptible"
    assert "MountFlags=shared" in unit, \
        "sans propagation partagee, le montage est invisible hors du service"


# ── Racines declarees : le confinement suit la declaration ───────────────────

def _roots_env(tmp_path, content):
    rf = tmp_path / "media.roots"
    rf.write_text(content)
    env = _env(tmp_path)
    env["SECUBOX_MEDIA_ROOTS_FILE"] = str(rf)
    env["SECUBOX_MEDIA_EXTRA_ROOTS"] = ""
    return env


def test_a_service_library_is_a_source_not_a_destination(tmp_path):
    """Deposer un fichier dans /data/peertube ne l'inscrit pas dans sa base.

    Le systeme de fichiers autorise l'ecriture ; la politique non. Sans cette
    garde, un transfert « reussi » produirait un fichier invisible du service
    et occupant la place."""
    lib = tmp_path / "lib"; lib.mkdir()
    src = tmp_path / "src"; src.mkdir(); (src / "a.txt").write_text("x")
    env = _roots_env(tmp_path, f"Biblio | {lib} | ro\nDepot | {src} | rw\n")
    r = _run(["copy", str(src / "a.txt"), str(lib)], env)
    d = json.loads(r.stdout)
    assert d["ok"] is False
    assert "declaree inscriptible" in d["error"]


def test_a_declared_writable_root_accepts_the_transfer(tmp_path):
    """La garde ne doit pas tout refuser : une destination declaree rw passe."""
    dest = tmp_path / "dest"; dest.mkdir()
    src = tmp_path / "src"; src.mkdir(); (src / "a.txt").write_text("x")
    env = _roots_env(tmp_path, f"Source | {src} | ro\nDepot | {dest} | rw\n")
    r = _run(["copy", str(src / "a.txt"), str(dest)], env)
    assert json.loads(r.stdout)["ok"] is True


def test_an_undeclared_path_stays_out_of_reach(tmp_path):
    """Ce qui n'est pas declare reste inaccessible — rootfs, sauvegardes."""
    env = _roots_env(tmp_path, "Depot | /tmp | rw\n")
    d = json.loads(_run(["browse", "/etc"], env).stdout)
    assert d["ok"] is False


def test_already_mounted_reports_the_actual_mode():
    """« Deja monte » doit dire le mode REEL, pas repondre ok sans rien dire.

    Cliquer « Monter (lecture seule) » sur un support deja monte en ecriture
    repondait ok : l'utilisateur croyait le support protege alors qu'il etait
    inscriptible. Une fausse assurance sur une propriete de surete est pire
    qu'un refus."""
    fn = _func("cmd_mount")
    head = fn[:fn.index("mkdir -p")]
    assert "mismatch" in head, "un mode different doit etre signale"
    assert "findmnt" in head, "le mode reel doit etre lu, pas suppose"


def test_mount_refuses_a_system_partition():
    """Masquer n'est pas refuser.

    detect ecarte deja les partitions systeme de l'affichage, mais les lettres
    /dev/sdX changent d'un demarrage a l'autre : apres un redemarrage reel, un
    /dev/sdb1 memorise designait la partition EFI — et elle a ete montee."""
    fn = _func("cmd_mount")
    head = fn[:fn.index("_fs_support")]
    assert "/boot/efi" in head and "EFI" in head, \
        "les partitions systeme doivent etre refusees AVANT toute tentative"


def test_detect_exposes_a_stable_identifier():
    """Le panneau ne doit pas memoriser une lettre de peripherique."""
    src = CTL.read_text()
    assert "/dev/disk/by-uuid/" in src
    assert '"uuid"' in src


def test_mount_operations_run_in_the_host_namespace():
    """Le service tourne dans un espace de noms de montage PRIVE.

    `MountFlags=shared` ne suffit pas : sa racine est `shared:N master:1`,
    donc ESCLAVE de l'hote — il reçoit les montages de l'hote mais ne lui en
    renvoie aucun. Consequence observee : un support monte depuis le panneau
    etait invisible de ksmbd (partage vide), du minuteur de drainage, et du
    conteneur Lyrion — qui ne voyait donc pas le disque."""
    src = CTL.read_text()
    assert "nsenter -t 1 -m" in src, "les montages doivent viser l'espace de l'hote"
    for fn_name in ("cmd_mount", "cmd_unmount"):
        fn = _func(fn_name)
        for verb in ("mount ", "umount ", "mkdir -p", "rmdir "):
            for line in fn.splitlines():
                st = line.strip()
                if st.startswith("#") or verb not in st:
                    continue
                if st.startswith(("case", "local", "printf", "[", "for")):
                    continue
                assert "_host_ns" in st, f"{fn_name}: hors espace hote -> {st}"


def test_host_ns_is_a_noop_when_already_on_the_host():
    """Appele depuis un shell root ordinaire, le ctl doit marcher sans nsenter."""
    fn = _func("_host_ns")
    assert "_in_host_mountns" in fn
    assert 'command -v nsenter' in fn, "absence de nsenter ne doit pas tout casser"


def test_detect_prefers_the_mountpoint_it_manages():
    """Un peripherique peut avoir PLUSIEURS points de montage.

    Lyrion lie chaque support dans le rootfs de son conteneur ; lsblk n'en
    rapporte qu'un, le dernier. detect annonçait alors
    /data/lxc/lyrion/rootfs/... et la navigation echouait sur « chemin hors
    des racines autorisees » — le confinement avait raison, la detection avait
    tort."""
    src = CTL.read_text()
    assert "preferred_mountpoint" in src and "mountpoints_by_source" in src
    assert 'findmnt", "-rno", "SOURCE,TARGET"' in src, \
        "il faut TOUS les points de montage, pas celui que lsblk choisit"
    # La fonction doit etre APPELEE, pas seulement definie. La premiere version
    # de ce test verifiait l'existence et passait avec le site d'appel non
    # branche : le bug etait toujours la, et le test le declarait corrige.
    assert "mp = preferred_mountpoint(" in src, \
        "detect doit UTILISER le choix, pas seulement le definir"
    assert 'mp = d.get("MOUNTPOINT"' not in src, \
        "le point de montage brut de lsblk ne doit plus etre utilise tel quel"


def test_a_loadable_driver_counts_as_mountable():
    """« module » = pilote disponible mais pas encore charge.

    L'omettre de la liste des etats montables rendait tout support
    « illisible » apres chaque redemarrage, jusqu'au premier modprobe manuel :
    hfsplus a disparu de l'interface pour cette seule raison, alors que le
    noyau savait parfaitement le lire."""
    src = CTL.read_text()
    assert '"mountable": support in ("kernel", "module", "fuse")' in src


def test_mount_loads_the_driver_before_giving_up():
    """Sinon le premier montage apres un redemarrage echoue sans raison."""
    fn = _func("cmd_mount")
    assert "modprobe" in fn
    assert fn.index("modprobe") < fn.index("non pris en charge"), \
        "il faut tenter le chargement AVANT de declarer non supporte"


def test_already_mounted_check_runs_in_the_host_namespace():
    """Le service a son propre espace de noms ; un montage pose par nsenter y
    est invisible. Sans cette correction, le ctl croit le support libre et
    relance un montage — « already mounted on ... »."""
    fn = _func("cmd_mount")
    line = next(l for l in fn.splitlines() if "mountpoint -q" in l)
    assert "_host_ns" in line, f"verification hors espace hote : {line.strip()}"
