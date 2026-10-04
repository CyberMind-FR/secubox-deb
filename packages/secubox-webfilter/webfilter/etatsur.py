# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Accès SÛR au dossier d'état, que contrôle un compte non root (relecture de sécurité #1962, phase 2).

Le contrôleur root lit `config.json` et les listes, et écrit `resultat.json` et `carte.json` dans un dossier où un autre compte peut poser des liens
symboliques ou en remplacer le contenu. Ici : le dossier est ouvert UNE fois sans suivre de lien (`O_NOFOLLOW|O_DIRECTORY`), son propriétaire et
ses droits sont vérifiés, et toute opération ultérieure est RELATIVE au descripteur ouvert — jamais un chemin, donc jamais de course entre le contrôle
et l'usage."""
import contextlib
import os
import secrets
import stat


class ErreurEtat(RuntimeError):
    pass


class Budget:
    """Plafond d'octets lus, partagé par toutes les listes d'une application : un dépassement refuse l'application, il ne ronge pas la mémoire de root."""

    def __init__(self, octets: int):
        self.reste = octets

    def prendre(self, n: int) -> None:
        if n > self.reste:
            raise ErreurEtat("listes trop volumineuses : budget d'octets dépassé")
        self.reste -= n


class EtatSur:
    def __init__(self, chemin, proprietaire_uid=None):
        chemin = os.fspath(chemin)
        try:
            avant = os.lstat(chemin)
        except OSError:
            raise ErreurEtat("dossier d'état absent") from None
        if not stat.S_ISDIR(avant.st_mode):
            raise ErreurEtat("dossier d'état : ce n'est pas un vrai dossier (lien symbolique ?)")
        try:
            fd = os.open(chemin, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise ErreurEtat("dossier d'état inaccessible") from None
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino) != (avant.st_dev, avant.st_ino):
            os.close(fd)
            raise ErreurEtat("dossier d'état remplacé pendant l'ouverture")
        if st.st_mode & 0o022:
            os.close(fd)
            raise ErreurEtat("dossier d'état inscriptible par d'autres comptes")
        if proprietaire_uid is not None and st.st_uid != proprietaire_uid:
            os.close(fd)
            raise ErreurEtat("dossier d'état : propriétaire inattendu")
        self.fd, self.uid, self.gid = fd, st.st_uid, st.st_gid

    def fermer(self) -> None:
        with contextlib.suppress(OSError):
            os.close(self.fd)

    def lire(self, nom: str, maxi: int):
        """Octets d'un fichier régulier du dossier, ou None s'il n'existe pas. Lien, fichier non régulier ou trop gros : ErreurEtat."""
        try:
            f = os.open(nom, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        except OSError:
            raise ErreurEtat(f"{nom} : lien symbolique ou fichier illisible") from None
        try:
            if not stat.S_ISREG(os.fstat(f).st_mode):
                raise ErreurEtat(f"{nom} : fichier non régulier")
            brut = os.read(f, maxi + 1)
        finally:
            os.close(f)
        if len(brut) > maxi:
            raise ErreurEtat(f"{nom} : trop volumineux")
        return brut

    def ecrire(self, nom: str, octets: bytes, mode: int) -> None:
        """Écriture atomique : fichier temporaire créé en exclusivité, propriétaire du dossier, renommage relatif au descripteur. Un lien posé à la
        place de la cible est REMPLACÉ, jamais suivi."""
        tmp = ".wf-" + secrets.token_hex(8)
        f = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            with os.fdopen(f, "wb") as h:
                h.write(octets)
                h.flush()
                os.fchmod(h.fileno(), mode)                                 # AVANT fchown : sans CAP_FOWNER, un fichier déjà donné à un autre compte ne se chmod plus
                with contextlib.suppress(PermissionError):
                    os.fchown(h.fileno(), self.uid, self.gid)
                os.fsync(h.fileno())
            os.replace(tmp, nom, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=self.fd)
            raise

    def supprimer(self, nom: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(nom, dir_fd=self.fd)

    def sous_dossier(self, nom: str) -> int:
        """Descripteur d'un sous-dossier ouvert sans suivre de lien (FileNotFoundError s'il n'existe pas ; ErreurEtat si c'est un lien)."""
        try:
            return os.open(nom, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
        except FileNotFoundError:
            raise
        except OSError:
            raise ErreurEtat(f"{nom} : lien symbolique ou dossier invalide") from None
