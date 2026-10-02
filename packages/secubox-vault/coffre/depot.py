# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Session de signature du dépôt apt (Coffre P2, #1367).

La clé qui signe apt.secubox.in (219BA872) était EN CLAIR dans /root/.gnupg
(constat #1364). Ici :

- `proteger` lui pose une phrase ALÉATOIRE que personne ne connaît : elle est
  rangée au Coffre AVANT d'être appliquée (on ne peut pas la perdre), puis
  vérifiée (signe avec, refuse sans). La seule phrase humaine reste celle du
  Coffre.
- `session` la donne à gpg-agent (gpg-preset-passphrase) pour N minutes, puis
  l'agent l'oublie (CLEAR_PASSPHRASE planifié par systemd). Coffre scellé :
  pas de session, pas de signature.

Niveau 0 (« conservation sans phrase humaine, déverrouillée au démarrage ») :
- `proteger_demarrage` pose la même phrase aléatoire, mais la range au NIVEAU 0
  (systemd-creds, chiffrée par la clé d'hôte) au lieu du Coffre : aucune phrase
  détenue par un humain, aucune ouverture du Coffre nécessaire ;
- `deverrouiller` la redonne à gpg-agent, sans échéance (TTL d'un an), et le fait au
  démarrage (secubox-depot-deverrouille.service). Le fichier de clé sur disque
  reste chiffré en permanence : une copie du disque ou de /root/.gnupg ne signe pas.
  En contrepartie, root sur la box peut signer à tout moment — c'est le choix du niveau 0.

La phrase ne passe jamais par la ligne de commande : un fichier 0600 dans un
répertoire 0700, détruit aussitôt.
"""
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Optional

GNUPGHOME_DEFAUT = "/root/.gnupg"
PRESET = "/usr/lib/gnupg/gpg-preset-passphrase"
SESSION_MAX_MIN = 60


class ErreurDepot(RuntimeError):
    pass


def nom_secret(empreinte: str) -> str:
    return "depot-" + empreinte[-16:].lower()


def _env(gnupghome: str) -> dict:
    e = dict(os.environ)
    e["GNUPGHOME"] = gnupghome
    return e


def _gpg(args, gnupghome, **k):
    return subprocess.run(["gpg", "--batch", *args], env=_env(gnupghome), capture_output=True, text=True, **k)


def empreinte_signature(distributions: Path = Path("/srv/apt/conf/distributions"),
                        gnupghome: str = GNUPGHOME_DEFAUT) -> str:
    """La clé qui signe : `SignWith` de reprepro, ou la clé secrète par défaut."""
    choix = "default"
    if distributions.exists():
        for ligne in distributions.read_text().splitlines():
            if ligne.startswith("SignWith:"):
                choix = ligne.split(":", 1)[1].strip()
                break
    r = _gpg(["--with-colons", "--list-secret-keys"] + ([] if choix in ("default", "yes") else [choix]), gnupghome)
    for ligne in r.stdout.splitlines():
        if ligne.startswith("fpr:"):
            return ligne.split(":")[9]
    raise ErreurDepot("aucune clé secrète de signature trouvée")


def keygrips(empreinte: str, gnupghome: str = GNUPGHOME_DEFAUT) -> list:
    r = _gpg(["--with-colons", "--with-keygrip", "--list-secret-keys", empreinte], gnupghome)
    grips = [l.split(":")[9] for l in r.stdout.splitlines() if l.startswith("grp:")]
    if not grips:
        raise ErreurDepot(f"clé secrète {empreinte[-16:]} introuvable")
    return grips


def _keyinfo(grip: str, gnupghome: str) -> list:
    r = subprocess.run(["gpg-connect-agent", f"KEYINFO {grip}", "/bye"], env=_env(gnupghome),
                       capture_output=True, text=True)
    for ligne in r.stdout.splitlines():
        if ligne.startswith("S KEYINFO"):
            return ligne.split()
    return []


def etat(empreinte: str, gnupghome: str = GNUPGHOME_DEFAUT) -> dict:
    """protegee : toutes les parties portent une phrase ; en_cache : l'agent la tient."""
    parts = []
    for g in keygrips(empreinte, gnupghome):
        f = _keyinfo(g, gnupghome)
        # S KEYINFO <grip> <type> <serial> <idstr> <cached> <protection> ...
        parts.append({"keygrip": g, "en_cache": len(f) > 6 and f[6] == "1",
                      "protegee": len(f) > 7 and f[7] == "P"})
    return {"empreinte": empreinte, "parties": parts,
            "protegee": all(p["protegee"] for p in parts),
            "en_cache": all(p["en_cache"] for p in parts)}


def _assure_preset(gnupghome: str) -> None:
    conf = Path(gnupghome) / "gpg-agent.conf"
    lignes = conf.read_text().splitlines() if conf.exists() else []
    if "allow-preset-passphrase" not in (l.strip() for l in lignes):
        lignes.append("allow-preset-passphrase")
        conf.write_text("\n".join(lignes) + "\n")
        os.chmod(conf, 0o600)
    subprocess.run(["gpgconf", "--reload", "gpg-agent"], env=_env(gnupghome), capture_output=True)


def _fichier_phrase(phrase: str):
    rep = tempfile.mkdtemp(prefix="sbx-depot-")
    os.chmod(rep, 0o700)
    f = os.path.join(rep, "p")
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as h:
        h.write(phrase)
    return rep, f


def _detruit(rep: str) -> None:
    for racine, _, fichiers in os.walk(rep):
        for n in fichiers:
            p = os.path.join(racine, n)
            try:
                with open(p, "r+b") as h:
                    h.write(b"\0" * max(1, os.path.getsize(p)))
            except OSError:
                pass
    shutil.rmtree(rep, ignore_errors=True)


def _signe_essai(empreinte: str, gnupghome: str) -> bool:
    rep = tempfile.mkdtemp(prefix="sbx-depot-essai-")
    try:
        msg = os.path.join(rep, "m")
        Path(msg).write_text("secubox-coffre essai de signature\n")
        _gpg(["--pinentry-mode", "error", "-u", empreinte, "-o", msg + ".sig", "--detach-sign", msg], gnupghome)
        return os.path.exists(msg + ".sig") and os.path.getsize(msg + ".sig") > 0
    finally:
        shutil.rmtree(rep, ignore_errors=True)


def _preset(grips, phrase: str, gnupghome: str) -> None:
    for g in grips:
        r = subprocess.run([PRESET, "--preset", g], input=phrase, env=_env(gnupghome),
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise ErreurDepot("gpg-preset-passphrase a refusé (allow-preset-passphrase ?)")


def oublier(empreinte: str, gnupghome: str = GNUPGHOME_DEFAUT) -> None:
    for g in keygrips(empreinte, gnupghome):
        subprocess.run(["gpg-connect-agent", f"CLEAR_PASSPHRASE --mode=normal {g}", "/bye"],
                       env=_env(gnupghome), capture_output=True)


def proteger(empreinte: str, poser: Callable[[str, str], None], gnupghome: str = GNUPGHOME_DEFAUT) -> None:
    """Pose une phrase aléatoire sur la clé, rangée au Coffre AVANT d'être appliquée."""
    e = etat(empreinte, gnupghome)
    if e["protegee"]:
        raise ErreurDepot("la clé porte déjà une phrase — rien à faire")
    grips = [p["keygrip"] for p in e["parties"]]
    phrase = secrets.token_urlsafe(32)
    poser(nom_secret(empreinte), phrase)                  # 1. au Coffre d'abord
    _assure_preset(gnupghome)
    priv = Path(gnupghome) / "private-keys-v1.d"
    sauve = tempfile.mkdtemp(prefix="sbx-depot-sauve-")
    os.chmod(sauve, 0o700)
    rep = None
    try:
        for g in grips:                                   # 2. filet, détruit ensuite
            shutil.copy2(priv / f"{g}.key", Path(sauve) / f"{g}.key")
        rep, f = _fichier_phrase(phrase)
        r = _gpg(["--pinentry-mode", "loopback", "--passphrase-file", f, "--passwd", empreinte], gnupghome)
        subprocess.run(["gpgconf", "--reload", "gpg-agent"], env=_env(gnupghome), capture_output=True)
        apres = etat(empreinte, gnupghome)
        if r.returncode != 0 or not apres["protegee"]:
            raise ErreurDepot("gpg --passwd n'a pas protégé la clé")
        if _signe_essai(empreinte, gnupghome):            # 3. refuse sans la phrase
            raise ErreurDepot("la clé signe encore sans phrase")
        _preset(grips, phrase, gnupghome)                 # 4. signe avec
        ok = _signe_essai(empreinte, gnupghome)
        oublier(empreinte, gnupghome)
        if not ok:
            raise ErreurDepot("la clé ne signe pas avec la phrase du Coffre")
    except Exception:
        for g in grips:                                   # retour : la clé d'avant
            if (Path(sauve) / f"{g}.key").exists():
                shutil.copy2(Path(sauve) / f"{g}.key", priv / f"{g}.key")
        subprocess.run(["gpgconf", "--reload", "gpg-agent"], env=_env(gnupghome), capture_output=True)
        raise
    finally:
        if rep:
            _detruit(rep)
        _detruit(sauve)                                   # jamais de copie en clair qui traîne
        del phrase


TTL_LONG = 31536000      # un an : le preset ne doit pas expirer entre deux démarrages


def _assure_ttl_long(gnupghome: str) -> None:
    conf = Path(gnupghome) / "gpg-agent.conf"
    lignes = conf.read_text().splitlines() if conf.exists() else []
    gardees = [l for l in lignes if l.split(" ")[0] not in ("default-cache-ttl", "max-cache-ttl")]
    gardees += [f"default-cache-ttl {TTL_LONG}", f"max-cache-ttl {TTL_LONG}"]
    if gardees != lignes:
        conf.write_text("\n".join(gardees) + "\n")
        os.chmod(conf, 0o600)
    subprocess.run(["gpgconf", "--reload", "gpg-agent"], env=_env(gnupghome), capture_output=True)


def proteger_demarrage(empreinte: str, gnupghome: str = GNUPGHOME_DEFAUT) -> None:
    """Phrase aléatoire rangée au niveau 0 (systemd-creds), clé protégée puis déverrouillée."""
    from coffre import niveau0

    def poser(nom: str, phrase: str) -> None:
        niveau0.chiffrer(nom, phrase.encode())
        if niveau0.dechiffrer(nom).decode() != phrase:       # on ne peut pas la perdre
            raise ErreurDepot("la crédence de niveau 0 ne se relit pas à l'identique — clé NON modifiée")
    proteger(empreinte, poser, gnupghome=gnupghome)
    deverrouiller(empreinte, gnupghome)


def deverrouiller(empreinte: str, gnupghome: str = GNUPGHOME_DEFAUT) -> dict:
    """Redonne la phrase de niveau 0 à gpg-agent, sans échéance, et vérifie que la clé signe."""
    from coffre import niveau0
    try:
        phrase = niveau0.dechiffrer(nom_secret(empreinte)).decode()
    except niveau0.ErreurNiveau0 as e:
        raise ErreurDepot(f"pas de phrase de niveau 0 pour cette clé : {e}")
    grips = keygrips(empreinte, gnupghome)
    _assure_preset(gnupghome)
    _assure_ttl_long(gnupghome)
    _preset(grips, phrase, gnupghome)
    del phrase
    if not _signe_essai(empreinte, gnupghome):
        oublier(empreinte, gnupghome)
        raise ErreurDepot("la phrase de niveau 0 ne déverrouille pas la clé")
    return etat(empreinte, gnupghome)


def session(empreinte: str, phrase: str, minutes: int, planifier: Optional[Callable[[int, list], None]] = None,
            gnupghome: str = GNUPGHOME_DEFAUT) -> dict:
    """Donne la phrase à gpg-agent pour `minutes`, puis la fait oublier."""
    if not 1 <= int(minutes) <= SESSION_MAX_MIN:
        raise ErreurDepot(f"durée de session : 1 à {SESSION_MAX_MIN} minutes")
    grips = keygrips(empreinte, gnupghome)
    _assure_preset(gnupghome)
    _preset(grips, phrase, gnupghome)
    if not _signe_essai(empreinte, gnupghome):
        oublier(empreinte, gnupghome)
        raise ErreurDepot("la phrase du Coffre ne déverrouille pas la clé")
    (planifier or planifier_oubli)(int(minutes), [empreinte, gnupghome])
    return etat(empreinte, gnupghome)


def planifier_oubli(minutes: int, quoi: list) -> None:
    """systemd-run : l'agent oublie la phrase à l'échéance, même si personne n'y pense."""
    empreinte, gnupghome = quoi
    grips = keygrips(empreinte, gnupghome)
    cmd = ["systemd-run", "--quiet", "--collect", f"--on-active={minutes}min",
           "--unit", f"secubox-depot-oubli-{empreinte[-8:].lower()}-{secrets.token_hex(3)}",
           f"--setenv=GNUPGHOME={gnupghome}", "/bin/sh", "-c",
           " ; ".join(f"gpg-connect-agent 'CLEAR_PASSPHRASE --mode=normal {g}' /bye" for g in grips)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        oublier(empreinte, gnupghome)
        raise ErreurDepot("impossible de planifier l'oubli — session annulée")
