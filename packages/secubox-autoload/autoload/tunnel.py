# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload :: le TUNNEL (côté infrastructure) (#2189, parent #2182, décision D7)

Étoile : chaque box cliente ouvre un tunnel WireGuard SORTANT vers ce hub. Plage dédiée 10.64.0.0/16 (hub 10.64.0.1), distincte de wg-mesh
10.10.0.0/24, wg-ephemeral 10.11.0.0/24 et des autres ; UDP 51830. Un pair n'a droit qu'à sa propre adresse /32 : les clients ne se voient pas.

La clé privée du hub n'est JAMAIS dans la configuration : `PostUp = wg set %i private-key <fichier 0600>`.
Une adresse retirée n'est jamais réattribuée ; une clé retirée ne revient pas sans nouveau jeton.
"""
from __future__ import annotations

import asyncio
import contextlib
import errno
import fcntl
import ipaddress
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterator, List, Optional

RESEAU = "10.64.0.0/16"
HUB = "10.64.0.1"
PORT_UDP = 51830
INTERFACE = "wg-autoload"
INFRA = "admin.gk2.secubox.in"
CLE_HUB_DEFAUT = Path("/etc/secubox/secrets/autoload-hub.key")
CONF_DEFAUT = Path("/etc/wireguard/wg-autoload.conf")
UNITE = f"wg-quick@{INTERFACE}.service"
VERROU_DEFAUT = Path("/run/secubox/autoload-sync.lock")
TIMEOUT_S = 30

_CLE_WG = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class PlageEpuisee(Exception):
    """Plus d'adresse libre dans la plage des clients."""


class TunnelErreur(Exception):
    """Le système a refusé une commande WireGuard ou systemd."""


class Pairs:
    """Les pairs du hub : une clé publique, une adresse. Même base SQLite que les jetons (un seul fichier 0600 à protéger)."""

    def __init__(self, db: Path, horloge: Callable[[], float] = time.time, lecture_seule: bool = False):
        """`lecture_seule` : pour l'assistant root (tunnel-sync) — il lit les pairs, ne crée ni ne modifie jamais la base du service."""
        self.db, self._horloge, self._ro = Path(db), horloge, lecture_seule
        if lecture_seule:
            return
        self.db.parent.mkdir(parents=True, exist_ok=True)
        with self._cx() as cx:
            cx.executescript("CREATE TABLE IF NOT EXISTS pairs (cle_pub TEXT PRIMARY KEY, adresse TEXT NOT NULL UNIQUE, "
                             "cree_le INTEGER NOT NULL, retire_le INTEGER)")

    def _cx(self) -> sqlite3.Connection:
        if self._ro:
            cx = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True, timeout=15, isolation_level=None)
            cx.row_factory = sqlite3.Row
            return cx
        cx = sqlite3.connect(self.db, timeout=15, isolation_level=None)
        cx.row_factory = sqlite3.Row
        return cx

    def attribuer(self, cle_pub: str) -> str:
        """L'adresse (sans masque) de la box ; la même clé retrouve toujours la sienne."""
        if not isinstance(cle_pub, str) or not _CLE_WG.match(cle_pub):
            raise ValueError("clé publique WireGuard invalide")
        reseau = ipaddress.ip_network(RESEAU)
        with self._cx() as cx:
            cx.execute("BEGIN IMMEDIATE")
            try:
                r = cx.execute("SELECT adresse, retire_le FROM pairs WHERE cle_pub=?", (cle_pub,)).fetchone()
                if r is not None:
                    cx.execute("ROLLBACK")
                    if r["retire_le"] is not None:
                        raise ValueError("clé retirée : un nouveau jeton est nécessaire")
                    return r["adresse"]
                dernier = cx.execute("SELECT adresse FROM pairs").fetchall()
                plus_haute = max([int(ipaddress.ip_address(x["adresse"])) for x in dernier] + [int(ipaddress.ip_address(HUB))])
                suivante = ipaddress.ip_address(plus_haute + 1)
                if suivante not in reseau or suivante == reseau.broadcast_address:
                    cx.execute("ROLLBACK")
                    raise PlageEpuisee(f"plus d'adresse libre dans {RESEAU}")
                cx.execute("INSERT INTO pairs (cle_pub, adresse, cree_le) VALUES (?,?,?)", (cle_pub, str(suivante), int(self._horloge())))
                cx.execute("COMMIT")
                return str(suivante)
            except (ValueError, PlageEpuisee):
                raise
            except sqlite3.Error:
                cx.execute("ROLLBACK")
                raise

    def retirer(self, cle_pub: Optional[str]) -> bool:
        if not cle_pub:
            return False
        with self._cx() as cx:
            return cx.execute("UPDATE pairs SET retire_le=? WHERE cle_pub=? AND retire_le IS NULL", (int(self._horloge()), cle_pub)).rowcount > 0

    def actifs(self) -> List[dict]:
        with self._cx() as cx:
            return [dict(r) for r in cx.execute("SELECT cle_pub, adresse FROM pairs WHERE retire_le IS NULL ORDER BY adresse")]


def rendre_hub(pairs: List[dict], cle_privee: Path = CLE_HUB_DEFAUT) -> str:
    masque = ipaddress.ip_network(RESEAU).prefixlen
    lignes = ["# GÉNÉRÉ par autoloadctl (secubox-autoload) — ne pas éditer (#2189).", "[Interface]",
              f"Address = {HUB}/{masque}", f"ListenPort = {PORT_UDP}", f"PostUp = wg set %i private-key {cle_privee}"]
    for p in pairs:
        lignes += ["", "[Peer]", f"PublicKey = {p['cle_pub']}", f"AllowedIPs = {p['adresse']}/32"]
    return "\n".join(lignes) + "\n"


def gabarit_box(adresse: str, cle_pub_hub: str) -> dict:
    """Ce que l'infrastructure remet à une box qui vient de réclamer son jeton."""
    return {"endpoint": f"{INFRA}:{PORT_UDP}", "serveur_cle_pub": cle_pub_hub, "adresse": f"{adresse}/32", "hub": f"{HUB}/32"}


def _ecrit_prive(chemin: Path, texte: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=".sbx-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(texte)
        os.replace(tmp, chemin)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _avec_cle(strip: str, cle_hub: Path) -> str:
    """`wg syncconf` applique la configuration TELLE QUELLE : sans PrivateKey il ÉTEINT la clé de l'interface (constaté sur gk2 : le tunnel perdait sa clé à
    la première synchronisation, PostUp ne s'exécutant qu'à la montée). La clé est donc ajoutée au seul fichier passé à syncconf (0600, dossier privé,
    supprimé ensuite) ; elle n'est jamais dans la configuration posée ni en argument de commande."""
    cle = Path(cle_hub).read_text(encoding="ascii").strip()
    lignes = strip.splitlines()
    for i, ligne in enumerate(lignes):
        if ligne.strip() == "[Interface]":
            lignes.insert(i + 1, f"PrivateKey = {cle}")
            return "\n".join(lignes) + "\n"
    raise TunnelErreur("configuration sans section [Interface]")


def _ouvrir_verrou(chemin: Path) -> int:
    """Le descripteur du verrou : un fichier ORDINAIRE du compte courant (root en production), jamais suivi s'il est un lien.

    Il vit dans /run/secubox (1777, sticky) : un autre compte peut y avoir posé ce nom avant root (lien, FIFO, fichier à lui, que root ne peut
    d'ailleurs pas ouvrir : protected_regular, et l'assistant n'a pas CAP_DAC_OVERRIDE). Ce nom est alors retiré (root possède le dossier, le
    bit sticky le lui permet) puis recréé en O_EXCL. Un fichier à root n'est JAMAIS retiré : c'est le verrou d'un autre passage."""
    drapeaux = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    for _ in range(3):
        try:
            fd = os.open(chemin, drapeaux | os.O_CREAT, 0o600)
        except OSError as e:
            if e.errno not in (errno.ELOOP, errno.EACCES, errno.EPERM, errno.ENXIO):
                raise TunnelErreur(f"verrou {chemin} : {e.strerror}") from None
        else:
            st = os.fstat(fd)
            if stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid():
                return fd
            os.close(fd)
        try:
            os.unlink(chemin)
        except FileNotFoundError:
            pass
        except OSError as e:
            raise TunnelErreur(f"verrou {chemin} piégé et non retirable : {e.strerror}") from None
        try:
            return os.open(chemin, drapeaux | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        except OSError as e:
            raise TunnelErreur(f"verrou {chemin} : {e.strerror}") from None
    raise TunnelErreur(f"verrou {chemin} disputé")


@contextlib.contextmanager
def verrou_sync(chemin: Path = VERROU_DEFAUT) -> Iterator[None]:
    """tunnel-sync et exporter-pairs passent UN PAR UN, quel que soit l'appelant (enrôlement, révocation, abonnement, minuterie) (#3126, N3).

    Sans lui, un passage qui avait lu les pairs AVANT une révocation reposait le pair révoqué APRÈS la synchronisation de la révocation, pour
    une heure ; un export lent pouvait de même écraser une projection plus fraîche. Chaque passage lit la base sous le verrou, et toute
    écriture dans la base (révocation, enrôlement) est suivie d'un tunnel-sync : le dernier passage voit toujours le dernier état. L'écriture
    dans la base n'a pas besoin du verrou (le service le prendrait puis attendrait son propre tunnel-sync lancé par sudo). Attente bloquante :
    un passage est borné par les délais de ses commandes (TIMEOUT_S chacune)."""
    fd = _ouvrir_verrou(Path(chemin))
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)                                                                   # libère le verrou


def _unite_activee(executeur) -> bool:
    """L'unité de l'interface est-elle activée (au démarrage) ? « disabled » ou « masked » : l'exploitant l'a arrêtée."""
    try:
        r = executeur(["systemctl", "is-enabled", "--quiet", UNITE], capture_output=True, text=True, timeout=TIMEOUT_S)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def synchroniser(pairs: Pairs, conf: Path = CONF_DEFAUT, cle_hub: Path = CLE_HUB_DEFAUT, executeur=subprocess.run, activer: bool = True) -> int:
    """Valide la configuration (wg-quick strip), la pose atomiquement, puis `wg syncconf` : aucun pair existant n'est coupé.

    Interface absente : `activer` (enrôlement, révocation, abonnement) la monte (`enable --now`), même jamais activée (première box).
    `activer=False` (minuterie horaire, #3126 N4) : seulement si son unité est activée ; désactivée, l'exploitant l'a arrêtée, elle n'est pas
    relancée — la configuration est posée pour le jour où il la relancera."""
    conf = Path(conf)
    if not Path(cle_hub).is_file():
        raise TunnelErreur("clé du hub absente (autoloadctl tunnel-init)")
    conf.parent.mkdir(parents=True, exist_ok=True)
    actifs = pairs.actifs()
    texte = rendre_hub(actifs, cle_hub)
    with tempfile.TemporaryDirectory(prefix="sbx-wg-", dir=conf.parent) as tmpd:
        os.chmod(tmpd, 0o700)
        essai = Path(tmpd) / (INTERFACE + ".conf")
        essai.write_text(texte, encoding="utf-8")
        essai.chmod(0o600)
        r = executeur(["wg-quick", "strip", str(essai)], capture_output=True, text=True, timeout=TIMEOUT_S)
        if r.returncode != 0:
            raise TunnelErreur("configuration refusée par wg-quick : " + (r.stderr or "").strip()[:200])
        nu = Path(tmpd) / "strip.conf"
        nu.write_text(_avec_cle(r.stdout, cle_hub), encoding="utf-8")
        nu.chmod(0o600)
        _ecrit_prive(conf, texte)
        s = executeur(["wg", "syncconf", INTERFACE, str(nu)], capture_output=True, text=True, timeout=TIMEOUT_S)
        if s.returncode != 0:                                                       # interface pas encore montée : on la monte
            if not activer and not _unite_activee(executeur):
                print(f"autoload : {UNITE} désactivée par l'exploitant : configuration posée, interface non relancée", file=sys.stderr)
                return len(actifs)
            d = executeur(["systemctl", "enable", "--now", UNITE], capture_output=True, text=True, timeout=TIMEOUT_S)
            if d.returncode != 0:
                raise TunnelErreur("tunnel non monté : " + (d.stderr or s.stderr or "").strip()[:200])
    return len(actifs)


DOSSIER_DEFAUT = Path("/var/lib/secubox/autoload")
SUDO_SYNC = ["sudo", "-n", "/usr/sbin/autoloadctl", "tunnel-sync"]       # argv exacts : c'est ce que le sudoers du paquet accorde, rien d'autre
SUDO_SYNC_HORAIRE = SUDO_SYNC + ["--horaire"]                              # minuterie : ne relance pas une interface désactivée (#3126, N4)


def appliquer_par_sudo(executeur=subprocess.run, timeout: int = 30, argv: Optional[List[str]] = None) -> None:
    """Le service d'enrôlement n'est PAS root (et aucune nouvelle unité root n'est permise) : il demande l'application du tunnel au SEUL assistant
    que son sudoers lui accorde. L'enrôlement n'est confirmé à la box qu'une fois les pairs réellement appliqués."""
    try:
        r = executeur(argv or SUDO_SYNC, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise TunnelErreur(f"synchronisation impossible ({type(e).__name__})") from e
    if r.returncode != 0:
        raise TunnelErreur("synchronisation refusée : " + (r.stderr or r.stdout or "").strip()[:200])


def appliquer_horaire_par_sudo(executeur=subprocess.run, timeout: int = 30) -> None:
    """Le passage de la minuterie : `autoloadctl tunnel-sync --horaire` (argv exact du sudoers) réexporte la projection et resynchronise les
    pairs, mais ne relance jamais un wg-autoload dont l'unité est désactivée (#3126, N4)."""
    appliquer_par_sudo(executeur, timeout, SUDO_SYNC_HORAIRE)


REPUBLICATION_S = 3600            # R37 (#3126) : la projection publique est recalculée au moins une fois par heure
REPUBLICATION_DELAI_S = 60        # premier passage peu après le démarrage du service (projection fraîche après un arrêt)


async def republier_periodiquement(appliquer: Callable[[], None], intervalle_s: float = REPUBLICATION_S,
                                   premier_delai_s: float = REPUBLICATION_DELAI_S, attente=asyncio.sleep) -> None:
    """Minuterie horaire DU SERVICE (aucune unité de plus, aucune unité root, #2190) : relance `autoloadctl tunnel-sync` par l'argv sudo exact, qui
    réexporte la projection publique des pairs lue par le maître de pilotage. Un abonnement dont l'échéance vient de passer y devient `echu` sans
    aucune action d'administration (#3126, R37). Un passage en échec est journalisé, le suivant réessaie ; s'arrête à l'annulation."""
    await attente(premier_delai_s)
    while True:
        try:
            await asyncio.to_thread(appliquer)
        except Exception as e:  # noqa: BLE001 — sudo, wg, base : la minuterie ne s'arrête jamais sur un passage raté
            print(f"autoload : republication horaire impossible ({type(e).__name__} : {str(e)[:200]}) ; nouvel essai dans {int(intervalle_s)} s",
                  file=sys.stderr)
        await attente(intervalle_s)
