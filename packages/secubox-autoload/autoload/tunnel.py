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

import ipaddress
import os
import re
import sqlite3
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Callable, List, Optional

RESEAU = "10.64.0.0/16"
HUB = "10.64.0.1"
PORT_UDP = 51830
INTERFACE = "wg-autoload"
INFRA = "admin.gk2.secubox.in"
CLE_HUB_DEFAUT = Path("/etc/secubox/secrets/autoload-hub.key")
CONF_DEFAUT = Path("/etc/wireguard/wg-autoload.conf")
TIMEOUT_S = 30

_CLE_WG = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class PlageEpuisee(Exception):
    """Plus d'adresse libre dans la plage des clients."""


class TunnelErreur(Exception):
    """Le système a refusé une commande WireGuard ou systemd."""


class Pairs:
    """Les pairs du hub : une clé publique, une adresse. Même base SQLite que les jetons (un seul fichier 0600 à protéger)."""

    def __init__(self, db: Path, horloge: Callable[[], float] = time.time):
        self.db, self._horloge = Path(db), horloge
        self.db.parent.mkdir(parents=True, exist_ok=True)
        with self._cx() as cx:
            cx.executescript("CREATE TABLE IF NOT EXISTS pairs (cle_pub TEXT PRIMARY KEY, adresse TEXT NOT NULL UNIQUE, "
                             "cree_le INTEGER NOT NULL, retire_le INTEGER)")

    def _cx(self) -> sqlite3.Connection:
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


def synchroniser(pairs: Pairs, conf: Path = CONF_DEFAUT, cle_hub: Path = CLE_HUB_DEFAUT, executeur=subprocess.run) -> int:
    """Valide la configuration (wg-quick strip), la pose atomiquement, puis `wg syncconf` : aucun pair existant n'est coupé."""
    conf = Path(conf)
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
        nu.write_text(r.stdout, encoding="utf-8")
        nu.chmod(0o600)
        _ecrit_prive(conf, texte)
        s = executeur(["wg", "syncconf", INTERFACE, str(nu)], capture_output=True, text=True, timeout=TIMEOUT_S)
        if s.returncode != 0:                                                       # interface pas encore montée : on la monte
            d = executeur(["systemctl", "enable", "--now", f"wg-quick@{INTERFACE}.service"], capture_output=True, text=True, timeout=TIMEOUT_S)
            if d.returncode != 0:
                raise TunnelErreur("tunnel non monté : " + (d.stderr or s.stderr or "").strip()[:200])
    return len(actifs)


DOSSIER_DEFAUT = Path("/var/lib/secubox/autoload")


def demander_sync(dossier: Path = DOSSIER_DEFAUT, attente_s: float = 15.0, horloge: Callable[[], float] = time.monotonic,
                  dormir: Callable[[float], None] = time.sleep) -> None:
    """Le service d'enrôlement n'est PAS root : il dépose `sync.demande` (un jeton d'identification), l'unité `.path` lance `autoloadctl tunnel-sync` en root,
    qui recopie ce jeton dans `sync.fait`. On attend cet accusé : la box ne doit pas se voir répondre avant que son pair existe."""
    dossier = Path(dossier)
    marque = uuid.uuid4().hex
    tmp = dossier / f".sync-{marque}"
    tmp.write_text(marque, encoding="ascii")
    os.replace(tmp, dossier / "sync.demande")
    fin = horloge() + attente_s
    while horloge() < fin:
        try:
            if (dossier / "sync.fait").read_text(encoding="ascii").strip() == marque:
                return
        except OSError:
            pass
        dormir(0.25)
    raise TunnelErreur("le tunnel n'a pas été appliqué à temps")


def accuser_sync(dossier: Path = DOSSIER_DEFAUT) -> None:
    """Côté root, après un `tunnel-sync` réussi : rend à la demande en attente son accusé."""
    dossier = Path(dossier)
    try:
        marque = (dossier / "sync.demande").read_text(encoding="ascii").strip()
    except OSError:
        return
    if re.fullmatch(r"[0-9a-f]{32}", marque):
        _ecrit_prive(dossier / "sync.fait", marque)
