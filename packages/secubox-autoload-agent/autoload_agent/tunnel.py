# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload-agent :: le TUNNEL (côté box) (#2189, parent #2182, décision D7)

Sortant seulement : pas de ListenPort, pas de route par défaut (AllowedIPs = le hub /32). La clé privée est générée SUR LA BOX, jamais dans
l'image, écrite en 0600 sous /etc/secubox/secrets/, et ne passe jamais en argument de commande ni dans la configuration (`wg set … private-key <fichier>`).

Tout ce que l'infrastructure répond est validé (nom d'hôte épinglé, plage 10.64.0.0/16, clés WireGuard, aucun retour à la ligne) AVANT d'écrire un fichier.
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict

INFRA = "admin.gk2.secubox.in"
RESEAU = ipaddress.ip_network("10.64.0.0/16")
HUB = ipaddress.ip_address("10.64.0.1")
INTERFACE = "wg-autoload"
CLE_DEFAUT = Path("/etc/secubox/secrets/autoload-wg.key")
CONF_DEFAUT = Path("/etc/wireguard/wg-autoload.conf")
TIMEOUT_S = 30
CHAMPS = frozenset({"endpoint", "serveur_cle_pub", "adresse", "hub"})
_CLE_WG = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_ENDPOINT = re.compile(r"^([a-z0-9.-]{4,253}):([0-9]{1,5})$")


class TunnelInvalide(ValueError):
    """La réponse de l'infrastructure n'est pas acceptable : rien n'est écrit."""


class TunnelErreur(Exception):
    """Le système a refusé une commande WireGuard ou systemd."""


def assurer_cle(chemin: Path = CLE_DEFAUT, executeur=subprocess.run) -> str:
    """Rend la clé publique de la box ; crée la clé privée (0600) si elle n'existe pas. Une clé existante n'est jamais remplacée."""
    chemin = Path(chemin)
    if not chemin.exists():
        if not chemin.parent.exists():
            chemin.parent.mkdir(parents=True)
            os.chmod(chemin.parent, 0o700)                                           # notre dossier seulement ; un parent existant n'est jamais resserré
        g = executeur(["wg", "genkey"], capture_output=True, text=True, timeout=TIMEOUT_S)
        privee = (g.stdout or "").strip()
        if g.returncode != 0 or not privee:
            raise TunnelErreur("wg genkey a échoué")
        fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=".sbx-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(privee + "\n")
            os.replace(tmp, chemin)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
    p = executeur(["wg", "pubkey"], input=chemin.read_text(encoding="ascii").strip() + "\n", capture_output=True, text=True, timeout=TIMEOUT_S)
    pub = (p.stdout or "").strip()
    if p.returncode != 0 or not _CLE_WG.match(pub):
        raise TunnelErreur("wg pubkey a échoué")
    return pub


def valider(reponse: Dict[str, str], infra: str = INFRA) -> Dict[str, str]:
    if not isinstance(reponse, dict) or set(reponse) != CHAMPS or not all(isinstance(v, str) for v in reponse.values()):
        raise TunnelInvalide("réponse du tunnel : champs attendus " + ", ".join(sorted(CHAMPS)))
    m = _ENDPOINT.match(reponse["endpoint"])
    if not m or m.group(1) != infra or not 1 <= int(m.group(2)) <= 65535:
        raise TunnelInvalide(f"endpoint : {infra}:<port> uniquement")
    if not _CLE_WG.match(reponse["serveur_cle_pub"]):
        raise TunnelInvalide("serveur_cle_pub : clé WireGuard invalide")
    try:
        adresse = ipaddress.ip_interface(reponse["adresse"])
        hub = ipaddress.ip_interface(reponse["hub"])
    except ValueError as e:
        raise TunnelInvalide("adresse ou hub illisible") from e
    if adresse.network.prefixlen != 32 or adresse.ip not in RESEAU or adresse.ip == HUB or adresse.ip == RESEAU.broadcast_address:
        raise TunnelInvalide("adresse : une /32 de 10.64.0.0/16, hors hub")
    if str(hub) != f"{HUB}/32":
        raise TunnelInvalide(f"hub : {HUB}/32 uniquement")
    return reponse


def rendre_conf(reponse: Dict[str, str], cle: Path = CLE_DEFAUT, infra: str = INFRA) -> str:
    r = valider(reponse, infra)
    return "\n".join(["# GÉNÉRÉ par secubox-autoload-agent — ne pas éditer (#2189).", "[Interface]", f"Address = {r['adresse']}",
                      f"PostUp = wg set %i private-key {cle}", "", "[Peer]", f"PublicKey = {r['serveur_cle_pub']}",
                      f"Endpoint = {r['endpoint']}", f"AllowedIPs = {r['hub']}", "PersistentKeepalive = 25"]) + "\n"


def monter(reponse: Dict[str, str], cle: Path = CLE_DEFAUT, conf: Path = CONF_DEFAUT, infra: str = INFRA, executeur=subprocess.run) -> None:
    """Valide, écrit la configuration (0600) et active l'unité. Si l'activation échoue, la configuration posée est retirée."""
    texte = rendre_conf(reponse, cle, infra)
    conf = Path(conf)
    conf.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=conf.parent, prefix=".sbx-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(texte)
        os.replace(tmp, conf)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    r = executeur(["systemctl", "enable", "--now", f"wg-quick@{INTERFACE}.service"], capture_output=True, text=True, timeout=TIMEOUT_S)
    if r.returncode != 0:
        conf.unlink(missing_ok=True)
        raise TunnelErreur("tunnel non monté : " + (r.stderr or "").strip()[:200])
