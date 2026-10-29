# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
secubox_core.unites — piloter une unité secubox-*.service depuis une API (#3258, audit R1)
==========================================================================================
UN SEUL contrôle pour toute route qui démarre, arrête, relance ou recharge une unité :
`/system/service_control` (secubox-system, User=secubox, autorisé par polkit) et
`/admin/service/<nom>/<action>` (secubox-admin, root, donc SANS polkit). Avant, le nom passait tel quel à
systemctl (un « -H… » ou « --… » devenait une option), toute unité, cœur compris, pouvait être arrêtée, et rien
n'était audité ; la page /admin/ contournait même le refus de /system/.

`piloter` est bloquant (systemctl) : une route async l'appelle par `await asyncio.to_thread(...)`.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path

from fastapi import HTTPException

from .logger import get_logger

log = get_logger("unites")

# Même motif que la règle polkit de secubox-system (polkit/50-secubox-system.rules) : ce que l'API accepte est ce
# que polkit autorise. Les unités Debian (nginx, nftables…) ne se pilotent pas par une API.
MOTIF_UNITE = re.compile(r"^secubox-[A-Za-z0-9@._-]+\.service$")
ACTIONS = ("start", "stop", "restart", "reload")

# Unités qu'aucune API ne peut ARRÊTER (start, restart et reload restent permis : ils servent à réparer).
# À GARDER SYNCHRONE avec PROTECTED_IDS de packages/secubox-profiles/api/manifest.py (audit #3258 R1/R8), qui en est
# le sous-ensemble côté moteur de profils ; ici s'ajoutent les briques dont l'arrêt coupe l'entrée, le maillage ou
# la défense (WAF, hub, HAProxy, p2p, WireGuard, durcissement, dns-guard) et l'API système elle-même.
# Seules les unités livrées par un paquet du dépôt y figurent (« firewall » de PROTECTED_IDS n'a pas d'unité
# secubox-firewall.service) : packages/secubox-system/tests/test_service_control_3258.py le vérifie.
UNITES_PROTEGEES = frozenset({
    "secubox-auth.service", "secubox-aggregator.service", "secubox-core.service",
    "secubox-profiles.service", "secubox-vault.service", "secubox-autoload-agent.service",
    "secubox-waf-ng.service", "secubox-hub.service", "secubox-system.service", "secubox-haproxy.service",
    "secubox-p2p.service", "secubox-wireguard.service", "secubox-hardening.service", "secubox-dns-guard.service",
})

# Ruling R2 du contrôleur (#3258) : /admin/ (root) liste TOUS les services systemd. Quatre unités Debian y restent
# réparables (start, restart, reload), JAMAIS arrêtables : sans elles, plus d'entrée web, de résolution DNS ni de
# shell distant. Option explicite `avec_unites_debian`, que seules les routes /admin/ activent ; service_control
# (secubox-system, polkit) reste sur secubox-*. Toute autre unité hors secubox-* : 400.
UNITES_DEBIAN_ADMIN = frozenset({"nginx.service", "haproxy.service", "unbound.service", "ssh.service"})

# Journal d'audit central, en ajout seul (patron de secubox-freebox, _journal_fichier : une ligne JSON par décision,
# « module » = l'émetteur). Jamais la sortie de systemctl : seulement qui, quoi, sur quoi, et le résultat.
AUDIT_LOG = Path("/var/log/secubox/audit.log")


def journaliser(module: str, acteur: str, action: str, unite: str, resultat: str, code: int, motif: str = "") -> None:
    entree = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "module": module,
              "evenement": "service_control", "acteur": acteur, "action": action, "unite": unite,
              "resultat": resultat, "code": code}
    if motif:
        entree["motif"] = motif
    ligne = json.dumps(entree, ensure_ascii=False)
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(ligne + "\n")
    except OSError as e:
        # Un audit qui ne s'écrit pas ne doit pas passer en silence (audit #3258 R13) : il reste au journal du service.
        log.warning("audit.log non écrit (%s) : %s", e.__class__.__name__, ligne)


def normaliser(nom: str) -> str:
    """Les pages envoient le nom nu (« secubox-dpi ») : systemctl le complétait en « .service ».
    On le complète ICI, avant de valider et de contrôler la protection, et c'est ce nom-là qui part à systemctl.
    Un nom qui porte déjà un point garde son suffixe (« secubox-hub.timer » reste refusé)."""
    return nom if "." in nom else nom + ".service"


def _systemctl(action: str, unite: str, delai: int) -> tuple[bool, str]:
    """`systemctl <action> -- <unité>` : le « -- » interdit qu'un nom soit lu comme une option."""
    try:
        r = subprocess.run(["systemctl", action, "--", unite],
                           capture_output=True, text=True, timeout=delai, check=True)
        return True, ((r.stdout or "") + (r.stderr or "")).strip()
    except subprocess.CalledProcessError as e:
        return False, ((e.stdout or "") + (e.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return False, f"Délai dépassé en attendant {unite}"


def piloter(module: str, acteur: str, action: str, nom: str, *, delai: int = 30,
            avec_unites_debian: bool = False) -> dict:
    """Valide, protège, exécute et audite. 400 : action ou nom invalide ; 403 : arrêt d'une unité protégée.
    `avec_unites_debian` (routes /admin/ seulement) : UNITES_DEBIAN_ADMIN acceptées, sauf pour un arrêt.
    Un échec de systemctl n'est pas une exception : `success` faux, la raison dans `output` (jamais dans l'audit)."""
    unite = normaliser(nom)
    if action not in ACTIONS:
        journaliser(module, acteur, action[:32], unite[:128], "refuse", 400, "action invalide")
        raise HTTPException(400, "action invalide")
    debian = avec_unites_debian and unite in UNITES_DEBIAN_ADMIN
    if not debian and not MOTIF_UNITE.fullmatch(unite):
        journaliser(module, acteur, action, unite[:128], "refuse", 400, "nom d'unité invalide")
        raise HTTPException(400, "nom d'unité invalide : secubox-<nom>.service attendu")
    if action == "stop" and (debian or unite in UNITES_PROTEGEES):
        journaliser(module, acteur, action, unite, "refuse", 403, "unité Debian protégée" if debian else "unité protégée")
        raise HTTPException(403, "unité protégée : arrêt refusé")
    ok, sortie = _systemctl(action, unite, delai)
    journaliser(module, acteur, action, unite, "ok" if ok else "echec", 200)
    log.info("%s : %s %s → %s", module, action, unite, "OK" if ok else "ÉCHEC")
    return {"success": ok, "service": unite, "unit": unite, "action": action, "output": sortie[:300]}
