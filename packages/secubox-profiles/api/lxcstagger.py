# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — étalement du démarrage des conteneurs
CyberMind — https://cybermind.fr

POURQUOI CE MODULE EXISTE

23 conteneurs déclaraient `lxc.start.auto = 1` **sans ordre ni délai**. Ils
partaient donc tous ensemble, chacun démarrant une pile systemd complète, sur
4 cœurs. Mesuré au redémarrage du 2026-08-07 : **charge 120**, 27 jobs systemd
en attente, `multi-user.target` jamais atteint, HAProxy jamais lancé — la board
revenait à moitié levée et il fallait la finir à la main.

Ce n'est pas un problème de lenteur mais de SIMULTANÉITÉ : les mêmes
conteneurs démarrent très bien les uns après les autres.

DEUX RÉGLAGES LXC, ET ILS NE FONT PAS LA MÊME CHOSE

  lxc.start.order  Ordre de passage. `lxc-autostart` trie par ordre
                   DÉCROISSANT : le plus grand démarre en PREMIER.
  lxc.start.delay  Secondes d'attente APRÈS avoir lancé ce conteneur, avant
                   de lancer le suivant. C'est lui qui étale réellement.

L'ordre vient de la `priority` du manifeste (0-100), déjà utilisée par
l'actionneur pour ordonner les plans : une seule source de vérité, pas un
second classement à tenir à jour.

Le délai, lui, est gradué par priorité : l'infrastructure passe vite (elle
porte le reste), les applications attendent davantage — c'est leur démarrage
qui coûte, et personne ne les attend dans la seconde.
"""
from __future__ import annotations

import re
from pathlib import Path

DEFAULT_LXC_PATH = Path("/data/lxc")

# Délai après lancement, en secondes, par tranche de priorité.
#
# Volontairement généreux sur les basses priorités : un conteneur applicatif
# met plusieurs secondes à monter sa pile systemd, et le suivant qui démarre
# pendant ce pic est exactement ce qu'on cherche à éviter.
_DELAY_BANDS = (
    (80, 3),    # priorité >= 80 : infrastructure — vite, le reste en dépend
    (60, 5),
    (40, 8),
    (0, 12),    # priorité < 40 : applicatif — on laisse retomber la charge
)

_ORDER_RE = re.compile(r"^\s*lxc\.start\.order\s*=.*$", re.M)
_DELAY_RE = re.compile(r"^\s*lxc\.start\.delay\s*=.*$", re.M)
_AUTO_RE = re.compile(r"^\s*lxc\.start\.auto\s*=\s*(\d+)", re.M)


def delay_for(priority: int) -> int:
    for threshold, delay in _DELAY_BANDS:
        if priority >= threshold:
            return delay
    return _DELAY_BANDS[-1][1]


def plan(manifests, *, lxc_path: Path = DEFAULT_LXC_PATH) -> list[dict]:
    """Ce qu'il faudrait écrire, sans rien écrire.

    Ne concerne QUE les conteneurs en démarrage automatique : régler l'ordre
    d'un conteneur que personne ne démarre au boot n'a aucun effet et brouille
    la lecture du fichier."""
    out: list[dict] = []
    for m in sorted(manifests.values(), key=lambda x: -x.priority):
        if m.runtime != "lxc" or not m.lxc:
            continue
        cfg = Path(lxc_path) / m.lxc / "config"
        if not cfg.is_file():
            continue
        try:
            text = cfg.read_text(encoding="utf-8")
        except OSError:
            continue
        auto = _AUTO_RE.search(text)
        if not auto or auto.group(1) == "0":
            continue
        cur_order = _ORDER_RE.search(text)
        cur_delay = _DELAY_RE.search(text)
        want_order, want_delay = m.priority, delay_for(m.priority)

        # NE JAMAIS RETROGRADER UN ORDRE POSE A LA MAIN.
        #
        # `toolbox-mitm` et `toolbox-mitm-wg` portaient order=110 et 120 —
        # deliberement, pour passer avant tout le reste. Or la plupart des
        # manifestes gardent la priorite par defaut (50) : appliquer la
        # priorite telle quelle les aurait rétrogrades, cassant une intention
        # explicite dont la trace n'existe que dans ce fichier.
        #
        # Un ordre existant PLUS ELEVE est donc conserve, et signale.
        existing = None
        if cur_order:
            mo = re.search(r"=\s*(\d+)", cur_order.group(0))
            existing = int(mo.group(1)) if mo else None
        kept = existing is not None and existing > want_order
        if kept:
            want_order = existing
        out.append({
            "module": m.id, "lxc": m.lxc, "config": str(cfg),
            "order": want_order, "delay": want_delay,
            # `kept` distingue « je decide » de « je respecte une decision
            # anterieure » — sans quoi la sortie laisse croire que l'ordre
            # vient de la priorite alors qu'il vient du fichier.
            "kept_manual_order": kept,
            "changed": (cur_order is None or f"= {want_order}" not in cur_order.group(0)
                        or cur_delay is None or f"= {want_delay}" not in cur_delay.group(0)),
        })
    return out


def _set_key(text: str, regex: re.Pattern, line: str) -> str:
    if regex.search(text):
        return regex.sub(line, text, count=1)
    return text.rstrip("\n") + "\n" + line + "\n"


def apply(manifests, *, lxc_path: Path = DEFAULT_LXC_PATH) -> list[str]:
    """Écrit ordre et délai. Retourne les modules modifiés.

    L'écriture est idempotente : relancer ne produit aucun changement, ce qui
    permet de l'appeler après chaque installation sans redouter une dérive."""
    changed: list[str] = []
    for item in plan(manifests, lxc_path=lxc_path):
        if not item["changed"]:
            continue
        cfg = Path(item["config"])
        text = cfg.read_text(encoding="utf-8")
        text = _set_key(text, _ORDER_RE, f"lxc.start.order = {item['order']}")
        text = _set_key(text, _DELAY_RE, f"lxc.start.delay = {item['delay']}")
        cfg.write_text(text, encoding="utf-8")
        changed.append(item["module"])
    return changed


def total_window(manifests, *, lxc_path: Path = DEFAULT_LXC_PATH) -> int:
    """Durée totale d'étalement, en secondes.

    À dire à l'utilisateur : un étalement qui repousse le dernier conteneur à
    dix minutes n'est pas un réglage, c'est une panne différée."""
    return sum(i["delay"] for i in plan(manifests, lxc_path=lxc_path))
