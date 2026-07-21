# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — schéma et chargement des manifestes module
CyberMind — https://cybermind.fr

Un manifeste décrit le CYCLE DE VIE d'un module : ses units, son runtime, son
exposition, sa priorité. Il ne duplique pas menu.d/ (path, ordre, icône), qui
reste la source UI avec son propre cycle de vie.

La validation est stricte et bruyante : en Phase 3 un manifeste mal typé
deviendrait une décision d'extinction erronée. Mieux vaut refuser au chargement.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

RUNTIMES = ("native", "lxc")
EXPOSURES = ("public", "lan", "internal")
CATEGORIES = ("media", "security", "network", "infra", "dev", "mesh")
LIFECYCLES = ("always-on", "eager", "on-demand", "manual")
WAKE_CLASSES = ("normal", "urgent")

DEFAULT_PRIORITY = 50
# Fleet-safe default (#896 follow-up): a manifest that declares no lifecycle
# must never become sleep-eligible by accident. On a 184-module fleet,
# `eager` as the silent default made EVERY existing module idle-sleep
# eligible, including core services with no manifest opinion of their own
# (admin, gitea, nextcloud...). Sleep is now strictly opt-in: a module only
# idles/wakes if its manifest explicitly declares `eager` or `on-demand`.
DEFAULT_LIFECYCLE = "always-on"
DEFAULT_WAKE_CLASS = "normal"

# Le noyau protégé : éteindre l'un de ceux-là retire à l'utilisateur le moyen
# de rallumer quoi que ce soit (auth coupée = plus aucun login ; aggregator
# coupé = plus aucun webui de gestion ; etc.). C'est une propriété du SCHÉMA,
# pas une donnée que chaque manifeste peut librement déclarer : le design
# prévoit que modules.d/*.toml est shipé par le paquet du module lui-même
# (voir docs de conception), donc un `secubox-auth` un peu négligent pourrait
# shipper un manifeste avec `protected = false` et désactiver silencieusement
# la protection du cœur. On refuse de laisser la donnée décider de ça :
# load_manifest() force protected=True pour ces id, quoi que dise le fichier.
PROTECTED_IDS = frozenset({"auth", "aggregator", "core", "nginx", "firewall", "profiles"})


class ManifestError(Exception):
    """Manifeste illisible ou invalide."""


@dataclass(frozen=True)
class Manifest:
    id: str
    category: str
    runtime: str
    exposure: str
    units: tuple[str, ...]
    lxc: str | None = None
    portal_domain: str | None = None
    priority: int = DEFAULT_PRIORITY
    protected: bool = False
    needs: tuple[str, ...] = ()
    lifecycle: str = DEFAULT_LIFECYCLE
    wake_class: str = DEFAULT_WAKE_CLASS


def _require(d: dict, key: str, path: Path):
    if key not in d:
        raise ManifestError(f"{path}: champ obligatoire manquant: {key}")
    return d[key]


def _enum(value, allowed: tuple[str, ...], key: str, path: Path) -> str:
    if value not in allowed:
        raise ManifestError(f"{path}: {key}={value!r} invalide (attendu: {', '.join(allowed)})")
    return value


def load_manifest(path: Path) -> Manifest:
    """Charge et valide un manifeste. Lève ManifestError sur tout écart."""
    try:
        d = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"{path}: illisible: {exc}") from exc

    mid = _require(d, "id", path)
    # L'id pilote pins et profils : s'il diverge du nom de fichier, un pin
    # viserait un module qui n'existe pas sous ce nom.
    if mid != path.stem:
        raise ManifestError(f"{path}: id={mid!r} ne correspond pas au nom de fichier {path.stem!r}")

    runtime = _enum(_require(d, "runtime", path), RUNTIMES, "runtime", path)
    lxc = d.get("lxc")
    if runtime == "lxc" and not lxc:
        raise ManifestError(f"{path}: runtime='lxc' exige le champ lxc=<nom du conteneur>")

    units = _require(d, "units", path)
    if not isinstance(units, list) or not all(isinstance(u, str) for u in units):
        raise ManifestError(f"{path}: units doit être une liste de chaînes")

    priority = d.get("priority", DEFAULT_PRIORITY)
    if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= 100:
        raise ManifestError(f"{path}: priority={priority!r} hors bornes (entier 0-100)")

    portal = d.get("portal") or {}
    if not isinstance(portal, dict):
        raise ManifestError(f"{path}: portal doit être une table")

    protected = d.get("protected", False)
    if not isinstance(protected, bool):
        raise ManifestError(f"{path}: protected={protected!r} doit être un booléen (true/false)")
    # Structurel, pas data-driven (voir PROTECTED_IDS ci-dessus) : un paquet
    # module qui shippe modules.d/auth.toml avec protected=false ne doit pas
    # pouvoir désarmer la protection du noyau. On force à True plutôt que de
    # lever ManifestError — un manifeste sloppy ne doit pas casser tout
    # l'inventaire, mais il ne doit pas non plus pouvoir déprotéger le cœur.
    if mid in PROTECTED_IDS:
        protected = True

    needs = d.get("needs", [])
    if not isinstance(needs, list) or not all(isinstance(n, str) for n in needs):
        raise ManifestError(f"{path}: needs doit être une liste de chaînes")

    lifecycle = _enum(d.get("lifecycle", DEFAULT_LIFECYCLE), LIFECYCLES, "lifecycle", path)
    wake_class = _enum(d.get("wake_class", DEFAULT_WAKE_CLASS), WAKE_CLASSES, "wake_class", path)

    # Lowercase at the source: the whole front pipeline (waker._resolve
    # exact-match, sleeper's per-vhost keys, wafsync's on-demand-vhosts.json)
    # compares domains verbatim. A hand-edited mixed-case domain in TOML
    # would otherwise silently never wake (waker misses) nor sleep (sleeper
    # key misses) — see #896 final review, Fix 3.
    raw_domain = portal.get("domain")
    portal_domain = raw_domain.lower() if isinstance(raw_domain, str) else None

    return Manifest(
        id=mid,
        category=_enum(_require(d, "category", path), CATEGORIES, "category", path),
        runtime=runtime,
        exposure=_enum(_require(d, "exposure", path), EXPOSURES, "exposure", path),
        units=tuple(units),
        lxc=lxc,
        portal_domain=portal_domain,
        priority=priority,
        protected=protected,
        needs=tuple(needs),
        lifecycle=lifecycle,
        wake_class=wake_class,
    )


def load_all(directory: Path) -> dict[str, Manifest]:
    """Charge tous les *.toml d'un répertoire, indexés par id."""
    out: dict[str, Manifest] = {}
    for p in sorted(Path(directory).glob("*.toml")):
        m = load_manifest(p)
        out[m.id] = m
    return out
