# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: release.repo — reprepro-copy actuator (op-gated argv builders)."""
from __future__ import annotations

import os
from typing import List

REPREPRO_BASE = os.environ.get("SECUBOX_APT_BASE", "/data/apt")
RING_DISTS = {"draft": "draft", "internal": "internal", "published": "published"}


class RepoError(Exception):
    """Unknown ring, empty package set, or a promotion that would brick arm64."""


def has_arch(artifacts, arch: str = "arm64") -> bool:
    return any(a.get("kind") == "deb" and a.get("arch") == arch for a in artifacts)


def copy_argv(from_ring: str, to_ring: str, pkg_names: List[str]) -> List[str]:
    if from_ring not in RING_DISTS or to_ring not in RING_DISTS:
        raise RepoError(f"unknown ring {from_ring!r}/{to_ring!r}")
    if not pkg_names:
        raise RepoError("no packages to copy")
    return ["reprepro", "-b", REPREPRO_BASE, "copy", RING_DISTS[to_ring],
             RING_DISTS[from_ring], *pkg_names]


def plan_promote(evolution: dict, from_ring: str, to_ring: str) -> List[List[str]]:
    artifacts = evolution.get("artifacts", [])
    debs = [a["name"] for a in artifacts if a.get("kind") == "deb"]
    if debs and not has_arch(artifacts, "arm64"):
        raise RepoError("evolution has no arm64 deb — refusing to publish (would brick arm64)")
    return [copy_argv(from_ring, to_ring, debs)] if debs else []
