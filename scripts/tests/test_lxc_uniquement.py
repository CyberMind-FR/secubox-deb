# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""LXC uniquement : aucun paquet ne dépend de docker ni de podman (#1743).

Règle existante (`.claude/PATTERNS.md`, Pattern 11) : les services tournent en
conteneurs LXC, jamais sous docker ni podman — ni sur l'hôte ni dans un LXC.
Elle a été enfreinte sans que rien ne proteste. Ce test lit la relation de
chaque `debian/control` (Pre-Depends, Depends, Recommends, Suggests).

La liste TOLERES recense les contrevenants connus en attente de décision ou
de portage : elle ne peut que DÉCROÎTRE. Un paquet qui en sort doit en être
retiré (le test le signale), un nouveau contrevenant fait échouer la CI.
"""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
INTERDITS = re.compile(
    r"(docker(\.io|-ce|-ce-cli|-compose(-plugin)?)?|podman(-[a-z-]+)?|buildah"
    r"|crun|containerd(\.io)?|runc|skopeo)"
)
# Contrevenants connus (#1743) : plus aucun. La liste reste (vide) pour qu'un futur paquet en attente de portage y soit consigné, jamais allongée
# sans décision ; un nouveau contrevenant fait échouer la CI.
TOLERES: set[str] = set()


def _relations(texte):
    for m in re.finditer(
        r"^(Pre-Depends|Depends|Recommends|Suggests):((?:.*\n?)(?:[ \t].*\n?)*)",
        texte, re.M,
    ):
        for alt in re.split(r"[,|]", m.group(2)):
            nom = alt.strip().split("(")[0].split("[")[0].strip()
            if nom:
                yield m.group(1), nom


def _contrevenants():
    trouves = {}
    for control in sorted(RACINE.glob("packages/*/debian/control")):
        paquet = control.parents[1].name
        for champ, nom in _relations(control.read_text(encoding="utf-8")):
            if INTERDITS.fullmatch(nom):
                trouves.setdefault(paquet, []).append(f"{champ}: {nom}")
    return trouves


def test_aucun_nouveau_paquet_ne_depend_de_docker_ni_de_podman():
    nouveaux = {p: r for p, r in _contrevenants().items() if p not in TOLERES}
    assert not nouveaux, (
        "LXC uniquement (PATTERNS.md, Pattern 11) — dépendances interdites : "
        + "; ".join(f"{p} ({', '.join(r)})" for p, r in sorted(nouveaux.items()))
    )


def test_la_liste_des_toleres_ne_garde_que_des_contrevenants_reels():
    """Un paquet porté en LXC doit quitter TOLERES : la liste ne ment pas."""
    reels = set(_contrevenants())
    perimes = sorted(TOLERES - reels)
    assert not perimes, f"à retirer de TOLERES (plus de dépendance docker/podman) : {perimes}"


def test_le_motif_reconnait_les_formes_courantes():
    for nom in ("docker.io", "docker-ce", "docker-compose-plugin", "podman",
                "podman-docker", "buildah", "crun", "containerd.io", "runc", "skopeo"):
        assert INTERDITS.fullmatch(nom), nom
    for nom in ("lxc", "lxc-templates", "debootstrap", "dockerfile-lint-doc"):
        assert not INTERDITS.fullmatch(nom), nom
