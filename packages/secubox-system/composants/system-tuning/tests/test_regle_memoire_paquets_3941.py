# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Garde du dépôt (#3941) : aucun paquet ne livre un frein mémoire sous le plafond avec l'échange interdit.

Règle (README de system-tuning) : un générateur de configuration LXC qui pose `memory.max` pose aussi `memory.swap.max`,
borné et non nul ; `memory.high` n'est permis qu'avec cet échange borné. Une unité systemd ne combine jamais
`MemoryHigh` et `MemorySwapMax=0` (le plafond seul, sans frein, reste permis : le service est tué, pas étouffé).
"""
import os
import re
import subprocess
from pathlib import Path

import pytest

DEPOT = Path(__file__).resolve().parents[5]
DOSSIERS = ("packages", "common", "image", "scripts", "board")
IGNORES = {"tests", "node_modules", "__pycache__", ".git", "vendor"}
EXTENSIONS_IGNOREES = {".md", ".png", ".jpg", ".svg", ".woff2", ".deb", ".gz", ".xz", ".css", ".po", ".mo", ".pdf"}

LXC = re.compile(r"lxc\.cgroup2?\.memory\.(max|high|swap\.max)\s*=\s*([^\s\\\"']+)")
VIF_ZERO = re.compile(r"""(?:echo|printf)\s+(?:['"]?%s\S*\s+)?['"]?0(?:\\n)?['"]?\s*>+\s*\S*memory\.swap\.max"""
                      r"""|memory\.swap\.max['"]\s*[:,]\s*['"]?0['"]?\b|memory\.swap\.max['"]?\)?\.write_text\(['"]0""")
UNITE = re.compile(r"(?:^|[\s\"'])(MemoryHigh|MemoryMax|MemorySwapMax)\s*=\s*([^\s\"'\\]+)")
ZERO = re.compile(r"0(?:[KMGTkmgt]|%)?")


def octets(v):
    m = re.fullmatch(r"(\d+)([KMGkmg]?)", v)
    return int(m.group(1)) << {"": 0, "K": 10, "M": 20, "G": 30}[m.group(2).upper()] if m else None

# Exception : raison écrite, obligatoire. Aucune aujourd'hui.
EXCEPTIONS: dict[str, str] = {}


def constats(texte: str) -> list[str]:
    """Constats d'un fichier ; les lignes de commentaire ne comptent pas."""
    code = "\n".join(x for x in texte.splitlines() if not x.lstrip().startswith("#"))
    out = []
    lignes = LXC.findall(code)
    par = {c: [v for k, v in lignes if k == c] for c in ("max", "high", "swap.max")}
    if any(ZERO.fullmatch(v) for v in par["swap.max"]):
        out.append("lxc memory.swap.max = 0")
    if any((octets(e) or 0) > (octets(m) or 1 << 62) for m, e in zip(par["max"], par["swap.max"])):
        out.append("lxc : échange plus grand que le plafond")
    if len(par["swap.max"]) < max(len(par["max"]), len(par["high"])):
        out.append(f"lxc : {len(par['max'])} memory.max, {len(par['high'])} memory.high, "
                   f"{len(par['swap.max'])} memory.swap.max (un échange borné par bloc)")
    if VIF_ZERO.search(code):
        out.append("écriture à chaud de memory.swap.max à 0")
    for section in re.split(r"(?m)^\s*\[[A-Z][a-zA-Z]+\]\s*$|set-property", code):     # unités, heredocs, systemctl set-property
        u = dict(UNITE.findall(section))
        if ZERO.fullmatch(u.get("MemorySwapMax", "")) and u.get("MemoryHigh", "infinity") != "infinity":
            out.append(f"unité : MemoryHigh={u['MemoryHigh']} avec MemorySwapMax=0")
    return out


def fichiers():
    r = subprocess.run(["git", "-C", str(DEPOT), "ls-files", "-z", "-co", "--exclude-standard", *DOSSIERS],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        pytest.skip("dépôt git requis")
    for rel in filter(None, r.stdout.split("\0")):
        p = Path(rel)
        if IGNORES & set(p.parts) or p.suffix in EXTENSIONS_IGNOREES or p.name == "changelog":
            continue
        chemin = DEPOT / p
        if chemin.is_file() and not chemin.is_symlink() and os.path.getsize(chemin) < 2_000_000:
            yield rel, chemin


def test_aucun_paquet_ne_livre_la_combinaison_interdite():
    fautes, vus = [], 0
    for rel, chemin in fichiers():
        texte = chemin.read_text(encoding="utf-8", errors="ignore")
        if "emory" not in texte:
            continue
        vus += 1
        if rel not in EXCEPTIONS:
            fautes += [f"{rel} : {c}" for c in constats(texte)]
    assert vus > 40, "le parcours du dépôt ne voit plus les fichiers"
    assert not fautes, "\n".join(fautes)


def test_les_exceptions_existent_encore_et_portent_une_raison():
    for rel, raison in EXCEPTIONS.items():
        assert (DEPOT / rel).is_file() and len(raison) > 20
        assert constats((DEPOT / rel).read_text()), f"{rel} : exception devenue inutile"


@pytest.mark.parametrize("texte", [
    "lxc.cgroup2.memory.max = 512M\nlxc.cgroup2.memory.high = 384M\nlxc.cgroup2.memory.swap.max = 0\n",
    'echo "lxc.cgroup2.memory.swap.max = 0"\n',
    "lxc.cgroup2.memory.max = 512M\n",
    "lxc.cgroup2.memory.high = 1500M\nlxc.cgroup2.memory.max = 2G\n",
    "[Service]\nMemoryHigh=300M\nMemoryMax=400M\nMemorySwapMax=0\n",
    'echo 0 > "$cg/memory.swap.max"\n',
    "printf '%s' 0 > $cg/memory.swap.max\n",
    '(d / "memory.swap.max").write_text("0")\n',
    "lxc.cgroup2.memory.max = 256M\nlxc.cgroup2.memory.swap.max = 1G\n",
    "systemctl set-property x.service MemoryHigh=300M MemorySwapMax=0\n",
    "[Service]\nMemoryHigh=1G\nMemorySwapMax=0M\n[Service]\nMemoryMax=2G\n",
])
def test_les_cas_interdits_sont_vus(texte):
    assert constats(texte)


@pytest.mark.parametrize("texte", [
    "lxc.cgroup2.memory.max = 512M\nlxc.cgroup2.memory.swap.max = 256M\n",
    "lxc.cgroup2.memory.high = 1500M\nlxc.cgroup2.memory.max = 2G\nlxc.cgroup2.memory.swap.max = 1G\n",
    "[Service]\nMemoryMax=512M\nMemorySwapMax=0\n",
    "[Service]\nMemoryHigh=96M\nMemoryMax=128M\n",
    "# lxc.cgroup2.memory.swap.max = 0\n",
    "[Service]\nMemoryHigh=1G\n[Service]\nMemoryMax=2G\nMemorySwapMax=0\n",
])
def test_les_cas_permis_passent(texte):
    assert constats(texte) == []
