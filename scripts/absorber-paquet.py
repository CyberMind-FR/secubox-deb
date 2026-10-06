#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Absorbe un paquet dans un autre selon le patron du plan de simplification (#2050, dossier §10).

    scripts/absorber-paquet.py <absorbant> <absorbé> [--dry-run]
    scripts/absorber-paquet.py --comparer ancien.deb nouveau.deb

Le paquet absorbé devient un COMPOSANT du paquet absorbant : ses sources vont sous `composants/<absorbé>/`, ses fichiers sont
installés aux MÊMES chemins (mêmes unités, sockets, URL, dossiers), ses scripts de maintenance sont rejoués par ceux de
l'absorbant, et lui-même devient un paquet transitoire vide (`Section: oldlibs`). `--comparer` vérifie qu'aucun fichier du
.deb d'origine n'a disparu du .deb absorbant.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
P = RACINE / "packages"
GARDE_DEBIAN = {"control", "changelog", "rules", "postinst", "prerm", "postrm", "secubox.yaml", "compat", "source", "files",
                "conffiles", "triggers", "copyright", "debhelper-build-stamp"}
SCRIPTS = ("postinst", "prerm", "postrm")


def git(*a, check=True):
    return subprocess.run(["git", "-C", str(RACINE), *a], check=check, capture_output=True, text=True)


def suivis(dossier: Path) -> list[Path]:
    sortie = git("ls-files", str(dossier.relative_to(RACINE))).stdout.split("\n")
    return [RACINE / f for f in sortie if f and not re.search(r"/debian/secubox-[^/]+/", f)]


def champ(control: str, nom: str) -> list[str]:
    m = re.search(rf"(?ms)^{nom}:(.*?)(?=^\S|\Z)", control)
    if not m:
        return []
    return [x.strip() for x in re.sub(r"\s*\n\s*", " ", m.group(1)).split(",") if x.strip()]


def nom_pkg(dep: str) -> str:
    return re.split(r"[\s(|]", dep.strip(), maxsplit=1)[0]


def fusion_deps(existant: list[str], ajout: list[str], exclus: set[str]) -> list[str]:
    vus = {nom_pkg(d) for d in existant}
    sortie = list(existant)
    for d in ajout:
        n = nom_pkg(d)
        if n.startswith("${") or n in vus or n in exclus:
            continue
        sortie.append(d)
        vus.add(n)
    return sortie


def ecrire_champ(control: str, nom: str, valeurs: list[str]) -> str:
    texte = f"{nom}: " + (",\n ".join(valeurs)) + "\n" if valeurs else ""
    m = re.search(rf"(?ms)^{nom}:.*?(?=^\S|\Z)", control)
    if m:
        return control[:m.start()] + texte + control[m.end():]
    return control.replace("\nDescription:", f"\n{texte}Description:", 1) if texte else control


def traduire_rules(rules: str, ancien: str, absorbant: str, tops: set[str] | None = None) -> list[str]:
    """Les lignes de `override_dh_auto_install` de l'ancien, réécrites pour l'absorbant."""
    cibles = re.findall(r"(?m)^([A-Za-z_%][^\s:]*):", rules)
    # des cibles VIDES (override_dh_auto_build:, override_dh_auto_test:) ne font rien : elles sont permises
    vides = [c for c in cibles if re.search(rf"(?m)^{re.escape(c)}:[ \t]*\n(?!\t)", rules)]
    autres = [c for c in cibles if c not in ("%", "override_dh_auto_install", "override_dh_installsystemd") and c not in vides]
    if autres:
        raise SystemExit(f"{ancien} : cibles de rules non gérées {autres} — à fusionner à la main")
    m = re.search(r"(?ms)^override_dh_auto_install:\n(.*?)(?=^\S|\Z)", rules)
    if not m:
        raise SystemExit(f"{ancien} : pas de override_dh_auto_install")
    noms = set(tops or ()) | {"api", "www", "nginx", "systemd", "menu.d", "sbin", "config", "conf", "templates", "data", "lib", "bin", "etc",
                              "usr", "docs", "static", "debian", "app", "roundcube", "haproxy"}
    dirs = "(?:" + "|".join(re.escape(n) for n in sorted(noms, key=len, reverse=True)) + ")"
    sortie = []
    for ligne in m.group(1).split("\n"):
        if not ligne.strip():
            continue
        l = ligne.replace(f"debian/secubox-{ancien}", f"debian/secubox-{absorbant}")
        l = re.sub(rf"(?<![\w/.\-])((?!debian/secubox-)(?:{dirs})(?:/[^\s'\"]*)?)(?=[\s'\"]|$)",
                   lambda mo: f"composants/{ancien}/" + mo.group(1), l)
        sortie.append(l)
    return sortie


def absorber(absorbant: str, ancien: str, sec: bool) -> None:
    A, O = P / f"secubox-{absorbant}", P / f"secubox-{ancien}"
    C = A / "composants" / ancien
    if not A.is_dir() or not O.is_dir():
        raise SystemExit("paquet introuvable")
    if C.exists():
        raise SystemExit(f"{C} existe déjà")
    regles_o = (O / "debian/rules").read_text()
    ligne_regles = traduire_rules(regles_o, ancien, absorbant, {x.name for x in O.iterdir() if x.name != "debian"})
    ctrl_a, ctrl_o = (A / "debian/control").read_text(), (O / "debian/control").read_text()
    ver_a = re.match(r"\S+ \((\d+)\.(\d+)\.(\d+)-", (A / "debian/changelog").read_text()).groups()
    ver_o = re.match(r"\S+ \((\d+)\.(\d+)\.(\d+)-", (O / "debian/changelog").read_text()).groups()
    nv_a = f"{ver_a[0]}.{int(ver_a[1]) + 1}.0"
    nv_o = f"{ver_o[0]}.{ver_o[1]}.{int(ver_o[2]) + 1}"
    print(f"{ancien} {'.'.join(ver_o)} → transitoire {nv_o} ; {absorbant} {'.'.join(ver_a)} → {nv_a}")
    if sec:
        print("lignes de rules :", *ligne_regles, sep="\n  ")
        return
    # 1. sources et tests
    C.mkdir(parents=True)
    for f in suivis(O):
        rel = f.relative_to(O)
        if rel.parts[0] == "debian":
            if len(rel.parts) == 2 and rel.name in GARDE_DEBIAN:
                continue
            if rel.parts[1] in GARDE_DEBIAN and len(rel.parts) > 2:
                continue
        (C / rel).parent.mkdir(parents=True, exist_ok=True)
        git("mv", str(f.relative_to(RACINE)), str((C / rel).relative_to(RACINE)))
    for d in sorted((x for x in O.rglob("*") if x.is_dir() and "debian" not in x.parts), key=lambda x: len(x.parts), reverse=True):
        for junk in d.glob("__pycache__"):
            import shutil
            shutil.rmtree(junk, ignore_errors=True)
        try:
            d.rmdir()
        except OSError:
            pass
    for t in C.rglob("tests/*.py"):
        s = t.read_text()
        s2 = re.sub(r"parents\[(\d+)\]", lambda m: f"parents[{int(m.group(1)) + 2}]" if int(m.group(1)) >= 2 else m.group(0), s)
        if s2 != s:
            t.write_text(s2)
    # 2. scripts de maintenance de l'ancien → composants/<ancien>/debian/, installés puis rejoués
    scripts_installes = []
    for s in SCRIPTS:
        src = O / "debian" / s
        if src.is_file():
            corps = "\n".join(l for l in src.read_text().split("\n") if l.strip() != "#DEBHELPER#")
            (C / "debian").mkdir(exist_ok=True)
            (C / "debian" / s).write_text(corps if corps.endswith("\n") else corps + "\n")
            scripts_installes.append(s)
            ligne_regles.append(f"\tinstall -D -m 755 composants/{ancien}/debian/{s} debian/secubox-{absorbant}/usr/lib/secubox/{absorbant}/maintscripts/{ancien}.{s}")
    # 2 bis. unités nommées debian/<paquet>.service : debhelper les installait tout seul, plus maintenant
    for u in sorted((C / "debian").glob("*")) if (C / "debian").is_dir() else []:
        if u.suffix in (".service", ".timer", ".path", ".socket") and not u.name.startswith(("postinst", "prerm", "postrm")):
            ligne_regles.append(f"\tinstall -D -m 644 composants/{ancien}/debian/{u.name} debian/secubox-{absorbant}/usr/lib/systemd/system/{u.name}")
    # 3. rules de l'absorbant
    ra = (A / "debian/rules").read_text()
    m = re.search(r"(?ms)^override_dh_auto_install:\n(.*?)(?=^\S|\Z)", ra)
    if m:
        fin = m.end()
        bloc = ra[:fin].rstrip("\n") + "\n\t# Composant absorbé : " + ancien + " (#2050)\n" + "\n".join(ligne_regles) + "\n\n"
        ra = bloc + ra[fin:].lstrip("\n")
    else:
        ra = ra.rstrip("\n") + "\n\noverride_dh_auto_install:\n\t# Composant absorbé : " + ancien + " (#2050)\n" + "\n".join(ligne_regles) + "\n"
    (A / "debian/rules").write_text(ra)
    # 4. scripts de l'absorbant rejouent ceux de l'ancien
    for s in scripts_installes:
        f = A / "debian" / s
        boucle = (f"# Composants absorbés (#2050) : leurs scripts de maintenance, mêmes arguments.\n"
                  f"for _s in /usr/lib/secubox/{absorbant}/maintscripts/*.{s}; do\n"
                  f"  [ -f \"$_s\" ] && {{ sh \"$_s\" \"$@\" || echo \"{absorbant} : {s} de $(basename \"$_s\") en échec\" >&2; }}\n"
                  f"done\n")
        if f.is_file():
            t = f.read_text()
            marque = "#DEBHELPER#"
            t = t.replace(marque, boucle + marque, 1) if marque in t else t.rstrip("\n") + "\n" + boucle
            f.write_text(t)
        else:
            f.write_text("#!/bin/sh\nset -e\n" + boucle + "#DEBHELPER#\nexit 0\n")
            f.chmod(0o755)
    # 5. control de l'absorbant
    for nom in ("Depends", "Recommends", "Suggests"):
        ctrl_a = ecrire_champ(ctrl_a, nom, fusion_deps(champ(ctrl_a, nom), champ(ctrl_o, nom), {f"secubox-{absorbant}"}))
    deps = {nom_pkg(d) for d in champ(ctrl_a, "Depends")}
    for nom in ("Recommends", "Suggests"):
        ctrl_a = ecrire_champ(ctrl_a, nom, [d for d in champ(ctrl_a, nom) if nom_pkg(d) not in deps])
    for nom in ("Replaces", "Breaks"):
        ctrl_a = ecrire_champ(ctrl_a, nom, champ(ctrl_a, nom) + [f"secubox-{ancien} (<< {nv_o}~)"])
    (A / "debian/control").write_text(ctrl_a)
    ch = A / "debian/changelog"
    ch.write_text(f"secubox-{absorbant} ({nv_a}-1~bookworm1) bookworm; urgency=medium\n\n  * Absorbe secubox-{ancien} (#2050) comme composant : memes fichiers aux memes chemins (unites, URL, sockets),\n    sources sous composants/{ancien}/. Replaces/Breaks sur l'ancien paquet, devenu transitoire.\n\n -- Gérald Kerma <devel@cybermind.fr>  Tue, 06 Oct 2026 20:00:00 +0200\n\n" + ch.read_text())
    # 6. l'ancien devient transitoire
    desc = re.search(r"(?m)^Description:\s*(.*)$", ctrl_o).group(1)
    for f in ("secubox.yaml", "prerm", "postrm", "postinst", "conffiles", "triggers"):
        if (O / "debian" / f).is_file():
            git("rm", "-q", "-f", str((O / "debian" / f).relative_to(RACINE)))
    (O / "debian/control").write_text(f"""Source: secubox-{ancien}
Section: oldlibs
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://cybermind.fr/secubox
Rules-Requires-Root: no

Package: secubox-{ancien}
Architecture: all
Depends: ${{misc:Depends}}, secubox-{absorbant} (>= {nv_a})
Description: transitional package, replaced by secubox-{absorbant}
 {ancien} is now a component of secubox-{absorbant}. This empty package only pulls
 it in; it can be removed once nothing depends on it.
""")
    (O / "debian/rules").write_text("#!/usr/bin/make -f\n%:\n\tdh $@\n")
    (O / "README.md").write_text(f"<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->\n# secubox-{ancien} (transitoire)\n\nPaquet vide : {ancien} est un composant de `secubox-{absorbant}` depuis {nv_a} (#2050).\nIl sera retiré une fois publié un cycle complet.\n")
    git("add", "-f", str((O / "README.md").relative_to(RACINE)))
    och = O / "debian/changelog"
    och.write_text(f"secubox-{ancien} ({nv_o}-1~bookworm1) bookworm; urgency=medium\n\n  * Paquet transitoire : {ancien} est un composant de secubox-{absorbant} >= {nv_a} (#2050).\n\n -- Gérald Kerma <devel@cybermind.fr>  Tue, 06 Oct 2026 20:01:00 +0200\n\n" + och.read_text())
    # 7. arbre : l'ancien passe hors-arbre
    arbre = P / "secubox-meta/arbre.yaml"
    t = arbre.read_text()
    t = re.sub(rf"(?m)^  - secubox-{re.escape(ancien)}\b.*\n", "", t, count=0)
    t = t.replace("  - secubox-eye-square        #", f"  - secubox-{ancien}  # transitoire → secubox-{absorbant} (#2050)\n  - secubox-eye-square        #", 1)
    arbre.write_text(t)
    # 8. autres paquets qui dépendaient de l'ancien (champs de dépendance SEULEMENT ; jamais Replaces/Breaks/Conflicts/Provides,
    #    ni le paquet absorbant lui-même)
    liens = ("Depends", "Pre-Depends", "Recommends", "Suggests", "Enhances")
    champ_re = re.compile(r"(?ms)^(" + "|".join(liens) + r"):(.*?)(?=^\S|\Z)")
    for ctrl in sorted(P.glob("*/debian/control")):
        nom = ctrl.parts[-3]
        if nom in (f"secubox-{ancien}", f"secubox-{absorbant}", "secubox-meta") or "/debian/secubox-" in str(ctrl):
            continue
        t = ctrl.read_text()
        change = False

        def reecrire(mo):
            nonlocal change
            items = [x.strip() for x in re.sub(r"\s*\n\s*", " ", mo.group(2)).split(",") if x.strip()]
            if not any(nom_pkg(i) == f"secubox-{ancien}" for i in items):
                return mo.group(0)
            change = True
            neuf, vus = [], set()
            for i in items:
                n_ = nom_pkg(i)
                cible = f"secubox-{absorbant}" if n_ == f"secubox-{ancien}" else i
                cle = nom_pkg(cible)
                if cle in vus:
                    continue
                vus.add(cle)
                contrainte = f" (>= {nv_a})" if mo.group(1) in ("Depends", "Pre-Depends") else ""
                neuf.append(f"secubox-{absorbant}{contrainte}" if n_ == f"secubox-{ancien}" else i)
            return f"{mo.group(1)}: " + ",\n ".join(neuf) + "\n"
        n = champ_re.sub(reecrire, t)
        if change:
            # un paquet qui a déjà l'absorbant dans un AUTRE champ de dépendance garde les deux : valide, sans doublon dans un champ
            ctrl.write_text(n)
            ch = ctrl.parent / "changelog"
            m2 = re.match(r"(\S+) \((\d+)\.(\d+)\.(\d+)-", ch.read_text())
            nv = f"{m2.group(2)}.{m2.group(3)}.{int(m2.group(4)) + 1}"
            ch.write_text(f"{m2.group(1)} ({nv}-1~bookworm1) bookworm; urgency=medium\n\n  * Depend de secubox-{absorbant} au lieu de secubox-{ancien} (transitoire, #2050).\n\n -- Gérald Kerma <devel@cybermind.fr>  Tue, 06 Oct 2026 20:02:00 +0200\n\n" + ch.read_text())
            print("dépendance mise à jour :", nom, nv)


def comparer(ancien: str, nouveau: str) -> int:
    def fichiers(deb):
        s = subprocess.run(["dpkg-deb", "-c", deb], capture_output=True, text=True, check=True).stdout
        out = {}
        for l in s.splitlines():
            parts = l.split()
            chemin = " ".join(parts[5:]).split(" -> ")[0]
            if not chemin.endswith("/"):
                out[chemin.lstrip("./")] = parts[0]
        return out
    a, n = fichiers(ancien), fichiers(nouveau)
    manquants = [f for f in a if f not in n and "/share/doc/" not in f]
    modes = [f for f in a if f in n and a[f] != n[f] and "/share/doc/" not in f]
    print(f"{len(a)} fichiers dans l'ancien, {len(n)} dans le nouveau")
    for f in manquants:
        print("MANQUANT", f)
    for f in modes:
        print("MODE", f, a[f], "→", n[f])
    return 1 if manquants or modes else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("noms", nargs="*")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--comparer", nargs=2, metavar=("ANCIEN_DEB", "NOUVEAU_DEB"))
    a = ap.parse_args()
    if a.comparer:
        return comparer(*a.comparer)
    if len(a.noms) != 2:
        ap.error("absorbant et absorbé requis")
    absorber(a.noms[0], a.noms[1], a.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
