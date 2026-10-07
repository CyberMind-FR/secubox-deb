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


def install_vers_regles(texte: str, ancien: str) -> str:
    """Un paquet qui installe par `debian/<paquet>.install` (dh_install) : on le traduit en lignes `install`/`cp`
    de `override_dh_auto_install`, que traduire_rules réécrit ensuite comme les autres."""
    sortie = ["\noverride_dh_auto_install:"]
    for ligne in texte.splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#"):
            continue
        *sources, dest = ligne.split()
        d = f"debian/secubox-{ancien}/{dest.strip('/')}"
        sortie.append(f"\tinstall -d {d}")
        for src in sources:
            sortie.append(f"\tcp -r {src} {d}/")
    return "\n".join(sortie) + "\n"


def ecrire_postinst_transitoire(O: Path, ancien: str, absorbant: str) -> None:
    """L'ancien `prerm` arrête (et désactive) l'unité à la mise à jour, APRÈS que l'absorbant l'a démarrée selon l'ordre
    d'apt : le transitoire la remet en route à la fin, sauf si elle est masquée (constaté sur grafana, gk2)."""
    u = f"secubox-{ancien}.service"
    (O / "debian/postinst").write_text(f"""#!/bin/sh
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Transitoire (#2050) : l'unité {u} est désormais livrée par secubox-{absorbant}. L'ancien prerm
# de la version précédente l'arrête à la mise à jour ; on la rétablit une fois l'absorbant configuré.
set -e
#DEBHELPER#
if [ "$1" = configure ] && [ -e /usr/lib/systemd/system/{u} -o -e /lib/systemd/system/{u} ]; then
    if [ "$(systemctl is-enabled {u} 2>/dev/null)" != masked ]; then
        systemctl enable {u} >/dev/null 2>&1 || true
        systemctl start {u} >/dev/null 2>&1 || true
    fi
fi
exit 0
""")
    (O / "debian/postinst").chmod(0o755)


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
        # une SOURCE debian/secubox-<ancien>.<ext> (sudoers, install...) suit le composant ; l'arbre de destination
        # debian/secubox-<ancien>/ devient celui de l'absorbant
        l = re.sub(rf"(?<![\w/.\-])debian/secubox-{re.escape(ancien)}\.", f"composants/{ancien}/debian/secubox-{ancien}.", ligne)
        l = re.sub(rf"debian/secubox-{re.escape(ancien)}(?=/|\s|$)", f"debian/secubox-{absorbant}", l)
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
    liste = O / "debian" / f"secubox-{ancien}.install"
    if "override_dh_auto_install" not in regles_o and liste.exists():
        regles_o += install_vers_regles(liste.read_text(), ancien)
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
        # le conftest qui désigne l'ancien dossier du paquet : il est devenu un composant de l'absorbant
        s2 = s2.replace(f'"packages" / "secubox-{ancien}"', f'"packages" / "secubox-{absorbant}" / "composants" / "{ancien}"')
        if s2 != s:
            t.write_text(s2)
    for h in C.rglob("tests/helpers.bash"):
        hs = h.read_text()
        h2 = hs.replace('$BATS_TEST_DIRNAME/../../..', '$BATS_TEST_DIRNAME/../../../../..')
        if h2 != hs:
            h.write_text(h2)
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
            # debhelper : debian/<paquet>.<nom>.service est installé sous <nom>.service (le préfixe du paquet tombe)
            dest = u.name
            reste = u.name.removeprefix(f"secubox-{ancien}.")
            if reste != u.name and reste not in ("service", "timer", "path", "socket"):
                dest = reste
            ligne_regles.append(f"\tinstall -D -m 644 composants/{ancien}/debian/{u.name} debian/secubox-{absorbant}/usr/lib/systemd/system/{dest}")
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
            # APRÈS #DEBHELPER# : les snippets de debhelper (enable/start) passent d'abord, un `systemctl disable` explicite de
            # l'absorbé a le dernier mot. Avant `exit 0` s'il y en a un.
            if marque in t:
                t = t.replace(marque, marque + "\n" + boucle, 1)
            else:
                t = t.rstrip("\n") + "\n" + boucle
            t = re.sub(r"(?m)^exit 0\s*$", "", t).rstrip("\n") + "\nexit 0\n" if t.lstrip().startswith("#!") else t
            f.write_text(t)
        else:
            f.write_text("#!/bin/sh\nset -e\n#DEBHELPER#\n" + boucle + "exit 0\n")
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
    if (C / "debian" / f"secubox-{ancien}.service").exists() or any(C.rglob(f"secubox-{ancien}.service")):
        ecrire_postinst_transitoire(O, ancien, absorbant)
    (O / "README.md").write_text(f"<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->\n# secubox-{ancien} (transitoire)\n\nPaquet vide : {ancien} est un composant de `secubox-{absorbant}` depuis {nv_a} (#2050).\nIl sera retiré une fois publié un cycle complet.\n")
    git("add", "-f", str((O / "README.md").relative_to(RACINE)))
    och = O / "debian/changelog"
    och.write_text(f"secubox-{ancien} ({nv_o}-1~bookworm1) bookworm; urgency=medium\n\n  * Paquet transitoire : {ancien} est un composant de secubox-{absorbant} >= {nv_a} (#2050).\n\n -- Gérald Kerma <devel@cybermind.fr>  Tue, 06 Oct 2026 20:01:00 +0200\n\n" + och.read_text())
    # 7. arbre : l'ancien passe hors-arbre
    arbre = P / "secubox-meta/arbre.yaml"
    t = arbre.read_text()
    t = re.sub(rf"(?m)^  - secubox-{re.escape(ancien)}(?![\w-]).*\n", "", t, count=0)
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
        # Un commentaire au milieu d'un champ de dépendance (secubox-profils) : la réécriture par champ s'y arrêterait et
        # casserait la liste (constaté, dpkg-gencontrol refusait le paquet). On ne touche pas, on le dit.
        if re.search(rf"secubox-{re.escape(ancien)}(?![\w-])", t) and re.search(
                r"(?ms)^(?:" + "|".join(liens) + r"):[^\n]*\n(?:[ \t][^\n]*\n|#[^\n]*\n)*?#", t):
            print(f"À FAIRE À LA MAIN (commentaire dans un champ de dépendance) : {nom} référence secubox-{ancien}")
            continue

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
                if "|" in i and n_ == f"secubox-{ancien}":
                    # une alternative (`a | b`) : on ne remplace que la branche concernée, jamais la liste entière
                    alts = [x.strip() for x in i.split("|")]
                    alts = [f"secubox-{absorbant}{contrainte}" if nom_pkg(x) == f"secubox-{ancien}" else x for x in alts]
                    neuf.append(" | ".join(dict.fromkeys(alts)))
                    continue
                neuf.append(f"secubox-{absorbant}{contrainte}" if n_ == f"secubox-{ancien}" else i)
            return f"{mo.group(1)}: " + ",\n ".join(neuf) + "\n"
        n = champ_re.sub(reecrire, t)
        if change:
            # un paquet qui a déjà l'absorbant dans un AUTRE champ de dépendance garde les deux : valide, sans doublon dans un champ
            ch = ctrl.parent / "changelog"
            m2 = re.match(r"(\S+) \((\d+)\.(\d+)\.(\d+)-", ch.read_text())
            if m2 is None:
                # version « 0.6.0~aurora14 » : on monte le compteur aurora, la ligne de livraison est conservée
                ma = re.match(r"(\S+) \((\d+\.\d+\.\d+~aurora)(\d+)-", ch.read_text())
                if ma is None:
                    print(f"À FAIRE À LA MAIN (changelog hors gabarit) : {nom}")
                    continue
                ctrl.write_text(n)
                ch.write_text(f"{ma.group(1)} ({ma.group(2)}{int(ma.group(3)) + 1}-1~bookworm1) bookworm; urgency=medium\n\n  * Depend de secubox-{absorbant} au lieu de secubox-{ancien} (transitoire, #2050).\n\n -- Gérald Kerma <devel@cybermind.fr>  Tue, 06 Oct 2026 20:02:00 +0200\n\n" + ch.read_text())
                print("dépendance mise à jour (aurora) :", nom)
                continue
            ctrl.write_text(n)
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
