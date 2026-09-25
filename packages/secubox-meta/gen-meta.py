#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-meta :: générateur des métapaquets imbriqués (#1397).

    gen-meta.py            écrit debian/control depuis arbre.yaml
    gen-meta.py --check    échoue si debian/control a divergé (test, CI)
    gen-meta.py --json F   écrit l'arbre résolu (pour l'App Store)

Le générateur REFUSE plutôt que de produire un paquet qui échouera à
l'installation : référence inconnue, cycle, paquet transitionnel dans l'arbre,
paquet propre à une architecture en « requiert » (le métapaquet est `all`),
paquet du dépôt ni dans l'arbre ni hors-arbre (module neuf oublié).
Sans dépendance : ni PyYAML ni python-debian dans la chaîne de construction.
"""
import glob
import json
import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
PAQUETS = os.path.normpath(os.path.join(ICI, ".."))
LIENS = (("requiert", "Depends"), ("recommande", "Recommends"), ("suggere", "Suggests"))


# ── lecture de debian/control ─────────────────────────────────────────────
def strophes(chemin):
    """Les strophes d'un debian/control (champs repliés recollés)."""
    out, source = [], {}
    texte = open(chemin, encoding="utf-8", errors="replace").read()
    for bloc in re.split(r"\n\s*\n", texte):
        d, cle = {}, None
        for ligne in bloc.splitlines():
            if ligne.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$", ligne)
            if m:
                cle = m.group(1)
                d[cle] = m.group(2).strip()
                if cle == "Description":
                    d["_synopsis"] = d[cle]
            elif cle and ligne[:1] in (" ", "\t"):
                d[cle] += " " + ligne.strip()
        if "Source" in d:
            source = d
        if "Package" in d:
            d.setdefault("Section", source.get("Section", ""))
            d["_source"] = source.get("Source", d["Package"])
            out.append(d)
    return out


def relations(valeur):
    """« a (>= 1), b | c, ${misc:Depends} » → [{nom, contrainte, alternatives}]."""
    out = []
    for groupe in (valeur or "").split(","):
        groupe = groupe.strip()
        if not groupe or "${" in groupe:
            continue
        alts = []
        for a in groupe.split("|"):
            m = re.match(r"^\s*([a-z0-9][a-z0-9+.-]*)(?::any)?\s*(?:\(([^)]*)\))?", a)
            if m:
                alts.append({"nom": m.group(1), "contrainte": (m.group(2) or "").strip()})
        if alts:
            e = dict(alts[0])
            if len(alts) > 1:
                e["alternatives"] = [x["nom"] for x in alts[1:]]
            out.append(e)
    return out


def paquets_du_depot(exclure_source=None):
    """{binaire: fiche} pour chaque paquet du monorepo (hors copies de build)."""
    out = {}
    for c in sorted(glob.glob(os.path.join(PAQUETS, "secubox-*", "debian", "control"))):
        if exclure_source and os.path.basename(os.path.dirname(os.path.dirname(c))) == exclure_source:
            continue
        for s in strophes(c):
            synopsis = s.get("_synopsis", "")
            out[s["Package"]] = {
                "paquet": s["Package"],
                "source": s["_source"],
                "architecture": s.get("Architecture", "all"),
                "section": s.get("Section", ""),
                "resume": synopsis[:160],
                # Le RÉSUMÉ ou la section le disent ; la description longue
                # peut citer un ancien paquet transitionnel (magicmirror/mmpm).
                "transitionnel": "transitional" in synopsis.lower() or s.get("Section") == "oldlibs",
                "depends": relations(s.get("Depends")),
                "recommends": relations(s.get("Recommends")),
                "suggests": relations(s.get("Suggests")),
                "replaces": relations(s.get("Replaces")),
            }
    return out


# ── lecture de l'arbre ────────────────────────────────────────────────────
def lit_arbre(chemin=os.path.join(ICI, "arbre.yaml")):
    noeuds, hors, cur, liste = [], [], None, None
    for brut in open(chemin, encoding="utf-8"):
        ligne = re.sub(r"\s+#.*$", "", brut.rstrip("\n"))
        if not ligne.strip() or ligne.lstrip().startswith("#"):
            continue
        m = re.match(r"^([a-z-]+):\s*(.*)$", ligne)
        if m:
            cle, val = m.group(1), m.group(2).strip().strip('"')
            if cle == "hors-arbre":
                cur, liste = None, hors
            elif cle == "meta":
                cur = {"meta": val, "niveau": "", "label": val, "description": "",
                       "requiert": [], "recommande": [], "suggere": []}
                noeuds.append(cur)
                liste = None
            elif cur is not None and cle in ("niveau", "label", "description"):
                cur[cle] = val
            elif cur is not None and cle in ("requiert", "recommande", "suggere"):
                liste = cur[cle]
            else:
                raise SystemExit(f"arbre.yaml : clé inattendue « {cle} »")
            continue
        li = re.match(r"^\s+-\s+(\S+)\s*$", ligne)
        if li and liste is not None:
            liste.append(li.group(1))
        else:
            raise SystemExit(f"arbre.yaml : ligne illisible « {ligne.strip()} »")
    return noeuds, hors


# ── validation ────────────────────────────────────────────────────────────
def valide(noeuds, hors, depot):
    erreurs = []
    metas = {n["meta"]: n for n in noeuds}
    if len(metas) != len(noeuds):
        erreurs.append("un nœud est défini deux fois")
    vus = {}
    for n in noeuds:
        if n["niveau"] not in ("racine", "fonction", "service"):
            erreurs.append(f"{n['meta']} : niveau « {n['niveau']} » inconnu")
        if n["meta"] in depot:
            erreurs.append(f"{n['meta']} : porte le nom d'un paquet existant")
        for lien, _ in LIENS:
            for x in n[lien]:
                if x in metas:
                    continue
                if x not in depot:
                    erreurs.append(f"{n['meta']} → {x} : paquet inconnu du dépôt")
                    continue
                p = depot[x]
                if p["transitionnel"]:
                    erreurs.append(f"{n['meta']} → {x} : paquet transitionnel")
                if lien == "requiert" and p["architecture"] not in ("all", "any"):
                    erreurs.append(f"{n['meta']} requiert {x} ({p['architecture']} seulement) "
                                   "— le passer en recommande/suggere")
                if n["niveau"] != "service":
                    erreurs.append(f"{n['meta']} → {x} : un paquet réel se range sous un service")
                if x in vus:
                    erreurs.append(f"{x} rangé deux fois ({vus[x]} et {n['meta']})")
                vus[x] = n["meta"]

    # CYCLES (sur toutes les forces de lien : apt suit aussi les Recommends)
    etat = {}

    def visite(m, pile):
        etat[m] = 1
        for lien, _ in LIENS:
            for x in metas[m][lien]:
                if x in metas:
                    if etat.get(x) == 1:
                        erreurs.append("cycle : " + " → ".join(pile + [x]))
                    elif not etat.get(x):
                        visite(x, pile + [x])
        etat[m] = 2
    for m in metas:
        if not etat.get(m):
            visite(m, [m])

    # ATTEIGNABLES depuis une racine, et COUVERTURE du dépôt
    racines = [n["meta"] for n in noeuds if n["niveau"] == "racine"]
    atteints, a_voir = set(), list(racines)
    while a_voir:
        m = a_voir.pop()
        if m in atteints:
            continue
        atteints.add(m)
        if m in metas:
            for lien, _ in LIENS:
                a_voir.extend(metas[m][lien])
    for m in metas:
        if m not in atteints:
            erreurs.append(f"{m} : inatteignable depuis les racines")
    for x in hors:
        if x not in depot:
            erreurs.append(f"hors-arbre : {x} inconnu du dépôt")
        if x in vus:
            erreurs.append(f"{x} : à la fois dans l'arbre et hors-arbre")
    oublies = sorted(p for p in depot if p not in vus and p not in hors)
    if oublies:
        erreurs.append("paquets ni dans l'arbre ni hors-arbre : " + ", ".join(oublies))
    return erreurs


# ── production ────────────────────────────────────────────────────────────
ENTETE = """# GÉNÉRÉ par gen-meta.py depuis arbre.yaml (#1397) — ne pas éditer à la main.
Source: secubox-meta
Section: metapackages
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
"""

NIVEAU = {"racine": "racine", "fonction": "fonction", "service": "service"}


def control(noeuds):
    out = [ENTETE]
    for n in noeuds:
        s = [f"Package: {n['meta']}", "Architecture: all"]
        for lien, champ in LIENS:
            vals = n[lien]
            if champ == "Depends":
                vals = ["${misc:Depends}"] + vals
            if vals:
                s.append(f"{champ}: " + ",\n         ".join(vals))
        s.append(f"Description: SecuBox — {NIVEAU[n['niveau']]} « {n['label']} »")
        s.append(f" {n['description']}")
        s.append(" .")
        s.append(" Métapaquet généré depuis l'arbre de secubox-meta : Depends = requis,")
        s.append(" Recommends = installé par défaut mais retirable, Suggests = optionnel.")
        out.append("\n".join(s) + "\n")
    return "\n".join(out)


def resolu(noeuds, hors, depot):
    """L'arbre pour l'App Store : nœuds + fiche réelle de chaque feuille."""
    metas = {n["meta"] for n in noeuds}
    feuilles = sorted({x for n in noeuds for lien, _ in LIENS for x in n[lien] if x not in metas})
    # FAMILLES : qui a absorbé qui (Replaces + transitionnel ou disparu).
    absorbe = {}
    for nom, p in depot.items():
        if p["transitionnel"]:
            continue
        for r in p["replaces"]:
            cible = r["nom"]
            if cible == nom:
                continue
            q = depot.get(cible)
            dep_vers_nous = q and any(d["nom"] == nom for d in q["depends"])
            if (q and q["transitionnel"] and dep_vers_nous) or not q:
                absorbe.setdefault(nom, []).append(cible)
    fiches = {}
    for f in feuilles:
        p = dict(depot[f])
        p["absorbe"] = sorted(set(absorbe.get(f, [])))
        fiches[f] = p
    return {"version": 1, "noeuds": noeuds, "hors_arbre": hors, "paquets": fiches}


def main(argv):
    depot = paquets_du_depot(exclure_source="secubox-meta")
    noeuds, hors = lit_arbre()
    erreurs = valide(noeuds, hors, depot)
    if erreurs:
        for e in erreurs:
            print("gen-meta: " + e, file=sys.stderr)
        return 1
    txt = control(noeuds)
    cible = os.path.join(ICI, "debian", "control")
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w", encoding="utf-8") as f:
            json.dump(resolu(noeuds, hors, depot), f, ensure_ascii=False, indent=1)
        return 0
    if "--check" in argv:
        actuel = open(cible, encoding="utf-8").read() if os.path.exists(cible) else ""
        if actuel != txt:
            print("gen-meta: debian/control a divergé d'arbre.yaml — relancer gen-meta.py", file=sys.stderr)
            return 1
        print(f"gen-meta: control à jour ({len(noeuds)} métapaquets)")
        return 0
    with open(cible, "w", encoding="utf-8") as f:
        f.write(txt)
    print(f"gen-meta: {len(noeuds)} métapaquets écrits dans debian/control")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
