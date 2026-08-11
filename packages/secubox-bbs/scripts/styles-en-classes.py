#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: BBS — sortir les styles en ligne des gabarits.

POURQUOI

Le service envoie une politique de securite stricte : `style-src 'self'`. Elle
interdit les attributs `style="…"`, et c'est voulu — un attribut de style est
un vecteur d'injection quand une valeur vient d'ailleurs.

Or les gabarits ont ete tires de la maquette validee, qui en est pleine. Les
reecrire a la main risquerait de s'ecarter du rendu approuve ; les traduire
mecaniquement garantit un rendu IDENTIQUE, declaration par declaration.

Les classes sont nommees d'apres une empreinte du contenu : deux elements
partageant le meme style partagent la classe, et relancer ce script sur des
gabarits inchanges ne produit aucune difference.

L'alternative — assouplir la politique avec `unsafe-hashes` ou `unsafe-inline`
— reviendrait a desarmer une protection pour eviter un travail mecanique.
"""
import hashlib
import pathlib
import re
import sys

RACINE = pathlib.Path(__file__).resolve().parent.parent
GABARITS = sorted((RACINE / "internal/web/templates").glob("*.html"))
CSS = RACINE / "internal/web/static/bbs.css"
BALISE = "/* ==== styles extraits des gabarits (scripts/styles-en-classes.py) ==== */"

def nom(decls: str) -> str:
    return "s" + hashlib.sha256(decls.encode()).hexdigest()[:7]


TAG = re.compile(r"<[a-zA-Z][^>]*>")
CLASSES = re.compile(r'\sclass="([^"]*)"')
STYLE = re.compile(r'\sstyle="([^"]*)"')


def traite_balise(t: str, vus: dict, alerte) -> str:
    """Fusionne class= et style= d'UNE balise, quel que soit l'ordre.

    Le premier jet ne fusionnait que des attributs ADJACENTS. Avec
    `class="board" href="…" style="…"` — c'est-a-dire la majorite des cas — il
    ajoutait un SECOND attribut class. Les analyseurs HTML gardent le premier
    et ignorent le second : les elements concernes perdaient donc leurs styles,
    et la mise en page s'effondrait dans les navigateurs stricts.
    """
    styles = STYLE.findall(t)
    classes = CLASSES.findall(t)
    if not styles and len(classes) < 2:
        return t
    if not styles:
        # REPARATION : une balise portant deja DEUX attributs class, heritee
        # d'une version anterieure de ce script. Les analyseurs HTML gardent le
        # premier et ignorent le second — l'element perd donc ses styles en
        # silence. On fusionne.
        fusion = " ".join(dict.fromkeys(" ".join(classes).split()))
        t = CLASSES.sub("", t)
        return re.sub(r"^<([a-zA-Z][a-zA-Z0-9]*)", r'<\1 class="%s"' % fusion, t, count=1)
    dyn = [d for d in styles if "{{" in d]
    stat = [d for d in styles if "{{" not in d]
    for d in dyn:
        alerte(d)
    ajout = []
    for d in stat:
        d = d.strip().rstrip(";")
        if not d:
            continue
        c = nom(d)
        vus[c] = d
        ajout.append(c)
    # Retirer les styles statiques, garder les dynamiques tels quels.
    def _st(m):
        return m.group(0) if "{{" in m.group(1) else ""
    t = STYLE.sub(_st, t)
    if not ajout:
        return t
    classes = CLASSES.findall(t)
    fusion = " ".join(dict.fromkeys(" ".join(classes).split() + ajout))
    t = CLASSES.sub("", t)          # retirer TOUS les class existants
    # reinjecter un unique attribut class juste apres le nom de balise
    return re.sub(r"^<([a-zA-Z][a-zA-Z0-9]*)", r'<\1 class="%s"' % fusion, t, count=1)


def main() -> int:
    vus: dict[str, str] = {}
    for g in GABARITS:
        texte = g.read_text()
        alerte = lambda d, g=g: print(
            f"  style dynamique conserve dans {g.name}: {d[:48]}", file=sys.stderr)
        texte = TAG.sub(lambda m: traite_balise(m.group(0), vus, alerte), texte)
        g.write_text(texte)

    css = CSS.read_text()
    if not vus:
        # NE RIEN ECRASER. Aucun style trouve veut dire que les gabarits ont
        # DEJA ete convertis : reecrire le bloc le viderait, et les classes que
        # les gabarits referencent disparaitraient de la feuille de style. Le
        # premier jet l'a fait — page sans mise en forme, sans erreur visible.
        print("  aucun style en ligne : gabarits deja convertis, CSS inchange")
        return verifie()
    if BALISE in css:
        css = css.split(BALISE)[0]
    bloc = [BALISE, "/* Genere. Ne pas editer a la main : relancer le script. */"]
    for c, d in sorted(vus.items()):
        bloc.append(f".{c}{{{d}}}")
    CSS.write_text(css.rstrip() + "\n\n" + "\n".join(bloc) + "\n")

    return verifie()


def verifie() -> int:
    """Aucun gabarit ne doit sortir avec deux attributs class."""
    mauvais = 0
    for g in GABARITS:
        for t in TAG.findall(g.read_text()):
            if len(CLASSES.findall(t)) > 1:
                mauvais += 1
                print(f"  DOUBLON dans {g.name}: {t[:70]}", file=sys.stderr)
    if mauvais:
        print(f"  {mauvais} balise(s) avec deux attributs class", file=sys.stderr)
        return 1
    print(f"  {len(GABARITS)} gabarits verifies, aucun doublon d'attribut class")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
