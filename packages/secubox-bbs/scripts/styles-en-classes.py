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

def main() -> int:
    vus: dict[str, str] = {}
    for g in GABARITS:
        texte = g.read_text()
        def remplace(m):
            decls = m.group(1).strip().rstrip(";")
            if "{{" in decls:
                # Un style calcule par le gabarit ne peut pas devenir une
                # classe statique. On le signale plutot que de le casser.
                print(f"  ATTENTION {g.name}: style dynamique conserve — {decls[:50]}", file=sys.stderr)
                return m.group(0)
            c = nom(decls)
            vus[c] = decls
            return f'class="{c}"' if 'class=' not in m.group(0) else m.group(0)
        # Fusionner avec une classe existante quand il y en a une.
        texte = re.sub(r'class="([^"]*)"\s+style="([^"]*)"',
                       lambda m: _fusion(m, vus), texte)
        texte = re.sub(r'style="([^"]*)"\s+class="([^"]*)"',
                       lambda m: _fusion2(m, vus), texte)
        texte = re.sub(r'style="([^"]*)"', remplace, texte)
        g.write_text(texte)

    css = CSS.read_text()
    if BALISE in css:
        css = css.split(BALISE)[0]
    bloc = [BALISE,
            "/* Genere. Ne pas editer a la main : relancer le script. */"]
    for c, d in sorted(vus.items()):
        bloc.append(f".{c}{{{d}}}")
    CSS.write_text(css.rstrip() + "\n\n" + "\n".join(bloc) + "\n")
    print(f"  {len(vus)} classes generees, {len(GABARITS)} gabarits reecrits")
    return 0

def _fusion(m, vus):
    cls, decls = m.group(1), m.group(2).strip().rstrip(";")
    if "{{" in decls:
        return m.group(0)
    c = nom(decls); vus[c] = decls
    return f'class="{cls} {c}"'

def _fusion2(m, vus):
    decls, cls = m.group(1).strip().rstrip(";"), m.group(2)
    if "{{" in decls:
        return m.group(0)
    c = nom(decls); vus[c] = decls
    return f'class="{cls} {c}"'

if __name__ == "__main__":
    raise SystemExit(main())
