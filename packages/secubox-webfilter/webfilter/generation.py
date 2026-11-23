# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Texte du drop-in Unbound de webfilter (#1962, phase 2) : une vue par configuration effective distincte, le réseau entier vers `wf-defaut`,
des adresses plus précises vers les vues des appareils assignés. Déterministe : un texte identique ne déclenche aucun rechargement.
Aucune valeur libre n'y entre : noms revalidés, adresses et réseaux par `ipaddress`."""
import ipaddress
import re
from dataclasses import dataclass, field

from . import domaines, profils, zones

ENTETE = "# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n# GÉNÉRÉ par secubox-webfilter-ctl — ne pas éditer à la main (#1962).\n"
VUE_DEFAUT = "wf-defaut"
_ADGUARD = re.compile(r"^\s*access-control-view:\s*(\S+)\s+\S+\s*$", re.M)


class ErreurGeneration(ValueError):
    pass


@dataclass
class Resultat:
    texte: str
    vues: dict
    zones: int
    exclus: dict
    entrees: int
    liens: dict = field(default_factory=dict)             # {adresse: {"mac", "vue"}} : la carte du démon d'alimentation


def _reseau(v) -> str:
    if not isinstance(v, str) or not v.isascii() or not v.isprintable() or "%" in v:
        raise ErreurGeneration("réseau invalide")
    try:
        return str(ipaddress.ip_network(v, strict=False))
    except ValueError:
        raise ErreurGeneration("réseau invalide") from None


def _adresse(v):
    if not isinstance(v, str) or "%" in v:
        return None
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def _noms(liste, quoi: str) -> list:
    sortie = []
    for n in liste:
        v = domaines.valider(n)
        if v is None or v != n:                                       # forme canonique exigée
            raise ErreurGeneration(f"{quoi} : nom de domaine invalide")
        sortie.append(v)
    return sortie


def adresses_adguard(texte: str) -> set:
    """Adresses d'APPAREILS déjà liées à une vue par ad-guard (entrées /32 et /128 de son drop-in) : webfilter n'y touche jamais."""
    sortie = set()
    for m in _ADGUARD.finditer(texte or ""):
        adr, _, lg = m.group(1).partition("/")
        a = _adresse(adr)
        if a and (not lg or lg == ("128" if ":" in a else "32")):
            sortie.add(a)
    return sortie


def _zones_vue(eff: dict, charger) -> tuple:
    """(zones bloquées, autorisations transparentes) d'une configuration effective. Une autorisation REMPLACE l'entrée listée du même nom."""
    bloquees = []
    for cat in profils.bloquees(eff):
        bloquees += _noms(charger(cat), f"liste {cat}")
    forces = sorted(set(_noms(eff.get("bloque", []), "blocage")))                 # domaines TOUJOURS refusés, même catégorie en observe (#2433)
    aut = [a for a in sorted(set(_noms(eff["autorise"], "autorisation"))) if a not in forces]
    base = [z for z in zones.dedoublonner(bloquees) if z not in aut]             # ordre d'origine : dédoublonner, PUIS retirer les autorisations
    return zones.dedoublonner(base + forces), aut


def generer(cfg, reseaux, voisins, adguard, charger, zones_max: int, adresses_box=frozenset()) -> Resultat:
    nets = sorted({_reseau(r) for r in reseaux})
    eff_defaut = profils.effective(cfg, "")
    cle_defaut = profils.cle_vue(eff_defaut)
    configs = {VUE_DEFAUT: eff_defaut}
    liens, deja, exclus, infos = [], set(), {}, {}
    for mac in sorted(cfg["appareils"]):
        eff = profils.effective(cfg, mac)
        cle = profils.cle_vue(eff)
        vue = VUE_DEFAUT if cle == cle_defaut else cle
        brutes = [a for a in (_adresse(x) for x in voisins.get(mac, [])) if a]
        if not brutes:
            exclus[mac] = "adresse inconnue"
            continue
        libres = [a for a in brutes if a not in adguard and a not in adresses_box and a not in deja]
        if not libres:
            exclus[mac] = ("geree par ad-guard" if any(a in adguard for a in brutes)
                           else "adresse de la box" if all(a in adresses_box for a in brutes) else "adresse en double")
            continue
        for a in libres:
            deja.add(a)
            liens.append((a, vue))
            infos[a] = {"mac": mac, "vue": vue}
        configs.setdefault(vue, eff)
    contenu = {nom: _zones_vue(eff, charger) for nom, eff in configs.items()}
    vues = {nom: len(b) + len(a) for nom, (b, a) in contenu.items()}
    if sum(vues.values()) > zones_max:
        raise ErreurGeneration(f"budget de zones dépassé : {sum(vues.values())} > {zones_max}")
    lignes = [ENTETE, "server:\n"]
    lignes += [f"    access-control-view: {n} {VUE_DEFAUT}\n" for n in nets]
    for a, vue in sorted(liens, key=lambda x: (ipaddress.ip_address(x[0]).version, ipaddress.ip_address(x[0]))):
        lignes.append(f"    access-control-view: {a}/{128 if ':' in a else 32} {vue}\n")
    lignes += _vues_compactes(contenu)
    return Resultat("".join(lignes), vues, sum(vues.values()), exclus, len(nets) + len(liens), infos)


_TYPES = ("always_nxdomain", "transparent")


def _vues_compactes(contenu: dict) -> list:
    """Les vues, chaque zone écrite UNE fois (#3893) : une zone présente (même nom, même type) dans plusieurs vues va dans
    l'ensemble de ces vues (`secubox-ensemble:`, déclaré avant elles), chaque vue appelle ses ensembles et garde ses zones
    propres. secubox-dns-listes recopie les ensembles dans les vues (compilation ET mode direct) : chaque vue charge
    exactement les mêmes zones qu'avant (une seule vue : aucun ensemble, texte de toujours). 863 674 lignes → 317 016 sur
    gk2 (trois vues dont deux identiques)."""
    noms = sorted(contenu)
    membres: dict = {}                                       # (zone, type) -> vues qui la portent, dans l'ordre des noms
    for nom in noms:
        b, a = contenu[nom]
        for t, zs in zip(_TYPES, (b, a)):
            for z in zs:
                membres.setdefault((z, t), []).append(nom)
    groupes: dict = {}                                       # vues -> {type: [zones]}
    for (z, t), vs in membres.items():
        groupes.setdefault(tuple(vs), {}).setdefault(t, []).append(z)
    partages = sorted((g for g in groupes if len(g) > 1), key=lambda g: (-len(g), g))
    nom_ens = {g: f"commun-{i}" for i, g in enumerate(partages)}
    lignes = []
    for g in partages:
        lignes.append(f'secubox-ensemble:\n    name: "{nom_ens[g]}"\n')
        for t in _TYPES:
            lignes += [f'    local-zone: "{z}." {t}\n' for z in sorted(groupes[g].get(t, []))]
    for nom in noms:
        lignes.append(f'view:\n    name: "{nom}"\n    view-first: yes\n')
        propres = groupes.get((nom,), {})
        for t in _TYPES:
            lignes += [f'    local-zone: "{z}." {t}\n' for z in sorted(propres.get(t, []))]
        lignes += [f'    secubox-ensemble: "{nom_ens[g]}"\n' for g in partages if nom in g]
    return lignes
