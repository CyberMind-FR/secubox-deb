# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""secubox-webfilter-ctl : applique les profils (phase 2). S'exécute en root (unité systemd déclenchée par fichier, jamais `sudo`).

`config.json` est écrit par un compte non root : lu avec O_NOFOLLOW, plafonné, validé comme une entrée hostile. Un fichier généré identique à
l'existant ne déclenche AUCUN rechargement ; un contrôle ou un rechargement qui échoue restaure l'ancien fichier octet pour octet."""
import argparse
import fcntl
import json
import os
import pwd
import sys
import time
from pathlib import Path

import secubox_unbound as _unbound          # D4 (#2050) : commande, écriture atomique, checkconf, reload, audit — un seul code
from secubox_unbound import ecrire_atomique as _ecrire_atomique_commun

from . import catalogue, etatsur, feed, generation, profils, voisins, zones

ETAT = "/var/lib/secubox/webfilter"
RACINE = "/var/lib/secubox-webfilter-ctl"
DROPIN = "/etc/unbound/unbound.conf.d/93-secubox-webfilter.conf"
CATALOGUE = "/etc/secubox/webfilter.toml"
AUDIT = Path("/var/log/secubox/audit.log")
ADGUARD = Path("/etc/unbound/unbound.conf.d/94-secubox-adguard-tv.conf")
MAX_CONFIG = 1024 * 1024
BUDGET_OCTETS = 256 * 1024 * 1024                                  # total des listes lues pour UNE application


class ErreurCtl(RuntimeError):
    pass


class Systeme(_unbound.SystemeUnbound):
    """Les effets de bord réels ; les tests injectent un faux. Les gestes sur Unbound (checkconf, reload, audit) viennent de secubox_unbound."""
    MODULE = "webfilter-ctl"
    ERREUR = ErreurCtl
    AUDIT = AUDIT

    def uid_service(self):
        """UID du compte du service : le dossier d'état doit lui appartenir (jamais un autre compte du groupe partagé). None s'il n'existe pas."""
        try:
            return pwd.getpwnam("secubox-webfilter").pw_uid
        except KeyError:
            return None

    def adguard_texte(self) -> str:
        try:
            return ADGUARD.read_text(encoding="utf-8")
        except OSError:
            return ""

    def voisins(self) -> dict:
        return voisins.depuis_systeme()

    def adresses_box(self) -> set:
        return feed.adresses_locales()


def _ecrire_atomique(chemin: Path, texte: str, mode: int = 0o644) -> None:
    _ecrire_atomique_commun(chemin, texte, mode, prefixe=".wf-")


def _restaurer(dropin: Path, actuel) -> list:
    echecs = []
    try:
        if actuel is None:
            dropin.unlink(missing_ok=True)
        else:
            _ecrire_atomique(dropin, actuel)
    except OSError as e:
        echecs.append(str(e))
    return echecs


def _changements(a: dict, n: dict) -> list:
    sortie = []
    for nom in sorted(n["profils"]):
        p, o = n["profils"][nom], a["profils"].get(nom)
        if o is None:
            sortie.append(f"profil {nom} cree")
            o = {"categories": {c: "observe" for c in p["categories"]}, "autorise": []}
        for c in sorted(p["categories"]):
            if o["categories"].get(c, "observe") != p["categories"][c]:
                sortie.append(f"profil {nom} {c} {o['categories'].get(c, 'observe')}->{p['categories'][c]}")
        if o["autorise"] != p["autorise"]:
            sortie.append(f"profil {nom} autorise +{len(set(p['autorise']) - set(o['autorise']))} -{len(set(o['autorise']) - set(p['autorise']))}")
    sortie += [f"profil {nom} supprime" for nom in sorted(set(a["profils"]) - set(n["profils"]))]
    for mac in sorted(n["appareils"]):
        d, o = n["appareils"][mac], a["appareils"].get(mac)
        if o is None:
            sortie.append(f"appareil {mac} ajoute profil {d['profil']}")
        else:
            if o["profil"] != d["profil"]:
                sortie.append(f"appareil {mac} profil {o['profil']}->{d['profil']}")
            if o["exceptions"] != d["exceptions"]:
                sortie.append(f"appareil {mac} exceptions {json.dumps(d['exceptions'], sort_keys=True)}")
    sortie += [f"appareil {mac} retire" for mac in sorted(set(a["appareils"]) - set(n["appareils"]))]
    return sortie


def appliquer(etat, racine_ctl, dropin, catalogue_chemin, systeme=None, verrou=None, maintenant=time.time) -> dict:
    s = systeme or Systeme()
    etat, racine_ctl, dropin = Path(etat), Path(racine_ctl), Path(dropin)
    racine_ctl.mkdir(parents=True, exist_ok=True)
    # Pas de chmod quand le mode est déjà bon : le profil AppArmor n'accorde pas `w` sur le dossier lui-même, et un chmod
    # sans effet y était refusé (EACCES), ce qui faisait échouer l'unité à chaque passage (gk2 et gk3, 04:00).
    if racine_ctl.stat().st_mode & 0o777 != 0o700:
        os.chmod(racine_ctl, 0o700)
    fd = os.open(verrou or racine_ctl / "verrou", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"statut": "refuse", "message": "une application est déjà en cours", "zones": 0, "vues": 0, "version": 0, "duree_s": 0.0}
        t0 = maintenant()
        try:
            es = etatsur.EtatSur(etat, s.uid_service())
        except etatsur.ErreurEtat as e:                                  # pas de dossier sûr : impossible d'écrire un résultat, on audite et on refuse
            s.audit("refuse", str(e)[:200])
            return {"statut": "refuse", "message": str(e)[:300], "zones": 0, "vues": 0, "version": 0, "duree_s": round(maintenant() - t0, 2)}
        try:
            return _appliquer(s, es, racine_ctl, dropin, Path(catalogue_chemin), maintenant, t0)
        finally:
            es.fermer()
    finally:
        os.close(fd)


def _ecrire_etat(es, nom: str, objet) -> None:
    try:
        es.ecrire(nom, json.dumps(objet, ensure_ascii=False).encode("utf-8"), 0o640)
    except (OSError, etatsur.ErreurEtat) as e:
        print(f"secubox-webfilter-ctl : {nom} non écrit : {e}", file=sys.stderr)


def _fin(s, es, statut, message, t0, maintenant, zones_n=0, vues=0, version=0, exclus=None, audit=None) -> dict:
    res = {"statut": statut, "message": message, "zones": zones_n, "vues": vues, "version": version, "duree_s": round(maintenant() - t0, 2),
           "ts": int(maintenant()), "exclus": exclus or {}}
    _ecrire_etat(es, "resultat.json", res)
    if audit:
        s.audit(*audit)
    return res


def _bloque_quelque_chose(cfg: dict) -> bool:
    return (any(m == "block" for p in cfg["profils"].values() for m in p["categories"].values())
            or any(m == "block" for a in cfg["appareils"].values() for m in a["exceptions"].values()))


def _appliquer(s, es, racine: Path, dropin: Path, cat_chemin: Path, maintenant, t0) -> dict:
    es.supprimer("appliquer.demande")                                   # consommée DÈS LE DÉBUT : une demande qui arrive pendant l'exécution n'est pas perdue
    try:
        conf = catalogue.charger_config(cat_chemin)
        ids = {c.id for c in conf.categories}
        brut = es.lire("config.json", MAX_CONFIG)
        if brut is None:
            return _fin(s, es, "inchange", "aucune configuration : rien à appliquer", t0, maintenant)
        try:
            obj = json.loads(brut.decode("utf-8"))
        except (ValueError, RecursionError):
            raise ErreurCtl("configuration : JSON invalide") from None
        cfg = profils.valider(obj, ids)
    except (ErreurCtl, etatsur.ErreurEtat, profils.ErreurProfils, catalogue.ErreurCatalogue) as e:
        msg = str(e).replace(str(cat_chemin), "…")
        return _fin(s, es, "refuse", f"configuration refusée : {msg}"[:300], t0, maintenant, audit=("refuse", f"configuration refusée : {msg}"[:200]))
    bloque = _bloque_quelque_chose(cfg)
    res = None
    if bloque:
        sources = {c.id: [x.nom for x in c.sources] for c in conf.categories}
        budget = etatsur.Budget(BUDGET_OCTETS)
        comptes: dict = {}

        def charger(cat):
            noms = zones.charger_sur(es, cat, sources.get(cat, []), budget)
            comptes[cat] = len(noms)
            return noms
        try:
            res = generation.generer(cfg, conf.reseaux, s.voisins(), generation.adresses_adguard(s.adguard_texte()), charger, conf.zones_max,
                                     frozenset(s.adresses_box()))
        except (generation.ErreurGeneration, etatsur.ErreurEtat) as e:
            return _fin(s, es, "refuse", str(e)[:300], t0, maintenant, version=cfg["version"], audit=("refuse", str(e)[:200]))
        vides = sorted(c for c, n in comptes.items() if n == 0)
        if vides:                                                       # après une mise à jour, les listes brutes manquent jusqu'à la prochaine synchronisation
            msg = f"catégorie {', '.join(vides)} en block mais aucune liste disponible : lancer une synchronisation des listes"
            return _fin(s, es, "refuse", msg[:300], t0, maintenant, version=cfg["version"], audit=("refuse", msg[:200]))
    voulu = res.texte if res else None                                  # aucun blocage : AUCUN drop-in (rien à écrire, rien à recharger)
    try:
        actuel = dropin.read_text(encoding="utf-8")
    except FileNotFoundError:
        actuel = None
    eff_def = profils.effective(cfg, "")
    carte = {"version": cfg["version"],
             "adresses": ({a: {"mac": i["mac"], "profil": cfg["appareils"][i["mac"]]["profil"], "vue": i["vue"], "modes": profils.effective(cfg, i["mac"])["modes"]}
                           for a, i in sorted(res.liens.items())} if res else {}),
             "defaut": {"reseaux": list(conf.reseaux), "modes": eff_def["modes"]}}
    zones_n, vues_n, exclus = (res.zones, len(res.vues), res.exclus) if res else (0, 0, {})
    if voulu == actuel:
        _ecrire_etat(es, "carte.json", carte)
        msg = "aucun changement : Unbound n'est pas rechargé" if bloque else "aucun blocage configuré : Unbound n'est pas touché"
        return _fin(s, es, "inchange", msg, t0, maintenant, zones_n, vues_n, cfg["version"], exclus)
    precedent = racine / "precedent.conf"
    if actuel is None:
        precedent.unlink(missing_ok=True)
    else:
        _ecrire_atomique(precedent, actuel, 0o600)
    if voulu is None:
        dropin.unlink(missing_ok=True)
    else:
        _ecrire_atomique(dropin, voulu)
    ok, sortie = s.verifier_unbound()
    if not ok:
        echecs = _restaurer(dropin, actuel)
        msg = "unbound-checkconf refuse la configuration : " + sortie
        if echecs:
            msg += " ; restauration INCOMPLÈTE : " + "; ".join(echecs)
            return _fin(s, es, "erreur", msg[:300], t0, maintenant, version=cfg["version"], audit=("restauration-echouee", msg[:200]))
        return _fin(s, es, "refuse", msg[:300], t0, maintenant, version=cfg["version"], audit=("refuse", msg[:200]))
    try:
        s.recharger_unbound()
    except ErreurCtl as e:
        echecs = _restaurer(dropin, actuel)
        retour = ""
        if not echecs:
            try:
                s.recharger_unbound()                                    # Unbound repart sur l'ancien état
            except ErreurCtl as e2:
                retour = f" ; second rechargement : {e2}"
        msg = f"{e}{retour}" + (" ; restauration INCOMPLÈTE : " + "; ".join(echecs) if echecs else "")
        return _fin(s, es, "erreur", msg[:300], t0, maintenant, version=cfg["version"], audit=("rechargement-echoue", msg[:200]))
    try:
        ancienne = profils.valider(json.loads((racine / "applique.json").read_text(encoding="utf-8")), ids)
    except (OSError, ValueError, profils.ErreurProfils):
        ancienne = profils.vide(ids)
    for ligne in _changements(ancienne, cfg):
        s.audit("changement", ligne)
    _ecrire_atomique(racine / "applique.json", json.dumps(cfg, sort_keys=True), 0o600)
    _ecrire_etat(es, "carte.json", carte)
    if res is None:
        return _fin(s, es, "applique", "plus aucun blocage : drop-in retiré", t0, maintenant, 0, 0, cfg["version"], {},
                    audit=("application", f"zones=0 vues=0 entrees=0 version={cfg['version']}"))
    return _fin(s, es, "applique", f"{res.zones} zones dans {len(res.vues)} vues", t0, maintenant, res.zones, len(res.vues), cfg["version"], res.exclus,
                audit=("application", f"zones={res.zones} vues={len(res.vues)} entrees={res.entrees} version={cfg['version']}"))


def principal(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="secubox-webfilter-ctl", description="Applique les profils de secubox-webfilter à Unbound.")
    ap.add_argument("--etat", default=ETAT)
    ap.add_argument("--racine", default=RACINE)
    ap.add_argument("--dropin", default=DROPIN)
    ap.add_argument("--catalogue", default=CATALOGUE)
    ap.add_argument("commande", choices=["apply", "status"])
    a = ap.parse_args(argv)
    if a.commande == "status":
        try:
            es = etatsur.EtatSur(a.etat)
            try:
                brut = es.lire("resultat.json", MAX_CONFIG)
            finally:
                es.fermer()
        except etatsur.ErreurEtat:
            brut = None
        if brut is None:
            print("secubox-webfilter-ctl : aucun résultat", file=sys.stderr)
            return 1
        print(brut.decode("utf-8", "replace"))
        return 0
    r = appliquer(a.etat, a.racine, a.dropin, a.catalogue)
    print(json.dumps(r, ensure_ascii=False))
    return 0 if r["statut"] in ("applique", "inchange") else 1
