# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""secubox-webfilter-ctl : applique les profils (phase 2). S'exécute en root (unité systemd déclenchée par fichier, jamais `sudo`).

`config.json` est écrit par un compte non root : lu avec O_NOFOLLOW, plafonné, validé comme une entrée hostile. Un fichier généré identique à
l'existant ne déclenche AUCUN rechargement ; un contrôle ou un rechargement qui échoue restaure l'ancien fichier octet pour octet."""
import argparse
import contextlib
import fcntl
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import catalogue, feed, generation, profils, voisins, zones

ETAT = "/var/lib/secubox/webfilter"
RACINE = "/var/lib/secubox-webfilter-ctl"
DROPIN = "/etc/unbound/unbound.conf.d/93-secubox-webfilter.conf"
CATALOGUE = "/etc/secubox/webfilter.toml"
AUDIT = Path("/var/log/secubox/audit.log")
ADGUARD = Path("/etc/unbound/unbound.conf.d/94-secubox-adguard-tv.conf")
CHECKCONF = "/usr/sbin/unbound-checkconf"
CONTROL = "/usr/sbin/unbound-control"
MAX_CONFIG = 1024 * 1024


class ErreurCtl(RuntimeError):
    pass


def _commande(args, delai):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=delai, check=False)
    except subprocess.TimeoutExpired:
        return False, f"{Path(args[0]).name} : délai de {delai} s dépassé"
    except OSError as e:
        return False, f"{Path(args[0]).name} : {e}"
    return r.returncode == 0, (r.stdout + r.stderr).strip()[-300:]


class Systeme:
    """Les effets de bord réels ; les tests injectent un faux."""

    def verifier_unbound(self):
        return _commande([CHECKCONF], 60)

    def recharger_unbound(self):
        ok, sortie = _commande([CONTROL, "reload"], 120)
        if not ok:
            raise ErreurCtl("unbound-control reload a échoué : " + sortie)

    def adguard_texte(self) -> str:
        try:
            return ADGUARD.read_text(encoding="utf-8")
        except OSError:
            return ""

    def voisins(self) -> dict:
        return voisins.depuis_systeme()

    def adresses_box(self) -> set:
        return feed.adresses_locales()

    def audit(self, action: str, detail: str = "") -> None:
        try:
            with open(AUDIT, "a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "module": "webfilter-ctl", "action": action,
                                    "detail": detail[:300]}, ensure_ascii=False) + "\n")
        except OSError as e:
            print(f"secubox-webfilter-ctl : audit non écrit ({action}) : {e}", file=sys.stderr)


def _ecrire_atomique(chemin: Path, texte: str, mode: int = 0o644) -> None:
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=".wf-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(texte)
            f.flush()
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _ecrire_json_etat(chemin: Path, objet, etat: Path) -> None:
    """Fichier lisible par le compte du service : propriétaire du dossier d'état, 0640, remplacement atomique (jamais de suivi de lien)."""
    st = os.stat(etat)
    fd, tmp = tempfile.mkstemp(dir=etat, prefix=".wf-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(objet, f, ensure_ascii=False)
            f.flush()
            with contextlib.suppress(PermissionError):
                os.fchown(f.fileno(), st.st_uid, st.st_gid)
            os.fchmod(f.fileno(), 0o640)
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _lire_config(chemin: Path):
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ErreurCtl("configuration absente ou illisible") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ErreurCtl("configuration : fichier non régulier")
        brut = os.read(fd, MAX_CONFIG + 1)
    finally:
        os.close(fd)
    if len(brut) > MAX_CONFIG:
        raise ErreurCtl("configuration trop volumineuse")
    try:
        return json.loads(brut.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ErreurCtl("configuration : JSON invalide") from None


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
    os.chmod(racine_ctl, 0o700)
    fd = os.open(verrou or racine_ctl / "verrou", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"statut": "refuse", "message": "une application est déjà en cours", "zones": 0, "vues": 0, "version": 0, "duree_s": 0.0}
        return _appliquer(s, etat, racine_ctl, dropin, Path(catalogue_chemin), maintenant)
    finally:
        os.close(fd)


def _fin(s, etat, statut, message, t0, maintenant, zones_n=0, vues=0, version=0, exclus=None, audit=None) -> dict:
    res = {"statut": statut, "message": message, "zones": zones_n, "vues": vues, "version": version, "duree_s": round(maintenant() - t0, 2),
           "ts": int(maintenant()), "exclus": exclus or {}}
    with contextlib.suppress(OSError):
        _ecrire_json_etat(etat / "resultat.json", res, etat)
    if audit:
        s.audit(*audit)
    return res


def _appliquer(s, etat: Path, racine: Path, dropin: Path, cat_chemin: Path, maintenant) -> dict:
    t0 = maintenant()
    try:
        conf = catalogue.charger_config(cat_chemin)
        cfg = profils.valider(_lire_config(etat / "config.json"), {c.id for c in conf.categories})
    except (ErreurCtl, profils.ErreurProfils, catalogue.ErreurCatalogue) as e:
        msg = str(e).replace(str(etat), "…").replace(str(cat_chemin), "…")
        return _fin(s, etat, "refuse", f"configuration refusée : {msg}"[:300], t0, maintenant, audit=("refuse", f"configuration refusée : {msg}"[:200]))
    try:
        res = generation.generer(cfg, conf.reseaux, s.voisins(), generation.adresses_adguard(s.adguard_texte()),
                                 lambda cat: zones.charger(etat / "listes", cat), conf.zones_max, frozenset(s.adresses_box()))
    except generation.ErreurGeneration as e:
        return _fin(s, etat, "refuse", str(e)[:300], t0, maintenant, version=cfg["version"], audit=("refuse", str(e)[:200]))
    try:
        actuel = dropin.read_text(encoding="utf-8")
    except FileNotFoundError:
        actuel = None
    if actuel == res.texte:
        return _fin(s, etat, "inchange", "aucun changement : Unbound n'est pas rechargé", t0, maintenant, res.zones, len(res.vues), cfg["version"], res.exclus)
    precedent = racine / "precedent.conf"
    if actuel is None:
        precedent.unlink(missing_ok=True)
    else:
        _ecrire_atomique(precedent, actuel, 0o600)
    _ecrire_atomique(dropin, res.texte)
    ok, sortie = s.verifier_unbound()
    if not ok:
        echecs = _restaurer(dropin, actuel)
        msg = "unbound-checkconf refuse la configuration : " + sortie
        if echecs:
            msg += " ; restauration INCOMPLÈTE : " + "; ".join(echecs)
            return _fin(s, etat, "erreur", msg[:300], t0, maintenant, version=cfg["version"], audit=("restauration-echouee", msg[:200]))
        return _fin(s, etat, "refuse", msg[:300], t0, maintenant, version=cfg["version"], audit=("refuse", msg[:200]))
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
        return _fin(s, etat, "erreur", msg[:300], t0, maintenant, version=cfg["version"], audit=("rechargement-echoue", msg[:200]))
    try:
        ancienne = profils.valider(json.loads((racine / "applique.json").read_text(encoding="utf-8")), {c.id for c in conf.categories})
    except (OSError, ValueError, profils.ErreurProfils):
        ancienne = profils.vide({c.id for c in conf.categories})
    for ligne in _changements(ancienne, cfg):
        s.audit("changement", ligne)
    _ecrire_atomique(racine / "applique.json", json.dumps(cfg, sort_keys=True), 0o600)
    eff_def = profils.effective(cfg, "")
    carte = {"version": cfg["version"],
             "adresses": {a: {"mac": i["mac"], "profil": cfg["appareils"][i["mac"]]["profil"], "vue": i["vue"], "modes": profils.effective(cfg, i["mac"])["modes"]}
                          for a, i in sorted(res.liens.items())},
             "defaut": {"reseaux": list(conf.reseaux), "modes": eff_def["modes"]}}
    with contextlib.suppress(OSError):
        _ecrire_json_etat(etat / "carte.json", carte, etat)
    return _fin(s, etat, "applique", f"{res.zones} zones dans {len(res.vues)} vues", t0, maintenant, res.zones, len(res.vues), cfg["version"], res.exclus,
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
            print((Path(a.etat) / "resultat.json").read_text(encoding="utf-8"))
            return 0
        except OSError:
            print("secubox-webfilter-ctl : aucun résultat", file=sys.stderr)
            return 1
    r = appliquer(a.etat, a.racine, a.dropin, a.catalogue)
    print(json.dumps(r, ensure_ascii=False))
    return 0 if r["statut"] in ("applique", "inchange") else 1
