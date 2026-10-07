# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: openpgp — l'annuaire des clés PERSONNELLES de la box (#1738, phase 2)
CyberMind — https://cybermind.fr

Ce que la box garde ici : des clés PUBLIQUES, publiées par leur personne.
La clé secrète vit dans le compartiment de la personne, au Coffre (#1367 P5) ;
ce démon ne la voit jamais.

HORS DU JOURNAL DE L'ANNUAIRE. Ce journal-là est public et indélébile (RGPD) :
aucune clé personnelle n'y entre. L'annuaire des clés est un fichier par
personne sur CETTE box, servi aux box liées par un document signé de la clé
de box, et retirable à tout moment.

UNE ADRESSE N'EST « VÉRIFIÉE » QUE SI LA BOX L'A CONFIÉE À LA PERSONNE : sa
boîte, telle que l'Identity Manager l'a liée (sbx_app_links, app = email).
Une autre adresse portée par la clé reste « déclarée ». Seules les adresses
vérifiées sont servies par WKD : sans cette règle, quiconque publierait une
clé au nom de la boîte d'un autre.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from .gpg import EMPREINTE, ErreurGpg, Trousseau, _cles_colons

SBX_DB = Path(os.environ.get("SECUBOX_SBX_DB", "/var/lib/secubox/sbxid/sbx.db"))
PERSONNE_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
COURRIEL_RE = re.compile(r"^[^@\s<>\"]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
DID_RE = re.compile(r"^did:[a-z0-9]+:[A-Za-z0-9._:-]{3,128}$")
MAX_CLE = 64 * 1024
MAX_KEYDATA = 6 * 1024              # octets binaires d'une clé publique minimale servie en en-tête Autocrypt
ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"


class RefusCle(ValueError):
    """La clé soumise n'entre pas dans l'annuaire ; le motif est sûr à montrer."""


# ── WKD ──────────────────────────────────────────────────────────────────────

def zbase32(octets: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in octets)
    bits += "0" * (-len(bits) % 5)
    return "".join(ZBASE32[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def hash_wkd(partie_locale: str) -> str:
    """Le nom WKD d'une adresse : z-base-32 du SHA-1 de sa partie locale en minuscules."""
    return zbase32(hashlib.sha1(partie_locale.lower().encode()).digest())


def armure_vers_binaire(armure: str) -> bytes:
    lignes = armure.strip().splitlines()
    try:
        debut = next(i for i, l in enumerate(lignes) if l.startswith("-----BEGIN PGP PUBLIC KEY BLOCK"))
        fin = next(i for i, l in enumerate(lignes) if l.startswith("-----END PGP PUBLIC KEY BLOCK"))
    except StopIteration:
        raise RefusCle("bloc de clé publique introuvable") from None
    corps = lignes[debut + 1:fin]
    while corps and corps[0].strip() and ":" in corps[0]:      # en-têtes d'armure
        corps = corps[1:]
    corps = [l for l in corps if l.strip() and not l.startswith("=")]
    return base64.b64decode("".join(corps))


# ── vérifier une clé soumise ─────────────────────────────────────────────────

def _uids(texte_colons: str) -> List[str]:
    out = []
    for l in texte_colons.splitlines():
        c = l.split(":")
        if c[0] == "uid" and c[1] not in ("r", "e", "i") and len(c) > 9:
            out.append(re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), c[9]))
    return out


def _courriels(uids: List[str]) -> List[str]:
    out = []
    for u in uids:
        m = re.search(r"<([^<>]+)>\s*$", u)
        a = (m.group(1) if m else u).strip().lower()
        if COURRIEL_RE.match(a) and a not in out:
            out.append(a)
    return out


def verifier_cle(armure: str, gpg: str = "gpg", maintenant: Optional[float] = None) -> dict:
    """Une clé PUBLIQUE, une seule primaire, valide, qui sait chiffrer.
    Rend {empreinte, uids, courriels, expire, armure} — l'armure réexportée
    en `export-minimal` dans un trousseau jetable : ce que la box sert n'est
    jamais le texte tel qu'il a été soumis."""
    t = time.time() if maintenant is None else maintenant
    if not isinstance(armure, str) or not armure.strip() or len(armure) > MAX_CLE:
        raise RefusCle("bloc de clé absent ou trop grand")
    if "PRIVATE KEY BLOCK" in armure:
        raise RefusCle("c'est une clé SECRÈTE : seule la clé publique se publie")
    if "BEGIN PGP PUBLIC KEY BLOCK" not in armure:
        raise RefusCle("bloc de clé publique attendu (armure ASCII)")
    rep = tempfile.mkdtemp(prefix="sbxp-")
    os.chmod(rep, 0o700)
    try:
        tr = Trousseau(rep, gpg=gpg)
        r = tr._gpg("--show-keys", "--with-colons", "--fixed-list-mode", entree=armure.encode(), verifier=False)
        texte = r.stdout.decode(errors="replace")
        if r.returncode != 0:
            raise RefusCle("bloc illisible")
        if any(l.startswith(("sec:", "ssb:")) for l in texte.splitlines()):
            raise RefusCle("matière secrète présente : seule la clé publique se publie")
        primaires = [l for l in texte.splitlines() if l.startswith("pub:")]
        cles = _cles_colons(texte)
        if len(primaires) != 1 or len(cles) != 1:
            raise RefusCle("une seule clé primaire, valide, est attendue")
        c = cles[0]
        if c["expire"] and c["expire"] < t:
            raise RefusCle("clé expirée")
        if not c["chiffrement"]:
            raise RefusCle("aucune sous-clé de chiffrement valide")
        tr._gpg("--import", "--import-options", "import-minimal", entree=armure.encode())
        propre = tr.exporter_public(c["empreinte"])
        uids = _uids(texte)
        return {"empreinte": c["empreinte"], "uids": uids, "courriels": _courriels(uids),
                "expire": c["expire"], "armure": propre}
    except ErreurGpg as e:
        raise RefusCle(f"clé refusée par gpg ({e})") from None
    finally:
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], env={**os.environ, "GNUPGHOME": rep},
                       capture_output=True)
        shutil.rmtree(rep, ignore_errors=True)


# ── l'annuaire ───────────────────────────────────────────────────────────────

class Annuaire:
    def __init__(self, racine: Path, sbx_db: Path = SBX_DB, gpg: str = "gpg"):
        self.racine = Path(racine)
        self.dossier = self.racine / "personnes"
        self.dossier_pairs = self.racine / "pairs-cles"
        self.fichier_retraits = self.racine / "personnes-retirees.json"
        self.sbx_db = Path(sbx_db)
        self.gpg = gpg

    # ── plomberie ───────────────────────────────────────────────────────
    @staticmethod
    def _ecrit(chemin: Path, donnees) -> None:
        chemin.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        tmp = chemin.with_suffix(".tmp")
        tmp.write_text(json.dumps(donnees, ensure_ascii=False, indent=1))
        os.chmod(tmp, 0o640)
        tmp.replace(chemin)

    @staticmethod
    def _lit(chemin: Path, defaut):
        try:
            return json.loads(chemin.read_text())
        except (OSError, ValueError):
            return defaut

    def _fiche(self, user_uuid: str) -> Path:
        if not PERSONNE_RE.match(user_uuid or ""):
            raise RefusCle("personne invalide")
        return self.dossier / f"{user_uuid}.json"

    def adresses_de(self, user_uuid: str) -> set:
        """Les boîtes que la box a confiées à la personne (Identity Manager)."""
        try:
            c = sqlite3.connect(f"file:{self.sbx_db}?mode=ro", uri=True, timeout=2)
        except sqlite3.Error:
            return set()
        try:
            lignes = c.execute("SELECT app_id, app_handle FROM sbx_app_links WHERE app='email' AND user_uuid=?",
                               (user_uuid,)).fetchall()
        except sqlite3.Error:
            return set()
        finally:
            c.close()
        return {str(v).strip().lower() for l in lignes for v in l if v and COURRIEL_RE.match(str(v).strip())}

    # ── la personne ─────────────────────────────────────────────────────
    def publier(self, user_uuid: str, pseudo: str, armure: str) -> dict:
        fiche = self._fiche(user_uuid)
        k = verifier_cle(armure, gpg=self.gpg)
        confiees = self.adresses_de(user_uuid)
        ancienne = self._lit(fiche, None)
        entree = {"personne": user_uuid, "pseudo": str(pseudo or "")[:64], "empreinte": k["empreinte"],
                  "uids": k["uids"], "courriels": k["courriels"],
                  "verifies": [a for a in k["courriels"] if a in confiees],
                  "expire": k["expire"], "publiee": int(time.time()), "cle_publique": k["armure"]}
        if ancienne and ancienne.get("empreinte") != k["empreinte"]:
            self._note_retrait(ancienne["empreinte"])           # rotation : l'ancienne ne vaut plus
        self._ecrit(fiche, entree)
        return entree

    def mienne(self, user_uuid: str) -> Optional[dict]:
        return self._lit(self._fiche(user_uuid), None)

    def retirer(self, user_uuid: str) -> Optional[str]:
        fiche = self._fiche(user_uuid)
        e = self._lit(fiche, None)
        if not e:
            return None
        fiche.unlink(missing_ok=True)
        self._note_retrait(e["empreinte"])
        return e["empreinte"]

    def _note_retrait(self, empreinte: str) -> None:
        r = self._lit(self.fichier_retraits, {})
        r[empreinte] = int(time.time())
        self._ecrit(self.fichier_retraits, r)

    def locales(self) -> List[dict]:
        out = []
        if self.dossier.is_dir():
            for f in sorted(self.dossier.glob("*.json")):
                e = self._lit(f, None)
                if e and EMPREINTE.match(e.get("empreinte", "")):
                    out.append(e)
        return out

    def autocrypt(self, maintenant: Optional[float] = None) -> Dict[str, str]:
        """Table adresse → `keydata` Autocrypt (clé PUBLIQUE minimale, base64 d'une seule ligne) pour l'en-tête
        `Autocrypt:` des courriels SORTANTS de cette box (#1852, P2).

        Seules les adresses VÉRIFIÉES (confiées à la personne par la box) y figurent : une clé déclarée au nom de la boîte
        d'un autre ne doit jamais partir en en-tête. Une clé expirée est omise. Une clé trop grosse est omise aussi : un
        en-tête de plusieurs dizaines de Ko ferait refuser le courriel par des relais. Aucune clé secrète n'est lue."""
        t = time.time() if maintenant is None else maintenant
        table: Dict[str, str] = {}
        for e in self.locales():
            if e.get("expire") and e["expire"] < t:
                continue
            try:
                binaire = armure_vers_binaire(e.get("cle_publique", ""))
            except RefusCle:
                continue
            if not 0 < len(binaire) <= MAX_KEYDATA:
                continue
            keydata = base64.b64encode(binaire).decode()
            for adresse in e.get("verifies", []):
                if COURRIEL_RE.match(adresse):
                    table[adresse.lower()] = keydata
        return table

    # ── les box liées ───────────────────────────────────────────────────
    def export(self) -> dict:
        """Ce qu'on sert aux box liées : sans l'identifiant interne des personnes."""
        return {"cles": [{k: e[k] for k in ("pseudo", "empreinte", "uids", "courriels", "verifies", "expire",
                                            "publiee", "cle_publique")} for e in self.locales()],
                "retirees": self._lit(self.fichier_retraits, {})}

    def enregistrer_pair(self, did: str, boxname: str, doc: dict, recu: float) -> int:
        if not DID_RE.match(did or ""):
            raise RefusCle("did invalide")
        cles = []
        for e in doc.get("cles") or []:
            try:
                k = verifier_cle(e.get("cle_publique", ""), gpg=self.gpg, maintenant=recu)
            except RefusCle:
                continue
            if k["empreinte"] != e.get("empreinte"):
                continue
            cles.append({"pseudo": str(e.get("pseudo", ""))[:64], "empreinte": k["empreinte"], "uids": k["uids"],
                         "courriels": k["courriels"],
                         "verifies": [a for a in (e.get("verifies") or []) if a in k["courriels"]],
                         "expire": k["expire"], "cle_publique": k["armure"]})
        nom = hashlib.sha256(did.encode()).hexdigest()[:24]
        self._ecrit(self.dossier_pairs / f"{nom}.json",
                    {"did": did, "boxname": str(boxname or "")[:32], "recu": int(recu), "cles": cles,
                     "retirees": {k: int(v) for k, v in (doc.get("retirees") or {}).items() if EMPREINTE.match(k)}})
        return len(cles)

    def des_pairs(self) -> List[dict]:
        out = []
        if self.dossier_pairs.is_dir():
            for f in sorted(self.dossier_pairs.glob("*.json")):
                d = self._lit(f, None)
                if not d:
                    continue
                for e in d.get("cles", []):
                    out.append({**e, "origine": d.get("boxname") or d.get("did"), "did": d.get("did"),
                                "recu": d.get("recu")})
        return out

    # ── consulter ───────────────────────────────────────────────────────
    def toutes(self, boxname: str = "") -> List[dict]:
        locales = [{**{k: v for k, v in e.items() if k != "personne"}, "origine": boxname or "cette box"}
                   for e in self.locales()]
        return locales + self.des_pairs()

    def par_empreinte(self, empreinte: str, boxname: str = "") -> Optional[dict]:
        return next((e for e in self.toutes(boxname) if e["empreinte"] == empreinte), None)

    def wkd(self, domaine: str, hu: str, local: Optional[str] = None) -> Optional[bytes]:
        """WKD : la clé d'une adresse VÉRIFIÉE de cette box, au domaine demandé."""
        domaine = (domaine or "").lower()
        for e in self.locales():
            for a in e.get("verifies", []):
                lp, _, dom = a.partition("@")
                if dom == domaine and hash_wkd(lp) == hu and (local is None or local.lower() == lp):
                    return armure_vers_binaire(e["cle_publique"])
        return None
