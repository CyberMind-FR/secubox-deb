# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: cookies — magasin des cookies capturés (#1058).

Distinct de l'ingest `mitm_events`, qui ne garde que les NOMS de cookies pour
l'anti-pistage. Ici on garde les VALEURS, pour rejouer une session — donc avec
des règles strictes :

  - rien n'est capturé hors d'une fenêtre d'armement explicite ; le silence
    n'ouvre jamais la collecte ;
  - tout est chiffré au repos, hôte compris ; la valeur ne sort jamais en clair
    ailleurs que dans l'export cookies.txt réclamé ;
  - un cookie expiré n'est ni rendu ni exporté.

Un « avatar » est un PROFIL : un ensemble de cookies capturés qui, ensemble,
forment une identité réutilisable (le compte YouTube = les cookies youtube.com
ET google.com). L'armement vise un profil ; l'export rend le cookies.txt de ce
profil. À défaut de nom, tout va dans le profil « defaut ».
"""

import json
import os
import time
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

PROFIL_DEFAUT = "defaut"


class MagasinCapture:
    def __init__(self, fichier: Path, cle_fichier: Path,
                 marqueur: Optional[Path] = None):
        self.fichier = Path(fichier)
        self.cle_fichier = Path(cle_fichier)
        # Le marqueur est le SEUL lien avec sbxmitm : tant qu'il existe et n'est
        # pas echu, le proxy capture ; retire, il s'arrete. C'est ici, dans
        # armer/desarmer, qu'on le tient synchrone avec la fenetre interne.
        self.marqueur = Path(marqueur) if marqueur else None
        self._arme_jusqua: float = 0.0
        self._profil_actif: str = PROFIL_DEFAUT
        # profil -> hote -> nom -> cookie
        self._data: dict = self._charger()

    # ── clé de chiffrement ────────────────────────────────────────────────
    def _fernet(self) -> Fernet:
        if self.cle_fichier.exists():
            return Fernet(self.cle_fichier.read_bytes())
        # Génère une clé neuve, à accès restreint : ces valeurs sont des jetons
        # porteurs, l'accès au fichier de clé vaut accès aux comptes.
        cle = Fernet.generate_key()
        self.cle_fichier.parent.mkdir(parents=True, exist_ok=True)
        # Écrit à 0600 dès la création, jamais un instant plus permissif.
        fd = os.open(self.cle_fichier, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(cle)
        return Fernet(cle)

    # ── persistance chiffrée ──────────────────────────────────────────────
    def _charger(self) -> dict:
        if not self.fichier.exists():
            return {}
        try:
            clair = self._fernet().decrypt(self.fichier.read_bytes())
            return json.loads(clair)
        except (InvalidToken, ValueError, OSError):
            return {}

    def _sauver(self) -> None:
        chiffre = self._fernet().encrypt(json.dumps(self._data).encode())
        self.fichier.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.fichier.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(chiffre)
        os.replace(tmp, self.fichier)

    # ── armement ──────────────────────────────────────────────────────────
    def armer(self, duree_s: int = 300, profil: str = PROFIL_DEFAUT,
              hotes: Optional[list] = None) -> None:
        """Ouvre une fenêtre de capture, pour un profil (avatar) donné.

        `hotes` limite le périmètre : sbxmitm ne capturera QUE ces hôtes (et
        leurs sous-domaines). Liste vide/None = tout hôte visité pendant la
        fenêtre — le périmètre est alors la navigation elle-même.
        """
        self._profil_actif = profil or PROFIL_DEFAUT
        self._arme_jusqua = time.time() + max(0, duree_s)
        self._ecrire_marqueur(hotes or [])

    def _ecrire_marqueur(self, hotes: list) -> None:
        """Écrit le marqueur que sbxmitm lit — le seul lien avec le proxy."""
        if self.marqueur is None:
            return
        payload = {
            "deadline": int(self._arme_jusqua),
            "profil": self._profil_actif,
            "hotes": [h.strip().lower() for h in hotes if h.strip()],
        }
        try:
            self.marqueur.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.marqueur.with_suffix(".tmp")
            # 0644 : sbxmitm tourne sous un AUTRE utilisateur et doit le lire.
            # Le marqueur ne porte que des metadonnees (profil, hotes,
            # echeance) — jamais une valeur de cookie, qui reste dans le
            # fichier chiffre 0600.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(payload))
            os.replace(tmp, self.marqueur)
        except OSError:
            pass

    def desarmer(self) -> None:
        self._arme_jusqua = 0.0
        # Retirer le marqueur ferme la capture cote sbxmitm immediatement,
        # sans attendre l'echeance.
        if self.marqueur is not None:
            try:
                self.marqueur.unlink()
            except OSError:
                pass

    def est_arme(self) -> bool:
        return time.time() < self._arme_jusqua

    def reste_s(self) -> int:
        return max(0, int(self._arme_jusqua - time.time()))

    # ── capture ───────────────────────────────────────────────────────────
    def recevoir(self, hote: str, cookies: list) -> int:
        """Enregistre des cookies pour un hôte — seulement si armé.

        Rend le nombre de cookies retenus (0 hors fenêtre).
        """
        if not self.est_arme():
            return 0
        prof = self._data.setdefault(self._profil_actif, {})
        seau = prof.setdefault(hote, {})
        n = 0
        for c in cookies:
            nom = c.get("name")
            if not nom or "value" not in c:
                continue
            seau[nom] = {
                "name": nom,
                "value": c["value"],
                "domain": c.get("domain") or hote,
                "path": c.get("path") or "/",
                "expires": int(c.get("expires") or 0),
                "secure": bool(c.get("secure")),
                "httponly": bool(c.get("httponly")),
                "captured_at": int(time.time()),
            }
            n += 1
        if n:
            self._sauver()
        return n

    # ── lecture ───────────────────────────────────────────────────────────
    @staticmethod
    def _vivant(c: dict) -> bool:
        exp = int(c.get("expires") or 0)
        # expires 0 = cookie de session : pas d'échéance à l'horloge, il vaut
        # tant que la capture le détient.
        return exp == 0 or exp > time.time()

    def _profil(self, profil: Optional[str]) -> str:
        return profil or PROFIL_DEFAUT

    def pour_hote(self, hote: str, profil: Optional[str] = None) -> list:
        prof = self._data.get(self._profil(profil), {})
        return [c for c in prof.get(hote, {}).values() if self._vivant(c)]

    def oublier(self, hote: str, profil: Optional[str] = None) -> None:
        prof = self._data.get(self._profil(profil), {})
        if hote in prof:
            del prof[hote]
            self._sauver()

    def avatars(self) -> list:
        """Les profils connus, avec leur nombre d'hôtes et de cookies vivants."""
        out = []
        for nom, hotes in self._data.items():
            vivants = sum(1 for h in hotes.values()
                          for c in h.values() if self._vivant(c))
            out.append({"avatar": nom, "hotes": len(hotes), "cookies": vivants})
        return sorted(out, key=lambda x: x["avatar"])

    def statut(self) -> dict:
        """État SANS aucune valeur : hôtes, comptes, fraîcheur seulement."""
        hotes = []
        for prof, hs in self._data.items():
            for hote, seau in hs.items():
                vivants = [c for c in seau.values() if self._vivant(c)]
                if not vivants:
                    continue
                hotes.append({
                    "avatar": prof,
                    "hote": hote,
                    "cookies": len(vivants),
                    "dernier": max(c["captured_at"] for c in vivants),
                    # échéance la plus proche (0 = que des cookies de session)
                    "expire_min": min((c["expires"] for c in vivants
                                       if c["expires"]), default=0),
                })
        return {
            "arme": self.est_arme(),
            "reste_s": self.reste_s(),
            "profil_actif": self._profil_actif if self.est_arme() else None,
            "hotes": sorted(hotes, key=lambda x: (x["avatar"], x["hote"])),
        }

    # ── export (le seul endroit où la valeur ressort) ─────────────────────
    def netscape(self, hotes: Optional[list] = None,
                 profil: Optional[str] = None) -> str:
        """Rend un cookies.txt au format Netscape, ce que yt-dlp lit.

        Par hôtes (réclamation d'un connecteur : youtube + google) ou par
        profil entier (un avatar). Les cookies expirés sont écartés.
        """
        prof = self._data.get(self._profil(profil), {})
        cibles = hotes if hotes is not None else list(prof.keys())
        lignes = ["# Netscape HTTP Cookie File",
                  "# Généré par SecuBox — capture de session (#1058)", ""]
        for hote in cibles:
            for c in prof.get(hote, {}).values():
                if not self._vivant(c):
                    continue
                domaine = c["domain"]
                # Le drapeau « tous sous-domaines » est TRUE quand le domaine
                # commence par un point, comme l'attend le format.
                flag = "TRUE" if domaine.startswith(".") else "FALSE"
                lignes.append("\t".join([
                    domaine, flag, c["path"],
                    "TRUE" if c["secure"] else "FALSE",
                    str(c["expires"]), c["name"], c["value"],
                ]))
        return "\n".join(lignes) + "\n"
