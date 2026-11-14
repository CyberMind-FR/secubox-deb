# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Contexte automatique du moteur local (#3583) : lecteur d'en-tête GGUF sans dépendance.

Module autonome (bibliothèque standard seulement) : importé par l'API et par le contrôleur root
(`demarrer`), il ne doit dépendre ni de FastAPI, ni de httpx, ni de `reglages`.
"""
import os
import stat
import struct
from pathlib import Path

CTX_AUTO_MIN, CTX_AUTO_MAX = 4096, 32768

# Bornes de lecture : un fichier mal formé ne doit pas pouvoir épuiser la mémoire.
_MAX_KV = 100_000
_MAX_CLE = 1024
_MAX_CHAINE_LUE = 1 << 20      # chaîne demandée
_MAX_TABLEAU_LU = 1 << 16      # tableau demandé
_MAX_PROFONDEUR = 4

_FIXES = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<f", 7: "<?", 10: "<Q", 11: "<q", 12: "<d"}
_T_CHAINE, _T_TABLEAU = 8, 9


class _Lecteur:
    def __init__(self, f, taille):
        self.f, self.taille = f, taille

    def lire(self, n):
        if n < 0 or n > self.taille - self.f.tell():
            raise ValueError("lecture hors du fichier")
        b = self.f.read(n)
        if len(b) != n:
            raise ValueError("fichier tronqué")
        return b

    def entier(self, fmt):
        return struct.unpack(fmt, self.lire(struct.calcsize(fmt)))[0]

    def sauter(self, n):
        if n < 0 or n > self.taille - self.f.tell():
            raise ValueError("saut hors du fichier")
        self.f.seek(n, 1)

    def valeur(self, type_, garder, profondeur=0):
        """Lit la valeur (garder=True) ou la saute ; renvoie None quand elle est sautée."""
        if type_ in _FIXES:
            if garder:
                return self.entier(_FIXES[type_])
            self.sauter(struct.calcsize(_FIXES[type_]))
            return None
        if type_ == _T_CHAINE:
            n = self.entier("<Q")
            if garder and n <= _MAX_CHAINE_LUE:
                return self.lire(n).decode("utf-8", "replace")
            self.sauter(n)
            return None
        if type_ == _T_TABLEAU:
            if profondeur >= _MAX_PROFONDEUR:
                raise ValueError("tableaux trop imbriqués")
            sous = self.entier("<I")
            n = self.entier("<Q")
            if n > self.taille:
                raise ValueError("tableau absurde")
            garder = garder and n <= _MAX_TABLEAU_LU
            if sous in _FIXES and not garder:
                self.sauter(n * struct.calcsize(_FIXES[sous]))
                return None
            res = [self.valeur(sous, garder, profondeur + 1) for _ in range(n)]
            return res if garder else None
        raise ValueError(f"type GGUF inconnu : {type_}")


def lire_meta_gguf(chemin: Path, cles: set[str]) -> dict:
    """Lit dans l'en-tête GGUF (v2/v3, petit-boutiste) les seules clés demandées ; les autres sont sautées.

    S'arrête dès que toutes les clés sont trouvées, et en tout cas avant les descripteurs de tenseurs.
    Renvoie {clé: valeur} pour les clés présentes. Lève ValueError (ou OSError) si le fichier n'est pas
    un GGUF lisible ou dépasse les bornes de lecture."""
    trouve: dict = {}
    # Jamais bloquant ni suivi de lien : le contrôleur root peut être appelé sur un chemin choisi par autrui.
    fd = os.open(chemin, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("pas un fichier régulier")
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as f:
        taille = st.st_size
        lec = _Lecteur(f, taille)
        if lec.lire(4) != b"GGUF":
            raise ValueError("signature GGUF absente")
        if lec.entier("<I") not in (2, 3):
            raise ValueError("version GGUF non gérée")
        lec.entier("<Q")  # nombre de tenseurs : sans intérêt ici
        nb = lec.entier("<Q")
        if nb > _MAX_KV:
            raise ValueError("nombre de paires absurde")
        for _ in range(nb):
            if len(trouve) == len(cles):
                break
            n = lec.entier("<Q")
            if n > _MAX_CLE:
                raise ValueError("clé trop longue")
            cle = lec.lire(n).decode("utf-8", "replace")
            type_ = lec.entier("<I")
            veut = cle in cles
            v = lec.valeur(type_, veut)
            if veut and v is not None:
                trouve[cle] = v
    return trouve


_kv_connus: dict = {}


def _entier(x):
    """Entier strictement positif (ni booléen, ni flottant, ni chaîne), sinon None."""
    return x if isinstance(x, int) and not isinstance(x, bool) and x > 0 else None


def _entier_max(x):
    """Entier positif, ou le plus grand d'une liste d'entiers positifs ; sinon None."""
    if isinstance(x, list):
        vals = [_entier(e) for e in x]
        return max(vals) if vals and None not in vals else None
    return _entier(x)


def _stat_regulier(chemin: Path):
    """lstat d'un fichier régulier (pas de lien, jamais d'ouverture), sinon None."""
    try:
        st = os.lstat(chemin)
    except OSError:
        return None
    return st if stat.S_ISREG(st.st_mode) else None


def kv_par_jeton(chemin) -> tuple[int | None, int | None]:
    """(octets de cache par jeton en f16, contexte maximal du modèle), lus dans l'en-tête GGUF ; (None, None) sinon.
    Modèles hybrides (qwen35…) : seule une couche sur `full_attention_interval` garde un cache d'attention.
    Toute métadonnée qui n'est pas un entier positif rend l'en-tête illisible (le contexte maximal seul est ignoré)."""
    chemin = Path(chemin)
    st = _stat_regulier(chemin)
    if st is None:
        return None, None
    cle = (str(chemin), st.st_mtime_ns, st.st_size)
    if cle in _kv_connus:
        return _kv_connus[cle]
    try:
        arch = lire_meta_gguf(chemin, {"general.architecture"})["general.architecture"]
        if not isinstance(arch, str):
            raise ValueError("architecture illisible")
        noms = {f"{arch}.{s}" for s in ("block_count", "attention.head_count", "attention.head_count_kv",
                                        "embedding_length", "attention.key_length", "attention.value_length",
                                        "full_attention_interval", "context_length")}
        m = lire_meta_gguf(chemin, noms)

        def val(s):
            return m.get(f"{arch}.{s}")

        couches = _entier(val("block_count"))
        tetes = _entier_max(val("attention.head_count")) if val("attention.head_count") is not None else 1
        kv = _entier_max(val("attention.head_count_kv")) if val("attention.head_count_kv") is not None else tetes
        emb = _entier(val("embedding_length")) if val("embedding_length") is not None else 0
        kl, vl = val("attention.key_length"), val("attention.value_length")
        k = _entier(kl) if kl is not None else (emb // tetes if tetes and emb is not None else None)
        v = _entier(vl) if vl is not None else (emb // tetes if tetes and emb is not None else None)
        iv = val("full_attention_interval")
        intervalle = _entier(iv) if iv is not None else 1
        if None in (couches, tetes, kv, k, v, intervalle):
            raise ValueError("métadonnées inexploitables")
        attention = couches // intervalle if intervalle > 1 else couches
        res = (attention * kv * (k + v) * 2 or None, _entier(val("context_length")))
    except Exception:  # noqa: BLE001 — un en-tête illisible ramène au contexte minimal, jamais une panne
        res = (None, None)
    _kv_connus[cle] = res
    return res


def contexte_auto(chemin, dispo_mo: int, memoire_max_mo: int, reserve_mo: int = 512) -> int:
    """Plus grande taille de contexte (en jetons, multiple de 1024) qui tient en mémoire, entre 4 096 et 32 768.

    `dispo_mo` : mémoire vive disponible (MemAvailable) en Mo, mesurée moteur arrêté ; on en retranche
    `reserve_mo` (air laissé au poste) puis le poids du modèle (taille du fichier). `memoire_max_mo` : plafond
    mémoire du moteur (MemoryMax) en Mo, dont on retranche aussi le poids. Le budget du cache est le plus petit
    des deux, le résultat est plafonné par le contexte maximal du modèle. En-tête illisible, fichier non
    régulier ou absent : 4 096. Ne lève jamais."""
    chemin = Path(chemin)
    par_jeton, ctx_modele = kv_par_jeton(chemin)
    st = _stat_regulier(chemin)
    if not par_jeton or st is None:
        return CTX_AUTO_MIN
    poids_mo = st.st_size / 1024 ** 2
    budget_mo = min(dispo_mo - reserve_mo - poids_mo, memoire_max_mo - poids_mo)
    ctx = int(budget_mo * 1024 ** 2 // par_jeton) // 1024 * 1024 if budget_mo > 0 else 0
    return max(CTX_AUTO_MIN, min(ctx, CTX_AUTO_MAX, ctx_modele or CTX_AUTO_MAX))
