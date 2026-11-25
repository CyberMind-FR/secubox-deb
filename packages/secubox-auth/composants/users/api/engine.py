# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Single mutation entry point for SecuBox users.

Every API handler and the CLI call into this module. No code outside
`engine.Engine` writes users.json directly.
"""
from __future__ import annotations

import contextlib
import fcntl
import functools
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("secubox.users.engine")

# Même règle que le helper de services (#1456) : le point est admis au milieu
# (« ani.skywalker », homonyme d'un compte BBS), jamais en tête ni doublé.
USERNAME_RE = re.compile(r"^(?!.*\.\.)[a-z0-9_][a-z0-9._-]{0,30}[a-z0-9_-]$")
ALLOWED_ROLES = {"admin", "operator", "viewer"}
# Second facteur PAR COMPTE (#2745). defaut = suit le réglage global (facultatif sur le LAN) ; hors_lan = exigé hors du LAN seulement ; toujours = exigé partout ;
# jamais = jamais exigé, même depuis internet (le secret TOTP est conservé).
OTP_MODES = ("defaut", "hors_lan", "toujours", "jamais")


class EngineError(ValueError):
    """Raised for any policy/state violation. Maps to HTTP 4xx in API."""


class EngineBusy(EngineError):
    """Verrou du registre indisponible : HTTP 503, réessayer."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _comptes_admin():
    """La règle des comptes admin sans mot de passe (#3708), par son CHEMIN si secubox_core n'est pas déjà chargé : le
    paquet tire FastAPI, et le postinst comme le renommage (délai borné) n'en ont pas besoin."""
    import importlib.util
    import sys

    nom = "secubox_core.comptes_admin"
    if nom in sys.modules:
        return sys.modules[nom]
    if "secubox_core" in sys.modules:
        return importlib.import_module(nom)
    cle = "_sbx_comptes_admin"
    if cle not in sys.modules:
        paquet = importlib.util.find_spec("secubox_core")
        if paquet is None or not paquet.submodule_search_locations:
            raise EngineError("secubox_core introuvable (paquet secubox-core)")
        spec = importlib.util.spec_from_file_location(
            cle, Path(list(paquet.submodule_search_locations)[0]) / "comptes_admin.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        sys.modules[cle] = mod
    return sys.modules[cle]


def _ecrit(f):
    """Toute mutation tient le verrou commun de users.json, de la lecture à l'écriture (#3708)."""
    @functools.wraps(f)
    def _f(self, *a, **k):
        with self.verrou():
            return f(self, *a, **k)
    return _f


class Engine:
    """Atomic, single-file mutation engine."""

    #: Etat d'anti-rejeu TOTP. DELIBEREMENT hors du magasin d'utilisateurs
    #: (#990) : `last_step` est de l'etat d'execution, pas de la configuration,
    #: et /etc/secubox appartient a root alors que le service auth tourne en
    #: `secubox`. Ecrire l'anti-rejeu dans le magasin faisait echouer en 500
    #: tout code VALIDE — `_save` n'etant appele que dans la branche de succes,
    #: un mauvais code repondait proprement 401 et un bon code plantait.
    DEFAULT_REPLAY_PATH = Path("/var/lib/secubox/totp-replay.json")

    def __init__(self, users_path: Path, replay_path: Optional[Path] = None):
        self.users_path = Path(users_path)
        # Surcharge par SECUBOX_TOTP_REPLAY_PATH : sans elle, tout Engine
        # construit sans argument explicite ecrit dans un fichier SYSTEME
        # partage. En production c'est voulu ; dans une suite de tests c'est un
        # etat qui fuit d'un test a l'autre et rend les resultats dependants de
        # la machine — constate en ecrivant ce correctif, un test existant
        # s'est mis a echouer parce qu'un run precedent avait laisse une entree.
        env_override = os.environ.get("SECUBOX_TOTP_REPLAY_PATH")
        if replay_path:
            self.replay_path = Path(replay_path)
        elif env_override:
            self.replay_path = Path(env_override)
        else:
            self.replay_path = self.DEFAULT_REPLAY_PATH
        self._revoke_cb: Optional[Callable[[str], int]] = None
        self._audit_cb: Optional[Callable[[str, str, Dict[str, Any]], None]] = None

    # ── Wiring ────────────────────────────────────────────────────────

    def set_revoke_callback(self, cb: Callable[[str], int]) -> None:
        """Set callback invoked on disable_user. Returns number of sessions revoked."""
        self._revoke_cb = cb

    def set_audit_callback(self, cb: Callable[[str, str, Dict[str, Any]], None]) -> None:
        """Set callback for engine-emitted audit events."""
        self._audit_cb = cb

    def _audit(self, event: str, user: str, details: Optional[Dict[str, Any]] = None) -> None:
        if self._audit_cb:
            try:
                self._audit_cb(event, user, details or {})
            except Exception as exc:
                log.warning("audit callback failed: %s", exc)

    @contextlib.contextmanager
    def verrou(self):
        """Le verrou de users.json, pour qui lit puis écrit (`_load` … `_save`) hors du moteur aussi."""
        garde = _comptes_admin().verrou(self.users_path)
        try:
            garde.__enter__()
        except OSError as exc:                        # occupé, illisible, anormal : rien n'est changé
            raise EngineBusy(f"registre des comptes indisponible ({exc}) : réessayer") from None
        try:
            yield
        finally:
            garde.__exit__(None, None, None)

    # ── File I/O ──────────────────────────────────────────────────────

    def _load(self) -> Dict[str, Any]:
        if not self.users_path.exists():
            return {"version": 2, "users": [], "groups": []}
        return json.loads(self.users_path.read_text())

    @_ecrit
    def _save(self, doc: Dict[str, Any]) -> None:
        """Atomic write: temp + os.replace in the same dir.

        Preserves the existing file's owner + mode. Without this, a root-run CLI
        (``sudo usersctl set-password``) would leave users.json as root:root 0600
        — unreadable by the secubox-owned auth service, which then falls back to
        the auth.toml emergency users and rejects every login. Mirrors
        secubox_core.user_store.set_password's owner-preservation.
        """
        _comptes_admin().poser_marque(doc)         # première fois qu'un administrateur est configuré : durable (#3708)
        self.users_path.parent.mkdir(parents=True, exist_ok=True)
        prev_stat = None
        try:
            prev_stat = self.users_path.stat()
        except FileNotFoundError:
            pass
        fd, tmp_path = tempfile.mkstemp(
            prefix=".users.json.", dir=str(self.users_path.parent)
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(doc, f, indent=2, sort_keys=True)
            if prev_stat is not None:
                # Re-apply the prior owner/mode so a root writer does not strip
                # the secubox service's access. Fail-open: a non-root writer that
                # cannot chown keeps its own (identical) ownership.
                try:
                    os.chown(tmp_path, prev_stat.st_uid, prev_stat.st_gid)
                except OSError:
                    pass
                try:
                    os.chmod(tmp_path, prev_stat.st_mode & 0o777)
                except OSError:
                    pass
            os.replace(tmp_path, self.users_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _find(self, doc: Dict[str, Any], username: str) -> Optional[Dict[str, Any]]:
        for u in doc.get("users", []):
            if u.get("username") == username:
                return u
        return None

    # ── Lifecycle ────────────────────────────────────────────────────

    def list_users(self) -> List[Dict[str, Any]]:
        return list(self._load().get("users", []))

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        return self._find(self._load(), username)

    def create_user(self, username: str, email: Optional[str], role: str, password: Optional[str] = None,
                    must_change: bool = False, origine: Optional[str] = None) -> Dict[str, Any]:
        """Avec `password`, le compte naît avec : jamais un instant sans mot de passe dans le registre."""
        empreinte = None
        if password:
            from argon2 import PasswordHasher
            from . import password_policy

            password_policy.validate(password, {"username": username})
            empreinte = PasswordHasher().hash(password)
        return self._create_user(username, email, role, empreinte, must_change, origine)

    @_ecrit
    def _create_user(self, username, email, role, empreinte, must_change, origine) -> Dict[str, Any]:
        if not USERNAME_RE.match(username):
            raise EngineError(f"username invalid: {username!r}")
        if role not in ALLOWED_ROLES:
            raise EngineError(f"role invalid: {role!r}")
        doc = self._load()
        if self._find(doc, username):
            raise EngineError(f"user exists: {username}")
        u = {
            "username": username,
            "email": email,
            "role": role,
            "enabled": True,
            "password_hash": empreinte,
            "must_change_password": bool(must_change or not empreinte),
            "totp": None,
            "google": None,
            "services": [],
            "created": _now_iso(),
            "last_login": None,
        }
        if origine:
            u["origine"] = origine
        doc.setdefault("users", []).append(u)
        self._save(doc)
        self._audit("user_created", username, {"role": role})
        return u

    @_ecrit
    def disable_user(self, username: str) -> int:
        """Disable user, revoke sessions. Returns count of revoked sessions."""
        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"user not found: {username}")
        u["enabled"] = False
        self._save(doc)
        revoked = 0
        if self._revoke_cb:
            try:
                revoked = int(self._revoke_cb(username) or 0)
            except Exception as exc:
                log.warning("revoke_cb failed for %s: %s", username, exc)
        self._audit("user_disabled", username, {"revoked": revoked})
        return revoked

    @_ecrit
    def enable_user(self, username: str) -> None:
        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"user not found: {username}")
        u["enabled"] = True
        u.pop("desactive_motif", None)
        self._save(doc)
        self._audit("user_enabled", username, {})

    # ── Comptes admin sans mot de passe (#3708) ───────────────────────
    #
    # Une décision non auditée n'a pas lieu : la ligne d'audit part AVANT l'écriture, et une écriture qui échoue
    # s'audite à son tour. Jamais de suppression : `usersctl set-password NOM` puis `usersctl enable NOM` défont.

    def _auditer_securite(self, evenement: str, **champs: Any) -> None:
        try:
            _comptes_admin().auditer(evenement, **champs)
        except OSError as exc:
            raise EngineError(f"audit impossible ({exc.__class__.__name__}) : rien n'est changé") from None

    def _decider(self, decision: Callable[[Dict[str, Any]], List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Décide, audite, RELIT, écrit. Le verrou exclut les écrivains à jour ; un écrivain qui ne le prend pas (code
        d'avant encore chargé pendant la mise à jour) est vu par la relecture : la décision est annulée (auditée) et
        reprise sur l'état neuf, jamais écrite par-dessus."""
        for _ in range(3):
            with self.verrou():
                doc = self._load()
                avant = json.dumps(doc, sort_keys=True)
                lignes = decision(doc)
                if not lignes:
                    return []
                for ligne in lignes:
                    self._auditer_securite(**ligne)
                if json.dumps(self._load(), sort_keys=True) != avant:
                    self._auditer_securite("comptes_admin_decision_annulee", motif="users.json a changé",
                                           comptes=[x.get("compte") for x in lignes])
                    continue
                try:
                    self._save(doc)
                except OSError as exc:
                    self._auditer_securite("comptes_admin_echec", erreur=exc.__class__.__name__,
                                           comptes=[x.get("compte") for x in lignes])
                    raise EngineError(f"users.json non écrit ({exc.__class__.__name__}) : rien n'est changé") from None
                return lignes
        raise EngineError("users.json change sans cesse : rien n'est changé")

    def _fermer(self, doc: Dict[str, Any], nom: str) -> None:
        u = self._find(doc, nom)
        u["enabled"] = False
        u["desactive_motif"] = _comptes_admin().MOTIF_FERMETURE

    @_ecrit
    def semer_comptes(self, machine: str = "") -> List[str]:
        """Sème `admin` s'il manque, et le compte au nom de la machine tant qu'AUCUN administrateur n'a de mot de passe.
        Un `admin` semé sur une box configurée est refermé par la désactivation qui suit (il doit exister : premier-pas
        et l'état du mot de passe par défaut le cherchent)."""
        ca = _comptes_admin()
        semes = []
        if not self._find(self._load(), "admin"):
            self.create_user("admin", email=None, role="admin")
            semes.append("admin")
        doc = self._load()
        if (machine and not self._find(doc, machine) and machine not in ca.comptes_systeme()
                and not ca.configure_un_jour(doc) and not ca.admin_avec_mot_de_passe(doc)):
            self.create_user(machine, email=None, role="admin")
            semes.append(machine)
        return semes

    def desactiver_admins_sans_mot_de_passe(self, origine: str = "") -> List[str]:
        """Désactive tout admin actif JAMAIS SERVI, sans mot de passe (ou encore au mot de passe du premier démarrage),
        dès qu'un AUTRE admin est configuré. Idempotent ; ne touche ni un compte qui sert, ni un compte de service, ni un
        non-admin, ni le dernier admin actif."""
        ca = _comptes_admin()
        ca.a_refermer(self._load())                           # argon2 d'avance : le verrou ne dure que l'écriture

        def decision(doc):
            motifs = ca.a_refermer(doc)
            for n in motifs:
                self._fermer(doc, n)
            return [{"evenement": "admin_sans_mot_de_passe_desactive", "compte": n, "motif": m,
                     "origine": origine or None} for n, m in motifs.items()]
        noms = [x["compte"] for x in self._decider(decision)]
        for n in noms:
            self._audit("user_disabled", n, {"motif": "admin sans mot de passe"})
        return noms

    @_ecrit
    def marquer_configure(self) -> bool:
        """Postinst : une box qui a déjà un admin au mot de passe choisi (même « à changer ») est marquée configurée."""
        doc = self._load()
        if not _comptes_admin().poser_marque(doc, provisoire_compte=True):
            return False
        self._auditer_securite("box_marquee_configuree")
        self._save(doc)
        return True

    @_ecrit
    def rouvrir_premiere_configuration(self) -> None:
        """Geste ROOT de remise à zéro : retire la marque, donc rouvre la revendication des comptes sans mot de passe
        depuis le LAN. Refusé tant qu'un administrateur est configuré (il suffit de s'en servir)."""
        ca = _comptes_admin()
        if os.geteuid() != 0:
            raise EngineError("réservé à root")
        doc = self._load()
        if ca.admin_configure(doc):
            raise EngineError("un administrateur est configuré : rien à rouvrir")
        self._auditer_securite("premiere_configuration_rouverte")
        doc.pop(ca.CLE_MARQUE, None)
        self._save(doc)

    def renommer_compte_machine(self, ancien: str, nouveau: str, acteur: Optional[str] = None) -> str:
        """Après un renommage de box : plus de compte admin semé sous l'ancien nom. Rend « aucun » (rien à faire, dont
        un compte à mot de passe), « desactive » (un autre admin est configuré, ou le nouveau nom n'est pas disponible
        et un autre admin reste), « renomme » (box pas encore configurée) ou « garde » (il sert, ou c'est le dernier
        admin actif)."""
        ca = _comptes_admin()
        ca.admin_configure(self._load())
        etat = "aucun"

        def decision(doc):
            nonlocal etat
            etat = "aucun"
            u, systeme = self._find(doc, ancien), ca.comptes_systeme()
            if (ancien == nouveau or ancien == "admin" or not u or ancien in systeme or not ca.est_admin_actif(u)
                    or not ca.sans_mot_de_passe(u)):
                return []
            libre = bool(USERNAME_RE.match(nouveau)) and nouveau not in systeme and not self._find(doc, nouveau)
            autre = any(ca.est_admin_actif(x) and x["username"] != ancien and x["username"] not in systeme
                        for x in ca.comptes(doc))
            if not ca.jamais_servi(u, ca.traces_d_usage()):
                etat = "garde"
                return []
            if libre and not ca.admin_configure(doc) and not ca.configure_un_jour(doc):
                etat = "renomme"
                u["username"] = nouveau
                return [{"evenement": "compte_machine_renomme", "compte": ancien, "nouveau": nouveau, "acteur": acteur}]
            if not autre:
                etat = "garde"
                return []
            etat = "desactive"
            self._fermer(doc, ancien)
            return [{"evenement": "admin_sans_mot_de_passe_desactive", "compte": ancien, "motif": "sans_mot_de_passe",
                     "origine": "renommage", "acteur": acteur}]
        self._decider(decision)
        if etat in ("renomme", "desactive"):
            self._audit("user_renamed" if etat == "renomme" else "user_disabled", ancien, {"nouveau": nouveau})
        return etat

    # ── Passwords ────────────────────────────────────────────────────

    def set_password(self, username: str, plaintext: str, verifie: Optional[Callable[[Dict[str, Any]], None]] = None,
                     must_change: bool = False) -> None:
        """Hash + store password. Validates policy. `verifie(doc)` est appelé SOUS LE VERROU, sur le registre relu : il
        lève pour refuser (#3708)."""
        from argon2 import PasswordHasher
        from . import password_policy

        u = self.get_user(username)
        if not u:
            raise EngineError(f"utilisateur inconnu : {username}")
        password_policy.validate(plaintext, u)
        empreinte = PasswordHasher().hash(plaintext)          # hors du verrou : argon2 est lent
        with self.verrou():
            doc = self._load()
            u = self._find(doc, username)
            if not u:
                raise EngineError(f"utilisateur inconnu : {username}")
            if verifie:
                verifie(doc)
            ca = _comptes_admin()
            if ca.configure_un_jour(doc) and ca.est_le_defaut(plaintext):
                raise EngineError("le mot de passe du premier démarrage ne se choisit plus")
            u["password_hash"] = empreinte
            u["must_change_password"] = bool(must_change)
            u.pop("origine", None)                            # choisi par une personne : plus un compte de service
            self._save(doc)
        self._audit("password_set", username, {})

    @_ecrit
    def clear_password(self, username: str) -> None:
        """Remove password hash and force re-set on next login."""
        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"utilisateur inconnu : {username}")
        u["password_hash"] = None
        u["must_change_password"] = True
        self._save(doc)
        self._audit("password_cleared", username, {})

    def verify_password_for_user(self, username: str, plaintext: str) -> bool:
        from argon2 import PasswordHasher
        from argon2.exceptions import InvalidHash, VerifyMismatchError

        u = self._find(self._load(), username)
        if not u or not u.get("enabled") or not u.get("password_hash"):
            return False
        try:
            return PasswordHasher().verify(u["password_hash"], plaintext)
        except (VerifyMismatchError, InvalidHash):
            return False

    # ── TOTP ─────────────────────────────────────────────────────────

    def enroll_totp(self, username: str, secret: str) -> list:
        """Persist secret + freshly generated backup codes. Returns the 10 plaintext codes (shown once)."""
        from . import totp as _totp

        def libre(doc):
            u = self._find(doc, username)
            if not u:
                raise EngineError(f"user not found: {username}")
            if u.get("totp") and u["totp"].get("enabled"):
                raise EngineError(f"TOTP already enrolled for {username}")
            return u

        libre(self._load())
        plain = _totp.generate_backup_codes(n=10, length=10)
        codes = [{"hash": _totp.hash_backup_code(c), "used_at": None} for c in plain]     # lent : hors du verrou
        with self.verrou():
            doc = self._load()
            libre(doc)["totp"] = {"secret": secret, "enabled": True, "enrolled_at": _now_iso(), "last_step": None,
                                  "backup_codes": codes}
            self._save(doc)
        self._audit("totp_enrolled", username, {})
        return plain

    # ── Anti-rejeu TOTP (#990) ────────────────────────────────────────
    #
    # Stocke le dernier pas consomme par utilisateur, dans un fichier que le
    # service auth peut ecrire. Best-effort en LECTURE (un fichier absent ou
    # corrompu ne doit pas empecher de se connecter), strict en ECRITURE : si
    # l'etat ne peut pas etre persiste, l'erreur remonte — sans lui, un code
    # redevient rejouable dans sa fenetre, et c'est la seule raison d'etre de
    # ce mecanisme.

    def _replay_load(self) -> Dict[str, Any]:
        try:
            return json.loads(self.replay_path.read_text())
        except (OSError, ValueError):
            return {}

    def _replay_record(self, username: str, step: int) -> None:
        state = self._replay_load()
        state[username] = step
        self.replay_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.replay_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        os.replace(tmp, self.replay_path)

    @contextlib.contextmanager
    def _verrou_plancher(self):
        """Lire, vérifier, consigner d'un seul tenant, entre fils et processus (#3708) : le MÊME verrou que
        secubox_core.second_facteur, qui tient le même fichier."""
        self.replay_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.replay_path) + ".verrou", os.O_RDONLY | os.O_CREAT | os.O_CLOEXEC, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def verify_totp_for_user(self, username: str, code: str, window: int = 1) -> bool:
        with self._verrou_plancher():
            return self._verify_totp_verrouille(username, code, window)

    def _verify_totp_verrouille(self, username: str, code: str, window: int) -> bool:
        import pyotp
        import time

        doc = self._load()
        u = self._find(doc, username)
        if not u or not u.get("enabled") or not (u.get("totp") and u["totp"].get("enabled")):
            return False

        secret = u["totp"]["secret"]
        # Plancher = le plus RECENT des deux sources. Le last_step herite de
        # users.json doit continuer de compter apres migration, sinon les codes
        # deja consommes redeviendraient acceptables.
        legacy_step = u["totp"].get("last_step")
        replay_step = self._replay_load().get(username)
        candidates = [x for x in (legacy_step, replay_step) if x is not None]
        last_step = max(candidates) if candidates else None
        step_size = 30
        now = int(time.time())
        current = now // step_size

        for delta in range(-window, window + 1):
            step = current + delta
            if pyotp.TOTP(secret).at(step * step_size) == code:
                if last_step is not None and step <= last_step:
                    return False
                # JAMAIS self._save(doc) ici : la verification est un chemin de
                # lecture, et le magasin appartient a root (mutations reservees
                # a `sudo usersctl`, cf. la docstring de _save).
                self._replay_record(username, step)
                self._audit("totp_verified", username, {"step": step, "window": window})
                return True
        return False

    def consume_backup_code(self, username: str, code: str) -> bool:
        from . import totp as _totp

        doc = self._load()
        u = self._find(doc, username)
        if not u or not (u.get("totp") and u["totp"].get("enabled")):
            return False
        for trouve in u["totp"]["backup_codes"]:
            if trouve["used_at"] is None and _totp.verify_backup_code(trouve["hash"], code):
                with self.verrou():                           # vérifié hors du verrou (lent), consommé dedans, une fois
                    doc = self._load()
                    u = self._find(doc, username) or {}
                    bc = next((x for x in ((u.get("totp") or {}).get("backup_codes") or [])
                               if x["hash"] == trouve["hash"] and x["used_at"] is None), None)
                    if bc is None:
                        return False
                    bc["used_at"] = _now_iso()
                    self._save(doc)
                self._audit("backup_code_used", username, {
                    "remaining": sum(1 for x in u["totp"]["backup_codes"] if x["used_at"] is None)
                })
                return True
        return False

    @_ecrit
    def disable_totp(self, username: str) -> None:
        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"user not found: {username}")
        u["totp"] = None
        self._save(doc)
        self._audit("totp_disabled", username, {})

    @_ecrit
    def set_otp_mode(self, username: str, mode: Any, par: Optional[str] = None, confirme: Optional[bool] = None) -> None:
        """Règle le second facteur du compte (#2745). `defaut` retire le champ (users.json reste propre). Le secret TOTP n'est PAS touché : réactiver ne demande
        pas de ré-enrôlement. Un mode inchangé n'écrit ni ne journalise rien. Le journal dit qui (`par`), quel compte, l'ancien et le nouveau mode."""
        if not isinstance(mode, str) or mode not in OTP_MODES:
            raise EngineError(f"otp mode invalid: {mode!r}")
        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"user not found: {username}")
        ancien = u.get("otp_mode") if u.get("otp_mode") in OTP_MODES else "defaut"
        if mode == ancien:
            return
        if mode == "defaut":
            u.pop("otp_mode", None)
        else:
            u["otp_mode"] = mode
        self._save(doc)
        details: Dict[str, Any] = {"ancien": ancien, "nouveau": mode}
        if par is not None:
            details["par"] = par
        if confirme is not None:
            details["confirme"] = confirme
        self._audit("otp_mode_change", username, details)

    def regenerate_backup_codes(self, username: str) -> list:
        from . import totp as _totp

        def enrole(doc):
            u = self._find(doc, username)
            if not u or not (u.get("totp") and u["totp"].get("enabled")):
                raise EngineError(f"TOTP not enrolled for {username}")
            return u

        enrole(self._load())
        plain = _totp.generate_backup_codes(n=10, length=10)
        codes = [{"hash": _totp.hash_backup_code(c), "used_at": None} for c in plain]
        with self.verrou():
            doc = self._load()
            enrole(doc)["totp"]["backup_codes"] = codes
            self._save(doc)
        self._audit("backup_codes_regenerated", username, {})
        return plain

    # ── Sessions / audit helpers ─────────────────────────────────────

    @_ecrit
    def delete_user(self, username: str) -> None:
        doc = self._load()
        before = len(doc.get("users", []))
        doc["users"] = [u for u in doc.get("users", []) if u.get("username") != username]
        if len(doc["users"]) == before:
            raise EngineError(f"user not found: {username}")
        self._save(doc)
        self._audit("user_deleted", username, {})

    def touch_last_login(self, username: str) -> None:
        """Ne fait jamais échouer une connexion : registre occupé, la date attendra la suivante."""
        try:
            self._touch_last_login(username)
        except (EngineError, OSError) as exc:
            log.warning("last_login de %s non noté (%s)", username, exc)

    @_ecrit
    def _touch_last_login(self, username: str) -> None:
        doc = self._load()
        u = self._find(doc, username)
        if not u:
            return
        u["last_login"] = _now_iso()
        self._save(doc)

    def revoke_sessions(self, username: str) -> int:
        """Dispatch to the revoke callback. Returns count revoked."""
        if not self._revoke_cb:
            return 0
        try:
            return int(self._revoke_cb(username) or 0)
        except Exception as exc:
            log.warning("revoke_sessions(%s) failed: %s", username, exc)
            return 0
