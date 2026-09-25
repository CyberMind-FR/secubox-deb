# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: sbxid — SBX Identity Mesh, le socle (#1417, docs/AUTH_V3.md M1)
CyberMind — https://cybermind.fr

Les quatre entités (Node, User, Device, Certificate), les rôles-capacités, la
forme canonique et la DOUBLE SIGNATURE : la personne signe par la clé non
exportable d'un de ses appareils (ECDSA P-256, WebCrypto), son nœud d'accueil
signe par node.key (Ed25519). L'une sans l'autre ne vaut rien.

Bibliothèque PURE : aucun effet de bord, aucun service ne l'appelle encore
(M1 ne change aucun comportement). Les formats sont ceux déjà en service :
  - appareil : point SEC1 non compressé en hex, signature `r‖s` en hex (ce que
    rend WebCrypto, cf. secubox-acces/api/identite.py) ;
  - nœud : clé publique Ed25519 brute en hex, signature en hex, DID
    `did:plc:<sha256(pub)[:32]>` (cf. secubox-annuaire/annuaire/crypto.py) ;
  - forme canonique : json.dumps(sort_keys, separators=(",",":")), ASCII,
    SANS flottant (le canon Go de la fédération les refuse).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric import utils as _asym

API_VERSION = "sbxos/v1"

# ── Capacités ──────────────────────────────────────────────────────────────
# Une capacité ouvre un MODULE ou une FONCTIONNALITÉ SBX OS, rien d'autre.
CAPACITES = (
    "hall.read", "hall.write",
    "bbs.read", "bbs.write", "bbs.moderate",
    "billets.read", "billets.publish",
    "radio.listen", "radio.chat",
    "metablog.publish", "peertube.upload", "nextcloud.files",
    "reelbox.use", "reelbox.beta", "modules.experimental",
    "admin.users", "admin.invites", "admin.modules", "admin.audit",
)
_INTERDIT = re.compile(r"^(ssh|sudo|root|system\.)", re.I)
_FORME_CAP = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_.]*$")

_BASE = ("hall.read", "bbs.read", "billets.read", "radio.listen")
_MEMBRE = _BASE + ("hall.write", "bbs.write", "billets.publish", "radio.chat")
ROLES: Dict[str, tuple] = {
    "guest": _BASE,
    "member": _MEMBRE,
    # DÉRIVÉ d'un abonnement actif (premium, association) — jamais attribué à la main.
    "subscriber": _MEMBRE + ("metablog.publish", "peertube.upload", "nextcloud.files", "reelbox.use"),
    "beta_tester": _MEMBRE + ("reelbox.beta", "modules.experimental", "metablog.publish"),
    "moderator": _MEMBRE + ("bbs.moderate",),
    "sbx_operator": _MEMBRE + ("bbs.moderate", "metablog.publish", "peertube.upload",
                               "nextcloud.files", "reelbox.use", "admin.users",
                               "admin.invites", "admin.modules", "admin.audit"),
}
ROLES_DERIVES = {"subscriber"}
TIERS = ("free", "premium", "association")
TIERS_ABONNE = {"premium", "association"}

# Comptes système : JAMAIS dans SBX OS (AUTH v2 §1).
COMPTES_SYSTEME = frozenset({"root", "admin", "gk2", "operator"})


class Refus(ValueError):
    """Une règle de l'Identity Mesh interdit l'opération demandée."""


def valide_capacite(cap: str) -> str:
    c = (cap or "").strip().lower()
    if _INTERDIT.match(c):
        raise Refus(f"capacité interdite : {c!r} — une capacité SBX OS ne touche jamais au système")
    if not _FORME_CAP.match(c):
        raise Refus(f"capacité mal formée : {c!r} (module.action attendu)")
    return c


def roles_effectifs(roles: Iterable[str], tier: Optional[str] = None) -> List[str]:
    """Rôles attribués + `subscriber` DÉRIVÉ de l'abonnement ; inconnus refusés."""
    out: List[str] = []
    for r in roles:
        if r in ROLES_DERIVES:
            continue                       # jamais attribué à la main
        if r not in ROLES:
            raise Refus(f"rôle inconnu : {r!r}")
        if r not in out:
            out.append(r)
    if tier in TIERS_ABONNE:
        out.append("subscriber")
    return out


def capacites(roles: Iterable[str], tier: Optional[str] = None,
              table: Optional[Dict[str, Iterable[str]]] = None,
              suspendu: bool = False) -> List[str]:
    """Union des capacités des rôles effectifs, dans l'ordre canonique."""
    if suspendu:
        return []
    t = table or ROLES
    s = set()
    for r in roles_effectifs(roles, tier):
        s.update(valide_capacite(c) for c in t.get(r, ()))
    connues = [c for c in CAPACITES if c in s]
    return connues + sorted(s - set(CAPACITES))


# ── Forme canonique ────────────────────────────────────────────────────────
def _sans_flottant(o: Any, chemin: str = "$") -> None:
    if isinstance(o, float):
        raise Refus(f"flottant interdit dans un enregistrement signé ({chemin})")
    if isinstance(o, dict):
        for k, v in o.items():
            _sans_flottant(v, f"{chemin}.{k}")
    elif isinstance(o, (list, tuple)):
        for i, v in enumerate(o):
            _sans_flottant(v, f"{chemin}[{i}]")


def canonical_bytes(obj: Dict[str, Any]) -> bytes:
    """Identique à annuaire.crypto.canonical_bytes, flottants refusés."""
    _sans_flottant(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── Nœud (Ed25519) ─────────────────────────────────────────────────────────
def did_noeud(pub_hex: str) -> str:
    return "did:plc:" + hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]


@dataclass(frozen=True)
class Node:
    did: str
    pubkey: str                     # Ed25519 brute, hex

    @classmethod
    def depuis_cle(cls, pub_hex: str) -> "Node":
        return cls(did=did_noeud(pub_hex), pubkey=pub_hex.lower())


def signe_noeud(graine_hex: str, message: bytes) -> str:
    cle = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(graine_hex))
    return cle.sign(message).hex()


def pub_noeud(graine_hex: str) -> str:
    from cryptography.hazmat.primitives import serialization as _ser
    cle = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(graine_hex))
    return cle.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw).hex()


def verifie_noeud(pub_hex: str, message: bytes, sig_hex: str) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(sig_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


# ── Appareil (ECDSA P-256, format WebCrypto) ───────────────────────────────
_RE_POINT = re.compile(r"^04[0-9a-f]{128}$")
_RE_SIG = re.compile(r"^[0-9a-f]{128}$")


def did_appareil(point_hex: str) -> str:
    """did:sbx — RECALCULÉ depuis la clé, jamais cru sur parole (audit #1405)."""
    p = point_hex.strip().lower()
    if not _RE_POINT.match(p):
        raise Refus("clé d'appareil invalide : point P-256 non compressé attendu")
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(p))
    return "did:sbx:" + hashlib.sha256(bytes.fromhex(p)).hexdigest()[:32]


def empreinte_cle(point_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(point_hex.strip().lower())).hexdigest()


def signe_appareil(cle_privee: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    """Ce que fait `crypto.subtle.sign` dans le navigateur : r‖s en hex.
    Côté serveur, ne sert qu'aux tests et aux outils ; la vraie clé ne quitte
    jamais l'appareil."""
    der = cle_privee.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = _asym.decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def verifie_appareil(point_hex: str, message: bytes, sig_hex: str) -> bool:
    s = (sig_hex or "").strip().lower()
    if not _RE_SIG.match(s):
        return False
    try:
        cle = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(point_hex.strip().lower()))
        brut = bytes.fromhex(s)
        der = _asym.encode_dss_signature(int.from_bytes(brut[:32], "big"),
                                         int.from_bytes(brut[32:], "big"))
        cle.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# ── Entités ────────────────────────────────────────────────────────────────
@dataclass
class User:
    user_uuid: str
    home_node: str
    pseudo: str
    epoch: int = 1
    email: str = ""
    roles: List[str] = field(default_factory=lambda: ["member"])
    tier: str = "free"
    status: str = "active"

    def __post_init__(self):
        uuid.UUID(self.user_uuid)
        if self.pseudo.strip().lower() in COMPTES_SYSTEME:
            raise Refus(f"{self.pseudo!r} est un compte système : jamais une identité SBX OS")
        if self.tier not in TIERS:
            raise Refus(f"abonnement inconnu : {self.tier!r}")
        roles_effectifs(self.roles, self.tier)

    @property
    def capacites(self) -> List[str]:
        return capacites(self.roles, self.tier, suspendu=self.status == "suspended")


@dataclass
class Device:
    device_uuid: str
    user_uuid: str
    public_key: str                 # point SEC1 non compressé, hex
    name: str = ""
    kind: str = ""
    trust: str = "pending"
    revoked_at: Optional[int] = None

    def __post_init__(self):
        uuid.UUID(self.device_uuid)
        uuid.UUID(self.user_uuid)
        self.public_key = self.public_key.strip().lower()
        self.did = did_appareil(self.public_key)

    @property
    def empreinte(self) -> str:
        return empreinte_cle(self.public_key)


# ── Certificats : la double signature ──────────────────────────────────────
KINDS = ("device", "user", "migration", "revocation")


def _maintenant() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Certificate:
    payload: Dict[str, Any]
    sig_user: str = ""
    signer_device: str = ""         # device_uuid dont la clé a produit sig_user
    sig_node: str = ""
    sig_node_2: str = ""            # migration : le second nœud

    # Messages signés ------------------------------------------------------
    def message_user(self) -> bytes:
        return canonical_bytes(self.payload)

    def message_node(self) -> bytes:
        return canonical_bytes({**self.payload, "sig_user": self.sig_user,
                                "signer_device": self.signer_device})

    def message_node_2(self) -> bytes:
        return canonical_bytes({**self.payload, "sig_user": self.sig_user,
                                "signer_device": self.signer_device, "sig_node": self.sig_node})

    def en_dict(self) -> Dict[str, Any]:
        d = {"payload": self.payload, "sig_user": self.sig_user,
             "signer_device": self.signer_device, "sig_node": self.sig_node}
        if self.sig_node_2:
            d["sig_node_2"] = self.sig_node_2
        return d


def nouveau_certificat(kind: str, user: User, device: Device, *, node: Node,
                       validite_jours: int = 365, extra: Optional[Dict[str, Any]] = None,
                       emis: Optional[str] = None) -> Certificate:
    """Prépare la CHARGE (sans signature). Aucune donnée personnelle : ni pseudo,
    ni courriel — le certificat peut finir dans le journal public."""
    if kind not in KINDS:
        raise Refus(f"sorte de certificat inconnue : {kind!r}")
    if device.user_uuid != user.user_uuid:
        raise Refus("l'appareil n'appartient pas à cette personne")
    if user.home_node != node.did:
        raise Refus("seul le nœud d'accueil certifie une personne")
    emis = emis or _maintenant()
    t = datetime.strptime(emis, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    expire = datetime.fromtimestamp(t.timestamp() + validite_jours * 86400, timezone.utc)
    p = {"apiVersion": API_VERSION, "kind": kind, "serial": str(uuid.uuid4()),
         "user_uuid": user.user_uuid, "device_uuid": device.device_uuid,
         "device_key_sha256": device.empreinte, "home_node": node.did,
         "epoch": int(user.epoch), "roles": roles_effectifs(user.roles, user.tier),
         "capabilities": user.capacites, "issued": emis,
         "expires": expire.strftime("%Y-%m-%dT%H:%M:%SZ")}
    if extra:
        p.update(extra)
    canonical_bytes(p)                       # refuse tôt un flottant
    return Certificate(payload=p)


def signe_par_la_personne(cert: Certificate, signer: Device,
                          cle_privee: ec.EllipticCurvePrivateKey) -> Certificate:
    if signer.revoked_at:
        raise Refus("un appareil révoqué ne signe plus")
    if signer.user_uuid != cert.payload["user_uuid"]:
        raise Refus("l'appareil signataire appartient à une autre personne")
    cert.signer_device = signer.device_uuid
    cert.sig_user = signe_appareil(cle_privee, cert.message_user())
    return cert


def contresigne_par_le_noeud(cert: Certificate, graine_hex: str) -> Certificate:
    if not cert.sig_user:
        raise Refus("le nœud ne signe pas avant la personne")
    if did_noeud(pub_noeud(graine_hex)) != cert.payload["home_node"]:
        raise Refus("ce nœud n'est pas le nœud d'accueil du certificat")
    cert.sig_node = signe_noeud(graine_hex, cert.message_node())
    return cert


@dataclass
class Verdict:
    valide: bool
    motif: str = ""


def verifie_certificat(cert: Certificate, *, cle_noeud: str,
                       appareils: Dict[str, Device], epoque_connue: int = 0,
                       maintenant: Optional[str] = None,
                       cle_noeud_2: Optional[str] = None) -> Verdict:
    """Les quatre contrôles d'AUTH v3 §2 : nœud, personne, époque, échéance."""
    p = cert.payload
    if p.get("apiVersion") != API_VERSION or p.get("kind") not in KINDS:
        return Verdict(False, "forme inconnue")
    if did_noeud(cle_noeud) != p.get("home_node"):
        return Verdict(False, "la clé présentée n'est pas celle du nœud d'accueil")
    if not cert.sig_node or not verifie_noeud(cle_noeud, cert.message_node(), cert.sig_node):
        return Verdict(False, "signature du nœud invalide")
    dev = appareils.get(cert.signer_device)
    if dev is None:
        return Verdict(False, "appareil signataire inconnu")
    if dev.user_uuid != p.get("user_uuid"):
        return Verdict(False, "appareil signataire d'une autre personne")
    if dev.revoked_at:
        return Verdict(False, "appareil signataire révoqué")
    if not cert.sig_user or not verifie_appareil(dev.public_key, cert.message_user(), cert.sig_user):
        return Verdict(False, "signature de la personne invalide")
    if int(p.get("epoch", 0)) < int(epoque_connue):
        return Verdict(False, "époque périmée (rejeu d'un ancien certificat)")
    if (maintenant or _maintenant()) >= p.get("expires", ""):
        return Verdict(False, "certificat expiré")
    for c in p.get("capabilities", []):
        try:
            valide_capacite(c)
        except Refus as e:
            return Verdict(False, str(e))
    if p.get("kind") == "migration":
        if not cle_noeud_2 or did_noeud(cle_noeud_2) != p.get("to_node"):
            return Verdict(False, "migration : clé du nœud d'accueil manquante")
        if not cert.sig_node_2 or not verifie_noeud(cle_noeud_2, cert.message_node_2(), cert.sig_node_2):
            return Verdict(False, "migration : signature du nœud d'accueil invalide")
    return Verdict(True)


def contresigne_migration(cert: Certificate, graine_accueil_hex: str) -> Certificate:
    """Le nœud d'ACCUEIL signe en dernier : la migration exige les deux nœuds."""
    if cert.payload.get("kind") != "migration":
        raise Refus("seule une migration porte deux signatures de nœud")
    if not cert.sig_node:
        raise Refus("le nœud d'origine signe avant le nœud d'accueil")
    if did_noeud(pub_noeud(graine_accueil_hex)) != cert.payload.get("to_node"):
        raise Refus("ce nœud n'est pas le nœud d'accueil de la migration")
    cert.sig_node_2 = signe_noeud(graine_accueil_hex, cert.message_node_2())
    return cert


# ── Présentation YAML sbxos/v1 ─────────────────────────────────────────────
def en_yaml(cert: Certificate) -> str:
    """Présentation lisible (la vérification se fait sur la forme canonique)."""
    p = cert.payload
    lignes = [f"apiVersion: {p['apiVersion']}", f"kind: {p['kind'].capitalize()}Certificate",
              f"serial: {p['serial']}", "identity:", f"  node: {p['home_node']}",
              f"  user: {p['user_uuid']}", f"  device: {p['device_uuid']}",
              f"  device_key_sha256: {p['device_key_sha256']}",
              f"roles: [{', '.join(p['roles'])}]",
              f"capabilities: [{', '.join(p['capabilities'])}]",
              "restrictions: {system: none}", f"epoch: {p['epoch']}",
              f"issued: {p['issued']}", f"expires: {p['expires']}", "signatures:",
              f"  - {{by: user, device: {cert.signer_device}, algorithm: ecdsa-p256, value: \"{cert.sig_user}\"}}",
              f"  - {{by: {p['home_node']}, algorithm: ed25519, value: \"{cert.sig_node}\"}}"]
    if cert.sig_node_2:
        lignes.append(f"  - {{by: {p.get('to_node')}, algorithm: ed25519, value: \"{cert.sig_node_2}\"}}")
    return "\n".join(lignes) + "\n"


# ── Schéma sbx.db (AUTH v2 §4 + v3) ────────────────────────────────────────
SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS sbx_nodes (did TEXT PRIMARY KEY, pubkey TEXT NOT NULL, x25519 TEXT, label TEXT, seen_at INTEGER);
CREATE TABLE IF NOT EXISTS sbx_users (
  user_uuid TEXT PRIMARY KEY, pseudo TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('invited','active','suspended','departed','deleted')),
  home_node TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL,
  CHECK (lower(pseudo) NOT IN ('root','admin','gk2','operator')));
CREATE TABLE IF NOT EXISTS sbx_roles (role_id TEXT PRIMARY KEY, label TEXT NOT NULL, derived INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sbx_capabilities (capability TEXT PRIMARY KEY CHECK (
  lower(capability) NOT GLOB 'ssh*' AND lower(capability) NOT GLOB 'sudo*' AND
  lower(capability) NOT GLOB 'root*' AND lower(capability) NOT GLOB 'system.*'));
CREATE TABLE IF NOT EXISTS sbx_role_capabilities (role_id TEXT REFERENCES sbx_roles, capability TEXT REFERENCES sbx_capabilities, PRIMARY KEY (role_id, capability));
CREATE TABLE IF NOT EXISTS sbx_user_roles (user_uuid TEXT REFERENCES sbx_users, role_id TEXT REFERENCES sbx_roles, granted_by TEXT, granted_at INTEGER, PRIMARY KEY (user_uuid, role_id));
CREATE TABLE IF NOT EXISTS sbx_devices (
  device_uuid TEXT PRIMARY KEY, user_uuid TEXT REFERENCES sbx_users, device_name TEXT NOT NULL,
  device_kind TEXT, did TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL,
  trust_level TEXT NOT NULL DEFAULT 'pending' CHECK (trust_level IN ('pending','verified','trusted')),
  last_seen_at INTEGER, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS sbx_certificates (
  serial TEXT PRIMARY KEY, kind TEXT NOT NULL, user_uuid TEXT NOT NULL, device_uuid TEXT,
  epoch INTEGER NOT NULL, issued TEXT NOT NULL, expires TEXT NOT NULL, body TEXT NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS sbx_sessions (
  session_uuid TEXT PRIMARY KEY, user_uuid TEXT NOT NULL REFERENCES sbx_users, device_uuid TEXT NOT NULL REFERENCES sbx_devices,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ip TEXT, user_agent TEXT, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS sbx_replay (
  replay_id TEXT PRIMARY KEY, session_uuid TEXT NOT NULL REFERENCES sbx_sessions, audience TEXT NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER);
CREATE TABLE IF NOT EXISTS sbx_invites (
  invite_uuid TEXT PRIMARY KEY, email TEXT, pseudo_propose TEXT, role_propose TEXT DEFAULT 'member',
  device_uuid TEXT, code_hash TEXT, created_by TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  validated_by TEXT, validated_at INTEGER, refused_at INTEGER, motif TEXT);
CREATE TABLE IF NOT EXISTS sbx_subscriptions (
  subscription_uuid TEXT PRIMARY KEY, user_uuid TEXT NOT NULL REFERENCES sbx_users, reelbox_uuid TEXT,
  tier TEXT NOT NULL CHECK (tier IN ('free','premium','association')),
  started_at INTEGER NOT NULL, expires_at INTEGER, renewed_at INTEGER, auto_renew INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sbx_preferences (user_uuid TEXT REFERENCES sbx_users, cle TEXT, valeur TEXT, PRIMARY KEY (user_uuid, cle));
CREATE TABLE IF NOT EXISTS sbx_app_links (user_uuid TEXT REFERENCES sbx_users, app TEXT, app_id TEXT, app_handle TEXT, PRIMARY KEY (app, app_id));
CREATE TABLE IF NOT EXISTS sbx_migrations (
  migration_uuid TEXT PRIMARY KEY, user_uuid TEXT NOT NULL, from_node TEXT NOT NULL, to_node TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('requested','accepted','released','transferred','finalized','refused')),
  certificate TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sbx_audit (at INTEGER NOT NULL, actor TEXT NOT NULL, event TEXT NOT NULL, detail TEXT);
"""


def initialise(conn) -> None:
    """Crée le schéma et sème rôles et capacités (idempotent)."""
    conn.executescript(SCHEMA)
    for c in CAPACITES:
        conn.execute("INSERT OR IGNORE INTO sbx_capabilities VALUES (?)", (c,))
    libelles = {"guest": "Invité", "member": "Membre", "subscriber": "Abonné",
                "beta_tester": "Bêta-testeur", "moderator": "Modérateur",
                "sbx_operator": "Opérateur SBX"}
    for r, caps in ROLES.items():
        conn.execute("INSERT OR IGNORE INTO sbx_roles VALUES (?,?,?)",
                     (r, libelles[r], 1 if r in ROLES_DERIVES else 0))
        for c in caps:
            conn.execute("INSERT OR IGNORE INTO sbx_role_capabilities VALUES (?,?)", (r, c))
    conn.commit()
