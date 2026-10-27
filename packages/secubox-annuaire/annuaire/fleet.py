# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: fleet
Sign / verify / resolve security core for fleet metrics (MetricSnapshot).

PURE — no IO, no subprocess (that lives in the collector/transport layer, T3/T4).

Trust model
-----------
A peer serves its own MetricSnapshot over the mesh. A puller must be able to
verify it WITHOUT a pubkey registry, so the signed record carries its own
`signer_pub` (hex Ed25519 pubkey). `verify_snapshot` is the trust boundary: it
enforces that the DID derived from `signer_pub` matches `signer_did`,
`node_did` AND `issued_by` — ALL FOUR must agree — before trusting the Ed25519
signature check. Without this chain, a malicious peer could serve a record
whose payload claims a different node's `node_did` while still signing with
its own key (impersonation). Fail-closed throughout: any exception, missing
field, or mismatch is treated as an untrusted record (→ False / stale).
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from . import crypto
from .model import MetricSnapshot, ModulesSnapshot

_EXCLUDED_FROM_PAYLOAD = ("sig", "signer_did", "signer_pub")


def sign_snapshot(priv: bytes, fields: Dict[str, Any]) -> Dict[str, Any]:
    """Sign a metrics snapshot with the node's private key.

    Args:
        priv: 32-byte raw Ed25519 private key.
        fields: the snapshot fields (node_did, issued_by, hostname, ts, ...)
            WITHOUT sig/signer_did/signer_pub — those are computed here.

    Returns:
        The full signed record: validated payload + sig + signer_did + signer_pub.

    Raises:
        pydantic.ValidationError if `fields` does not fit MetricSnapshot's shape.
    """
    pub = crypto.public_from_private(priv)
    signer_did = crypto.did_from_pubkey(pub)

    payload = {k: v for k, v in fields.items() if k not in _EXCLUDED_FROM_PAYLOAD}
    # Validate and normalize — the model's validators apply here (cap modules_down, default counters).
    m = MetricSnapshot(**payload)
    payload = m.model_dump(exclude={"sig", "signer_did", "signer_pub"})

    sig = crypto.sign(priv, crypto.canonical_bytes(payload))
    return {**payload, "sig": sig, "signer_did": signer_did, "signer_pub": pub.hex()}


def verify_snapshot(rec: Dict[str, Any]) -> bool:
    """Verify a pulled peer snapshot. FAIL-CLOSED: any exception → False.

    Enforces that the signer's pubkey-derived DID is bound to signer_did,
    node_did, AND issued_by (all four equal), then checks the Ed25519
    signature over the canonical payload bytes.
    """
    try:
        sig = rec["sig"]
        signer_did = rec["signer_did"]
        signer_pub = rec["signer_pub"]
        node_did = rec["node_did"]
        issued_by = rec["issued_by"]
        if not (sig and signer_did and signer_pub and node_did and issued_by):
            return False

        payload = {k: v for k, v in rec.items() if k not in _EXCLUDED_FROM_PAYLOAD}

        derived_did = crypto.did_from_pubkey(bytes.fromhex(signer_pub))
        if not (derived_did == signer_did == node_did == issued_by):
            return False

        return crypto.verify(signer_pub, crypto.canonical_bytes(payload), sig)
    except Exception:
        return False


def sign_modules(priv: bytes, fields: Dict[str, Any]) -> Dict[str, Any]:
    """Signe le relevé de validation des modules de cette box (#3212), validé par ModulesSnapshot (borné).

    Même chaîne de confiance que sign_snapshot : signer_pub → signer_did = node_did = issued_by."""
    pub = crypto.public_from_private(priv)
    payload = {k: v for k, v in fields.items() if k not in _EXCLUDED_FROM_PAYLOAD}
    payload = ModulesSnapshot(**payload).model_dump(exclude={"sig", "signer_did", "signer_pub"})
    sig = crypto.sign(priv, crypto.canonical_bytes(payload))
    return {**payload, "sig": sig, "signer_did": crypto.did_from_pubkey(pub), "signer_pub": pub.hex()}


def charger_json(texte: Any) -> Any:
    """json.loads sans NaN ni Infinity : la valeur serait signée, validée, puis ferait échouer la réponse JSON (#3212)."""
    def refus(c: str) -> Any:
        raise ValueError(f"constante JSON refusée : {c}")
    return json.loads(texte, parse_constant=refus)


def normaliser_modules(rec: Any) -> Optional[Dict[str, Any]]:
    """Relevé d'un pair VÉRIFIÉ (signature ET forme), rendu tel que le modèle le décrit — jamais l'objet brut du pair.
    None s'il ne se vérifie pas. FAIL-CLOSED."""
    try:
        if not isinstance(rec, dict) or not verify_snapshot(rec):
            return None
        return ModulesSnapshot(**rec).model_dump()
    except Exception:
        return None


def verify_modules(rec: Dict[str, Any]) -> bool:
    """Relevé d'un pair : signature ET forme. Un pair signe ce qu'il veut ; un relevé hors bornes (taille, noms, états)
    est refusé même bien signé. FAIL-CLOSED."""
    return normaliser_modules(rec) is not None


def resoudre_releves(
    soi: Optional[Dict[str, Any]],
    resultats: List[Any],
    attendus: Dict[str, str],
    maintenant: str,
    ttl_s: int,
) -> "tuple[List[Dict[str, Any]], List[Dict[str, str]]]":
    """La vue du parc à partir des relevés DÉJÀ vérifiés (#3212, revue).

    resultats : [(pair {mesh_ip, name}, relevé normalisé ou None, raison ou None)] ; attendus : {mesh_ip: did} tirés des
    fiches signées du répertoire (une adresse revendiquée par un seul did). Un relevé n'est retenu que s'il vient de la
    box qui le sert : did attendu pour cette adresse, did pas déjà vu (dont la box locale), horodatage pas dans le futur.
    Sinon la box est NOMMÉE avec sa raison — jamais une box qui disparaît, jamais un pair qui en remplace un autre. Les
    relevés liés à leur adresse passent d'abord : un rejeu non lié ne chasse pas la vraie box. Un nom d'hôte revendiqué
    par deux did est marqué `nom_conteste`."""
    noeuds: Dict[str, Dict[str, Any]] = {}
    indisponibles: List[Dict[str, str]] = []
    if soi:
        noeuds[soi["node_did"]] = {**soi, "stale": is_stale(soi, maintenant, ttl_s)}
    else:
        indisponibles.append({"nom": "cette box", "mesh_ip": "", "raison": "relevé non publié"})
    futur = _parse_ts(maintenant) + timedelta(minutes=5)

    def lie(item: Any) -> int:
        pair, rec, _raison = item
        return 0 if rec and attendus.get(str(pair.get("mesh_ip") or "")) == rec.get("node_did") else 1

    for pair, rec, raison in sorted(resultats, key=lie):
        ip = str(pair.get("mesh_ip") or "")
        nom = str(pair.get("name") or ip or "?")
        if raison is None and not rec:
            raison = "relevé non publié"
        elif raison is None:
            attendu = attendus.get(ip)
            if (attendu and attendu != rec["node_did"]) or rec["node_did"] in noeuds:
                raison = "relevé d'une autre box"
            else:
                try:
                    if _parse_ts(rec["ts"]) > futur:
                        raison = "horodatage dans le futur"
                except Exception:
                    raison = "horodatage illisible"
        if raison:
            indisponibles.append({"nom": nom, "mesh_ip": ip, "raison": raison})
            continue
        noeuds[rec["node_did"]] = {**rec, "stale": is_stale(rec, maintenant, ttl_s)}
    compte = Counter(n.get("hostname") for n in noeuds.values())
    sortie = [{**n, "nom_conteste": compte[n.get("hostname")] > 1} for n in noeuds.values()]
    return sorted(sortie, key=lambda n: (str(n.get("hostname")), n["node_did"])), indisponibles


def fleet_snapshots(
    self_rec: Optional[Dict[str, Any]],
    peer_recs: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Resolve the fleet map: keep only verified records, keyed by node_did.

    Never raises — unverifiable records are silently dropped.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for rec in [self_rec, *peer_recs]:
        if rec and verify_snapshot(rec):
            out[rec["node_did"]] = rec
    return out


def _parse_ts(ts: str) -> datetime:
    """Parse an RFC3339 timestamp, accepting both trailing 'Z' and isoformat offsets."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def is_stale(rec: Dict[str, Any], now_ts: str, ttl_s: int) -> bool:
    """True if the record's `ts` is older than `ttl_s` relative to `now_ts`.

    Fail-closed: any parse error is treated as stale.
    """
    try:
        ts = _parse_ts(rec["ts"])
        now = _parse_ts(now_ts)
        return (now - ts).total_seconds() > ttl_s
    except Exception:
        return True


def health(rec: Dict[str, Any]) -> str:
    """Derive a coarse health label from a snapshot's fields."""
    if rec.get("modules_down"):
        return "down"
    if rec.get("load1", 0) > 4.0 or rec.get("disk_pct", 0) > 90:
        return "warn"
    return "ok"
