# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Accès — L'IDENTITÉ D'UN APPAREIL, ET CE QU'ELLE ENGAGE (#1344).

CE QUE CE FICHIER RÉPARE. Dans la première version, la « clé publique » envoyée
par le client était un nombre tiré au hasard :

    var octets = new Uint8Array(32); crypto.getRandomValues(octets);
    return { did: 'did:sbx:' + hex.slice(0,24), cle: hex };

L'empreinte qu'on faisait comparer à l'administrateur n'engageait donc PERSONNE.
N'importe qui pouvait annoncer n'importe quelle empreinte : aucun secret ne lui
correspondait, et rien ne reliait l'empreinte validée à l'appareil qui se
présenterait ensuite. Le geste de vérification était du théâtre.

CE QU'UNE VRAIE CLÉ CHANGE. L'appareil engendre une paire ECDSA P-256 dont la
partie privée est NON EXPORTABLE (WebCrypto `extractable: false`) : le
navigateur peut signer avec, personne ne peut la lire — ni un script injecté,
ni l'utilisateur, ni nous. L'empreinte dérive de la partie publique. Comparer
l'empreinte devient donc une vraie décision : elle désigne l'unique appareil
capable de signer ensuite.

POURQUOI P-256 ET PAS X25519. Notre cœur cryptographique (#1288) est en X25519 /
Ed25519, et c'est le bon choix côté serveur. Mais ici la clé est engendrée par
un NAVIGATEUR, et WebCrypto n'expose Ed25519/X25519 que depuis très récemment.
P-256 (ECDSA, SHA-256) est disponible partout depuis dix ans, et c'est un
algorithme du même registre — FIPS 186-4, recommandé par l'ANSSI. On préfère une
vraie clé que tout le monde peut engendrer à une meilleure clé que la moitié des
appareils refuserait.

ET ON SIGNE, ON NE CHIFFRE PAS. Prouver qu'on détient la clé se fait en signant
un défi. Un échange de clés (ECDH) demanderait de dériver un secret partagé pour
déchiffrer quelque chose — plus de pièces mobiles pour la même garantie.
"""
from __future__ import annotations

import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

#: Point public SEC1 non compressé : 0x04 ‖ X(32) ‖ Y(32) = 65 octets = 130 hex.
#: C'est le format que rend `crypto.subtle.exportKey("raw", …)` pour P-256.
_RE_POINT = re.compile(r"^04[0-9a-f]{128}$")

#: Signature WebCrypto : r ‖ s, 32 octets chacun. Elle N'EST PAS en DER — d'où
#: la conversion ci-dessous, qui est le piège classique de cet appariement.
_RE_SIG = re.compile(r"^[0-9a-f]{128}$")

COURBE = ec.SECP256R1()


class CleInvalide(ValueError):
    """La clé publique n'a pas la forme attendue, ou n'est pas sur la courbe."""


def charge_cle(point_hex: str) -> ec.EllipticCurvePublicKey:
    """Décode une clé publique P-256 depuis son point SEC1 hexadécimal.

    VALIDER LA COURBE N'EST PAS UNE FORMALITÉ : un point qui satisfait la forme
    sans appartenir à la courbe permet des attaques par courbe invalide.
    `from_encoded_point` refuse ces points — on s'appuie dessus plutôt que de
    recalculer l'équation nous-mêmes.
    """
    p = (point_hex or "").strip().lower()
    if not _RE_POINT.match(p):
        raise CleInvalide("clé publique invalide : point P-256 non compressé attendu")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(COURBE, bytes.fromhex(p))
    except ValueError as e:
        raise CleInvalide(f"clé publique hors courbe : {e}") from e


def empreinte_courte(point_hex: str) -> str:
    """Six groupes de quatre, dérivés de la clé publique.

    C'EST LE REMPLAÇANT DU QR CODE, et maintenant il porte quelque chose :
    l'empreinte désigne l'unique appareil capable de signer. On la découpe parce
    qu'une chaîne de 24 signes d'affilée ne se compare pas — l'œil décroche au
    huitième, et c'est précisément au milieu qu'une substitution se cacherait.
    """
    brut = hashlib.sha256(bytes.fromhex(point_hex.strip().lower())).hexdigest()[:24]
    return " ".join(brut[i:i + 4] for i in range(0, 24, 4))


def verifie_signature(point_hex: str, message: bytes, signature_hex: str) -> bool:
    """Vérifie une signature ECDSA P-256 / SHA-256 produite par WebCrypto.

    WEBCRYPTO REND `r ‖ s`, PAS DU DER — et `cryptography` attend du DER. C'est
    l'erreur d'appariement classique entre les deux mondes : sans la conversion,
    toutes les signatures échouent, y compris les bonnes, et l'on cherche
    longtemps un bug de clé qui n'existe pas.
    """
    s = (signature_hex or "").strip().lower()
    if not _RE_SIG.match(s):
        return False
    try:
        cle = charge_cle(point_hex)
    except CleInvalide:
        return False

    brut = bytes.fromhex(s)
    r = int.from_bytes(brut[:32], "big")
    t = int.from_bytes(brut[32:], "big")
    der = asym_utils.encode_dss_signature(r, t)
    try:
        cle.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
