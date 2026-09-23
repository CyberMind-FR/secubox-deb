# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-zigbee :: couleur et charge utile d'une commande.

POURQUOI UN MODULE À PART. Deux raisons, et la seconde est la vraie.

La première : c'est de l'arithmétique pure, sans courtier ni réseau, donc
testable sans rien monter.

La seconde : la conversion d'un « #RRGGBB » en coordonnées CIE appartient à
CELUI QUI POSSÈDE L'APPAREIL. Une lampe Zigbee ne connaît pas le sRGB ; elle
connaît `color_xy`. Si l'appelant devait convertir lui-même, chaque appelant
referait le calcul — et le referait différemment, parce que la matrice n'est
pas unique. Le module qui parle au pont tranche une fois pour tous.
"""


def _lineaire(canal: float) -> float:
    """Défait la correction gamma du sRGB.

    Sans elle, un « #808080 » sorti d'un sélecteur de couleur donnerait une
    luminance de 50 % alors que l'œil le voit à 21 %. Les coordonnées CIE se
    calculent sur de la lumière, pas sur des octets d'affichage.
    """
    if canal > 0.04045:
        return ((canal + 0.055) / 1.055) ** 2.4
    return canal / 12.92


def xy_depuis_hex(couleur: str) -> tuple:
    """« #RRGGBB » → (x, y) en CIE 1931.

    La matrice est celle dite « Wide RGB D65 », que les lampes Zigbee de ce
    parc — et Hue, dont elles reprennent le profil — utilisent. Prendre la
    matrice sRGB standard donnerait des couleurs plausibles mais décalées,
    surtout dans les verts ; l'erreur serait invisible à la lecture du code et
    seulement visible au mur.
    """
    c = (couleur or "").strip().lstrip("#")
    if len(c) != 6:
        raise ValueError("couleur attendue au format #RRGGBB")
    try:
        r, v, b = (int(c[i:i + 2], 16) / 255 for i in (0, 2, 4))
    except ValueError:
        raise ValueError("couleur attendue au format #RRGGBB")
    r, v, b = _lineaire(r), _lineaire(v), _lineaire(b)
    X = r * 0.664511 + v * 0.154324 + b * 0.162028
    Y = r * 0.283881 + v * 0.668433 + b * 0.047685
    Z = r * 0.000088 + v * 0.072310 + b * 0.986039
    somme = X + Y + Z
    if somme <= 0:
        # Le noir n'a pas de chromaticité. On rend le blanc D65 plutôt que de
        # diviser par zéro : demander « éteins la couleur » n'est pas une
        # erreur de l'appelant, c'est une demande sans objet.
        return (0.3127, 0.3290)
    return (round(X / somme, 4), round(Y / somme, 4))


def charge_pour(capacites, etat=None, couleur=None, luminosite=None) -> dict:
    """La charge utile MQTT, ou ValueError si l'appareil ne sait pas faire.

    REFUSER PLUTÔT QU'IGNORER. Un interrupteur à qui l'on envoie une couleur
    l'ignore en silence : la commande réussit, la lampe ne change pas, et
    l'appelant croit avoir agi. Ce silence-là coûte plus cher à déboguer que
    n'importe quel code d'erreur — on cherche le bug dans le réseau, dans le
    pont, dans la radio, partout sauf dans l'évidence qu'on a demandé à un
    interrupteur de devenir bleu.

    `capacites` vient du pont lui-même (les `features` de l'`expose`), pas
    d'une table de modèles tenue ici : deux références peuvent porter le même
    nom de modèle et n'exposer ni l'une ni l'autre la même chose.
    """
    caps = set(capacites or ())
    charge = {}

    if etat is not None:
        e = str(etat).upper()
        if e not in ("ON", "OFF", "TOGGLE"):
            raise ValueError("etat doit valoir ON, OFF ou TOGGLE")
        charge["state"] = e

    if couleur is not None:
        if "color_xy" not in caps:
            raise ValueError("cet appareil n'a pas de couleur")
        x, y = xy_depuis_hex(couleur)
        charge["color"] = {"x": x, "y": y}

    if luminosite is not None:
        if "brightness" not in caps:
            raise ValueError("cet appareil n'a pas de luminosite")
        try:
            lum = int(luminosite)
        except (TypeError, ValueError):
            raise ValueError("luminosite doit etre un entier de 1 a 254")
        if not 1 <= lum <= 254:
            raise ValueError("luminosite doit etre un entier de 1 a 254")
        charge["brightness"] = lum

    if not charge:
        raise ValueError("rien a commander : etat, couleur ou luminosite")
    return charge
