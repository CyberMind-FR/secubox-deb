# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Configuration normalisée → {chemin: texte}. Les commentaires reprennent l'explication des fichiers posés à la main sur gk2."""
import ipaddress

MARQUE = "GÉNÉRÉ par secubox-dns-lan"
ENTETE = ("# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
          "# GÉNÉRÉ par secubox-dns-lan — ne pas éditer à la main : modifier /etc/secubox/dns-lan.toml puis `secubox-dns-lan generate` (#1938).\n")

F_LAN = "96-secubox-lan.conf"
F_IPV6 = "96-secubox-lan-ipv6.conf"
F_VUE = "96-secubox-gk2-local.conf"
F_HOTES = "98-secubox-voicestudio-lan.conf"


def _lan(c: dict) -> str:
    t = ENTETE + "# secubox : Unbound sert le DNS des clients LAN (le DHCP annonce cette adresse).\nserver:\n"
    t += f"    interface: {c['interface']}\n"
    return t + "".join(f"    access-control: {a} allow\n" for a in c["acces"])


def _ipv6(c: dict) -> str:
    t = (ENTETE + "# DNS du LAN en IPv6 : la Freebox annonce son propre résolveur IPv6, qui répond l'IP publique pour les noms\n"
         "# internes (réservés au LAN). gk2 répond en IPv6 pour que le champ « DNS IPv6 personnalisé » de Freebox OS puisse le\n"
         "# désigner. Accès limité aux réseaux listés : jamais un résolveur ouvert.\nserver:\n    ip-freebind: yes\n")
    t += "".join(f"    interface: {i}\n" for i in c["interfaces"])
    return t + "".join(f"    access-control: {a} allow\n" for a in c["acces"])


def _vue(c: dict) -> str:
    z = c["zone"]
    return (ENTETE + "# Vue LOCALE des services de la box (split-horizon).\n"
            "# Sans elle, chaque nom du sous-domaine résout vers l'IP PUBLIQUE depuis le réseau local, alors que la box ne fait pas\n"
            "# de retour en épingle sur sa propre adresse publique : le nom est injoignable de l'intérieur. La réponse porte sur\n"
            "# TOUT le sous-domaine : un seul enregistrement couvre les services présents et à venir.\n"
            f'server:\n    local-zone: "{z}." redirect\n    local-data: "{z}. {"AAAA" if ":" in c["adresse"] else "A"} {c["adresse"]}"\n')


def _hotes(hs: list[dict]) -> str:
    t = (ENTETE + "# Machines du LAN atteintes DIRECTEMENT par les postes locaux. Les noms voisins gardent leur résolution\n"
         "# publique : seuls les noms listés sont redirigés.\nserver:\n")
    for h in hs:
        a = h["adresse"]
        genre = "AAAA" if ipaddress.ip_address(a).version == 6 else "A"
        t += f'    local-zone: "{h["nom"]}." transparent\n    local-data: "{h["nom"]}. {h["ttl"]} IN {genre} {a}"\n'
    return t


def _reseau(c: dict) -> str:
    return (ENTETE +
            "# Adresse IPv6 STABLE sur le LAN : celle que la Freebox annonce comme DNS IPv6. Fixe et sans durée de vie (contrairement à\n"
            "# l'adresse SLAAC). Si l'opérateur change le préfixe délégué, elle est à revoir.\n"
            f"[Address]\nAddress={c['stable']}\n")


def rendre(cfg: dict) -> dict[str, str]:
    """{chemin absolu: texte} des seuls fichiers dont la section existe dans la configuration."""
    d = cfg["dossier"].rstrip("/")
    sortie: dict[str, str] = {}
    if "lan" in cfg:
        sortie[f"{d}/{F_LAN}"] = _lan(cfg["lan"])
    if "ipv6" in cfg:
        sortie[f"{d}/{F_IPV6}"] = _ipv6(cfg["ipv6"])
        sortie[cfg["ipv6"]["dropin_reseau"]] = _reseau(cfg["ipv6"])
    if "vue_locale" in cfg:
        sortie[f"{d}/{F_VUE}"] = _vue(cfg["vue_locale"])
    if "hote" in cfg:
        sortie[f"{d}/{F_HOTES}"] = _hotes(cfg["hote"])
    return sortie
