// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox :: routage automatique .onion -> Tor. Tout le reste en DIRECT
// (l'inspection transparente wg-toolbox s'en charge déjà). SOCKS5 est requis
// pour que la résolution du nom .onion soit déléguée à Tor (remote DNS).
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.onion") || shExpMatch(host, "onion"))
        return "SOCKS5 192.168.1.200:9050";
    return "DIRECT";
}
