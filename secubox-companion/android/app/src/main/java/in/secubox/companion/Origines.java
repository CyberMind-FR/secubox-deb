// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package in.secubox.companion;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Companion 2.0 : origines (schéma, hôte, port), en Java pur (java.net.URI, sans Android).
 *
 * Seule source de vérité native sur « quelle box » et « même origine » : BoitePlugin et
 * BoxActivity s'en servent, et les tests la compilent et l'exécutent hors Android.
 */
final class Origines {

    private static final Pattern HOTE_NOM = Pattern.compile("[a-z0-9.-]+");
    private static final Pattern HOTE_IPV6 = Pattern.compile("\\[[0-9a-f:.]+\\]");
    private static final Pattern SCHEMA = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]*");

    private Origines() {}

    private static URI lire(String brut) {
        if (brut == null || brut.isEmpty()) return null;
        try {
            return new URI(brut);
        } catch (URISyntaxException e) {
            return null;
        }
    }

    /**
     * Origine https stricte, normalisée en « https://hôte[:port] » (hôte en minuscules,
     * port 443 retiré) ; null si l'adresse porte des identifiants, un chemin autre que « / »,
     * une requête, un fragment, un port mal formé, un hôte hors [a-z0-9.-] ou IPv6, ou localhost.
     */
    static String origineHttps(String brut) {
        URI u = lire(brut);
        if (u == null || u.isOpaque() || !"https".equalsIgnoreCase(u.getScheme())) return null;
        String hote = u.getHost();
        String autorite = u.getRawAuthority();
        if (hote == null || autorite == null) return null;
        int port = u.getPort();
        // L'autorité doit être exactement « hôte » ou « hôte:port » : ni identifiants, ni « hôte: ».
        if (!autorite.equals(port == -1 ? hote : hote + ":" + port)) return null;
        if (port == 0 || port > 65535) return null;
        String chemin = u.getRawPath();
        if (chemin != null && !chemin.isEmpty() && !"/".equals(chemin)) return null;
        if (u.getRawQuery() != null || u.getRawFragment() != null) return null;
        hote = hote.toLowerCase(Locale.ROOT);
        if (!HOTE_NOM.matcher(hote).matches() && !HOTE_IPV6.matcher(hote).matches()) return null;
        String sansPoint = hote.endsWith(".") ? hote.substring(0, hote.length() - 1) : hote;
        if ("localhost".equals(sansPoint) || sansPoint.endsWith(".localhost")) return null;
        return port == -1 || port == 443 ? "https://" + hote : "https://" + hote + ":" + port;
    }

    /** Schéma en minuscules (« » si absent ou illisible), sans interpréter le reste. */
    static String schema(String url) {
        if (url == null) return "";
        int i = url.indexOf(':');
        if (i <= 0) return "";
        String s = url.substring(0, i);
        return SCHEMA.matcher(s).matches() ? s.toLowerCase(Locale.ROOT) : "";
    }

    private static int portEffectif(URI u) {
        if (u.getPort() != -1) return u.getPort();
        if ("https".equalsIgnoreCase(u.getScheme())) return 443;
        if ("http".equalsIgnoreCase(u.getScheme())) return 80;
        return -1;
    }

    /** true si url a le même schéma, hôte et port (ports par défaut compris) que origine. */
    static boolean memeOrigine(String origine, String url) {
        URI o = lire(origine);
        URI u = lire(url);
        if (o == null || u == null || o.isOpaque() || u.isOpaque()) return false;
        if (o.getScheme() == null || u.getScheme() == null) return false;
        if (o.getHost() == null || u.getHost() == null) return false;
        return o.getScheme().equalsIgnoreCase(u.getScheme())
            && o.getHost().toLowerCase(Locale.ROOT).equals(u.getHost().toLowerCase(Locale.ROOT))
            && portEffectif(o) == portEffectif(u);
    }
}
