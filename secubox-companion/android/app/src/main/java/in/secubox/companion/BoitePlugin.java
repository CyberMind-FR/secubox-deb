// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package in.secubox.companion;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Companion 2.0 : pont entre les écrans locaux et la vue native de l'admin.
 *
 * ouvrir({origine})    : démarre BoxActivity (WebView sans pont natif) sur l'origine https.
 * navigateur({url})    : ouvre une adresse https dans le navigateur du téléphone.
 *
 * Retour d'échec : BoxActivity signale l'origine injoignable par {@link #signalerInjoignable},
 * en mémoire du processus (aucun intent exporté ne peut la forger) ; au retour de MainActivity
 * au premier plan, le WebView local passe sur #injoignable=<origine encodée>.
 */
@CapacitorPlugin(name = "Boite")
public class BoitePlugin extends Plugin {

    private static final Object VERROU = new Object();
    private static String injoignableEnAttente = null;

    /** Appelé par BoxActivity quand le premier chargement de la box échoue. */
    static void signalerInjoignable(String origine) {
        synchronized (VERROU) {
            injoignableEnAttente = origine;
        }
    }

    private static String prendreInjoignable() {
        synchronized (VERROU) {
            String o = injoignableEnAttente;
            injoignableEnAttente = null;
            return o;
        }
    }

    /** Origine https stricte (schéma, hôte, port), sans identifiants, chemin, requête ni fragment. */
    static String origineHttps(String brut) {
        if (brut == null || brut.isEmpty()) return null;
        Uri u = Uri.parse(brut);
        if (!"https".equalsIgnoreCase(u.getScheme())) return null;
        String hote = u.getHost();
        if (hote == null || hote.isEmpty()) return null;
        if (u.getUserInfo() != null) return null;
        String chemin = u.getPath();
        if (chemin != null && !chemin.isEmpty() && !"/".equals(chemin)) return null;
        if (u.getQuery() != null || u.getFragment() != null) return null;
        int port = u.getPort();
        String origine = "https://" + hote.toLowerCase(java.util.Locale.ROOT);
        if (port != -1 && port != 443) origine += ":" + port;
        return origine;
    }

    @PluginMethod
    public void ouvrir(PluginCall call) {
        String origine = origineHttps(call.getString("origine"));
        if (origine == null) {
            call.reject("origine https invalide");
            return;
        }
        Intent intent = new Intent(getContext(), BoxActivity.class);
        intent.putExtra(BoxActivity.EXTRA_ORIGINE, origine);
        try {
            getActivity().startActivity(intent);
        } catch (RuntimeException e) {
            call.reject("vue native indisponible");
            return;
        }
        JSObject res = new JSObject();
        res.put("joignable", true);
        call.resolve(res);
    }

    @PluginMethod
    public void navigateur(PluginCall call) {
        String url = call.getString("url");
        Uri u = url == null ? null : Uri.parse(url);
        if (u == null || !"https".equalsIgnoreCase(u.getScheme()) || u.getHost() == null || u.getHost().isEmpty()) {
            call.reject("adresse https requise");
            return;
        }
        Intent intent = new Intent(Intent.ACTION_VIEW, u);
        intent.addCategory(Intent.CATEGORY_BROWSABLE);
        try {
            getActivity().startActivity(intent);
        } catch (ActivityNotFoundException e) {
            call.reject("aucun navigateur");
            return;
        }
        call.resolve();
    }

    @Override
    protected void handleOnResume() {
        super.handleOnResume();
        String origine = prendreInjoignable();
        if (origine == null || getBridge() == null || getBridge().getWebView() == null) return;
        String cible = "https://localhost/#injoignable=" + Uri.encode(origine);
        getBridge().getWebView().post(() -> getBridge().getWebView().loadUrl(cible));
    }
}
