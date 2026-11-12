// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package in.secubox.companion;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebView;
import com.getcapacitor.BridgeActivity;

/**
 * Companion 2.0 : écrans locaux (Capacitor) et réception du lien secubox://associer.
 *
 * Le lien est transmis tel quel, encodé, aux écrans locaux (#associer=…) : la validation
 * reste dans boites.js, rien n'est interprété ici. Le lien ne porte aucun secret.
 */
public class MainActivity extends BridgeActivity {

    private static final String ACCUEIL_ASSOCIER = "https://localhost/#associer=";

    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(BoitePlugin.class);
        super.onCreate(savedInstanceState);
        // Démarrage à froid : BridgeActivity.load() appelle onNewIntent(getIntent()) pendant
        // super.onCreate, le lien est donc déjà pris en charge ; rien à refaire ici.
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (intent == null) return;
        Uri lien = intent.getData();
        if (lien == null || !"secubox".equalsIgnoreCase(lien.getScheme())) return;
        // Consommé une fois : une recréation de l'activité ne rejoue pas le lien.
        Intent consomme = new Intent(intent);
        consomme.setData(null);
        setIntent(consomme);
        if (getBridge() == null) return;
        WebView vue = getBridge().getWebView();
        if (vue == null) return;
        String cible = ACCUEIL_ASSOCIER + Uri.encode(lien.toString());
        vue.post(() -> vue.loadUrl(cible));
    }
}
