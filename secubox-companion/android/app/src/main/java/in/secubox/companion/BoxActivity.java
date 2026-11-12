// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package in.secubox.companion;

import android.annotation.SuppressLint;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.webkit.CookieManager;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;
import java.util.Locale;

/**
 * Companion 2.0 : l'admin web d'une box, dans un WebView nu.
 *
 * Aucun pont natif : ni interface JavaScript, ni Capacitor. Le WebView ne connaît qu'une
 * origine (schéma, hôte, port) ; toute autre adresse http(s) part dans le navigateur du
 * téléphone, tout autre schéma est ignoré. Si la frame principale échoue au premier
 * chargement, l'activité se ferme et MainActivity affiche l'écran « injoignable ».
 */
public class BoxActivity extends AppCompatActivity {

    static final String EXTRA_ORIGINE = "origine";
    private static final String SUFFIXE_UA = " SecuBoxCompanion/2.0";

    private WebView vue;
    private Uri origine;
    private boolean premierChargementFait = false;
    private boolean enEchec = false;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle etat) {
        super.onCreate(etat);
        String o = BoitePlugin.origineHttps(getIntent().getStringExtra(EXTRA_ORIGINE));
        if (o == null) {
            finish();
            return;
        }
        origine = Uri.parse(o);

        vue = new WebView(this);
        WebSettings s = vue.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        s.setSupportMultipleWindows(false);
        s.setUserAgentString(s.getUserAgentString() + SUFFIXE_UA);

        CookieManager cookies = CookieManager.getInstance();
        cookies.setAcceptCookie(true);
        cookies.setAcceptThirdPartyCookies(vue, true);

        vue.setWebViewClient(new Client());
        setContentView(vue);

        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (vue.canGoBack()) vue.goBack();
                else finish();
            }
        });

        if (etat == null || vue.restoreState(etat) == null) {
            vue.loadUrl(o + "/");
        } else {
            premierChargementFait = true;
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle etat) {
        super.onSaveInstanceState(etat);
        if (vue != null) vue.saveState(etat);
    }

    @Override
    protected void onPause() {
        super.onPause();
        CookieManager.getInstance().flush();
    }

    @Override
    protected void onDestroy() {
        if (vue != null) {
            vue.stopLoading();
            vue.destroy();
            vue = null;
        }
        super.onDestroy();
    }

    private static int portEffectif(Uri u) {
        if (u.getPort() != -1) return u.getPort();
        if ("https".equalsIgnoreCase(u.getScheme())) return 443;
        if ("http".equalsIgnoreCase(u.getScheme())) return 80;
        return -1;
    }

    private boolean memeOrigine(Uri u) {
        if (u == null || u.getScheme() == null || u.getHost() == null) return false;
        return u.getScheme().equalsIgnoreCase(origine.getScheme())
            && u.getHost().toLowerCase(Locale.ROOT).equals(origine.getHost().toLowerCase(Locale.ROOT))
            && portEffectif(u) == portEffectif(origine);
    }

    /** true : la navigation est prise en charge ici (le WebView ne la suit pas). */
    private boolean intercepter(Uri u, boolean framePrincipale) {
        if (memeOrigine(u)) return false;
        String schema = u == null || u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        boolean web = "https".equals(schema) || "http".equals(schema);
        if (!framePrincipale) {
            // Sous-cadre d'une autre origine : https seulement, jamais de sortie de l'appli.
            return !"https".equals(schema);
        }
        if (web) {
            Intent intent = new Intent(Intent.ACTION_VIEW, u);
            intent.addCategory(Intent.CATEGORY_BROWSABLE);
            try {
                startActivity(intent);
            } catch (ActivityNotFoundException e) {
                // Aucun navigateur : on reste sur la page courante.
            }
        }
        // Tout autre schéma (intent:, file:, javascript:, content:, secubox:…) : ignoré.
        return true;
    }

    private void echec() {
        if (premierChargementFait || enEchec) return;
        enEchec = true;
        if (vue != null) vue.stopLoading();
        BoitePlugin.signalerInjoignable(origine.toString());
        finish();
    }

    private class Client extends WebViewClient {

        @Override
        public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest req) {
            return intercepter(req.getUrl(), req.isForMainFrame());
        }

        @Override
        @SuppressWarnings("deprecation")
        public boolean shouldOverrideUrlLoading(WebView v, String url) {
            // API 22-23 seulement : la surcharge à WebResourceRequest prend le relais ensuite.
            return intercepter(Uri.parse(url), true);
        }

        @Override
        public void onPageStarted(WebView v, String url, Bitmap favicon) {
            super.onPageStarted(v, url, favicon);
            // Une redirection vers une autre origine au premier chargement n'est pas l'admin.
            if (!premierChargementFait && !memeOrigine(Uri.parse(url))) {
                v.stopLoading();
                echec();
            }
        }

        @Override
        public void onPageFinished(WebView v, String url) {
            super.onPageFinished(v, url);
            if (!enEchec && memeOrigine(Uri.parse(url))) premierChargementFait = true;
        }

        @Override
        public void onReceivedError(WebView v, WebResourceRequest req, WebResourceError err) {
            if (req.isForMainFrame()) echec();
        }

        @Override
        @SuppressWarnings("deprecation")
        public void onReceivedError(WebView v, int code, String description, String url) {
            // API 22 seulement (au-delà, la surcharge à WebResourceRequest est appelée).
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) echec();
        }

        @Override
        public void onReceivedHttpError(WebView v, WebResourceRequest req, WebResourceResponse rep) {
            if (req.isForMainFrame() && rep != null && rep.getStatusCode() >= 500) echec();
        }

        @Override
        @SuppressLint("WebViewClientOnReceivedSslError")
        public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError err) {
            // Certificat refusé, toujours ; au premier chargement de l'origine, c'est un échec.
            handler.cancel();
            if (err != null && memeOrigine(Uri.parse(err.getUrl()))) echec();
        }
    }
}
