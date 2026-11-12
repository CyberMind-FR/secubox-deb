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
import android.view.ViewGroup;
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
import java.io.ByteArrayInputStream;
import java.util.Collections;

/**
 * Companion 2.0 : l'admin web d'une box, dans un WebView nu.
 *
 * Aucun pont natif : ni interface JavaScript, ni Capacitor. Le WebView ne connaît qu'une
 * origine (schéma, hôte, port) ; toute autre adresse http(s) part dans le navigateur du
 * téléphone, tout autre schéma est ignoré ; une navigation de la frame principale qui
 * échappe à shouldOverrideUrlLoading (POST d'un formulaire) est refusée en 403. Si la frame
 * principale échoue au premier chargement (erreur, HTTP >= 500, TLS, redirection vers une
 * autre origine), l'activité se ferme et MainActivity affiche l'écran « injoignable ».
 */
public class BoxActivity extends AppCompatActivity {

    static final String EXTRA_ORIGINE = "origine";
    private static final String SUFFIXE_UA = " SecuBoxCompanion/2.0";

    private WebView vue;
    private volatile String origine;
    private boolean premierChargementFait = false;
    private boolean enEchec = false;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle etat) {
        super.onCreate(etat);
        String o = Origines.origineHttps(getIntent().getStringExtra(EXTRA_ORIGINE));
        if (o == null) {
            finish();
            return;
        }
        origine = o;

        // Réglage global du processus : jamais d'inspection à distance de l'admin.
        WebView.setWebContentsDebuggingEnabled(false);
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
            if (vue.getParent() instanceof ViewGroup) ((ViewGroup) vue.getParent()).removeView(vue);
            vue.destroy();
            vue = null;
        }
        super.onDestroy();
    }

    private boolean memeOrigine(String url) {
        return Origines.memeOrigine(origine, url);
    }

    /** true : la navigation est prise en charge ici (le WebView ne la suit pas). */
    private boolean intercepter(Uri u, boolean framePrincipale) {
        String url = u == null ? null : u.toString();
        if (memeOrigine(url)) return false;
        if (framePrincipale && !premierChargementFait) {
            // Redirection (ou clic) vers une autre origine avant que l'admin ait chargé.
            echec();
            return true;
        }
        String schema = Origines.schema(url);
        if (!framePrincipale) {
            // Sous-cadre d'une autre origine : https seulement, jamais de sortie de l'appli.
            return !"https".equals(schema);
        }
        if ("https".equals(schema) || "http".equals(schema)) {
            Intent intent = new Intent(Intent.ACTION_VIEW, u);
            intent.addCategory(Intent.CATEGORY_BROWSABLE);
            try {
                startActivity(intent);
            } catch (ActivityNotFoundException e) {
                // Aucun navigateur : on reste sur la page courante.
            }
        }
        // Tout autre schéma qui arrive ici (intent:, file:, content:, data:, secubox:…) : ignoré.
        // Les URL javascript: ne passent pas par shouldOverrideUrlLoading : elles s'exécutent
        // dans la page courante, de la même origine, sans pont natif à atteindre.
        return true;
    }

    private void echec() {
        if (premierChargementFait || enEchec) return;
        enEchec = true;
        if (vue != null) vue.stopLoading();
        BoitePlugin.signalerInjoignable(origine);
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
        public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest req) {
            // Fil d'arrière-plan. Une navigation de la frame principale vers une autre origine
            // qui arrive ici a échappé à shouldOverrideUrlLoading (POST) : réponse vide 403.
            if (req.isForMainFrame() && !memeOrigine(req.getUrl().toString())) {
                return new WebResourceResponse("text/plain", "utf-8", 403, "Forbidden",
                    Collections.<String, String>emptyMap(), new ByteArrayInputStream(new byte[0]));
            }
            return null;
        }

        @Override
        public void onPageStarted(WebView v, String url, Bitmap favicon) {
            super.onPageStarted(v, url, favicon);
            if (memeOrigine(url)) return;
            v.stopLoading();
            if (!premierChargementFait) {
                // Une redirection vers une autre origine au premier chargement n'est pas l'admin.
                echec();
            } else if (v.canGoBack()) {
                v.goBack();
            } else {
                finish();
            }
        }

        @Override
        public void onPageCommitVisible(WebView v, String url) {
            super.onPageCommitVisible(v, url);
            if (!enEchec && memeOrigine(url)) premierChargementFait = true;
        }

        @Override
        public void onPageFinished(WebView v, String url) {
            super.onPageFinished(v, url);
            if (!enEchec && memeOrigine(url)) premierChargementFait = true;
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
            if (err != null && memeOrigine(err.getUrl())) echec();
        }
    }
}
