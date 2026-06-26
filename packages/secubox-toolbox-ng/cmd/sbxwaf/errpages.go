// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf :: errpages — graduated WAF response pages
//
// Task 3.2: ported from WARNING_PAGE (secubox_waf.py ~line 221) and the inline
// ban response (secubox_waf.py ~line 1068-1072).
//
// writeWarning — HTTP 403, cyberpunk-styled warning page with the
//
//	X-SecuBox-WAF: warning header.  The HTML comment
//	"<!-- sbxwaf-warning -->" acts as a machine-readable marker for tests
//	and log parsers.
//
// writeBan — HTTP 403, minimal ban page with X-SecuBox-WAF: banned header.
//
//	The HTML comment "<!-- sbxwaf-banned -->" is the machine-readable marker.
//
// Task 7.1: synthetic upstream error pages (502/503/504).
//
//	errorPage(code, host) — loads the embedded themed HTML template for the
//	given upstream error code (502/503/504), substitutes {host} and {time},
//	and returns the rendered bytes.  Faithful port of the error() hook in
//	secubox_waf.py (~line 1096):
//	  - Connection refused → 502 (ERROR_502_PAGE + {host}/{time} sub)
//	  - Timeout             → 504 (ERROR_502_PAGE with 502→504 / Bad Gateway→Gateway Timeout)
//	  - Other              → 503 (ERROR_503_PAGE, no {host} in the Python page)
//
//	writeErrorPage(w, code, host) — sets Content-Type + X-SecuBox-WAF header,
//	writes the status code, then writes errorPage output.
package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"net/http"
	"time"
)

// Embedded templates — verbatim copies of the Python secubox_waf.py pages.
//
//go:embed templates/error-502.html
var tmpl502 []byte

//go:embed templates/error-503.html
var tmpl503 []byte

//go:embed templates/error-504.html
var tmpl504 []byte

// errorPage returns the themed HTML body for the given upstream HTTP error code.
// host is substituted into {host} placeholders (both the 502 and 504 templates
// contain the upstream hostname in the error box).  The {time} placeholder is
// replaced with the current wall-clock time (HH:MM:SS), matching the Python
// error() hook behaviour.
//
// Unknown codes fall back to the 502 template (sane default — keeps tests
// forward-compatible if new codes are added later).
func errorPage(code int, host string) []byte {
	var tmpl []byte
	switch code {
	case 503:
		tmpl = tmpl503
	case 504:
		tmpl = tmpl504
	default: // 502 and any unknown code
		tmpl = tmpl502
	}

	now := time.Now().Format("15:04:05")
	out := bytes.ReplaceAll(tmpl, []byte("{host}"), []byte(host))
	out = bytes.ReplaceAll(out, []byte("{time}"), []byte(now))
	return out
}

// writeErrorPage writes a themed upstream error response.
// Maps the error code to the WAF header value and delegates to errorPage.
func writeErrorPage(w http.ResponseWriter, code int, host string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-SecuBox-WAF", fmt.Sprintf("error-%d", code))
	w.WriteHeader(code)
	_, _ = w.Write(errorPage(code, host))
}

// writeWarning writes a 403 cyberpunk-styled warning page.
// cat is the WAF category ID (e.g. "sqli") shown in the body.
// Faithful port of WARNING_PAGE from secubox_waf.py.
func writeWarning(w http.ResponseWriter, cat string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-SecuBox-WAF", "warning")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!DOCTYPE html>
<!-- sbxwaf-warning -->
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecuBox WAF - Security Alert</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #0a0a0f 0%%, #1a0a0f 100%%);
            color: #e8e6d9;
            font-family: "JetBrains Mono", monospace;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container { text-align: center; padding: 2rem; max-width: 800px; }
        .alert-icon {
            font-size: 6rem;
            margin-bottom: 1.5rem;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%%, 100%% { transform: scale(1); opacity: 1; }
            50%% { transform: scale(1.1); opacity: 0.8; }
        }
        h1 { color: #e63946; font-size: 2.5rem; margin-bottom: 1rem;
             text-shadow: 0 0 20px rgba(230, 57, 70, 0.5); }
        .warning-box {
            background: rgba(230, 57, 70, 0.1);
            border: 2px solid #e63946;
            border-radius: 12px;
            padding: 2rem;
            margin: 2rem 0;
        }
        .warning-text { color: #e63946; font-size: 1.2rem; margin-bottom: 1rem; }
        .details { color: #6b6b7a; font-size: 0.9rem; margin-top: 1rem; }
        .license-box {
            background: rgba(201, 168, 76, 0.1);
            border: 1px solid #c9a84c;
            border-radius: 8px;
            padding: 1.5rem;
            margin-top: 2rem;
            text-align: left;
        }
        .license-title { color: #c9a84c; font-size: 1rem; margin-bottom: 0.5rem; }
        .license-text { color: #6b6b7a; font-size: 0.75rem; line-height: 1.5; }
        .footer { margin-top: 2rem; color: #6b6b7a; font-size: 0.8rem; }
        .footer a { color: #c9a84c; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="alert-icon">&#x26A0;&#xFE0F;</div>
        <h1>SECURITY ALERT</h1>
        <div class="warning-box">
            <p class="warning-text">&#x1F6A8; Suspicious Activity Detected</p>
            <p>Your request contains patterns that match known attack signatures.</p>
            <p class="details">Category: %s</p>
            <p class="details">This incident has been logged and your IP address recorded.</p>
            <p class="details">Continued malicious activity will result in automatic IP ban.</p>
        </div>
        <div class="license-box">
            <p class="license-title">&#x1F4DC; SecuBox Security Notice</p>
            <p class="license-text">
                This system is protected by SecuBox WAF (Web Application Firewall).<br>
                All access attempts are monitored, logged, and may be reported to authorities.<br>
                Continued malicious activity will result in automatic IP ban.<br><br>
                &copy; 2024-2026 CyberMind Security Platform<br>
                ANSSI CSPN Candidate | https://secubox.in
            </p>
        </div>
        <p class="footer">
            Protected by <a href="https://cybermind.fr">CyberMind</a> |
            <a href="https://secubox.in">SecuBox</a>
        </p>
    </div>
</body>
</html>`, cat)
}

// writeBan writes a 403 IP banned response.
// Mirrors the inline ban response from secubox_waf.py lines 1068-1072.
func writeBan(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-SecuBox-WAF", "banned")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `<!DOCTYPE html>
<!-- sbxwaf-banned -->
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden | SecuBox WAF</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #0a0a0f;
            color: #e8e6d9;
            font-family: "JetBrains Mono", monospace;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container { text-align: center; padding: 2rem; max-width: 600px; }
        h1 { color: #e63946; font-size: 3rem; margin-bottom: 1rem; }
        p { color: #6b6b7a; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>&#x1F6AB; 403 Forbidden</h1>
        <p>Your IP has been banned.</p>
        <p>This incident has been reported to the security platform.</p>
        <p style="margin-top:2rem; font-size:0.8rem; color:#3a3a4a;">
            SecuBox WAF &mdash; ANSSI CSPN | <a href="https://secubox.in" style="color:#c9a84c;">secubox.in</a>
        </p>
    </div>
</body>
</html>`)
}
